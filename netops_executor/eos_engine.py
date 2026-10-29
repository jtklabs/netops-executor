"""Unattended Arista EOS upgrades over SSH. Ambiguous writes are never replayed.

The switch boots one .swi image through EOS's native install mode
(`install source flash:<image> now reload`), never a hand-set boot variable. An MLAG peer
is a separate job; `mlag_peer` reserves it so the two never reload together.
"""

import hashlib
import time
from datetime import datetime, timezone
from functools import partial

from .config import under
from .eos import Eos, normalized
from .eos_models import EosUpgradeRequest
from .image_cache import cached_image
from .ssh import DeviceError, digest
from .stepped import StepRunner

COUNTS = {"routes": "min_route_percent", "mac": "min_mac_percent", "arp": "min_arp_percent"}
# Baseline values that mean an object carries traffic and must recover after the reload.
RESTORED = {
    "interfaces": {"connected"},
    "bgp_peers": {"established"},
    "ospf_neighbors": {"full"},
    "port_channels": {"active"},
}


def compare(baseline, current, policy, restored=RESTORED, counts=COUNTS, informational=()):
    """Critical failures, reportable differences and metrics for two traffic snapshots.

    Count categories must stay at their policy minimum, restored categories must bring back
    every object that carried traffic, informational ones only report changes, and every
    other category is compared object by object.
    """
    critical, findings, metrics = [], [], {}
    skipped = set(baseline.get("gaps", []))
    for category in [c for c in baseline if c != "gaps"]:
        if category in skipped:
            continue
        if category in current.get("gaps", []):
            critical.append(category + " could not be collected after the upgrade")
            continue
        before, after = baseline[category], current[category]
        if category in counts:
            minimum = getattr(policy, counts[category])
            percent = 100 * after / before if before else 100
            metrics[category + "_percent"] = round(percent, 1)
            if minimum is not None and percent < minimum:
                critical.append(f"{category} count {after} is below {minimum}% of {before}")
            continue
        if category in informational:
            changed = sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k))
            if changed:
                findings.append({"category": category, "change": "state changed", "objects": changed[:100]})
            continue
        up = restored.get(category)

        def lost_object(key, value):
            if up:
                return value in up and after.get(key) not in up
            # An LLDP neighbor is restored when the same device and port appear on that port again.
            return after.get(key) != value

        lost = sorted(k for k, v in before.items() if lost_object(k, v))
        changed = sorted(
            k for k in set(before) | set(after) if before.get(k) != after.get(k) and k not in lost
        )
        if lost:
            if policy.restore_required:
                critical.append(category + " not restored: " + ", ".join(lost[:20]))
            else:
                findings.append({"category": category, "change": "not restored", "objects": lost[:100]})
        if changed:
            findings.append({"category": category, "change": "state changed", "objects": changed[:100]})
    return critical, findings, metrics


def mlag_problems(mlag):
    if mlag["state"] == "disabled":
        return []
    problems = []
    if mlag["state"] != "active":
        problems.append("MLAG state is " + mlag["state"])
    if mlag["neg_status"] != "connected":
        problems.append("MLAG negotiation is " + (mlag["neg_status"] or "unknown"))
    if mlag["peer_link"] != "up":
        problems.append("MLAG peer link is " + (mlag["peer_link"] or "unknown"))
    if mlag["config_sanity"] not in ("", "consistent"):
        problems.append("MLAG configuration sanity is " + mlag["config_sanity"])
    return problems


class EosRunner(StepRunner):
    device_errors = (DeviceError,)
    error = DeviceError

    def __init__(
        self, settings, store, job, worker, eos=None, peer=None, sleep=time.sleep, clock=time.monotonic
    ):
        super().__init__(settings, store, job, worker, sleep, clock)
        self.eos, self.peer = eos, peer

    def setup(self):
        r = self.request = EosUpgradeRequest.model_validate(self.job["request"])
        self.device = self.settings.device(r.device)
        if self.eos is None:
            self.eos = Eos(self.settings, self.device, self.guard, r.credential_profiles, self.audit)
        if r.mlag_peer and self.peer is None:
            self.peer = Eos(
                self.settings,
                self.settings.device(r.mlag_peer),
                self.guard,
                r.credential_profiles,
                lambda data: self.audit({**data, "connection": "mlag_peer"}),
            )

    def reserve(self):
        r = self.request
        keys = [self.job["lock_key"], "endpoint:" + self.device.host]
        if r.mlag_peer:
            peer = self.settings.device(r.mlag_peer)
            # The same keys F5, SSH and EOS jobs take for that switch, so the peer cannot reload now.
            keys += ["device:" + peer.id, "endpoint:" + peer.host] + (
                ["group:" + peer.lock_group] if peer.lock_group else []
            )
        if not self.store.reserve(self.job["id"], self.worker, keys):
            if self.result.get("mutations"):
                raise DeviceError("reservation changed during continuation")
            self.store.defer(self.job["id"], self.worker)
        self.event("resources_reserved", keys=keys)

    def config_hash(self):
        return hashlib.sha256(normalized(self.eos.running_config()).encode()).hexdigest()

    def prevalidate(self):
        r = self.request
        info = self.eos.version()
        boot = self.eos.boot_image()
        self.result["source"] = {**info, "boot_image": boot}
        if r.approved_models and info["model"] not in r.approved_models:
            raise DeviceError("hardware model is not approved: " + info["model"])
        on_target = info["version"] == r.target_version
        if not on_target and info["version"] not in r.allowed_source_versions:
            raise DeviceError("running version " + info["version"] + " is outside allowed_source_versions")
        if on_target and boot != r.image.name and not r.stage_only:
            raise DeviceError(
                "running the target, but boot-config points at " + boot + "; a reload would not boot it"
            )
        self.result["upgrade_needed"] = not on_target
        mlag = self.eos.mlag()
        self.result["mlag"] = mlag
        if not r.stage_only and not on_target:
            problems = mlag_problems(mlag)
            if problems:
                raise DeviceError(problems[0])
            self.check_peer()
        self.result["rollback"] = {"version": info["version"], "boot_image": boot}
        self.result["pre_validation"] = (
            {}
            if r.stage_only
            else {
                "traffic": self.eos.traffic(),
                "config_sha256": self.config_hash(),
                "unsaved": self.eos.unsaved(),
            }
        )
        self.event("pre_validation_completed", upgrade_needed=not on_target)

    def check_peer(self):
        """The MLAG peer must be healthy from its own side before this switch reloads."""
        if not self.peer:
            return
        mlag = self.peer.mlag()
        self.result["mlag_peer"] = mlag
        problems = mlag_problems(mlag)
        if mlag["state"] == "disabled":
            problems.append("MLAG is disabled on the configured peer")
        if problems:
            raise DeviceError("MLAG peer " + self.request.mlag_peer + ": " + problems[0])

    def backup(self):
        r = self.request
        directory = under(self.settings.backup_root, r.backup_directory or "eos/" + self.device.id)
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        prefix = self.job["id"] + "-" + self.device.id
        if r.config_backup:
            path = directory / (prefix + "-running-config.txt")
            self.write_private(path, self.eos.running_config().encode())
            self.artifact(self.device.id, "config", path, "eos-running-config")
        if r.tech_support:
            self.report("tech_support", self.device.id)
            path = directory / (prefix + "-tech-support.txt")
            self.write_private(path, self.eos.tech_support().encode())
            self.artifact(self.device.id, "tech_support", path)

    def stage(self):
        r, image = self.request, self.request.image
        self.checkpoint()
        free, size = self.eos.flash(image.name)
        software = self.result["software"] = {"image": image.name, "already_on_flash": size is not None}
        expected = image.sha512
        local = None
        if size is None or expected is None:
            self.report("image_cache", self.device.id, file=image.name)
            local = cached_image(self.settings, image, self.job["id"], self.checkpoint)
            if not local.is_file() or digest(local) != image.sha256:
                raise DeviceError("executor image missing or SHA-256 mismatch: " + image.name)
            expected = expected or digest(local, "sha512")
        if size is None:
            needed = local.stat().st_size + r.minimum_free_bytes
            if free < needed:
                raise DeviceError(f"insufficient flash space: {free} bytes free, {needed} required")

            def sent(done, total, file=image.name):
                self.report(
                    "upload",
                    self.device.id,
                    min(100, 100 * done / total) if total else 0,
                    force=done >= total,
                    file=file,
                    bytes=min(done, total),
                    total_bytes=total,
                )
                self.checkpoint()

            self.event("software_upload_started", file=image.name, bytes=local.stat().st_size)
            self.eos.upload(local, image.name, sent)
            software["uploaded"] = True
            self.event("software_upload_completed", file=image.name)
        self.report("image_verification", self.device.id, file=image.name)
        if self.eos.sha512(image.name) != expected:
            raise DeviceError("flash:" + image.name + " SHA-512 does not match the approved image")
        software["sha512_verified"] = True
        self.event("software_staged", file=image.name)

    def save(self):
        if not self.eos.unsaved():
            return
        if not self.request.save_config:
            raise DeviceError("running and startup configuration differ and save_config is false")
        self.event("write_memory_started")
        self.eos.save()
        if self.eos.unsaved():
            raise DeviceError("running and startup configuration still differ after write memory")
        # write memory changes startup-config only; the running baseline stays as captured.
        self.event("write_memory_completed")

    def install(self):
        r = self.request
        self.checkpoint()
        # Refuse a stale authorization: nothing may have changed since the baseline.
        info = self.eos.version()
        if info["version"] != self.result["source"]["version"]:
            raise DeviceError("software changed since precheck; rerun required")
        if self.config_hash() != self.result["pre_validation"]["config_sha256"]:
            raise DeviceError("configuration changed since precheck; rerun required")
        problems = mlag_problems(self.eos.mlag())
        if problems:
            raise DeviceError(problems[0])
        self.check_peer()
        self.result["install"] = {"image": r.image.name, "status": "started"}
        self.result["reboot_requested_at"] = datetime.now(timezone.utc).isoformat()
        start = self.clock()
        self.intent("install_reload", image=r.image.name)
        try:
            self.eos.install_reload(r.image.name, r.install_timeout)
        except Exception:
            # The reload drops the session. Only a new boot on the target verifies it happened.
            self.event("install_response_uncertain")
        self.eos.close()
        deadline = start + r.reboot_timeout
        while self.clock() < deadline:
            self.wait(15)
            self.report(
                "reboot",
                self.device.id,
                elapsed_seconds=round(self.clock() - start),
                timeout_seconds=r.reboot_timeout,
                status="waiting for a new boot on " + r.target_version,
            )
            try:
                info = self.eos.version()
            except DeviceError:
                self.eos.close()
                continue
            uptime = info["uptime_seconds"]
            if (
                info["version"] == r.target_version
                and uptime is not None
                and uptime <= self.clock() - start + 120
            ):
                self.result["install"]["status"] = "completed"
                self.result["boot_verified"] = {"version": info["version"], "uptime_seconds": uptime}
                self.event("reboot_completed")
                return
        raise DeviceError("a new boot on the target version was not verified before timeout")

    def system_sample(self):
        r = self.request
        critical, findings = [], []
        info = self.eos.version()
        if info["version"] != r.target_version:
            critical.append("running version is " + info["version"])
        source = self.result["source"]
        if (info["model"], info["mac"]) != (source["model"], source["mac"]):
            critical.append("a different switch answered after the reload")
        boot = self.eos.boot_image()
        if boot != r.image.name:
            critical.append("boot-config points at " + boot)
        if self.eos.unsaved():
            findings.append({"category": "config", "change": "running and startup configuration differ"})
        if self.config_hash() != self.result["pre_validation"]["config_sha256"]:
            findings.append(
                {"category": "config", "change": "running configuration changed across the upgrade"}
            )
        cause = self.eos.reload_cause()
        if cause and "requested by the user" not in cause.lower():
            findings.append({"category": "reload_cause", "change": cause[:200]})
        self.result["post_system"] = info
        return critical, findings

    def traffic_sample(self):
        critical = []
        if self.result["mlag"]["state"] != "disabled":
            # A pair that was in MLAG must come back active, with the peer link up.
            mlag = self.eos.mlag()
            critical += mlag_problems(mlag) if mlag["state"] != "disabled" else ["MLAG is disabled"]
        current = self.eos.traffic()
        failures, findings, metrics = compare(
            self.result["pre_validation"]["traffic"], current, self.request.validation_policy
        )
        self.result["post_validation"] = {"traffic": current, "metrics": metrics}
        return critical + failures, findings

    def planned_steps(self):
        r = self.request
        if not self.result["upgrade_needed"]:
            if r.stage_only:
                return []
            self.result["already_on_target"] = True
            return [("validate_current", lambda: self.validate("validate_current", self.traffic_sample))]
        steps = [] if r.stage_only or not (r.config_backup or r.tech_support) else [("backup", self.backup)]
        steps.append(("stage", self.stage))
        if r.stage_only:
            return steps
        return steps + [
            ("save_config", self.save),
            ("install_reload", self.install),
            ("settle", self.settle),
            ("validate_system", lambda: self.validate("validate_system", self.system_sample)),
            ("validate_traffic", partial(self.validate, "validate_traffic", self.traffic_sample)),
        ]

    def upgrade(self):
        self.setup()
        r = self.request
        self.reserve()
        self.checkpoint()
        self.decision = self.store.apply_decision(self.job["id"], self.worker)
        self.result["plan"] = r.plan()
        self.step("prevalidate", self.prevalidate)
        steps = self.planned_steps()
        progress = self.result.setdefault("progress", {})
        done = len(self.result["completed_steps"])
        progress.update(steps_total=done + sum(key not in self.result["completed_steps"] for key, _ in steps))
        progress.update(steps_completed=done, percent=round(100 * done / progress["steps_total"]))
        for key, action in steps:
            self.step(key, action)
        if r.stage_only:
            self.result["preloaded"] = True
            return
        self.result["validated_version"] = r.target_version
        self.result["validation_accepted"] = True

    def unsafe(self):
        # A started install may have rewritten boot-config or reloaded into an unvalidated image.
        return self.result.get("install", {}).get("status") in ("started", "completed")

    def close(self):
        for client in (self.eos, self.peer):
            if client is not None:
                client.close()
