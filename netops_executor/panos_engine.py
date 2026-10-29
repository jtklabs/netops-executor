"""Unattended PAN-OS upgrades through Panorama. Ambiguous writes are never replayed.

An HA pair is one unit of work: a job for either member upgrades both, one at a time.
"""

import math
import os
import time
from datetime import datetime, timezone
from functools import partial

from .config import HTTPTarget, under
from .device import BigIP
from .image_cache import cached_image
from .panos import (
    FUNCTIONAL,
    HA_ELECTION,
    RESTART,
    SUSPEND,
    Firewall,
    Panorama,
    PanosError,
    PanosUnavailable,
    download,
    install,
    repository_download,
    repository_upload,
)
from .panos_models import PanosUpgradeRequest, feature_release, version_key
from .ssh import SSH, DeviceError, digest
from .store import CancelRequested, Deferred, LostOwnership, NeedsReview

TRAFFIC_CATEGORIES = ("interfaces", "routes", "bgp_peers", "ipsec_tunnels", "sessions", "arp")
# Values that mean an object carries traffic; baseline objects in this state must recover.
RESTORED = {"interfaces": {"up"}, "bgp_peers": {"established"}, "ipsec_tunnels": {"active"}}


def compare(baseline, current, policy):
    """Return critical failures, reportable differences and metrics for two traffic snapshots."""
    critical, findings, metrics = [], [], {}
    skipped = set(baseline.get("gaps", []))
    for category in TRAFFIC_CATEGORIES:
        if category in skipped:
            continue
        if category in current.get("gaps", []):
            critical.append(category + " could not be collected after the upgrade")
            continue
        before, after = baseline[category], current[category]
        if category in RESTORED:
            up = RESTORED[category]
            lost = sorted(k for k, v in before.items() if v in up and after.get(k) not in up)
            changed = sorted(
                k for k in set(before) | set(after) if before.get(k) != after.get(k) and k not in lost
            )
            if lost:
                item = category + " not restored: " + ", ".join(lost[:20])
                if policy.restore_required:
                    critical.append(item)
                else:
                    findings.append({"category": category, "change": "not restored", "objects": lost[:100]})
            if changed:
                findings.append({"category": category, "change": "state changed", "objects": changed[:100]})
        elif category == "routes":
            removed, added = sorted(set(before) - set(after)), sorted(set(after) - set(before))
            percent = 100 * len(after) / len(before) if before else 100
            metrics["route_percent"] = round(percent, 1)
            if policy.min_route_percent is not None and percent < policy.min_route_percent:
                critical.append(
                    f"route count {len(after)} is below {policy.min_route_percent}% of {len(before)}"
                )
            if removed:
                findings.append({"category": "routes", "change": "removed", "objects": removed[:100]})
            if added:
                findings.append({"category": "routes", "change": "added", "objects": added[:100]})
        else:
            minimum = policy.min_session_percent if category == "sessions" else policy.min_arp_percent
            percent = 100 * after / before if before else 100
            metrics[category + "_percent"] = round(percent, 1)
            # Counts always move; they only fail an explicit threshold.
            if minimum is not None and percent < minimum:
                critical.append(f"{category} count {after} is below {minimum}% of {before}")
    return critical, findings, metrics


def functional(state):
    return state in ("active", "passive") or state.startswith("active-")


def staged(member):
    """True once a member may boot or run software that was not validated: an install or reboot."""
    return bool(
        member.get("reboot_requested_at")
        or member.get("install", {}).get("status") in ("started", "completed")
    )


def unsynchronized(states):
    """Running configuration is out of sync on a member that has HA config sync enabled."""
    return any(h["sync_enabled"] != "no" and h["running_sync"] != "synchronized" for h in states)


def carries(state):
    """Active/passive "active", or "active-primary"/"active-secondary" in active/active."""
    return state == "active" or state.startswith("active-")


class PanosRunner:
    def __init__(
        self, settings, store, job, worker, panorama=None, sleep=time.sleep, clock=time.monotonic, f5=None
    ):
        self.settings, self.store, self.job, self.worker = settings, store, job, worker
        self.sleep, self.clock = sleep, clock
        self.result = job["result"]
        self.phase = "connect"
        self.request = self.decision = None
        self.panorama = panorama
        self.firewalls = {}
        self.direct_clients = {}
        self.f5_device = f5
        self.last_report = float("-inf")

    def setup(self):
        # Inside run(): a removed Panorama target or credential fails this job, never the worker.
        self.request = PanosUpgradeRequest.model_validate(self.job["request"])
        if self.panorama is None:
            if self.request.panorama not in self.settings.http_targets:
                raise PanosError("Panorama HTTP target is not configured: " + self.request.panorama)
            self.panorama = Panorama(
                self.settings,
                self.store,
                self.request.panorama,
                self.request.credential_profiles,
                self.guard,
                self.audit,
            )

    def fw(self, serial):
        if serial not in self.firewalls:
            self.firewalls[serial] = Firewall(self.panorama, serial)
        return self.firewalls[serial]

    def guard(self):
        self.store.guard(self.job["id"], self.worker)

    def checkpoint(self):
        self.store.checkpoint(self.job["id"], self.worker)

    def audit(self, data):
        self.store.credential_event(self.job["id"], self.worker, {**data, "phase": self.phase})

    def event(self, step, **data):
        self.phase = step
        self.store.record(self.job["id"], self.worker, step, data, self.result)

    def intent(self, step, **data):
        # Persist BEFORE issuing a disruptive write. An interrupted operation is never replayed.
        self.result.setdefault("mutations", []).append(step)
        self.event(step + "_started", **data)

    def wait(self, seconds):
        self.guard()
        self.sleep(seconds)
        self.guard()

    @property
    def ha(self):
        return self.result["ha"]

    @property
    def members(self):
        return self.ha["members"]

    def member(self, serial):
        return self.result.setdefault("members", {}).setdefault(serial, {})

    def peer_of(self, serial):
        return next(s for s in self.members if s != serial)

    def version(self, serial):
        member = self.member(serial)
        return member.get("boot_verified", {}).get("version") or member["source"]["version"]

    def step(self, key, action):
        """Run each named step once; a review continuation resumes after the completed ones."""
        done = self.result.setdefault("completed_steps", [])
        if key in done:
            return
        progress = self.result.setdefault("progress", {})
        progress.update(step=key, operation=None)
        action()
        done.append(key)
        total = progress.get("steps_total")
        progress.update(
            steps_completed=len(done),
            percent=round(100 * len(done) / total) if total else None,
            operation=None,
        )
        self.event("step_completed", name=key)

    def report(self, kind, serial=None, percent=None, force=False, **detail):
        """Expose the current operation in result.progress for pollers.

        Saved at most every five seconds, or when the operation or its whole percent changes.
        """
        progress = self.result.setdefault("progress", {})
        previous = progress.get("operation") or {}
        operation = {
            "kind": kind,
            "serial": serial,
            "percent": None if percent is None else round(percent, 1),
        }
        progress["operation"] = {**operation, **detail}
        progress["updated_at"] = datetime.now(timezone.utc).isoformat()
        changed = (previous.get("kind"), previous.get("serial")) != (kind, serial) or (
            percent is not None and int(percent) != int(previous.get("percent") or -1)
        )
        if force or changed or self.clock() - self.last_report >= 5:
            self.last_report = self.clock()
            self.store.record(self.job["id"], self.worker, "progress", progress["operation"], self.result)

    def take(self, phase):
        """Consume the operator decision for the gate this phase opened, if any."""
        if not self.decision or self.decision["phase"] != phase:
            return None
        decision, self.decision = self.decision, None
        action = decision["decision"]["action"]
        if action == "accept":
            self.result.setdefault("manual_validations", []).append({**decision["decision"], "phase": phase})
            self.event("manual_validation_applied", gate_id=decision["id"], phase=phase)
        return action

    def unsafe(self):
        # A staged image boots on the next restart; a suspended unit carries no traffic.
        members = self.result.get("members", {}).values()
        return (
            any(m.get("suspended") or staged(m) for m in members)
            or any(p["current"] != p["original"] for p in self.result.get("preemption", {}).values())
            or self.f5_drained()
        )

    def reserve(self):
        self.phase = "discover_ha"
        serial = self.request.serial
        # A review continuation keeps its recorded pair: a suspended or rebooting unit may be
        # unreachable, and validation samples recheck HA state anyway.
        topology = self.result.get("ha")
        if topology is None:
            entry = self.panorama.device(serial)
            if entry is None:
                raise PanosError("firewall is not managed by this Panorama")
            if not entry["connected"]:
                raise PanosError("firewall is not connected to Panorama")
            ha = self.fw(serial).ha_state()
            peer = entry["ha_peer"] if ha["enabled"] else None
            if ha["enabled"] and not peer:
                raise PanosError("HA is enabled but Panorama does not report the peer serial")
            topology = {
                "enabled": ha["enabled"],
                "peer": peer,
                "mode": ha["mode"],
                "members": [serial, peer] if peer else [serial],
            }
        peer = topology["peer"]
        keys = [self.job["lock_key"], "panos:" + serial]
        if peer:
            keys += ["panos:" + peer, "panos-ha:" + ":".join(sorted((serial, peer)))]
        if self.request.f5_drain:
            # The same keys F5 upgrade, SSH and HTTP jobs take, so none can overlap the drain.
            f5 = self.settings.device(self.request.f5_drain.device)
            keys += ["device:" + f5.id, "endpoint:" + f5.host] + (
                ["group:" + f5.lock_group] if f5.lock_group else []
            )
        if not self.store.reserve(self.job["id"], self.worker, keys):
            if self.result.get("mutations"):
                raise PanosError("reservation changed during continuation")
            self.store.defer(self.job["id"], self.worker)
        self.result["ha"] = topology
        self.event("resources_reserved", keys=keys)

    def traffic(self, firewall):
        data, gaps = {}, []
        for category, read in (
            ("interfaces", firewall.interfaces),
            ("routes", firewall.routes),
            ("bgp_peers", firewall.bgp_peers),
            ("ipsec_tunnels", firewall.tunnels),
            ("sessions", firewall.session_count),
            ("arp", firewall.arp_count),
        ):
            try:
                data[category] = read()
            except PanosUnavailable:
                raise
            except PanosError:
                # An unsupported or unconfigured feature is an explicit gap, never an empty pass.
                gaps.append(category)
        data["gaps"] = gaps
        return data

    def wait_for_jobs(self, firewall):
        deadline = self.clock() + self.request.job_wait_timeout
        while True:
            running = [j for j in firewall.jobs() if j["status"] in ("ACT", "PEND")]
            if not running:
                return
            if self.clock() >= deadline:
                raise PanosError(
                    firewall.serial + " jobs are still running: " + ", ".join(j["type"] for j in running)
                )
            self.event(
                "waiting_for_firewall_jobs",
                serial=firewall.serial,
                jobs=[{"id": j["id"], "type": j["type"]} for j in running],
            )
            self.checkpoint()
            self.wait(15)

    def precheck(self, serial):
        r = self.request
        firewall = self.fw(serial)
        info = firewall.system_info()
        if info["serial"] and info["serial"] != serial:
            raise PanosError(serial + " reported a different serial")
        if info["operational_mode"] not in ("", "normal"):
            raise PanosError(serial + " operational mode is " + info["operational_mode"])
        entry = self.panorama.device(serial)
        if not entry or not entry["connected"]:
            raise PanosError(serial + " is not connected to Panorama")
        self.member(serial)["source"] = {
            "version": info["sw_version"],
            "model": info["model"],
            "hostname": info["hostname"],
            "app_version": info["app_version"],
            "threat_version": info["threat_version"],
            "av_version": info["av_version"],
            "family": r.software_family or entry["family"],
        }
        self.member(serial)["address"] = r.management_addresses.get(serial) or entry.get("address", "")
        if r.approved_models and info["model"] not in r.approved_models:
            raise PanosError(serial + " hardware model is not approved: " + info["model"])
        if info["sw_version"] != r.target_version:
            if r.software_source == "executor" and not self.member(serial)["address"]:
                raise PanosError("no management address for " + serial + "; set management_addresses")
            if info["sw_version"] not in r.allowed_source_versions:
                raise PanosError(
                    serial + " running version " + info["sw_version"] + " is outside allowed_source_versions"
                )
            if r.software_source == "panorama" and not self.member(serial)["source"]["family"]:
                raise PanosError(
                    "Panorama did not report the platform family of " + serial + "; set software_family"
                )
        if not firewall.chassis_ready():
            raise PanosError(serial + " chassis is not ready")
        self.wait_for_jobs(firewall)
        # A preload only stages files; uncommitted changes matter for the upgrade itself.
        if not r.stage_only and firewall.pending_changes():
            raise PanosError(serial + " has uncommitted local changes")

    def ha_preflight(self, strict=True):
        states = {s: self.fw(s).ha_state() for s in self.members}
        mode = states[self.request.serial]["mode"]
        problems = []
        if mode not in ("active-passive", "active-active"):
            problems.append("unsupported HA mode: " + (mode or "unknown"))
        for serial, ha in states.items():
            if not ha["enabled"]:
                problems.append(serial + " does not report HA enabled")
            if ha["peer_conn"] != "up":
                problems.append(serial + " HA peer connection is not up")
            self.member(serial).update(role=ha["local"], preemptive=ha["preemptive"])
        roles = sorted(ha["local"] for ha in states.values())
        if mode == "active-passive" and roles != ["active", "passive"]:
            problems.append("active/passive HA requires one active and one passive member")
        if mode == "active-active" and not all(r.startswith("active-") for r in roles):
            problems.append("active/active HA requires both members active")
        same = len({self.version(s) for s in self.members}) == 1
        if same and self.request.ha_policy.require_running_sync and unsynchronized(states.values()):
            problems.append("HA running configuration is not synchronized")
        if problems and strict:
            raise PanosError(problems[0])
        if problems:
            # Staging never touches HA state; the upgrade job enforces these again.
            self.event("ha_preflight_warnings", problems=problems)
        self.ha["config_sync"] = (
            "disabled" if any(h["sync_enabled"] == "no" for h in states.values()) else "enabled"
        )
        self.ha["mode"] = mode
        self.event("ha_preflight_completed", roles={s: ha["local"] for s, ha in states.items()})

    def baseline(self):
        if not self.ha["enabled"]:
            return {self.request.serial: self.traffic(self.fw(self.request.serial))}
        if self.ha["mode"] == "active-passive":
            # Only the active member carries traffic; it is the pair's reference.
            active = next(s for s in self.members if self.member(s)["role"] == "active")
            return {"pair": self.traffic(self.fw(active)), "pair_source": active}
        return {s: self.traffic(self.fw(s)) for s in self.members}

    def upgrade_plan(self):
        r = self.request
        pending = [s for s in self.members if self.version(s) != r.target_version]
        if not self.ha["enabled"]:
            return [{"serial": s, "handoff": False} for s in pending]
        standby_first = r.ha_policy.upgrade_order == "standby_first"

        def rank(serial):
            standby = self.member(serial)["role"] in ("passive", "active-secondary")
            return 0 if standby == standby_first else 1

        plan = []
        for index, serial in enumerate(sorted(pending, key=rank)):
            # Only a passive member upgraded before any failover moves no traffic when suspended.
            quiet = (
                self.ha["mode"] == "active-passive"
                and self.member(serial)["role"] == "passive"
                and index == 0
            )
            plan.append({"serial": serial, "handoff": not quiet})
        return plan

    def f5(self):
        if self.f5_device is None:
            drain = self.request.f5_drain
            self.f5_device = BigIP(
                SSH(
                    self.settings,
                    self.settings.device(drain.device),
                    self.guard,
                    drain.credential_profiles,
                    lambda data: self.audit({**data, "connection": "f5_drain"}),
                )
            )
        return self.f5_device

    def f5_drained(self):
        return bool(self.result.get("f5_drain", {}).get("pending_restore"))

    def f5_selected(self, states):
        wanted = self.request.f5_drain.addresses
        # Recursive listings name addresses relative to "/"; requests use absolute paths.
        states = {"/" + a.lstrip("/"): enabled for a, enabled in states.items()}
        missing = [a for a in wanted if a not in states]
        if missing:
            raise PanosError("F5 virtual addresses not found: " + ", ".join(missing[:20]))
        return {a: e for a, e in states.items() if not wanted or a in wanted}

    def f5_precheck(self):
        drain = self.request.f5_drain
        if not drain:
            return
        if self.ha["enabled"]:
            raise PanosError("f5_drain applies to standalone firewalls")
        f5 = self.f5()
        topology = f5.topology()
        if topology["cluster"]:
            raise PanosError("f5_drain requires a standalone F5; " + drain.device + " is clustered")
        if topology["role"] != "active":
            raise PanosError("F5 " + drain.device + " is not active")
        f5.check_drain()
        states = self.f5_selected(f5.address_states())
        self.result["f5_drain"] = {
            "device": drain.device,
            "address_states": states,
            "to_disable": sorted(a for a, enabled in states.items() if enabled),
            "changed_addresses": [],
            "pending_restore": [],
            "restored": False,
        }
        self.event(
            "f5_precheck_completed", device=drain.device, enabled=len(self.result["f5_drain"]["to_disable"])
        )

    def f5_drain(self):
        drain, state = self.request.f5_drain, self.result["f5_drain"]
        f5 = self.f5()
        self.checkpoint()
        f5.check_drain()
        current = self.f5_selected(f5.address_states())
        baseline = f5.connections()
        threshold = (
            math.floor(baseline * (100 - drain.reduction_percent) / 100)
            if drain.reduction_percent is not None
            else (drain.remaining_connections or 0)
        )
        state.update(initial_connections=baseline, threshold=threshold, timed_out=False)
        self.event("f5_drain_snapshot", connections=baseline, threshold=threshold)
        for address, enabled in current.items():
            if not enabled:
                continue
            self.checkpoint()
            # Record before the command so a lost response still restores this address.
            state["changed_addresses"].append(address)
            state["pending_restore"].append(address)
            self.intent("f5_disable_virtual_address", address=address)
            f5.set_enabled(address, False)
        deadline = self.clock() + drain.timeout_seconds
        while True:
            self.checkpoint()
            connections = f5.connections()
            state["final_connections"] = connections
            span = baseline - threshold
            drained = (
                100 if connections <= threshold else 100 * (baseline - connections) / span if span > 0 else 0
            )
            self.report("f5_drain", percent=max(0, drained), connections=connections, threshold=threshold)
            self.event("f5_drain_sample", connections=connections, threshold=threshold)
            if connections <= threshold:
                return
            if self.clock() >= deadline:
                state["timed_out"] = True
                self.event("f5_drain_timeout", proceed=drain.proceed_on_timeout)
                if drain.proceed_on_timeout:
                    return
                raise PanosError(f"F5 drain timed out with {connections} connections above {threshold}")
            self.wait(min(5, max(0, deadline - self.clock())))

    def f5_restore(self):
        state = self.result.get("f5_drain")
        if not state or state["restored"]:
            return
        f5 = self.f5()
        for address in state["pending_restore"][:]:
            self.intent("f5_restore_virtual_address", address=address)
            f5.set_enabled(address, True)
            state["pending_restore"].remove(address)
        f5.ssh.tmsh("save /sys config", timeout=180)
        current = self.f5_selected(f5.address_states())
        still = [a for a in state["changed_addresses"] if not current.get(a)]
        if still:
            raise PanosError("F5 virtual addresses are not enabled after restore: " + ", ".join(still[:20]))
        state["restored"] = True
        self.event("f5_restored", device=state["device"], addresses=len(state["changed_addresses"]))

    def prevalidate(self):
        preload = self.request.stage_only
        for serial in self.members:
            self.precheck(serial)
        if self.ha["enabled"]:
            self.ha_preflight(strict=not preload)
        if not preload:
            self.f5_precheck()
        self.result["pre_validation"] = {"traffic": {} if preload else self.baseline()}
        self.result["upgrade_plan"] = self.upgrade_plan()
        self.event("pre_validation_completed", plan=self.result["upgrade_plan"])

    def artifact(self, serial, kind, path):
        item = {
            "name": path.name,
            "serial": serial,
            "kind": kind,
            "path": str(path.relative_to(self.settings.backup_root.resolve())),
            "sha256": digest(path),
            "bytes": path.stat().st_size,
        }
        self.result.setdefault("artifacts", []).append(item)
        if kind == "config" and "backup" not in self.result:
            self.result["backup"] = {**item, "format": "panos-running-config-xml"}
        self.event(kind + "_backup_completed", serial=serial, bytes=item["bytes"])

    def backup(self, serial):
        r = self.request
        if not (r.config_backup or r.tech_support):
            return
        directory = under(self.settings.backup_root, r.backup_directory or "panos/" + serial)
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        firewall = self.fw(serial)
        prefix = self.job["id"] + "-" + serial
        if r.config_backup:
            self.event("config_backup_started", serial=serial)
            path = directory / (prefix + "-running-config.xml")
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(firewall.running_config())
                stream.flush()
                os.fsync(stream.fileno())
            self.artifact(serial, "config", path)
        if r.tech_support:
            self.event("tech_support_backup_started", serial=serial)
            path = directory / (prefix + "-techsupport.tgz")

            started = self.clock()

            def wait(seconds):
                self.report("tech_support", serial, elapsed_seconds=round(self.clock() - started))
                self.checkpoint()
                self.wait(seconds)

            firewall.tech_support(path, r.tech_support_timeout, wait, self.clock)
            self.artifact(serial, "tech_support", path)

    def wait_job(self, job_id, timeout, label, cancellable, node, serial=None):
        deadline = self.clock() + timeout
        serial = serial or getattr(node, "serial", None)
        while True:
            if cancellable:
                self.checkpoint()
            try:
                job = node.job(job_id)
                if job["status"] == "FIN":
                    return job
                # PAN-OS reports a running job's progress as a whole percent.
                value = job["progress"]
                percent = float(value) if value.replace(".", "", 1).isdigit() else None
                self.report(label, serial, percent, job=job_id, status=job["status"])
            except PanosError:
                # Panorama may briefly lose the firewall; the job keeps running on the device.
                pass
            if self.clock() >= deadline:
                raise PanosError(label + " job " + str(job_id) + " did not finish before timeout")
            self.wait(10)

    def required_versions(self, serial, available):
        """Extra versions, then the feature release's base image when the source offers one, then the target.

        Base releases are not always X.Y.0 (12.1's base is 12.1.2). A release flagged Base wins;
        otherwise the base is the lowest offered release of the target's feature release below it.
        """
        r = self.request
        needed = list(r.download_versions)
        feature = feature_release(r.target_version)
        if r.auto_base_image and feature_release(self.version(serial)) != feature:
            lower = sorted(
                (
                    v
                    for v in available
                    if feature_release(v) == feature and version_key(v) < version_key(r.target_version)
                ),
                key=version_key,
            )
            flagged = [v for v in lower if available[v].get("base")]
            base = flagged[0] if flagged else lower[0] if lower else None
            if base and base not in needed:
                needed.insert(0, base)
        return needed + [r.target_version]

    def repository_versions(self, family):
        """Versions Panorama holds or offers for this platform family, mapped to filenames."""
        files = self.panorama.repository()
        if self.request.panorama_download:
            try:
                files = {**files, **self.panorama.repository(refresh=True)}
            except PanosUnavailable:
                raise
            except PanosError as exc:
                # An offline Panorama can still hold manually uploaded files.
                self.event("panorama_software_check_failed", error=str(exc)[:300])
        prefix = "PanOS_" + family + "-"
        return {
            f[len(prefix) :]: {"filename": f, **info} for f, info in files.items() if f.startswith(prefix)
        }

    def stage(self, serial):
        self.checkpoint()
        if self.request.software_source == "panorama":
            needed = self.push_from_panorama(serial)
        elif self.request.software_source == "executor":
            needed = self.push_from_executor(serial)
        else:
            needed = self.download_on_firewall(serial)
        versions = self.fw(serial).software()
        missing = [v for v in needed if not versions.get(v, {}).get("downloaded")]
        uploaded = self.member(serial)["software"].get("uploaded", [])
        if missing and not versions and set(missing) <= set(uploaded):
            # Without update information the firewall lists nothing, even after an upload. The
            # Panorama upload job is the evidence; the install job fails if an image is absent.
            self.member(serial)["software"]["verified_by"] = self.request.software_source + "_upload"
            self.event("software_listing_unavailable", serial=serial, versions=missing)
        elif missing:
            raise PanosError(serial + " does not report software as downloaded: " + ", ".join(missing))
        self.event("software_staged", serial=serial, versions=needed)

    def download_on_firewall(self, serial):
        r = self.request
        firewall = self.fw(serial)
        self.phase = "software_check"
        versions = firewall.software(refresh=True)
        needed = self.required_versions(serial, versions)
        missing = [v for v in needed if v not in versions]
        if missing:
            raise PanosError("software not offered to " + serial + ": " + ", ".join(missing))
        self.member(serial)["software"] = {
            "source": "update_server",
            "required": needed,
            "already_downloaded": [v for v in needed if versions[v]["downloaded"]],
        }
        self.event("software_check_completed", serial=serial)
        for version in needed:
            if versions[version]["downloaded"]:
                continue
            self.checkpoint()
            self.event("software_download_started", serial=serial, version=version)
            job_id = firewall.enqueue(download(version))
            job = self.wait_job(job_id, r.download_timeout, "software_download", True, firewall)
            if job["result"] != "OK":
                raise PanosError("download of " + version + " to " + serial + " failed: " + job["details"])
            self.event("software_download_completed", serial=serial, version=version, job=job_id)
        return needed

    def push_from_panorama(self, serial):
        r = self.request
        self.phase = "panorama_repository"
        # No update-server check on the firewall: it may have no internet access.
        versions = self.fw(serial).software()
        family = self.member(serial)["source"]["family"]
        needed = self.required_versions(serial, self.repository_versions(family))
        files = {v: "PanOS_" + family + "-" + v for v in needed}
        self.member(serial)["software"] = {
            "source": "panorama",
            "required": needed,
            "files": files,
            "already_downloaded": [v for v in needed if versions.get(v, {}).get("downloaded")],
            "uploaded": [],
        }
        self.event("software_check_completed", serial=serial)
        for version in needed:
            if versions.get(version, {}).get("downloaded"):
                continue
            self.repository_file(files[version])
            self.checkpoint()
            self.event("software_upload_started", serial=serial, version=version, file=files[version])
            job_id = self.panorama.enqueue(repository_upload(files[version], serial))
            job = self.wait_job(job_id, r.download_timeout, "software_upload", True, self.panorama, serial)
            if job["result"] != "OK":
                raise PanosError(
                    "upload of " + files[version] + " to " + serial + " failed: " + job["details"]
                )
            self.member(serial)["software"]["uploaded"].append(version)
            self.event("software_upload_completed", serial=serial, version=version, job=job_id)
        return needed

    def direct(self, serial):
        """Client for one firewall's own management API, used to upload images from this remote."""
        if serial not in self.direct_clients:
            address = self.member(serial)["address"]
            host = "[" + address + "]" if ":" in address else address
            target = HTTPTarget(
                id="panos-" + serial,
                base_url="https://" + host,
                auth_probe_path="/api/",
                auth_probe_params={"type": "version"},
                ca_file=str(self.settings.firewall_ca_file) if self.settings.firewall_ca_file else None,
                # Firewalls present self-signed certificates: pin the first one unless a CA is configured.
                tls="verify" if self.settings.firewall_ca_file else "pin",
            )
            self.direct_clients[serial] = Panorama(
                self.settings,
                self.store,
                target,
                self.request.firewall_credential_profiles,
                self.guard,
                lambda data: self.audit({**data, "connection": "firewall_direct"}),
                aliases=(serial, address),
            )
        return self.direct_clients[serial]

    def push_from_executor(self, serial):
        r = self.request
        self.phase = "executor_upload"
        member = self.member(serial)
        family = member["source"]["family"]
        images = {i.version: i for i in r.images if i.family == family}
        needed = self.required_versions(serial, {v: {} for v in images})
        missing = [v for v in needed if v not in images]
        if missing:
            raise PanosError(f"no executor image for {serial} (family {family}): " + ", ".join(missing))
        versions = self.fw(serial).software()
        member["software"] = {
            "source": "executor",
            "required": needed,
            "files": {v: images[v].name for v in needed},
            "already_downloaded": [],
            "uploaded": [],
        }
        self.event("software_check_completed", serial=serial)
        for version in needed:
            image, entry = images[version], versions.get(version, {})
            if entry.get("downloaded") and entry.get("sha256") in ("", "(null)", image.sha256):
                member["software"]["already_downloaded"].append(version)
                continue
            self.checkpoint()
            self.report("image_cache", serial, file=image.name)
            local = cached_image(self.settings, image, self.job["id"], self.checkpoint)
            if not local.is_file() or digest(local) != image.sha256:
                raise PanosError("executor image missing or SHA-256 mismatch: " + image.name)
            size = local.stat().st_size

            def sent(done, total=size, file=image.name, serial=serial):
                self.report(
                    "upload",
                    serial,
                    min(100, 100 * done / total) if total else 0,
                    force=done >= total,
                    file=file,
                    bytes=min(done, total),
                    total_bytes=total,
                )
                self.checkpoint()

            self.event(
                "software_upload_started", serial=serial, version=version, file=image.name, source="executor"
            )
            outcome = self.direct(serial).import_software(local, timeout=r.download_timeout, progress=sent)
            if not outcome["ok"]:
                # The firewall's web front end can answer 504 on a large import that still completes.
                self.event("software_import_unconfirmed", serial=serial, message=outcome["message"])
            self.wait_imported(serial, version, image.sha256, confirmed=outcome["ok"])
            member["software"]["uploaded"].append(version)
            self.event("software_upload_completed", serial=serial, version=version)
        return needed

    def wait_imported(self, serial, version, sha256, confirmed):
        """Wait for the firewall to list an imported image, and reject a different checksum."""
        deadline = self.clock() + (
            min(600, self.request.download_timeout) if confirmed else self.request.download_timeout
        )
        while True:
            self.checkpoint()
            try:
                listing = self.fw(serial).software()
            except PanosError:
                listing = None
            entry = (listing or {}).get(version, {})
            if entry.get("sha256") not in (None, "", "(null)", sha256):
                raise PanosError(serial + " reports a different SHA-256 for " + version)
            if entry.get("downloaded"):
                return
            if confirmed and listing == {}:
                # No update information yet; stage() accepts the confirmed import as evidence.
                return
            if self.clock() >= deadline:
                raise PanosError(serial + " did not list " + version + " after the upload")
            self.report("upload_confirmation", serial, status="waiting for the firewall to list " + version)
            self.wait(20)

    def repository_file(self, filename):
        """Make sure Panorama's shared software repository holds filename."""
        r = self.request
        files = self.panorama.repository()
        if files.get(filename, {}).get("available"):
            return
        if not r.panorama_download:
            raise PanosError(filename + " is not in Panorama's software repository")
        if filename not in files:
            try:
                files = self.panorama.repository(refresh=True)
            except PanosUnavailable:
                raise
            except PanosError as exc:
                # An offline Panorama can still hold manually uploaded files.
                self.event("panorama_software_check_failed", error=str(exc)[:300])
            if filename not in files:
                raise PanosError("Panorama does not offer " + filename + "; upload it or set software_family")
            if files[filename]["available"]:
                return
        self.event("panorama_download_started", file=filename)
        try:
            job_id = self.panorama.enqueue(repository_download(filename))
        except PanosUnavailable:
            raise
        except PanosError:
            # Another job may already be downloading the same file into the shared repository.
            if not any(
                j["status"] in ("ACT", "PEND") and "downl" in j["type"].lower() for j in self.panorama.jobs()
            ):
                raise
            deadline = self.clock() + r.download_timeout
            while not self.panorama.repository().get(filename, {}).get("available"):
                if self.clock() >= deadline:
                    raise PanosError("Panorama download of " + filename + " did not finish before timeout")
                self.checkpoint()
                self.wait(15)
            self.event("panorama_download_completed", file=filename, shared=True)
            return
        job = self.wait_job(job_id, r.download_timeout, "panorama_download", True, self.panorama)
        if job["result"] != "OK":
            raise PanosError("Panorama download of " + filename + " failed: " + job["details"])
        self.event("panorama_download_completed", file=filename, job=job_id)

    def wait_ha(self, serial, done, timeout, error):
        deadline = self.clock() + timeout
        while True:
            try:
                ha = self.fw(serial).ha_state()
                if done(ha):
                    return ha
            except PanosError:
                pass
            if self.clock() >= deadline:
                raise PanosError(error)
            self.wait(5)

    def preemption(self, value):
        """Set preemption on members that had it enabled (value "no"), or restore it (None)."""
        r = self.request
        state = self.result.setdefault("preemption", {})
        for serial in self.members:
            original = self.member(serial).get("preemptive")
            entry = state.setdefault(serial, {"original": original, "current": original})
            wanted = value if value is not None else entry["original"]
            if original != "yes" or entry["current"] == wanted:
                continue
            firewall = self.fw(serial)
            self.checkpoint()
            entry["current"] = "changing"
            self.intent("preemption_" + ("disable" if wanted == "no" else "restore"), serial=serial)
            firewall.set_config(HA_ELECTION, "<preemptive>" + wanted + "</preemptive>")
            job = self.wait_job(firewall.commit(), r.commit_timeout, "commit", False, firewall)
            if job["result"] != "OK":
                raise PanosError("commit on " + serial + " failed: " + job["details"])
            self.wait_ha(
                serial,
                lambda h: h["preemptive"] == wanted,
                120,
                serial + " does not report preemptive " + wanted,
            )
            entry["current"] = wanted
            self.event("preemption_committed", serial=serial, preemptive=wanted)

    def suspend(self, serial):
        member = self.member(serial)
        if member.get("suspended"):
            return
        # Never suspend both members: the peer must be functional and ready to carry traffic.
        other = self.fw(self.peer_of(serial)).ha_state()
        if not functional(other["local"]) or other["peer_conn"] != "up":
            raise PanosError("refusing to suspend " + serial + ": its peer is not functional")
        member["suspended"] = True
        self.intent("ha_suspend", serial=serial)
        self.fw(serial).command(SUSPEND)
        self.wait_ha(
            serial,
            lambda h: h["local"] == "suspended" and carries(h["peer_state"]),
            300,
            serial + " HA suspend did not complete with its peer active",
        )
        self.event("ha_suspended", serial=serial)

    def make_functional(self, serial):
        member = self.member(serial)
        if not member.get("suspended"):
            return
        self.intent("ha_functional", serial=serial)
        self.fw(serial).command(FUNCTIONAL)
        self.wait_ha(
            serial,
            lambda h: functional(h["local"]) and h["peer_conn"] == "up",
            600,
            serial + " did not return to a functional HA state",
        )
        member["suspended"] = False
        self.event("ha_functional", serial=serial)

    def failback(self, serial, survivor):
        # Traffic returns to the member that was carrying it; the failing survivor stays suspended.
        self.event("failback_started", serial=serial, survivor=survivor)
        self.make_functional(serial)
        self.suspend(survivor)
        self.event("failback_completed", serial=serial, survivor=survivor)

    def handoff(self, serial):
        """Move traffic off serial, then prove its peer carries it before serial is upgraded."""
        survivor = self.peer_of(serial)
        phase = "handoff:" + serial
        action = self.take(phase)
        if action:
            # A gate here followed any failback: return the survivor to service and hand off again.
            self.make_functional(survivor)
        self.checkpoint()
        self.suspend(serial)
        if action == "accept":
            return
        self.validate(
            phase,
            lambda: self.pair_sample(suspended={serial}),
            failback=(lambda: self.failback(serial, survivor)) if self.request.ha_policy.failback else None,
        )

    def install(self, serial):
        r = self.request
        firewall = self.fw(serial)
        self.checkpoint()
        member = self.member(serial)
        member["install"] = {"version": r.target_version, "status": "started"}
        self.intent("install", serial=serial, version=r.target_version)
        job_id = firewall.enqueue(install(r.target_version))
        member["install"]["job"] = job_id
        self.event("install_enqueued", serial=serial, job=job_id)
        # An install cannot safely be interrupted. Observe completion before honoring cancellation.
        job = self.wait_job(job_id, r.install_timeout, "install", False, firewall)
        if job["result"] != "OK":
            member["install"]["status"] = "failed"
            raise PanosError(
                "install of " + r.target_version + " on " + serial + " failed: " + job["details"]
            )
        member["install"]["status"] = "completed"
        self.event("install_completed", serial=serial, job=job_id)
        self.checkpoint()

    def reboot(self, serial):
        r = self.request
        firewall = self.fw(serial)
        member = self.member(serial)
        self.checkpoint()
        member["reboot_requested_at"] = datetime.now(timezone.utc).isoformat()
        start = self.clock()
        self.intent("reboot", serial=serial, version=r.target_version)
        try:
            firewall.command(RESTART)
        except PanosUnavailable:
            # Restart can drop the proxied session. Only a new boot on the target verifies it.
            self.event("reboot_response_uncertain", serial=serial)
        deadline = start + r.reboot_timeout
        while self.clock() < deadline:
            self.wait(15)
            self.report(
                "reboot",
                serial,
                elapsed_seconds=round(self.clock() - start),
                timeout_seconds=r.reboot_timeout,
                status="waiting for a new boot on " + r.target_version,
            )
            try:
                info = firewall.system_info()
            except PanosError:
                continue
            uptime = info["uptime_seconds"]
            if (
                info["sw_version"] == r.target_version
                and uptime is not None
                and uptime <= self.clock() - start + 120
            ):
                member["boot_verified"] = {"version": info["sw_version"], "uptime_seconds": uptime}
                self.event("reboot_completed", serial=serial)
                return
        raise PanosError(serial + ": a new boot on the target version was not verified before timeout")

    def validate(self, phase, sample, failback=None):
        if self.take(phase) == "accept":
            return
        policy, timeout = self.request.validation_policy, self.request.validation_timeout
        deadline = self.clock() + timeout
        passes = 0
        while True:
            self.checkpoint()
            try:
                critical, findings = sample()
            except PanosError as exc:
                critical, findings = ["device unavailable: " + str(exc)], []
            review = bool(findings) and policy.noncritical_differences == "require_review"
            self.result.setdefault("validation_findings", {})[phase] = findings
            self.result["validation_differences"] = [
                f for items in self.result["validation_findings"].values() for f in items
            ]
            self.result["validation_issues"] = critical
            passes = passes + 1 if not critical and not review else 0
            required = policy.consecutive_passes if timeout else 1
            self.report(
                "validation",
                phase=phase,
                consecutive_passes=passes,
                required_passes=required,
                critical=len(critical),
                differences=len(findings),
            )
            self.event(
                phase + "_sample",
                critical=critical,
                difference_count=len(findings),
                consecutive_passes=passes,
            )
            if passes >= required:
                return
            if self.clock() >= deadline:
                if failback:
                    failback()
                if policy.on_timeout == "fail":
                    raise PanosError(phase + " timed out; findings recorded")
                self.store.open_gate(
                    self.job["id"],
                    self.worker,
                    phase,
                    {"critical": critical, "differences": findings},
                    self.result,
                )
            self.wait(min(policy.sample_interval_seconds, max(0, deadline - self.clock())))

    def system_sample(self, serial):
        r = self.request
        firewall = self.fw(serial)
        critical, findings = [], []
        info = firewall.system_info()
        if info["sw_version"] != r.target_version:
            critical.append("running version is " + info["sw_version"])
        if info["operational_mode"] not in ("", "normal"):
            critical.append("operational mode is " + info["operational_mode"])
        if not firewall.chassis_ready():
            critical.append("chassis is not ready")
        commits = sorted(
            (j for j in firewall.jobs() if j["type"].lower() == "autocom"), key=lambda j: j["id"]
        )
        if not commits:
            findings.append(
                {"category": "auto_commit", "change": "no auto-commit job reported", "serial": serial}
            )
        elif commits[-1]["status"] != "FIN":
            critical.append("auto-commit is still running")
        elif commits[-1]["result"] != "OK":
            critical.append("auto-commit failed: " + commits[-1]["details"][:300])
        entry = self.panorama.device(serial)
        if not entry or not entry["connected"]:
            critical.append("firewall is not connected to Panorama")
        elif entry["sw_version"] != r.target_version:
            critical.append("Panorama reports version " + entry["sw_version"])
        source = self.member(serial)["source"]
        for key in ("app_version", "threat_version", "av_version"):
            if source.get(key) and info.get(key) and source[key] != info[key]:
                findings.append(
                    {
                        "category": "content",
                        "change": key + " changed",
                        "objects": [info[key]],
                        "serial": serial,
                    }
                )
        self.member(serial)["post_system"] = info
        return [serial + ": " + c for c in critical], findings

    def pair_sample(self, suspended=frozenset()):
        """HA state of every member plus traffic on each member that should carry it."""
        r = self.request
        critical, findings = [], []
        carriers = [r.serial]
        if self.ha["enabled"]:
            states = {s: self.fw(s).ha_state() for s in self.members}
            for serial, ha in states.items():
                if serial in suspended:
                    if ha["local"] != "suspended":
                        critical.append(serial + " is not suspended")
                elif not functional(ha["local"]):
                    critical.append(serial + " HA state is " + (ha["local"] or "unknown"))
                elif ha["peer_conn"] != "up":
                    critical.append(serial + " HA peer connection is " + (ha["peer_conn"] or "unknown"))
            serving = [s for s in self.members if s not in suspended]
            carriers = [s for s in serving if carries(states[s]["local"])]
            if self.ha["mode"] == "active-passive" and len(carriers) != 1:
                critical.append("active/passive HA requires exactly one active member")
            if self.ha["mode"] == "active-active" and carriers != serving:
                critical.append("every functional active/active member must be active")
            if (
                not suspended
                and len({self.version(s) for s in self.members}) == 1
                and r.ha_policy.require_running_sync
                and unsynchronized(states.values())
            ):
                critical.append("HA running configuration is not synchronized")
            if critical:
                return critical, []
        baselines = self.result["pre_validation"]["traffic"]
        post = self.result.setdefault("post_validation", {})
        policy = r.validation_policy
        if self.f5_drained():
            # Drained on purpose: session and ARP counts are only meaningful after the F5 restore.
            policy = policy.model_copy(update={"min_session_percent": None, "min_arp_percent": None})
        for serial in carriers:
            current = self.traffic(self.fw(serial))
            failures, items, metrics = compare(baselines.get(serial, baselines.get("pair")), current, policy)
            critical += [serial + ": " + f for f in failures]
            findings += [{**f, "serial": serial} for f in items]
            post[serial] = {"traffic": current, "metrics": metrics}
        return critical, findings

    def settle(self):
        remaining = self.request.validation_policy.settling_seconds
        while remaining > 0:
            self.report("settle", remaining_seconds=remaining)
            self.checkpoint()
            self.wait(min(15, remaining))
            remaining -= min(15, remaining)

    def member_steps(self, serial, handoff):
        steps = []
        if handoff:
            steps.append(("handoff:" + serial, partial(self.handoff, serial)))
        elif self.ha["enabled"]:
            steps.append(("suspend:" + serial, partial(self.suspend, serial)))
        steps += [
            ("install:" + serial, partial(self.install, serial)),
            ("reboot:" + serial, partial(self.reboot, serial)),
            ("settle:" + serial, self.settle),
        ]
        system = "validate_system:" + serial
        steps.append((system, lambda: self.validate(system, partial(self.system_sample, serial))))
        if self.ha["enabled"]:
            steps.append(("functional:" + serial, partial(self.make_functional, serial)))
        traffic = "validate_traffic:" + serial

        def validate_traffic():
            self.validate(traffic, self.pair_sample)
            self.member(serial)["validated"] = True

        steps.append((traffic, validate_traffic))
        return steps

    def planned_steps(self):
        """Every remaining step, in order, so pollers see a real total."""
        r = self.request
        plan = self.result["upgrade_plan"]
        if not plan:
            if r.stage_only:
                return []
            self.result["already_on_target"] = True
            return [("validate_current", lambda: self.validate("validate_current", self.pair_sample))]
        serials = [item["serial"] for item in plan]
        steps = [] if r.stage_only else [("backup:" + s, partial(self.backup, s)) for s in serials]
        steps += [("stage:" + s, partial(self.stage, s)) for s in serials]
        if r.stage_only:
            return steps
        preemption = self.ha["enabled"] and r.ha_policy.disable_preemption
        if preemption:
            steps.append(("preemption_disable", partial(self.preemption, "no")))
        if r.f5_drain:
            steps.append(("f5_drain", self.f5_drain))
        for item in plan:
            steps += self.member_steps(item["serial"], item["handoff"])
        if preemption:
            steps.append(("preemption_restore", partial(self.preemption, None)))
        if r.f5_drain:
            steps.append(("f5_restore", self.f5_restore))
            steps.append(("validate_restored", lambda: self.validate("validate_restored", self.pair_sample)))
        if self.ha["enabled"]:
            steps.append(("validate_final", lambda: self.validate("validate_final", self.pair_sample)))
        return steps

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

    def restore_service(self):
        # Before an install or reboot, an unchanged member returns to service and preemption is
        # restored. Upgraded but unvalidated members stay suspended so the peer keeps traffic.
        members = self.result.get("members", {})
        for serial, member in members.items():
            if member.get("suspended") and not staged(member):
                self.make_functional(serial)
        unchanged = not any(staged(m) for m in members.values())
        if unchanged and any(
            p["current"] != p["original"] for p in self.result.get("preemption", {}).values()
        ):
            self.preemption(None)
        # An unchanged firewall can take traffic again; an upgraded but unvalidated one stays drained.
        if unchanged and self.f5_drained():
            self.f5_restore()

    def run(self):
        try:
            self.upgrade()
            self.result["completed"] = True
            self.event("completed")
            # Panorama, firewall and F5 connections use different profiles; a warning means one
            # target fell back from one profile to another.
            profiles = {}
            for usage in self.store.get(self.job["id"])["credential_usage"]:
                if usage["outcome"] == "authenticated":
                    profiles.setdefault(usage["target"], set()).add(usage["profile"])
            warnings = bool(
                self.result.get("validation_differences")
                or self.result.get("manual_validations")
                or any(len(used) > 1 for used in profiles.values())
            )
            self.store.finish(
                self.job["id"], self.worker, "completed_with_warnings" if warnings else "succeeded"
            )
        except (LostOwnership, Deferred, NeedsReview):
            pass
        except CancelRequested:
            try:
                self.restore_service()
                self.result["cancelled_at"] = self.phase
                self.event("cancel_acknowledged")
                self.store.finish(
                    self.job["id"], self.worker, "recovery_required" if self.unsafe() else "cancelled"
                )
            except LostOwnership:
                pass
            except Exception:
                self.store.finish(self.job["id"], self.worker, "recovery_required")
        except Exception as exc:
            message = (
                str(exc)
                if isinstance(exc, (PanosError, DeviceError))
                else "operation failed (" + type(exc).__name__ + ")"
            )
            self.result["error"] = message
            try:
                try:
                    self.restore_service()
                except LostOwnership:
                    raise
                except Exception:
                    self.result["restore_failed"] = True
                self.event("failed", message=message)
                self.store.finish(
                    self.job["id"], self.worker, "recovery_required" if self.unsafe() else "failed"
                )
            except LostOwnership:
                pass
        finally:
            if self.panorama is not None:
                self.panorama.close()
            for client in self.direct_clients.values():
                client.close()
