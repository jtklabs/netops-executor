"""Unattended FortiGate (FortiOS 7.4) upgrades over SSH, optionally with FortiManager.

The image is staged in the alternate partition with FortiOS's controlled upgrade, pulled
from a one-time FTP server the executor runs for that operation only. A standalone unit
then boots that partition (`execute set-next-reboot secondary`, `execute reboot`). An FGCP
cluster upgrades itself from its primary, secondaries first, so a cluster's staged
partition only proves the image ahead of the window: `execute restore image ftp` on the
executor source, or FortiManager's `/um/image/upgrade` on the fortimanager source.
Ambiguous writes are never replayed.
"""

import hashlib
import time
from datetime import datetime, timezone
from functools import partial

from .config import under
from .eos_engine import compare
from .fortigate_models import FortigateUpgradeRequest
from .fortinet import Fortigate, FortiManager, compare_configs
from .ftp_staging import FTPError, OneShotFTP
from .image_cache import cached_image
from .iosxe_engine import masked
from .ssh import DeviceError, digest
from .stepped import StepRunner

RESTORED = {
    "interfaces": {"up"},
    "ipsec_tunnels": {"up"},
    "bgp_peers": {"established"},
    "ospf_neighbors": {"full"},
}
COUNTS = {"routes": "min_route_percent", "sessions": "min_session_percent"}


def release(value):
    return tuple(int(x) for x in value.split("."))


class FortigateRunner(StepRunner):
    device_errors = (DeviceError,)
    error = DeviceError

    def __init__(
        self, settings, store, job, worker, fgt=None, fmg=None, sleep=time.sleep, clock=time.monotonic
    ):
        super().__init__(settings, store, job, worker, sleep, clock)
        self.fgt, self.fmg = fgt, fmg

    def setup(self):
        r = self.request = FortigateUpgradeRequest.model_validate(self.job["request"])
        self.device = self.settings.device(r.device)
        if self.fgt is None:
            self.fgt = Fortigate(self.settings, self.device, self.guard, r.credential_profiles, self.audit)
        if r.software_source == "fortimanager" and self.fmg is None:
            if r.fortimanager not in self.settings.http_targets:
                raise DeviceError("unknown FortiManager HTTP target " + r.fortimanager)
            self.fmg = FortiManager(
                self.settings,
                self.store,
                r.fortimanager,
                r.fortimanager_credential_profiles,
                self.guard,
                lambda data: self.audit({**data, "connection": "fortimanager"}),
            )

    def directory(self):
        r = self.request
        path = under(self.settings.backup_root, r.backup_directory or "fortigate/" + self.device.id)
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        return path

    def reserve(self):
        keys = [self.job["lock_key"], "endpoint:" + self.device.host]
        if not self.store.reserve(self.job["id"], self.worker, keys):
            if self.result.get("mutations"):
                raise DeviceError("reservation changed during continuation")
            self.store.defer(self.job["id"], self.worker)
        self.event("resources_reserved", keys=keys)

    def cluster(self):
        return self.result["source"]["ha"] != "standalone"

    def config_hash(self, text=None):
        return hashlib.sha256((text or self.fgt.config()).encode()).hexdigest()

    def ha_problems(self, ha, members):
        problems = [] if ha["healthy"] else ["HA health is not OK"]
        if set(ha["members"]) != set(members):
            problems.append("cluster members changed: " + ", ".join(sorted(ha["members"])))
        problems += [
            f"{serial} is {state}" for serial, state in sorted(ha["sync"].items()) if state != "in-sync"
        ]
        if set(ha["sync"]) != set(members):
            problems.append("configuration sync status is missing for some members")
        return problems

    def prevalidate(self):
        r, image = self.request, self.request.image
        info = self.fgt.status()
        self.result.setdefault("console_output", self.fgt.console_output())
        self.result["source"] = info
        if r.approved_models and info["model"] not in r.approved_models:
            raise DeviceError("hardware model is not approved: " + info["model"])
        if info["model"].startswith("FortiGate-"):
            code = "FGT_" + info["model"][len("FortiGate-") :].replace("-", "_") + "-"
            if not image.name.startswith(code):
                raise DeviceError(f"{image.name} is not a {info['model']} image")
        on_target = info["build"] == image.build
        if not on_target:
            if info["version"] not in r.allowed_source_versions:
                raise DeviceError(
                    "running version " + info["version"] + " is outside allowed_source_versions"
                )
            if release(image.version) <= release(info["version"]):
                raise DeviceError(
                    "the image is not newer than the running firmware; downgrades are not supported"
                )
        if self.cluster():
            ha = self.fgt.ha()
            self.result["ha"] = ha
            if not r.stage_only:
                problems = self.ha_problems(ha, ha["members"])
                if ha["members"].get(info["serial"], {}).get("role") != "primary":
                    problems.insert(0, "the job must address the cluster primary")
                if problems:
                    raise DeviceError(problems[0])
        active = next(p for p in self.fgt.partitions() if p["active"])
        self.result["rollback"] = {
            "version": info["version"],
            "build": info["build"],
            "partition": active["partition"],
        }
        self.result["upgrade_needed"] = not on_target
        if r.software_source == "fortimanager" and not on_target:
            row = self.fmg.device(r.adom, info["serial"])
            self.result["fortimanager"] = {"device": row["name"], "adom": r.adom}
        if not r.stage_only:
            text = self.fgt.config()
            path = self.directory() / (self.job["id"] + "-" + self.device.id + "-config.txt")
            self.write_private(path, text.encode())
            self.artifact(self.device.id, "config", path, "fortios-config")
            self.result["pre_validation"] = {
                "traffic": self.fgt.traffic(),
                "config_sha256": self.config_hash(text),
                "baseline": {
                    "path": str(path.relative_to(self.settings.backup_root.resolve())),
                    "sha256": digest(path),
                },
            }
        self.event("pre_validation_completed", upgrade_needed=not on_target)

    def preview(self):
        image, fmg = self.request.image, self.result["fortimanager"]
        self.report("fortimanager_preview", self.device.id)
        self.fmg.preview(fmg["adom"], fmg["device"], image.version, image.build)
        fmg["preview"] = "reaches build " + str(image.build)
        self.event("fortimanager_preview_completed", device=fmg["device"])

    def staged(self):
        return any(not p["active"] and p["build"] == self.request.image.build for p in self.fgt.partitions())

    def local_image(self):
        """The executor's verified copy, checked before anything is sent to the FortiGate."""
        image = self.request.image
        if not self.settings.staging_address:
            raise DeviceError("NETOPS_STAGING_ADDRESS is required to stage FortiGate firmware")
        self.report("image_cache", self.device.id, file=image.name)
        local = cached_image(self.settings, image, self.job["id"], self.checkpoint)
        if not local.is_file() or digest(local) != image.sha256:
            raise DeviceError("executor image missing or SHA-256 mismatch: " + image.name)
        return local

    def serve(self, local, operation):
        """Run one FortiGate pull against a one-time FTP server for the verified image."""
        r, image = self.request, self.request.image
        client = r.staging_source_address or self.device.host
        try:
            with OneShotFTP(
                local, client, self.settings.staging_address, self.settings.staging_ports, r.stage_timeout
            ) as ftp:
                self.fgt.ssh.selector.secrets.add(ftp.password)

                def poll():
                    self.report(
                        "ftp_transfer",
                        self.device.id,
                        100 * ftp.sent / ftp.size if ftp.size else 0,
                        force=ftp.sent >= ftp.size,
                        file=image.name,
                        bytes=ftp.sent,
                        total_bytes=ftp.size,
                    )

                operation(ftp, poll)
                return ftp.completed.is_set()
        except FTPError as exc:
            raise DeviceError(str(exc)) from None

    def stage(self):
        r, image = self.request, self.request.image
        self.checkpoint()
        if self.staged():
            self.result["staged"] = {"partition": "alternate", "build": image.build, "already": True}
            self.event("stage_skipped_verified", build=image.build)
            return
        local = self.local_image()
        self.event("stage_started", file=image.name)
        self.serve(
            local,
            lambda ftp, poll: self.fgt.stage(
                image.name, ftp.address, ftp.user, ftp.password, r.stage_timeout, poll
            ),
        )
        if not self.staged():
            raise DeviceError(f"the alternate partition does not hold build {image.build} after staging")
        self.result["staged"] = {"partition": "alternate", "build": image.build, "already": False}
        self.event("stage_completed", build=image.build)

    def install(self):
        r = self.request
        self.checkpoint()
        # Refuse a stale authorization: nothing may have changed since the baseline.
        info = self.fgt.status()
        if info["build"] != self.result["source"]["build"]:
            raise DeviceError("firmware changed since precheck; rerun required")
        if self.config_hash() != self.result["pre_validation"]["config_sha256"]:
            raise DeviceError("configuration changed since precheck; rerun required")
        if self.cluster():
            problems = self.ha_problems(self.fgt.ha(), self.result["ha"]["members"])
            if problems:
                raise DeviceError(problems[0])
        start = self.clock()

        def started(step, **data):
            self.result["install"] = {"build": r.image.build, "status": "started"}
            self.result["reboot_requested_at"] = datetime.now(timezone.utc).isoformat()
            self.intent(step, **data)

        if not self.cluster():
            if not self.staged():
                raise DeviceError("the staged image is no longer in the alternate partition")
            started("boot_alternate_partition", build=r.image.build)
            self.fgt.set_next_reboot("secondary")
            try:
                self.fgt.reboot()
            except DeviceError:
                self.event("reboot_response_uncertain")
        elif r.software_source == "fortimanager":
            fmg = self.result["fortimanager"]
            started("fortimanager_cluster_upgrade", device=fmg["device"])
            fmg["task"] = task = self.fmg.upgrade(fmg["adom"], fmg["device"], r.image.version, r.image.build)
            self.follow(task, start + r.cluster_timeout)
        else:
            local = self.local_image()

            def restore(ftp, poll):
                started("cluster_upgrade", build=r.image.build)
                try:
                    self.fgt.restore(
                        r.image.name, ftp.address, ftp.user, ftp.password, r.cluster_timeout, poll
                    )
                except DeviceError as exc:
                    if "reported a failure" in str(exc):
                        raise
                    # A deadline or dropped session leaves the outcome to fresh observations.
                    self.event("restore_response_uncertain")

            self.serve(local, restore)
        self.fgt.close()
        self.await_target(start + (r.cluster_timeout if self.cluster() else r.reboot_timeout), start)

    def follow(self, task, deadline):
        while self.clock() < deadline:
            state = self.fmg.task(task)
            self.report(
                "fortimanager_task", self.device.id, state["percent"], task=task, state=state["state"]
            )
            if state["errors"] or state["state"] in ("error", "aborted", "cancelled"):
                raise DeviceError(f"FortiManager upgrade task {task} ended {state['state']}")
            if state["state"] == "done" or state["percent"] >= 100:
                return
            self.wait(30)
        raise DeviceError(f"FortiManager upgrade task {task} did not finish before timeout")

    def await_target(self, deadline, start):
        r, source = self.request, self.result["source"]
        status = "waiting for the reboot"
        while self.clock() < deadline:
            self.wait(30)
            self.report(
                "reboot",
                self.device.id,
                elapsed_seconds=round(self.clock() - start),
                status=status,
            )
            try:
                info = self.fgt.status()
                problems = [] if info["build"] == r.image.build else [f"running build {info['build']}"]
                uptime = info["uptime_seconds"]
                if uptime is None or uptime > self.clock() - start + 600:
                    problems.append("no fresh boot yet")
                if self.cluster():
                    problems += self.ha_problems(self.fgt.ha(), self.result["ha"]["members"])
                elif info["serial"] != source["serial"]:
                    problems.append("a different FortiGate answered")
            except DeviceError as exc:
                self.fgt.close()
                status = "unreachable (" + str(exc)[:80] + ")"
                continue
            if not problems:
                self.result["install"]["status"] = "completed"
                self.result["boot_verified"] = {"build": info["build"], "uptime_seconds": uptime}
                self.event("reboot_completed")
                return
            status = problems[0]
        raise DeviceError("the target firmware was not verified before timeout: " + status)

    def system_sample(self):
        r = self.request
        critical, findings = [], []
        info = self.fgt.status()
        if info["build"] != r.image.build:
            critical.append(f"running build {info['build']}, not {r.image.build}")
        if self.cluster():
            critical += self.ha_problems(self.fgt.ha(), self.result["ha"]["members"])
            if info["serial"] not in self.result["ha"]["members"]:
                critical.append("a FortiGate outside the cluster answered")
        elif info["serial"] != self.result["source"]["serial"]:
            critical.append("a different FortiGate answered")
        if info["model"] != self.result["source"]["model"]:
            critical.append("hardware model changed")
        saved = self.result["pre_validation"]["baseline"]
        path = under(self.settings.backup_root, saved["path"])
        if digest(path) != saved["sha256"]:
            raise DeviceError("baseline configuration file changed since precheck")
        running = self.fgt.config()
        result = compare_configs(path.read_text(), running, r.config_policy)
        self.record_config(result, running)
        for kind in ("removed", "added"):
            action = getattr(r.config_policy, kind)
            if not result[kind + "_count"] or action == "ignore":
                continue
            message = f"{result[kind + '_count']} configuration line(s) {kind} beyond the tolerated release differences"
            if action == "critical":
                critical.append(message)
            else:
                findings.append(
                    {"category": "config", "change": kind, "objects": [masked(x) for x in result[kind][:100]]}
                )
        self.result["post_system"] = {
            "version": info["version"],
            "build": info["build"],
            "serial": info["serial"],
        }
        return critical, findings

    def record_config(self, result, running):
        self.result["config_comparison"] = {
            "equivalent": result["equivalent"],
            "added_count": result["added_count"],
            "removed_count": result["removed_count"],
            "added": [masked(x) for x in result["added"][:50]],
            "removed": [masked(x) for x in result["removed"][:50]],
            "tolerated": result["tolerated"],
        }
        if result["equivalent"]:
            return
        text = "".join("- " + x + "\n" for x in result["removed"]) + "".join(
            "+ " + x + "\n" for x in result["added"]
        )
        path = self.directory() / (self.job["id"] + "-" + self.device.id + "-config-differences.txt")
        if not path.exists() or digest(path) != hashlib.sha256(text.encode()).hexdigest():
            self.write_private(path, text.encode())
            self.result["artifacts"] = [a for a in self.result.get("artifacts", []) if a["name"] != path.name]
            self.artifact(self.device.id, "config_differences", path)

    def traffic_sample(self):
        current = self.fgt.traffic()
        failures, findings, metrics = compare(
            self.result["pre_validation"]["traffic"],
            current,
            self.request.validation_policy,
            restored=RESTORED,
            counts=COUNTS,
        )
        self.result["post_validation"] = {"traffic": current, "metrics": metrics}
        return failures, findings

    def retrieve(self):
        """FortiManager did not run this reboot; ask it to read the configuration again."""
        fmg = self.result["fortimanager"]
        try:
            self.fmg.retrieve(fmg["adom"], fmg["device"])
            fmg["retrieve"] = "requested"
        except DeviceError as exc:
            fmg["retrieve"] = "failed: " + str(exc)[:200]
            self.result.setdefault("validation_findings", {})["fortimanager"] = [
                {"category": "fortimanager", "change": "configuration retrieve failed"}
            ]
            self.result["validation_differences"] = [
                f for items in self.result["validation_findings"].values() for f in items
            ]
        self.event("fortimanager_retrieve", result=fmg["retrieve"])

    def planned_steps(self):
        r = self.request
        if not self.result["upgrade_needed"]:
            if r.stage_only:
                return []
            self.result["already_on_target"] = True
            return [("validate_current", lambda: self.validate("validate_current", self.traffic_sample))]
        steps = [("fortimanager_preview", self.preview)] if r.software_source == "fortimanager" else []
        steps.append(("stage", self.stage))
        if r.stage_only:
            return steps
        steps += [
            ("install", self.install),
            ("settle", self.settle),
            ("validate_system", lambda: self.validate("validate_system", self.system_sample)),
            ("validate_traffic", partial(self.validate, "validate_traffic", self.traffic_sample)),
        ]
        if r.software_source == "fortimanager" and not self.cluster():
            steps.append(("fortimanager_retrieve", self.retrieve))
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
        self.result["validated_version"] = r.image.version
        self.result["validation_accepted"] = True

    def unsafe(self):
        return self.result.get("install", {}).get("status") in ("started", "completed")

    def close(self):
        # Netmiko switched console output to standard; put back what the job found.
        if self.fgt is not None:
            if self.result.get("console_output") == "more":
                try:
                    self.fgt.restore_console("more")
                except Exception:
                    self.result["console_restore_failed"] = True
            self.fgt.close()
        if self.fmg is not None:
            self.fmg.close()
