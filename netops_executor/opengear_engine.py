"""Resumable IM7200 upgrades. A flash command is recorded before dispatch and never replayed."""

import time
from datetime import datetime, timezone

from .config import under
from .image_cache import cached_image
from .opengear import Opengear, version_key
from .opengear_models import OpengearUpgradeRequest
from .ssh import DeviceError, digest
from .stepped import StepRunner


class OpengearRunner(StepRunner):
    device_errors = (DeviceError,)
    error = DeviceError

    def __init__(self, settings, store, job, worker, client=None, sleep=time.sleep, clock=time.monotonic):
        super().__init__(settings, store, job, worker, sleep, clock)
        self.client = client

    def setup(self):
        r = self.request = OpengearUpgradeRequest.model_validate(self.job["request"])
        self.device = self.settings.device(r.device)
        if self.client is None:
            self.client = Opengear(self.settings, self.device, self.guard, r.credential_profiles, self.audit)
        keys = [self.job["lock_key"], "endpoint:" + self.device.host]
        if not self.store.reserve(self.job["id"], self.worker, keys):
            if self.result.get("mutations"):
                raise DeviceError("reservation changed during continuation")
            self.store.defer(self.job["id"], self.worker)
        self.event("resources_reserved", keys=keys)

    def prevalidate(self):
        r = self.request
        self.client.preflight()
        info = self.client.version()
        self.result["source"] = info
        if r.approved_models and info["model"] not in r.approved_models:
            raise DeviceError("hardware model is not approved: " + info["model"])
        needed = info["version"] != r.target_version
        if needed:
            if info["version"] not in r.allowed_source_versions:
                raise DeviceError(
                    "running version " + info["version"] + " is outside allowed_source_versions"
                )
            if version_key(r.target_version) <= version_key(info["version"]):
                raise DeviceError("IM7200 downgrade is not supported by this upgrade workflow")
            if version_key(info["version"]) < (4, 13, 3, 0) and version_key(r.target_version) >= (5, 0, 0, 0):
                raise DeviceError("upgrade to at least 4.13.3 before upgrading to 5.x or later")
        self.result["upgrade_needed"] = needed
        self.result["rollback"] = {"supported": False, "source_version": info["version"]}
        self.result["pre_validation"] = {} if r.stage_only else self.client.snapshot()
        self.event("pre_validation_completed", upgrade_needed=needed)

    def directory(self):
        return self.client.prepare(self.request.staging_directory)

    def backup(self):
        r = self.request
        directory = under(self.settings.backup_root, r.backup_directory or "opengear/" + self.device.id)
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        name = self.job["id"] + "-config.opg"
        local = directory / name
        self.report("config_backup", self.device.id)
        self.client.backup(
            self.directory() + "/" + name, local, r.upload_timeout, lambda *_: self.checkpoint()
        )
        self.artifact(self.device.id, "config", local, "opengear-opg")

    def stage(self):
        r, image = self.request, self.request.image
        self.checkpoint()
        path = self.directory() + "/" + image.sha256 + ".flash"
        software = self.result["software"] = {"image": image.name, "remote_path": path}
        if self.client.staged(path):
            if self.client.sha256(path) != image.sha256:
                raise DeviceError("staged image SHA-256 does not match the approved image")
            software["reused"] = True
        else:
            self.report("image_cache", self.device.id, file=image.name)
            local = cached_image(self.settings, image, self.job["id"], self.checkpoint)
            if not local.is_file() or digest(local) != image.sha256:
                raise DeviceError("executor image missing or SHA-256 mismatch: " + image.name)
            free = self.client.free_bytes(self.request.staging_directory)
            needed = local.stat().st_size + r.minimum_free_bytes
            if free < needed:
                raise DeviceError(f"insufficient staging space: {free} bytes free, {needed} required")

            def progress(done, total):
                self.checkpoint()
                self.report(
                    "upload",
                    self.device.id,
                    min(100, 100 * done / total) if total else 0,
                    file=image.name,
                    bytes=min(done, total),
                    total_bytes=total,
                    force=done >= total,
                )

            self.client.upload(local, path, r.upload_timeout, progress, self.job["id"])
            software["uploaded"] = True
        if self.client.sha256(path) != image.sha256:
            raise DeviceError("device image SHA-256 does not match the approved image")
        software["sha256_verified"] = True
        self.event("software_staged", file=image.name)

    def install(self):
        r = self.request
        self.checkpoint()
        if self.result.get("install"):
            raise DeviceError("a flash was already attempted; inspect the device before recovery")
        self.client.preflight()
        if self.client.version() != self.result["source"]:
            raise DeviceError("device identity, version or boot changed since precheck; rerun required")
        if self.client.snapshot()["config_sha256"] != self.result["pre_validation"]["config_sha256"]:
            raise DeviceError("configuration changed since precheck; rerun required")
        path = self.result["software"]["remote_path"]
        if self.client.sha256(path) != r.image.sha256:
            raise DeviceError("staged image changed since verification")
        self.checkpoint()
        self.result["install"] = {"status": "started", "image": r.image.name}
        self.result["reboot_requested_at"] = datetime.now(timezone.utc).isoformat()
        self.intent("netflash", image=r.image.name)
        try:
            code = self.client.install_reload(path, r.install_timeout)
        except DeviceError:
            self.event("install_response_uncertain")
        else:
            self.result["install"]["exit_code"] = code
            if code not in (0, -1):
                self.event("netflash_rejected", exit_code=code)
                raise DeviceError("netflash returned exit code " + str(code) + "; inspect before recovery")
        self.client.close()
        start = self.clock()
        deadline = start + r.reboot_timeout
        while self.clock() < deadline:
            self.wait(min(15, deadline - self.clock()))
            self.report(
                "reboot",
                self.device.id,
                elapsed_seconds=round(self.clock() - start),
                timeout_seconds=r.reboot_timeout,
                status="waiting for a new boot on " + r.target_version,
            )
            try:
                info = self.client.version()
            except DeviceError:
                self.client.close()
                continue
            source = self.result["source"]
            if (info["model"], info["mac"]) != (source["model"], source["mac"]):
                raise DeviceError("a different console server answered after flashing")
            if info["version"] == r.target_version and info["boot_id"] != source["boot_id"]:
                self.result["install"]["status"] = "completed"
                self.result["boot_verified"] = info
                self.event("reboot_completed")
                return
            self.client.close()
        raise DeviceError("a new boot on the target version was not verified before timeout")

    def system_sample(self):
        r = self.request
        critical, findings = [], []
        info = self.client.version()
        source = self.result["source"]
        if (info["model"], info["mac"]) != (source["model"], source["mac"]):
            critical.append("a different console server answered after upgrade")
        if info["version"] != r.target_version:
            critical.append("running version is " + info["version"])
        if self.result.get("boot_verified") and info["boot_id"] != self.result["boot_verified"]["boot_id"]:
            critical.append("device rebooted again after firmware boot verification")
        current = self.client.snapshot()
        before = self.result["pre_validation"]
        if current["config_sha256"] != before["config_sha256"]:
            findings.append({"category": "config", "change": "configuration checksum changed across upgrade"})
        lost = sorted(
            n
            for n, state in before["interfaces"].items()
            if state == "up" and current["interfaces"].get(n) != "up"
        )
        if lost:
            if r.validation_policy.restore_interfaces:
                critical.append("Ethernet links did not return: " + ", ".join(lost))
            else:
                findings.append({"category": "interfaces", "change": "not restored", "objects": lost})
        self.result["post_validation"] = {**current, "system": info}
        return critical, findings

    def upgrade(self):
        self.setup()
        r = self.request
        self.checkpoint()
        self.decision = self.store.apply_decision(self.job["id"], self.worker)
        self.result["plan"] = r.plan()
        self.step("prevalidate", self.prevalidate)
        steps = []
        if self.result["upgrade_needed"]:
            if r.config_backup and not r.stage_only:
                steps.append(("backup", self.backup))
            steps.append(("stage", self.stage))
            if not r.stage_only:
                steps += [("netflash_and_reboot", self.install), ("settle", self.settle)]
        else:
            self.result["already_on_target"] = True
        if not r.stage_only:
            steps.append(("validate_system", lambda: self.validate("validate_system", self.system_sample)))
        done = self.result["completed_steps"]
        total = len(done) + sum(key not in done for key, _ in steps)
        self.result.setdefault("progress", {}).update(
            steps_total=total, steps_completed=len(done), percent=round(100 * len(done) / total)
        )
        for key, action in steps:
            self.step(key, action)
        if r.stage_only:
            self.result["preloaded"] = bool(self.result.get("software", {}).get("sha256_verified"))
        else:
            self.result.update(validated_version=r.target_version, validation_accepted=True)

    def unsafe(self):
        return bool(self.result.get("install"))

    def close(self):
        if self.client:
            self.client.close()
