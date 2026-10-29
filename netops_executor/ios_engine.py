"""Unattended Cisco Catalyst 2960-X and 2960-XR upgrades on classic IOS 15.2 over SSH.

The .tar is copied to flash (the switch's own copy from image.device_url first, SCP from the
executor as the fallback) and checksum-verified. `archive download-sw /imageonly /safe`
extracts it onto every stack member and points their boot paths at it, keeping the running
image until the new one is in place; a separate `reload` starts it. When the master's flash
cannot hold the .tar and the extracted image together, archive download-sw reads the .tar
straight from image.device_url instead.

Configuration and traffic validation are the IOS XE ones.
"""

import re
from datetime import datetime, timezone
from functools import partial

from .ios import Ios
from .ios_models import IosUpgradeRequest, version_token
from .iosxe_engine import IosxeRunner
from .ssh import DeviceError

FAMILY = re.compile(r"WS-C2960XR?-[A-Z0-9]+(?:-[A-Z])?")
IMAGE = "c2960x-universalk9-tar."


class IosRunner(IosxeRunner):
    subdirectory, backup_format = "ios", "ios-running-config"

    def setup(self):
        r = self.request = IosUpgradeRequest.model_validate(self.job["request"])
        self.device = self.settings.device(r.device)
        if self.ios is None:
            self.ios = Ios(self.settings, self.device, self.guard, r.credential_profiles, self.audit)
        self.token = version_token(r.target_version)

    def off_target(self, member):
        return member["version"].lower() != self.request.target_version.lower()

    def booting_target(self, paths):
        return all(self.token in path for path in paths)

    def prevalidate(self):
        r = self.request
        info, stack = self.ios.version(), self.ios.stack()
        members = info["members"]
        self.result["source"] = {**info, "stack": stack}
        problems = self.stack_problems(info, stack, on_target=False)
        if problems:
            raise DeviceError(problems[0])
        versions = {m["version"] for m in members.values()}
        if len(versions) != 1:
            raise DeviceError("stack members run mixed releases")
        models = sorted({m["model"] for m in members.values()})
        if not all(FAMILY.fullmatch(m) for m in models):
            raise DeviceError("hardware must be Catalyst 2960-X or 2960-XR: " + ", ".join(models))
        if r.approved_models and not set(models) <= set(r.approved_models):
            raise DeviceError("hardware model is not approved: " + ", ".join(models))
        if not r.image.name.startswith(IMAGE):
            raise DeviceError(f"{r.image.name} is not a Catalyst 2960-X image")
        current = versions.pop()
        on_target = current.lower() == r.target_version.lower()
        if not on_target and current.lower() not in {v.lower() for v in r.allowed_source_versions}:
            raise DeviceError("running release " + current + " is outside allowed_source_versions")
        boot = self.ios.boot_paths()
        if on_target and not r.stage_only and not self.booting_target(boot):
            raise DeviceError("running the target, but the boot path does not name it")
        self.result["family"] = "C2960X"
        self.result["upgrade_needed"] = not on_target
        self.result["rollback"] = {"version": current, "boot": boot}
        self.capture_baseline(self.ios.config("running-config"))
        self.event("pre_validation_completed", upgrade_needed=not on_target)

    def stage(self):
        r, image = self.request, self.request.image
        self.checkpoint()
        extracted = image.name.replace("-tar.", "-mz.")[: -len(".tar")]
        if self.ios.has_directory(extracted):
            raise DeviceError(f"flash:{extracted} already exists; remove it before upgrading")
        flash, master = self.flash()
        if master is None:
            raise DeviceError("show switch reported no master")
        present = flash[master][1] is not None
        local = self.local_image() if not present or not self.published() else None
        size = flash[master][1] if present else local.stat().st_size if local else None
        software = self.result["software"] = {"image": image.name, "already_on_flash": present}

        def short(listings, size, master_extra=0):
            # Each member extracts an image about the size of the .tar.
            need = size + r.minimum_free_bytes
            return [
                n for n, (free, _) in listings.items() if free < need + (master_extra if n == master else 0)
            ]

        if size is not None and short(flash, size, 0 if present else size):
            if present or r.stage_only or not image.device_url or short(flash, size):
                raise DeviceError("insufficient flash for the .tar and the extracted image")
            # No room for the .tar: archive download-sw reads it from the URL, unverified on flash.
            software["source"] = "device_url"
            self.event("software_staged", file=image.name, source="device_url")
            return
        if not present:
            self.copy(local)
            software["copied"] = True
            flash, master = self.flash()
            size = flash[master][1]
            if size is None:
                raise DeviceError("the copied .tar is not on flash")
            if short(flash, size):
                raise DeviceError("insufficient flash to extract the image after the copy")
        self.report("image_verification", self.device.id, file=image.name, algorithm=image.verify)
        if self.ios.verify(image.name, image.verify) != self.expected(local):
            raise DeviceError(f"flash:{image.name} {image.verify} does not match the approved image")
        software.update(verified=image.verify, source="flash")
        self.event("software_staged", file=image.name, source="flash")

    def install(self):
        r = self.request
        self.checkpoint()
        # Refuse a stale authorization: nothing may have changed since the baseline.
        info, stack = self.ios.version(), self.ios.stack()
        if info["members"] != self.result["source"]["members"] or self.stack_problems(info, stack, False):
            raise DeviceError("software or stack membership changed since precheck; rerun required")
        if self.config_hash() != self.result["pre_validation"]["config_sha256"]:
            raise DeviceError("configuration changed since precheck; rerun required")
        if self.ios.boot_paths() != self.result["rollback"]["boot"]:
            raise DeviceError("boot path changed since precheck; rerun required")
        from_flash = self.result["software"]["source"] == "flash"
        self.result["install"] = {"image": r.image.name, "status": "started"}
        self.intent("archive_download_sw", image=r.image.name)
        self.ios.archive(
            "flash:" + r.image.name if from_flash else r.image.device_url,
            r.install_timeout,
            lambda line: self.report("archive", self.device.id, status=line),
        )
        boot = self.ios.boot_paths()
        if not self.booting_target(boot):
            raise DeviceError("archive download-sw finished, but the boot path does not name the target")
        self.result["install"]["boot"] = boot
        self.event("archive_download_sw_completed", boot=boot)
        if from_flash:
            try:
                self.ios.delete(r.image.name)
            except DeviceError:
                self.event("tar_delete_failed", file=r.image.name)
        if self.ios.unsaved():
            # Only the boot path may have changed; anything else changed during the job.
            if self.config_hash() != self.result["pre_validation"]["config_sha256"]:
                raise DeviceError("configuration changed during archive download-sw")
            self.ios.save()
        self.result["reboot_requested_at"] = datetime.now(timezone.utc).isoformat()
        self.intent("reload")
        try:
            self.ios.reload(300)
        except DeviceError:
            # A dropped session leaves the outcome to fresh observations.
            self.event("reload_response_uncertain")
        self.await_reload()

    def system_sample(self):
        critical, findings = [], []
        info, stack = self.ios.version(), self.ios.stack()
        critical += self.identity_problems(info, stack)
        if not self.booting_target(self.ios.boot_paths()):
            critical.append("the boot path does not name the target")
        self.config_sample(critical, findings)
        self.result["post_system"] = {
            "version": info["version"],
            "members": info["members"],
            "image": info["image"],
        }
        return critical, findings

    def planned_steps(self):
        r = self.request
        if not self.result["upgrade_needed"]:
            if r.stage_only:
                return []
            self.result["already_on_target"] = True
            return [("validate_current", lambda: self.validate("validate_current", self.traffic_sample))]
        steps = [("backup", self.backup)] if r.tech_support and not r.stage_only else []
        steps.append(("stage", self.stage))
        if r.stage_only:
            return steps
        return (
            steps
            + [
                ("save_config", self.save),
                ("install", self.install),
                ("settle", self.settle),
                ("validate_system", lambda: self.validate("validate_system", self.system_sample)),
                ("validate_traffic", partial(self.validate, "validate_traffic", self.traffic_sample)),
            ]
            + ([("save_after_validation", self.save_after)] if r.save_after_validation else [])
        )
