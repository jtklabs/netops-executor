"""Unattended Cisco IOS XE switch and stack upgrades over SSH. Ambiguous writes are never replayed.

The switch upgrades through IOS XE install mode, `install add file flash:<image> activate
commit`, which distributes the image to every stack member, activates it, reloads and
commits. The boot variable is only ever set to packages.conf, as install mode requires.

A new release re-renders the running configuration. Validation compares it with the
baseline through iosxe_config, which tolerates reordering and known rewrites; what remains
is reported per `config_policy`.
"""

import hashlib
import re
import time
from datetime import datetime, timezone
from functools import partial

from .config import under
from .eos_engine import compare
from .image_cache import cached_image
from .iosxe import Iosxe, boot_ok, family, release_in
from .iosxe_config import compare as compare_configs
from .iosxe_config import normalized
from .iosxe_models import IosxeUpgradeRequest, release
from .ssh import DeviceError, digest
from .stepped import StepRunner

COUNTS = {
    "routes": "min_route_percent",
    "mac": "min_mac_percent",
    "arp": "min_arp_percent",
    "access_sessions": "min_access_session_percent",
}
RESTORED = {
    "interfaces": {"up/up"},
    "bgp_peers": {"established"},
    "ospf_neighbors": {"full"},
    "port_channels": {"bundled"},
}
IMAGES = {
    "C3650": r"cat3k_caa-universalk9(?:ldpe)?\.",
    "C3850": r"cat3k_caa-universalk9(?:ldpe)?\.",
    "C9300": r"cat9k_iosxe\.",
    "C9350": r"cisco9k_iosxe(?:_npe)?\.",
}
# Install mode's one-shot `install add ... activate commit`, per family and per later PID.
FLOORS = {
    "C3650": (16, 8, 1, "a"),
    "C3850": (16, 8, 1, "a"),
    "C9300": (16, 6, 2, ""),
    "C9350": (17, 18, 1, ""),
}
PID_FLOORS = {"C9350-24HX": (26, 1, 1, "a"), "C9350-48HXN": (26, 1, 1, "a")}
SECRET = re.compile(
    r"(?i)\b(password|secret|key|key-string|community|pre-shared-key|authentication-key)((?:\s+\d{1,2})?\s+)\S+"
)


def masked(line):
    return SECRET.sub(r"\1\2<redacted>", line)


class IosxeRunner(StepRunner):
    device_errors = (DeviceError,)
    error = DeviceError

    def __init__(self, settings, store, job, worker, ios=None, sleep=time.sleep, clock=time.monotonic):
        super().__init__(settings, store, job, worker, sleep, clock)
        self.ios = ios

    def setup(self):
        r = self.request = IosxeUpgradeRequest.model_validate(self.job["request"])
        self.device = self.settings.device(r.device)
        if self.ios is None:
            self.ios = Iosxe(self.settings, self.device, self.guard, r.credential_profiles, self.audit)

    def directory(self):
        r = self.request
        path = under(self.settings.backup_root, r.backup_directory or "iosxe/" + self.device.id)
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        return path

    def reserve(self):
        keys = [self.job["lock_key"], "endpoint:" + self.device.host]
        for peer in map(self.settings.device, self.request.peers):
            # The keys every job takes for that device, so a peer never reloads at the same time.
            keys += ["device:" + peer.id, "endpoint:" + peer.host] + (
                ["group:" + peer.lock_group] if peer.lock_group else []
            )
        if not self.store.reserve(self.job["id"], self.worker, keys):
            if self.result.get("mutations"):
                raise DeviceError("reservation changed during continuation")
            self.store.defer(self.job["id"], self.worker)
        self.event("resources_reserved", keys=keys)

    def config_hash(self):
        return hashlib.sha256(normalized(self.ios.config("running-config"), boot=True).encode()).hexdigest()

    def stack_problems(self, info, stack, on_target):
        members = info["members"]
        problems = []
        if set(members) != set(stack):
            problems.append("show version and show switch disagree on stack members")
        problems += [
            f"member {n} is {s['state']}" for n, s in sorted(stack.items()) if s["state"].lower() != "ready"
        ]
        if on_target:
            problems += [
                f"member {n} runs {m['version']} in {m['mode']} mode"
                for n, m in sorted(members.items())
                if release(m["version"]) != release(self.request.target_version) or m["mode"] != "INSTALL"
            ]
        return problems

    def prevalidate(self):
        r = self.request
        info, stack, summary = self.ios.version(), self.ios.stack(), self.ios.install_summary()
        members = info["members"]
        self.result["source"] = {**info, "stack": stack}
        problems = self.stack_problems(info, stack, on_target=False)
        if problems:
            raise DeviceError(problems[0])
        versions = {release(m["version"]) for m in members.values()}
        modes = {m["mode"] for m in members.values()}
        if len(versions) != 1 or len(modes) != 1:
            raise DeviceError("stack members run mixed releases or boot modes")
        families = {family(m["model"]) for m in members.values()}
        if None in families or len(families) != 1:
            raise DeviceError("hardware must be one supported family (C9300, C9350, WS-C3650, WS-C3850)")
        platform = families.pop()
        models = sorted({m["model"] for m in members.values()})
        if r.approved_models and not set(models) <= set(r.approved_models):
            raise DeviceError("hardware model is not approved: " + ", ".join(models))
        if not re.match(IMAGES[platform], r.image.name):
            raise DeviceError(f"{r.image.name} is not a {platform} install image")
        current = next(iter(members.values()))["version"]
        target, running, mode = release(r.target_version), versions.pop(), modes.pop()
        floor = max(PID_FLOORS.get(m, FLOORS[platform]) for m in models)
        if target < floor or platform in ("C3650", "C3850") and target >= (16, 13, 0, ""):
            raise DeviceError(f"{platform} target {r.target_version} is outside the one-shot install range")
        # Cisco CSCwt90927: this stack path can corrupt the primary ROMMON.
        if (
            platform == "C9350"
            and len(members) > 1
            and (running, target) == ((17, 18, 1, ""), (17, 18, 3, ""))
        ):
            raise DeviceError("C9350 stacks must not upgrade 17.18.1 to 17.18.3 (Cisco CSCwt90927)")
        on_target = running == target
        if not on_target:
            if running not in {release(v) for v in r.allowed_source_versions}:
                raise DeviceError("running release " + current + " is outside allowed_source_versions")
            if running < floor:
                raise DeviceError(f"{platform} must run at least the one-shot install floor before upgrading")
        self.result["family"] = platform
        self.result["upgrade_needed"] = not on_target
        self.result["rollback"] = {"version": current, "mode": mode}
        if not r.stage_only:
            if mode == "BUNDLE" and (on_target or not r.allow_bundle_conversion):
                raise DeviceError("switch boots in BUNDLE mode; set allow_bundle_conversion to convert it")
            if summary["pending"] or summary["abort_timer"]:
                raise DeviceError("install state has uncommitted changes or an active auto-abort timer")
            if mode == "INSTALL" and (
                set(summary["committed"]) != set(members)
                or not all(release_in(v, current) for v in summary["committed"].values())
            ):
                raise DeviceError("committed image cannot be confirmed on every stack member")
        running_config = self.ios.config("running-config")
        if on_target and not r.stage_only and not boot_ok(running_config):
            raise DeviceError("running the target, but boot system is not flash:packages.conf")
        if r.stage_only:
            self.result["pre_validation"] = {}
        else:
            path = self.directory() / (self.job["id"] + "-" + self.device.id + "-running-config.txt")
            self.write_private(path, running_config.encode())
            self.artifact(self.device.id, "config", path, "iosxe-running-config")
            self.result["pre_validation"] = {
                "traffic": self.ios.traffic(),
                "config_sha256": hashlib.sha256(normalized(running_config, boot=True).encode()).hexdigest(),
                "baseline": {
                    "path": str(path.relative_to(self.settings.backup_root.resolve())),
                    "sha256": digest(path),
                },
                "unsaved": self.ios.unsaved(),
                "boot_ok": boot_ok(running_config),
            }
        self.event("pre_validation_completed", upgrade_needed=not on_target)

    def baseline_config(self):
        saved = self.result["pre_validation"]["baseline"]
        path = under(self.settings.backup_root, saved["path"])
        if digest(path) != saved["sha256"]:
            raise DeviceError("baseline configuration file changed since precheck")
        return path.read_text()

    def backup(self):
        self.report("tech_support", self.device.id)
        path = self.directory() / (self.job["id"] + "-" + self.device.id + "-tech-support.txt")
        self.write_private(path, self.ios.tech_support().encode())
        self.artifact(self.device.id, "tech_support", path)

    def published(self):
        image = self.request.image
        return image.sha512 if image.verify == "sha512" else image.md5

    def expected(self, local):
        image = self.request.image
        if self.published():
            return self.published()
        if local is None or not local.is_file():
            raise DeviceError(f"set image.{image.verify} or provide the executor's copy of {image.name}")
        return digest(local, image.verify)

    def local_image(self):
        image = self.request.image
        self.report("image_cache", self.device.id, file=image.name)
        local = cached_image(self.settings, image, self.job["id"], self.checkpoint)
        if not local.is_file():
            return None
        if digest(local) != image.sha256:
            raise DeviceError("executor image SHA-256 mismatch: " + image.name)
        return local

    def flash(self):
        stack = self.ios.stack()
        return {n: self.ios.flash(n, self.request.image.name) for n in sorted(stack)}, next(
            (n for n, s in stack.items() if s["role"] == "Active"), None
        )

    def stage(self):
        r, image = self.request, self.request.image
        self.checkpoint()
        summary = self.ios.install_summary()
        flash, active = self.flash()
        if active is None:
            raise DeviceError("show switch reported no active member")
        local = self.local_image() if flash[active][1] is None or not self.published() else None
        size = local.stat().st_size if local else flash[active][1] or 0

        def short(listings):
            return [
                n
                for n, (free, have) in listings.items()
                if have is None and free < size + r.minimum_free_bytes
            ]

        if summary["inactive"] and not r.remove_inactive and not r.stage_only:
            raise DeviceError("inactive install packages are present and remove_inactive is false")
        if r.remove_inactive and not summary["pending"] and (summary["inactive"] or short(flash)):
            # Also deletes unused .bin files, a preloaded image among them; so it runs before the copy.
            self.event("remove_inactive_started")
            self.ios.remove_inactive(
                r.install_timeout, lambda line: self.report("remove_inactive", self.device.id, status=line)
            )
            self.event("remove_inactive_completed")
            flash, active = self.flash()
        software = self.result["software"] = {
            "image": image.name,
            "already_on_flash": flash[active][1] is not None,
        }
        if flash[active][1] is None:
            if short(flash):
                raise DeviceError("insufficient flash on member(s) " + ", ".join(short(flash)))
            self.copy(local)
            software["copied"] = True
            flash, active = self.flash()
        self.report("image_verification", self.device.id, file=image.name, algorithm=image.verify)
        if self.ios.verify(image.name, image.verify) != self.expected(local):
            raise DeviceError(f"flash:{image.name} {image.verify} does not match the approved image")
        software["verified"] = image.verify
        size = flash[active][1]
        low = [n for n, (free, have) in flash.items() if free < r.minimum_free_bytes + (0 if have else size)]
        if low:
            raise DeviceError("insufficient expansion space on member(s) " + ", ".join(low))
        self.event("software_staged", file=image.name)

    def copy(self, local):
        r, image = self.request, self.request.image
        if image.device_url:
            self.event("device_copy_started", file=image.name)
            try:
                self.ios.device_copy(
                    image.device_url,
                    image.name,
                    r.upload_timeout,
                    lambda line: self.report("device_copy", self.device.id, file=image.name, status=line),
                )
                self.event("device_copy_completed", file=image.name)
                return
            except DeviceError as exc:
                if "copy of" not in str(exc):
                    raise
                # The switch answered with a failure and is back at its prompt; push it instead.
                self.event("device_copy_failed", message=str(exc))
                listings, active = self.flash()
                if listings[active][1] is not None:
                    self.ios.delete(image.name)
            local = local or self.local_image()
        if local is None:
            raise DeviceError("executor image missing: " + image.name)
        if "ip scp server enable" not in self.ios.config("running-config"):
            raise DeviceError("copying the image needs ip scp server enable on the switch")

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
        self.ios.upload(local, image.name, sent)
        self.event("software_upload_completed", file=image.name)

    def save(self):
        if not self.ios.unsaved():
            return
        if not self.request.save_config:
            raise DeviceError("running and startup configuration differ and save_config is false")
        self.event("write_memory_started")
        self.ios.save()
        if self.ios.unsaved():
            raise DeviceError("running and startup configuration still differ after write memory")
        self.event("write_memory_completed")

    def boot(self):
        if self.result["pre_validation"]["boot_ok"] and boot_ok(self.ios.config("running-config")):
            return
        self.intent("boot_packages_conf")
        self.result["boot_changed"] = True
        self.ios.configure_boot()
        self.ios.save()
        running, startup = self.ios.config("running-config"), self.ios.config("startup-config")
        if not boot_ok(running) or not boot_ok(startup) or self.ios.unsaved():
            raise DeviceError("boot system flash:packages.conf could not be verified as saved")
        if self.config_hash() != self.result["pre_validation"]["config_sha256"]:
            raise DeviceError("configuration changed beyond the boot settings")
        self.event("boot_packages_conf_completed")

    def install(self):
        r = self.request
        self.checkpoint()
        # Refuse a stale authorization: nothing may have changed since the baseline.
        info, stack = self.ios.version(), self.ios.stack()
        source = self.result["source"]
        if info["members"] != source["members"] or self.stack_problems(info, stack, on_target=False):
            raise DeviceError("software or stack membership changed since precheck; rerun required")
        if self.config_hash() != self.result["pre_validation"]["config_sha256"]:
            raise DeviceError("configuration changed since precheck; rerun required")
        if self.ios.install_summary()["pending"]:
            raise DeviceError("install state changed since precheck; rerun required")
        self.result["install"] = {"image": r.image.name, "status": "started"}
        self.result["reboot_requested_at"] = datetime.now(timezone.utc).isoformat()
        self.intent("install_add_activate_commit", image=r.image.name)
        try:
            self.ios.install(
                r.image.name,
                r.install_timeout,
                lambda line: self.report("install", self.device.id, status=line),
            )
        except DeviceError as exc:
            if "reported a failure" in str(exc) or "without success" in str(exc):
                raise
            # A deadline or dropped session leaves the outcome to fresh observations.
            self.event("install_response_uncertain")
        self.ios.close()
        start = self.clock()
        deadline = start + r.reboot_timeout
        status = "waiting for the stack to reload"
        while self.clock() < deadline:
            self.wait(30)
            self.report(
                "reboot",
                self.device.id,
                elapsed_seconds=round(self.clock() - start),
                timeout_seconds=r.reboot_timeout,
                status=status,
            )
            try:
                info, stack = self.ios.version(), self.ios.stack()
            except DeviceError:
                self.ios.close()
                continue
            missing = sorted(set(source["members"]) - set(info["members"]))
            problems = (
                ["member(s) " + ", ".join(missing) + " not back"] if missing else []
            ) + self.stack_problems(info, stack, on_target=True)
            uptime = info["uptime_seconds"]
            if uptime is None or uptime > self.clock() - start + 600:
                problems.append("no fresh boot yet")
            if not problems:
                self.result["install"]["status"] = "completed"
                self.result["boot_verified"] = {"version": info["version"], "uptime_seconds": uptime}
                self.event("reboot_completed")
                return
            status = problems[0]
        raise DeviceError("the stack was not verified on the target before timeout: " + status)

    def system_sample(self):
        r = self.request
        critical, findings = [], []
        info, stack = self.ios.version(), self.ios.stack()
        source = self.result["source"]
        missing = sorted(set(source["members"]) - set(info["members"]))
        if missing:
            critical.append("member(s) " + ", ".join(missing) + " missing")
        critical += self.stack_problems(info, stack, on_target=True)
        if {n: m["model"] for n, m in info["members"].items()} != {
            n: m["model"] for n, m in source["members"].items()
        } or (source["serials"] and info["serials"] != source["serials"]):
            critical.append("a different switch or stack answered after the reload")
        summary = self.ios.install_summary()
        if (
            set(summary["committed"]) != set(source["members"])
            or not all(release_in(v, r.target_version) for v in summary["committed"].values())
            or summary["pending"]
        ):
            critical.append("the target image is not committed on every member")
        running = self.ios.config("running-config")
        if not boot_ok(running):
            critical.append("boot system is not flash:packages.conf")
        result = compare_configs(self.baseline_config(), running, r.config_policy)
        self.record_config(result, running)
        for kind in ("removed", "added"):
            count = result[kind + "_count"]
            action = getattr(r.config_policy, kind)
            if not count or action == "ignore":
                continue
            message = f"{count} configuration line(s) {kind} beyond the tolerated release differences"
            if action == "critical":
                critical.append(message)
            else:
                findings.append(
                    {"category": "config", "change": kind, "objects": [masked(x) for x in result[kind][:100]]}
                )
        self.result["post_system"] = {"version": info["version"], "members": info["members"]}
        return critical, findings

    def record_config(self, result, running):
        """Masked summary in the job result; full lines in a private file next to the baseline."""
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
        post = self.directory() / (self.job["id"] + "-" + self.device.id + "-post-running-config.txt")
        self.write_private(post, running.encode())

    def traffic_sample(self):
        current = self.ios.traffic()
        failures, findings, metrics = compare(
            self.result["pre_validation"]["traffic"],
            current,
            self.request.validation_policy,
            restored=RESTORED,
            counts=COUNTS,
            informational=("hsrp",),
        )
        self.result["post_validation"] = {"traffic": current, "metrics": metrics}
        return failures, findings

    def save_after(self):
        comparison = self.result.get("config_comparison", {})
        if comparison.get("removed_count"):
            # Keep the pre-upgrade text in startup-config until someone reviews the removed lines.
            self.result["post_save"] = {"saved": False, "reason": "configuration lines were removed"}
            self.event("write_memory_skipped", reason="configuration lines were removed")
            return
        if self.ios.unsaved():
            self.event("write_memory_started")
            self.ios.save()
            self.event("write_memory_completed")
        self.result["post_save"] = {"saved": True}

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
                ("boot_packages_conf", self.boot),
                ("install", self.install),
                ("settle", self.settle),
                ("validate_system", lambda: self.validate("validate_system", self.system_sample)),
                ("validate_traffic", partial(self.validate, "validate_traffic", self.traffic_sample)),
            ]
            + ([("save_after_validation", self.save_after)] if r.save_after_validation else [])
        )

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
        # A started install may have activated an unvalidated image; a BUNDLE switch whose
        # boot variable now names packages.conf cannot boot its old image.
        return self.result.get("install", {}).get("status") in ("started", "completed") or bool(
            self.result.get("boot_changed") and self.result.get("rollback", {}).get("mode") == "BUNDLE"
        )

    def close(self):
        if self.ios is not None:
            self.ios.close()
