import json
import math
import os
import re
import time
from datetime import datetime, timezone

from .admin_password import PasswordCheckUnavailable, matches_admin_password, reset_admin_password
from .config import under
from .credentials import Vault
from .device import BigIP, differences, matches, name
from .image_cache import cached_image
from .models import JobRequest
from .ssh import SSH, DeviceError, digest
from .store import CancelRequested, Conflict, Deferred, LostOwnership, NeedsReview


class Runner:
    def __init__(self, settings, store, job, worker, device=None, sleep=time.sleep, clock=time.monotonic):
        self.settings, self.store, self.job, self.worker = settings, store, job, worker
        self.sleep, self.clock = sleep, clock
        self.result = job["result"]
        continuation = job.get("control", {}).get("continuation")
        admin = self.result.get("admin_password", {})
        self.changed = bool(
            self.result.get("inherited_lock")
            or (continuation and continuation != "admin_password_before")
            or admin.get("reset_in_progress")
            or any(check.get("reset_attempted") for check in admin.get("checks", []))
        )
        self.changed_addresses = (
            []
            if self.result.get("drain", {}).get("restored")
            else self.result.get("drain", {}).get("changed_addresses", [])[:]
        )
        self.boot_attempted = bool(self.result.get("boot_verified"))
        self.phase = "connect"
        self.io_deadline = None
        self.peer = None
        self.topology = None
        self.ssh = (
            SSH(
                settings,
                settings.device(job["device"]),
                self.guard,
                job["request"].get("credential_profiles"),
                self.audit,
            )
            if device is None
            else device.ssh
        )
        self.device = device or BigIP(self.ssh)
        self.ssh.transfer_guard = self.checkpoint
        self.ssh.progress = self.transfer_progress
        self.last_progress = 0

    def guard(self):
        self.store.guard(self.job["id"], self.worker)
        if self.io_deadline is not None and self.clock() >= self.io_deadline:
            raise DeviceError("validation collection deadline exceeded")

    def transfer_progress(self, done, total):
        if self.clock() - self.last_progress >= 5 or done == total:
            self.last_progress = self.clock()
            self.result["transfer_progress"] = {
                "bytes": done,
                "total_bytes": total,
                "percent": round(100 * done / total, 1) if total else 0,
            }
            self.event("transfer_progress", **self.result["transfer_progress"])

    def checkpoint(self):
        self.store.checkpoint(self.job["id"], self.worker)

    def audit(self, data):
        self.store.credential_event(self.job["id"], self.worker, {**data, "phase": self.phase})

    def reserve(self):
        self.phase = "discover_ha"
        self.topology = self.device.topology()
        original = self.result.get("ha")
        if original and (
            original["cluster"] != self.topology["cluster"] or original["self"] != self.topology["self"]
        ):
            raise DeviceError("device HA identity changed during continuation")
        keys = [self.job["lock_key"], "endpoint:" + self.settings.device(self.job["device"]).host]
        keys += ["device:" + self.settings.device(member["host"]).id for member in self.topology["members"]]
        keys += ["endpoint:" + member["host"] for member in self.topology["members"]]
        if self.topology["cluster"]:
            keys.append(self.topology["cluster"])
        if not self.store.reserve(self.job["id"], self.worker, keys):
            if self.changed:
                raise DeviceError("reservation changed during continuation")
            self.store.defer(self.job["id"], self.worker)
        self.result["ha"] = self.topology
        self.event("resources_reserved", keys=keys)

    def peer_device(self):
        if self.peer is None:
            member = next(m for m in self.topology["members"] if m["name"] != self.topology["self"])
            self.peer = BigIP(
                SSH(
                    self.settings,
                    self.settings.device(member["host"]),
                    self.guard,
                    self.job["request"].get("credential_profiles"),
                    lambda data: self.audit({**data, "connection": "ha_peer"}),
                )
            )
        return self.peer

    def ha_health(self, request, before=False):
        local = self.device.topology()
        if not local["cluster"]:
            if local["role"] != "active":
                raise DeviceError("standalone unit is not active")
            return
        peer = self.peer_device()
        other = peer.topology()
        if local["cluster"] != self.topology["cluster"] or other["cluster"] != local["cluster"]:
            raise DeviceError("HA membership changed or peer does not confirm membership")
        if set(local["groups"]) != set(other["groups"]):
            raise DeviceError("peer does not confirm the same failover groups")
        if any(
            t["sync"] in ("disconnected", "sync failure", "awaiting initial sync") for t in (local, other)
        ):
            raise DeviceError("HA synchronization health is unavailable or failed")
        if sorted([local["role"], other["role"]]) != ["active", "standby"]:
            raise DeviceError("HA requires one active and one available standby")
        left, right = self.device.owners(), peer.owners()
        expected = local["self"] if local["role"] == "active" else other["self"]
        if left != right or set(left.values()) != {expected}:
            raise DeviceError("HA traffic ownership is inconsistent or active-active")
        health = peer.snapshot()
        if not health.get("asm_ready", True):
            raise DeviceError("peer ASM is not ready")
        # Minor monitor differences remain reportable warnings. Config inventory must be present.
        baseline = self.result.get("pre_validation")
        if baseline:
            if baseline["waf_policy_names"] != health["waf_policy_names"]:
                raise DeviceError("peer WAF policy inventory differs")
            for category in ("virtual_servers", "pools", "nodes", "virtual_ips"):
                if set(baseline[category]["objects"]) != set(health[category]["objects"]):
                    raise DeviceError("peer object inventory differs: " + category)
        active = self.device.active()
        same_version = (active["version"], active["build"]) == (
            health["active"]["version"],
            health["active"]["build"],
        )
        if before and same_version and (local["sync"] != "in sync" or other["sync"] != "in sync"):
            raise DeviceError("HA configuration is not in sync")
        if before and not same_version:
            if not self.store.validated_peer(
                self.job["id"], local["cluster"], health["active"], other["self"]
            ):
                raise DeviceError("mixed-version peer needs a completed upgrade validation before continuing")
        self.result["peer_validation"] = {
            "device": other["self"],
            "active": health["active"],
            "role": other["role"],
            "owners": right,
        }
        self.event("ha_health_verified")
        if before and local["role"] == "active" and not request.ha_policy.allow_active_first:
            raise DeviceError("active-first upgrade is disabled by this request")

    def failover(self, request):
        self.phase = "ha_failover"
        self.ha_health(request, before=True)
        local = self.device.topology()
        if local["role"] == "active":
            self.checkpoint()
            self.intent("ha_failover")
            self.ssh.tmsh("run /sys failover standby")
            deadline = self.clock() + 120
            while True:
                local = self.device.topology()
                if local["role"] == "standby":
                    self.ha_health(request)
                    self.event("ha_failover_completed")
                    return
                if self.clock() >= deadline:
                    raise DeviceError("HA failover did not complete")
                self.wait(5)

    def select_volume(self, request, active):
        volumes = self.device.volumes()
        if request.target_volume is None:
            inactive = sorted(
                (
                    v
                    for v in volumes.values()
                    if not v["active"] and v["status"] == "complete" and not v.get("active_requested")
                ),
                key=lambda v: tuple(map(int, re.findall(r"\d+", v["volume"]))),
            )
            exact = [v for v in inactive if matches(v, request.expected_version, request.expected_build)]
            if exact:
                target = exact[0]["volume"]
            elif request.install and inactive:
                target = inactive[0]["volume"]
            elif request.install:
                prefix = active["volume"].split(".")[0]
                number = max(int(v.split(".")[1]) for v in volumes if v.startswith(prefix + ".")) + 1
                target = prefix + "." + str(number)
            else:
                raise DeviceError("no inactive volume matches the requested reboot version/build")
            request.target_volume = target
        if request.target_volume == active["volume"]:
            raise DeviceError("target volume must not be the active volume")
        if any(
            v["status"] != "complete" or (v.get("active_requested") and not v["active"])
            for v in volumes.values()
        ):
            raise DeviceError("another volume is not complete; inspect before upgrading")
        self.result["target_volume"] = request.target_volume
        self.event("target_volume_selected", volume=request.target_volume)

    def copy_config(self, request):
        self.phase = "copy_config"
        self.checkpoint()
        self.intent("save_config_for_target")
        self.ssh.tmsh("save /sys config", timeout=180)
        self.intent("copy_config", volume=request.target_volume)
        directory = self.device.start_copy(
            self.result["rollback"]["volume"], request.target_volume, self.job["id"]
        )
        self.result["config_copy"] = {"directory": directory, "completed": False}
        self.event("copy_config_polling")
        deadline = self.clock() + request.install_timeout
        # cpcfg cannot safely be interrupted. Observe completion before honoring cancellation.
        while not self.device.copy_status(directory):
            if self.clock() >= deadline:
                raise DeviceError("configuration copy timed out; inspect the device copy log")
            self.wait(5)
        self.result["config_copy"]["completed"] = True
        self.event("copy_config_completed")
        self.checkpoint()

    def event(self, step, **data):
        self.phase = step
        self.store.record(self.job["id"], self.worker, step, data, self.result)

    def intent(self, step, **data):
        # Persist BEFORE issuing a mutation. An interrupted operation is never automatically replayed.
        self.changed = True
        self.event(step + "_started", **data)

    def wait(self, seconds=5):
        self.guard()
        self.sleep(seconds)
        self.guard()

    def backup(self, request):
        d = self.settings.device(request.device)
        passphrase = None
        if not request.ucs_unencrypted:
            profiles = Vault(self.store, self.settings.credential_key_file).candidates(
                "ucs", [request.ucs_credential] if request.ucs_credential else None, (d.host, d.id)
            )
            if profiles:
                selected = profiles[0]
                passphrase = selected["passphrase"]
                self.result["ucs_credential"] = {"profile": selected["id"], "revision": selected["revision"]}
            else:
                passphrase = os.environ.get(d.ucs_passphrase_env)
        self.checkpoint()
        if not request.ucs_unencrypted and not passphrase:
            raise DeviceError("encrypted UCS requires the configured UCS passphrase environment variable")
        if passphrase and any(c in passphrase for c in "\r\n\x00"):
            raise DeviceError("UCS passphrase cannot contain newline or NUL")
        directory = under(self.settings.backup_root, request.backup_directory or request.device)
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        filename = self.job["id"] + ".ucs"
        path = directory / filename
        remote = "/var/local/ucs/" + filename
        self.intent("save_config")
        self.ssh.tmsh("save /sys config", timeout=180)
        command = "save /sys ucs " + filename
        if passphrase:
            quoted = passphrase.replace("\\", "\\\\").replace('"', '\\"')
            command += ' passphrase "' + quoted + '"'
        self.intent("create_ucs", encrypted=not request.ucs_unencrypted)
        self.ssh.tmsh(command, timeout=1800, secret=bool(passphrase))
        self.event("copy_ucs_started")
        self.ssh.get(remote, path)
        self.result["backup"] = {
            "path": str(path.relative_to(self.settings.backup_root.resolve())),
            "sha256": digest(path),
            "encrypted": not request.ucs_unencrypted,
            "bytes": path.stat().st_size,
        }
        self.event("copy_ucs_completed")

    def images(self, request):
        for image in request.images:
            remote = "/shared/images/" + image.name
            if "transfer" in request.plan():
                local = cached_image(self.settings, image, self.job["id"], self.checkpoint)
                if not local.is_file() or digest(local) != image.sha256:
                    raise DeviceError("local image missing or SHA-256 mismatch: " + image.name)
                try:
                    present = self.ssh.remote_digest(remote) == image.sha256
                except (DeviceError, KeyError):
                    present = False
                if present:
                    self.event("transfer_skipped_verified", image=image.name)
                else:
                    if self.device.free_bytes() < local.stat().st_size + request.minimum_free_bytes:
                        if request.cleanup_images:
                            self.cleanup_images(request)
                        if self.device.free_bytes() < local.stat().st_size + request.minimum_free_bytes:
                            raise DeviceError("insufficient image filesystem space and reserve")
                    partial = "/shared/images/." + self.job["id"] + ".partial"
                    self.checkpoint()
                    self.intent("transfer", image=image.name)
                    try:
                        self.ssh.put(local, partial)
                        if self.ssh.remote_digest(partial) != image.sha256:
                            raise DeviceError("transferred image SHA-256 mismatch")
                        self.ssh.shell("mv -- " + name(partial) + " " + name(remote))
                    except CancelRequested:
                        self.ssh.shell("rm -f -- " + name(partial))
                        raise
                    self.event("transfer_completed", image=image.name)
            if self.ssh.remote_digest(remote) != image.sha256:
                raise DeviceError("device image SHA-256 mismatch: " + image.name)
            # The software catalog can lag behind an SFTP rename while F5 scans the image.
            deadline = self.clock() + 120
            while True:
                try:
                    self.device.verify_image(image)
                    break
                except DeviceError:
                    if self.clock() >= deadline:
                        raise
                    self.wait(5)
            self.event("image_verified", image=image.name)

    def cleanup_images(self, request):
        from .device import blocks

        keep = {i.name for i in request.images}
        for kind in ("hotfix", "image"):
            catalog = blocks(self.ssh.tmsh("list /sys software " + kind), "sys software " + kind)
            for filename in sorted(catalog):
                if filename not in keep:
                    self.checkpoint()
                    self.intent("delete_installer", image=filename)
                    self.ssh.tmsh("delete /sys software " + kind + " " + name(filename))

    def install(self, request):
        if self.device.free_bytes() < request.minimum_free_bytes:
            if request.cleanup_images:
                self.cleanup_images(request)
            if self.device.free_bytes() < request.minimum_free_bytes:
                raise DeviceError("image filesystem reserve is below minimum_free_bytes")
        final = request.images[-1]
        if matches(self.device.volumes().get(request.target_volume), final.version, final.build):
            self.event("install_already_complete", image=final.name, volume=request.target_volume)
            return
        for image in request.images:
            self.checkpoint()
            volumes = self.device.volumes()
            if any(v["active"] and v["volume"] == request.target_volume for v in volumes.values()):
                raise DeviceError("refusing to install on active volume")
            if matches(volumes.get(request.target_volume), image.version, image.build):
                self.event("install_already_complete", image=image.name, volume=request.target_volume)
                continue
            self.intent("install", image=image.name, volume=request.target_volume)
            self.device.install(image, request.target_volume, request.target_volume not in volumes)
            deadline = self.clock() + request.install_timeout
            while True:
                target = self.device.volumes().get(request.target_volume)
                if target and "fail" in target["status"].lower():
                    raise DeviceError("software installation failed")
                if matches(target, image.version, image.build):
                    break
                if self.clock() >= deadline:
                    raise DeviceError("software installation did not complete with expected version/build")
                self.wait(10)
            self.event("install_completed", image=image.name)
            self.checkpoint()

    def drain(self, request):
        self.device.check_drain()
        states = self.device.address_states()
        baseline = self.device.connections()
        threshold = (
            math.floor(baseline * (100 - request.drain_percent) / 100)
            if request.drain_percent is not None
            else (request.drain_connections or 0)
        )
        self.result["drain"] = {
            "initial_connections": baseline,
            "threshold": threshold,
            "address_states": states,
            "changed_addresses": [],
            "timed_out": False,
        }
        self.event("drain_snapshot")
        for address, enabled in states.items():
            self.checkpoint()
            if enabled:
                # Include the in-flight command in recovery, even if the SSH response is lost.
                self.changed_addresses.append(address)
                self.result["drain"]["changed_addresses"] = self.changed_addresses[:]
                self.intent("disable_virtual_address", address=address)
                self.device.set_enabled(address, False)
        deadline = self.clock() + request.drain_timeout
        while True:
            self.checkpoint()
            current = self.device.connections()
            self.result["drain"]["final_connections"] = current
            self.event("drain_sample", connections=current, threshold=threshold)
            if current <= threshold:
                return
            if self.clock() >= deadline:
                self.result["drain"]["timed_out"] = True
                self.event("drain_timeout", forced_reboot=request.reboot_on_drain_timeout)
                if not request.reboot_on_drain_timeout:
                    raise DeviceError("drain timed out; reboot was not authorized on timeout")
                return
            self.wait(min(5, max(0, deadline - self.clock())))

    def restore_addresses(self):
        for address in self.changed_addresses[:]:
            self.intent("restore_virtual_address", address=address)
            self.device.set_enabled(address, True)
            self.changed_addresses.remove(address)
        if "drain" in self.result:
            self.ssh.tmsh("save /sys config", timeout=180)
            self.result["drain"]["restored"] = True
            self.event("virtual_addresses_restored")

    def reboot(self, volume, version, build, timeout):
        if not matches(self.device.volumes().get(volume), version, build):
            raise DeviceError("reboot target is not complete with expected version/build")
        if self.device.active()["volume"] == volume:
            raise DeviceError("reboot target is already active")
        old_boot = self.device.boot_id()
        self.checkpoint()
        self.boot_attempted = True
        self.result["reboot_requested_at"] = datetime.now(timezone.utc).isoformat()
        self.intent("reboot", volume=volume)
        try:
            self.device.reboot(volume)
        except DeviceError:
            # Reboot can close SSH before returning. Only a NEW boot identity verifies it happened.
            self.event("reboot_response_uncertain")
        finally:
            self.ssh.close()
        deadline = self.clock() + timeout
        while self.clock() < deadline:
            self.wait(5)
            try:
                if self.device.boot_id() != old_boot:
                    active = self.device.active()
                    if (
                        active["volume"] == volume
                        and active["version"] == version
                        and active["build"] == build
                    ):
                        self.result["boot_verified"] = active
                        self.event("reboot_completed")
                        return
            except DeviceError:
                self.ssh.close()
        raise DeviceError(
            "new boot identity and expected volume/version/build were not verified before timeout"
        )

    def postvalidate(self, baseline, request, phase="post_validation"):
        deadline = self.clock() + request.validation_timeout
        passes = 0
        while True:
            self.checkpoint()
            critical, findings = [], []
            self.io_deadline = deadline if request.validation_timeout else self.clock() + 120
            try:
                snapshot = self.device.snapshot()
                self.result["post_validation"] = snapshot
                findings = differences(baseline, snapshot, self.changed_addresses)
                if not snapshot.get("asm_ready", True):
                    critical.append("ASM is not ready")
                if request.reboot:
                    active = snapshot["active"]
                    if (active["volume"], active["version"], active["build"]) != (
                        request.target_volume,
                        request.expected_version,
                        request.expected_build,
                    ):
                        critical.append("running volume/version/build changed after reboot")
                if self.topology["cluster"]:
                    self.ha_health(request)
            except DeviceError as exc:
                critical.append(str(exc))
                self.event("post_validation_waiting_for_device")
            finally:
                self.io_deadline = None
            review = bool(findings) and request.validation_policy.noncritical_differences == "require_review"
            ltm = [
                f for f in findings if f["category"] in ("virtual_servers", "pools", "nodes", "virtual_ips")
            ]
            total = sum(baseline[c]["total"] for c in ("virtual_servers", "pools", "nodes", "virtual_ips"))
            unchanged = max(0, 100 * (total - len(ltm)) / total) if total else 100
            waf_names = set(baseline["waf_policy_names"])
            current = self.result.get("post_validation", {})
            unchanged_waf = sum(
                n in current.get("waf_policy_names", [])
                and baseline.get("waf_policy_attributes", {}).get(n)
                == current.get("waf_policy_attributes", {}).get(n)
                for n in waf_names
            )
            waf_percent = 100 * unchanged_waf / len(waf_names) if waf_names else 100
            if request.validation_policy.noncritical_differences == "require_review":
                # Thresholds waive object differences; unrelated configuration differences still require review.
                review = (
                    unchanged < request.validation_policy.ltm_min_unchanged_percent
                    or waf_percent < request.validation_policy.waf_min_unchanged_percent
                    or any(
                        f["category"]
                        not in ("virtual_servers", "pools", "nodes", "virtual_ips", "waf_policies")
                        for f in findings
                    )
                )
            self.result["validation_percentages"] = {"ltm_unchanged": unchanged, "waf_unchanged": waf_percent}
            self.result["validation_differences"] = findings
            self.result["validation_issues"] = critical + [
                f["category"] + ": " + f["change"] for f in findings
            ]
            passes = passes + 1 if not critical and not review else 0
            self.event(
                phase + "_sample",
                critical=critical,
                difference_count=len(findings),
                consecutive_passes=passes,
            )
            required = request.validation_policy.consecutive_passes if request.validation_timeout else 1
            if passes >= required:
                self.result["validation_accepted"] = True
                return
            if self.clock() >= deadline:
                if request.validation_policy.on_timeout == "fail":
                    raise DeviceError("validation timed out; findings recorded")
                self.store.open_gate(
                    self.job["id"],
                    self.worker,
                    phase,
                    {"critical": critical, "differences": findings},
                    self.result,
                )
            self.wait(min(10, max(0, deadline - self.clock())))

    def waf_requests(self, request):
        if not request.validation_policy.waf_request_check:
            return
        latest = self.result.get("post_validation", self.result["pre_validation"])
        if not latest["waf_policies"] or self.device.topology()["role"] != "active":
            self.result["waf_request_check"] = {
                "status": "skipped",
                "reason": "no policies or unit is standby",
            }
            self.event("waf_request_check_skipped")
            return
        command = self.settings.device(self.job["device"]).waf_request_command
        if not command:
            self.store.open_gate(
                self.job["id"],
                self.worker,
                "waf_requests",
                {"critical": ["configure a read-only waf_request_command or manually validate WAF traffic"]},
                self.result,
            )
        deadline = self.clock() + request.validation_timeout
        while True:
            self.checkpoint()
            try:
                data = json.loads(self.ssh.shell(command, timeout=30))
                stamp = datetime.fromisoformat(data["timestamp"].replace("Z", "+00:00"))
                boundary = datetime.fromisoformat(self.result["reboot_requested_at"])
                if stamp.tzinfo and stamp >= boundary and stamp <= datetime.now(timezone.utc) and data["id"]:
                    self.result["waf_request_check"] = {
                        "status": "passed",
                        "id": str(data["id"])[:128],
                        "timestamp": stamp.isoformat(),
                    }
                    self.event("waf_request_check_completed")
                    return
            except (DeviceError, ValueError, KeyError, TypeError):
                pass
            if self.clock() >= deadline:
                if request.validation_policy.on_timeout == "fail":
                    raise DeviceError("no post-upgrade WAF request observed before timeout")
                self.store.open_gate(
                    self.job["id"],
                    self.worker,
                    "waf_requests",
                    {"critical": ["no new WAF request observed"]},
                    self.result,
                )
            self.wait(min(10, max(0, deadline - self.clock())))

    def capture_restored(self):
        self.result["validation_snapshot_during_drain"] = self.result.get("post_validation")
        try:
            snapshot = self.device.snapshot()
        except DeviceError:
            self.store.open_gate(
                self.job["id"],
                self.worker,
                "post_restore_snapshot",
                {"critical": ["post-restoration snapshot unavailable"]},
                self.result,
            )
        self.result["post_validation"] = snapshot
        self.result["validation_differences"] = differences(self.result["pre_validation"], snapshot)
        self.event("post_restore_snapshot_completed")

    def check_admin_password(self, request, stage):
        policy = request.admin_password
        if not policy or not getattr(policy, stage):
            return
        self.checkpoint()
        state = self.result.setdefault("admin_password", {"account": "admin", "checks": []})
        report = {
            "stage": stage,
            "status": "checking",
            "checked_at": time.time(),
            "reset_attempted": False,
            "remediated": False,
        }
        state["checks"].append(report)

        def review(message):
            report["reason"] = message
            self.event("admin_password_check_failed", stage=stage, status=report["status"])
            self.store.open_gate(
                self.job["id"],
                self.worker,
                "admin_password_" + stage,
                {"critical": [message], "account": "admin", "stage": stage},
                self.result,
            )

        d = self.settings.device(request.device)
        selected_name = state.get("profile") or policy.credential_profile
        try:
            profiles = Vault(self.store, self.settings.credential_key_file).candidates(
                "f5_admin", [selected_name] if selected_name else None, (d.host, d.id)
            )
        except Conflict:
            profiles = []
        if not profiles:
            report["status"] = "unavailable"
            review("expected admin password profile is unavailable for this device")
        selected = profiles[0]
        state["profile"] = selected["id"]
        report.update(profile=selected["id"], revision=selected["revision"])
        password = selected["password"]
        # Add the separate expected password to transport redaction as well.
        if hasattr(self.ssh, "selector"):
            self.ssh.selector.secrets.add(password)
        self.event("admin_password_check_started", stage=stage)
        try:
            matched = matches_admin_password(self.ssh, password)
        except PasswordCheckUnavailable:
            report["status"] = "unverifiable"
            review("local admin password could not be verified; check permissions and hash format")
        report["initial_match"] = matched
        if not matched and policy.remediate:
            self.checkpoint()
            state["reset_in_progress"] = True
            report["status"] = "remediating"
            report["reset_attempted"] = True
            self.intent(
                "admin_password_reset", stage=stage, profile=selected["id"], revision=selected["revision"]
            )
            reset_admin_password(self.ssh, password)
            self.checkpoint()
            self.intent("admin_password_save", stage=stage)
            self.ssh.tmsh("save /sys config", timeout=180)
            state["reset_in_progress"] = False
            try:
                matched = matches_admin_password(self.ssh, password)
            except PasswordCheckUnavailable:
                report["status"] = "unverifiable"
                review("admin password reset was saved but readback could not be verified")
        report["status"] = "matched" if matched else "mismatch"
        report["remediated"] = bool(matched and report["reset_attempted"])
        self.audit(
            {
                "profile": selected["id"],
                "revision": selected["revision"],
                "transport": "ssh",
                "target": d.host,
                "purpose": "expected_admin_password",
                "stage": stage,
                "outcome": "password_verified" if matched else "password_mismatch",
            }
        )
        if not matched:
            review("local admin password does not match the configured expected password")
        self.event("admin_password_check_completed", stage=stage, remediated=report["remediated"])

    def complete_upgrade(self, request):
        restored = bool(self.changed_addresses)
        self.restore_addresses()
        if restored:
            self.capture_restored()
        self.checkpoint()
        self.waf_requests(request)
        self.sync_pair(request)
        self.check_admin_password(request, "after")

    def sync_pair(self, request):
        if not self.topology["cluster"] or not request.ha_policy.sync_after_upgrade:
            return
        peer = self.peer_device()
        local, other = self.device.active(), peer.active()
        if (local["version"], local["build"]) != (other["version"], other["build"]):
            self.result["config_sync"] = "deferred until both members run the same version/build"
            self.event("config_sync_deferred")
            return
        self.ha_health(request)
        topology = self.device.topology()
        if topology["sync"] == "in sync":
            self.result["config_sync"] = "in sync"
            return
        # The active member is the authoritative configuration source after failover.
        source = self.device if topology["role"] == "active" else peer
        self.checkpoint()
        for group in topology["groups"]:
            self.intent("config_sync", group=group)
            source.ssh.tmsh("run /cm config-sync to-group " + name(group), timeout=180)
        deadline = self.clock() + 120
        while self.device.topology()["sync"] != "in sync" or peer.topology()["sync"] != "in sync":
            if self.clock() >= deadline:
                self.store.open_gate(
                    self.job["id"],
                    self.worker,
                    "config_sync",
                    {"critical": ["HA sync did not complete"]},
                    self.result,
                )
            self.wait(5)
        self.result["config_sync"] = "in sync"
        self.event("config_sync_completed")

    def upgrade(self):
        r = JobRequest.model_validate(self.job["request"])
        self.reserve()
        self.checkpoint()
        decision = self.store.apply_decision(self.job["id"], self.worker)
        before_review = decision and decision["phase"] == "admin_password_before"
        if decision and decision["decision"]["action"] == "accept":
            self.result.setdefault("manual_validations", []).append(decision["decision"])
            self.event("manual_validation_applied", gate_id=decision["id"])
        if decision and not before_review:
            r.target_volume = self.result.get("target_volume")
            baseline = self.result["pre_validation"]
            if decision["phase"] == "admin_password_after":
                if decision["decision"]["action"] == "retry":
                    self.check_admin_password(r, "after")
            elif decision["phase"] == "post_validation":
                if decision["decision"]["action"] == "retry":
                    self.postvalidate(baseline, r)
                if r.reboot:
                    self.complete_upgrade(r)
                else:
                    self.check_admin_password(r, "after")
            elif decision["phase"] == "post_restore_snapshot":
                if decision["decision"]["action"] == "retry":
                    self.capture_restored()
                self.waf_requests(r)
                self.sync_pair(r)
                self.check_admin_password(r, "after")
            elif decision["phase"] == "waf_requests":
                if decision["decision"]["action"] == "retry":
                    self.waf_requests(r)
                self.sync_pair(r)
                self.check_admin_password(r, "after")
            elif decision["phase"] == "config_sync":
                if decision["decision"]["action"] == "retry":
                    self.sync_pair(r)
                self.check_admin_password(r, "after")
            return
        self.result["plan"] = r.plan()
        before = self.device.snapshot()
        self.result["pre_validation"] = before
        self.event("pre_validation_completed")
        active = before["active"]
        if r.install or r.reboot:
            if active["version"] not in r.allowed_source_versions:
                raise DeviceError("running version is outside allowed_source_versions")
            self.select_volume(r, active)
            if r.approved_models and not set(self.device.platform()) & set(r.approved_models):
                raise DeviceError("hardware model is not approved")
            if r.license_check_date and self.device.license_date() < r.license_check_date:
                raise DeviceError("license service-check date is older than required")
            self.result["rollback"] = {
                "volume": active["volume"],
                "version": active["version"],
                "build": active["build"],
                "from_volume": r.target_volume,
                "from_version": r.expected_version,
                "from_build": r.expected_build,
            }
            self.event("rollback_recorded")
            self.ha_health(r, before=True)
        if not (before_review and decision["decision"]["action"] == "accept"):
            self.check_admin_password(r, "before")
        if r.drain and not self.topology["cluster"]:
            self.device.check_drain()
            self.device.address_states()
        if "create_ucs" in r.plan():
            self.backup(r)
        self.checkpoint()
        if r.transfer or r.install:
            self.images(r)
        if r.install:
            self.install(r)
        if r.reboot and self.topology["cluster"]:
            self.failover(r)
        elif r.drain:
            self.drain(r)
        if r.install or r.reboot:
            self.copy_config(r)
        if r.reboot:
            self.reboot(r.target_volume, r.expected_version, r.expected_build, r.reboot_timeout)
            self.checkpoint()
            remaining = r.validation_policy.settling_seconds
            while remaining > 0:
                self.checkpoint()
                self.wait(min(5, remaining))
                remaining -= min(5, remaining)
        self.postvalidate(before, r if r.reboot else r.model_copy(update={"validation_timeout": 0}))
        if r.reboot:
            self.complete_upgrade(r)
        else:
            self.check_admin_password(r, "after")

    def rollback(self):
        source = self.store.get(self.job["parent"])
        saved, baseline = source["result"]["rollback"], source["result"]["pre_validation"]
        r = JobRequest(
            device=self.job["device"],
            reboot=True,
            ucs_unencrypted=True,
            target_volume=saved["volume"],
            expected_version=saved["version"],
            expected_build=saved["build"],
            allowed_source_versions=[saved["from_version"]],
            reboot_timeout=self.job["request"]["reboot_timeout"],
            validation_timeout=self.job["request"]["validation_timeout"],
        )
        self.reserve()
        self.result["pre_validation"] = baseline
        self.result["rollback_target"] = saved
        self.result["target_volume"] = saved["volume"]
        decision = self.store.apply_decision(self.job["id"], self.worker)
        if decision:
            if decision["decision"]["action"] == "retry":
                self.postvalidate(baseline, r)
            else:
                self.result.setdefault("manual_validations", []).append(decision["decision"])
            self.restore_addresses()
            return
        current = self.device.active()
        if (current["volume"], current["version"], current["build"]) != (
            saved["from_volume"],
            saved["from_version"],
            saved["from_build"],
        ):
            raise DeviceError("device no longer runs the source job's target; rollback refused")
        if self.topology["cluster"]:
            self.failover(r)
        self.changed_addresses = source["result"].get("drain", {}).get("changed_addresses", [])[:]
        self.result["drain"] = {"changed_addresses": self.changed_addresses[:], "restored": False}
        self.reboot(saved["volume"], saved["version"], saved["build"], r.reboot_timeout)
        self.postvalidate(baseline, r)
        self.restore_addresses()

    def run(self):
        try:
            self.rollback() if self.job["kind"] == "rollback" else self.upgrade()
            self.result["completed"] = True
            self.event("completed")
            audit = self.store.get(self.job["id"])["credential_summary"]
            warnings = bool(
                self.result.get("validation_differences")
                or self.result.get("manual_validations")
                or audit.get("multiple_profiles_used")
            )
            self.store.finish(
                self.job["id"], self.worker, "completed_with_warnings" if warnings else "succeeded"
            )
        except (LostOwnership, Deferred, NeedsReview):
            pass
        except CancelRequested:
            try:
                # Cleanup can run only while ownership remains. A verified reboot may leave traffic intentionally drained.
                if self.changed_addresses and not self.boot_attempted:
                    self.restore_addresses()
                self.result["cancelled_at"] = self.phase
                self.event("cancel_acknowledged")
                unsafe = (
                    bool(self.changed_addresses)
                    or self.boot_attempted
                    or self.result.get("admin_password", {}).get("reset_in_progress", False)
                )
                self.store.finish(self.job["id"], self.worker, "recovery_required" if unsafe else "cancelled")
            except LostOwnership:
                pass
            except Exception:
                self.store.finish(self.job["id"], self.worker, "recovery_required")
        except Exception as exc:
            message = (
                str(exc) if isinstance(exc, DeviceError) else "operation failed (" + type(exc).__name__ + ")"
            )
            self.result["error"] = message
            try:
                if self.changed_addresses and not self.boot_attempted:
                    try:
                        self.restore_addresses()
                    except Exception:
                        self.result["address_restore_failed"] = True
                self.event("failed", message=message)
                self.store.finish(
                    self.job["id"], self.worker, "recovery_required" if self.changed else "failed"
                )
            except LostOwnership:
                pass
        finally:
            self.ssh.close()
            if self.peer:
                self.peer.ssh.close()
