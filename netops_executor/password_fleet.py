"""Rotate one administrator everywhere a Panorama manages it.

1. Discover (read-only): templates and template stacks that define the account, the firewalls
   those templates reach, and every connected firewall with the account configured locally.
2. Templates: one locked change on Panorama sets the new hash in each template that defines
   the account, proves nothing else changed, and commits on Panorama only. Nothing is pushed:
   `push_required` lists the firewalls that receive the change at their next template push.
3. Firewalls: each firewall-local copy is rotated through Panorama's serial proxy with the same
   proofs as a single-firewall job (clean candidate, only this account staged, commit, running
   hash). Firewalls are done one at a time and each outcome is recorded before the next starts.

A firewall the job could not change (pending changes, a refused write or commit) is reported
and the job carries on; one whose outcome is unknown stops the job for recovery. Nothing is
ever replayed: a continuation skips firewalls already rotated and stops at one left mid-change.
"""

import copy
import time
import uuid
import xml.etree.ElementTree as ET

from .config import Device
from .credentials import Vault
from .panos import DEVICES, PENDING_CHANGES, Panorama, PanosError, PanosUnavailable, text
from .password_devices import ChangeNotAccepted, PasswordRejected, PermissionRefused, crypt_matches
from .password_engine import RotationFailure
from .password_models import PanoramaRotationOptions, PasswordRotationOptions
from .password_panos import CommitRefused, PanoramaAccounts, PanosAccountDevice, canonical
from .ssh import DeviceError
from .stepped import StepRunner

PANORAMA = "/config/devices/entry[@name='localhost.localdomain']"


def users_path(kind, name, username):
    return (
        PANORAMA
        + "/"
        + kind
        + "/entry[@name='"
        + name
        + "']/config/mgt-config/users/entry[@name='"
        + username
        + "']"
    )


def configuration(result):
    node = result if result.tag == "config" else result.find("config")
    if node is None or node.find("devices") is None:
        raise DeviceError("Panorama configuration is unavailable")
    return node


def scopes(config, username):
    """Templates and template stacks that define the account, with what each holds."""
    found = []
    devices = config.find("devices/entry[@name='localhost.localdomain']")
    for kind in ("template", "template-stack"):
        for entry in devices.findall(kind + "/entry") if devices is not None else []:
            users = entry.findall("config/mgt-config/users/entry")
            node = next((u for u in users if u.get("name") == username), None)
            if node is None:
                continue
            name = entry.get("name") or ""
            local = node.find("phash") is not None and text(node, "authentication-profile") in ("", "None")
            found.append({"kind": kind, "name": name, "local_password": local})
    return found


def push_targets(config, changed):
    """Firewall serials whose template stack includes a changed template or is one."""
    devices = config.find("devices/entry[@name='localhost.localdomain']")
    if devices is None:
        return []
    templates = {s["name"] for s in changed if s["kind"] == "template"}
    stacks = {s["name"] for s in changed if s["kind"] == "template-stack"}
    serials = set()
    for stack in devices.findall("template-stack/entry"):
        members = {m.text for m in stack.findall("templates/member")}
        if stack.get("name") in stacks or members & templates:
            serials.update(e.get("name") for e in stack.findall("devices/entry"))
    for template in devices.findall("template/entry"):
        if template.get("name") in templates:
            serials.update(e.get("name") for e in template.findall("devices/entry"))
    return sorted(s for s in serials if s)


def without_hashes(config, changed, username):
    """The configuration with the changed templates' password hashes removed."""
    config = copy.deepcopy(config)
    devices = config.find("devices/entry[@name='localhost.localdomain']")
    for scope in changed:
        for entry in devices.findall(scope["kind"] + "/entry"):
            if entry.get("name") != scope["name"]:
                continue
            for user in entry.findall("config/mgt-config/users/entry"):
                if user.get("name") == username and user.find("phash") is not None:
                    user.remove(user.find("phash"))
    return canonical(config)


class PanoramaRotationRunner(StepRunner):
    device_errors = (DeviceError,)
    error = RotationFailure

    def __init__(self, settings, store, job, worker, panorama=None, sleep=time.sleep, clock=time.monotonic):
        super().__init__(settings, store, job, worker, sleep, clock)
        self.panorama = panorama

    # Panorama itself, as the "firewall" of the shared account operations (lock, commit, revert).
    def local(self):
        accounts = PanoramaAccounts(
            self.settings,
            self.store,
            None,
            self.firewall_request(None, ""),
            self.password,
            self.guard,
            self.audit,
            panorama=self.panorama,
        )
        accounts.fw = self.panorama
        return accounts

    def config(self, running=False):
        result = self.panorama.request(
            {"type": "config", "action": "show" if running else "get", "xpath": "/config"},
            timeout=self.request.command_timeout,
        )
        return configuration(result)

    def discover(self):
        r = self.request
        result = self.result
        if r.templates:
            candidate = self.config()
            pending = text(self.panorama.op(PENDING_CHANGES, timeout=r.command_timeout), ".") or ""
            if pending.lower() == "yes" or canonical(candidate) != canonical(self.config(running=True)):
                raise DeviceError("Panorama has uncommitted changes; commit or revert them before rotation")
            result["templates"] = []
            for s in scopes(candidate, r.username):
                local = s.pop("local_password")
                if "'" in s["name"]:
                    s.update(status="skipped", reason="template name cannot be addressed safely")
                elif not local:
                    s.update(status="skipped", reason="the template's account has no local password")
                else:
                    s["status"] = "pending"
                result["templates"].append(s)
            result["push_required"] = push_targets(
                candidate, [s for s in result["templates"] if s["status"] == "pending"]
            )
        if r.firewalls:
            wanted = set(r.serials or [])
            firewalls = {}
            for entry in self.panorama.op(DEVICES, timeout=r.command_timeout).findall("devices/entry"):
                serial = text(entry, "serial") or entry.get("name") or ""
                if wanted and serial not in wanted:
                    continue
                row = {"hostname": text(entry, "hostname"), "address": text(entry, "ip-address")}
                if text(entry, "connected") != "yes":
                    if wanted:
                        firewalls[serial] = {
                            **row,
                            "status": "skipped",
                            "reason": "not connected to Panorama",
                        }
                    continue
                local = self.panorama.request(
                    {
                        "type": "config",
                        "action": "get",
                        "xpath": "/config/mgt-config/users/entry[@name='" + r.username + "']",
                        "target": serial,
                    },
                    timeout=r.command_timeout,
                )
                if local.find(".//entry[@name='" + r.username + "']") is not None:
                    firewalls[serial] = {**row, "status": "pending"}
                elif wanted:
                    firewalls[serial] = {**row, "status": "skipped", "reason": "no local account"}
            for serial in wanted - set(firewalls):
                firewalls[serial] = {"status": "skipped", "reason": "not managed by this Panorama"}
            result["firewalls"] = dict(sorted(firewalls.items()))
            keys = ["panos:" + s for s, row in firewalls.items() if row["status"] == "pending"]
            if keys:
                if not self.store.reserve(self.job["id"], self.worker, keys):
                    self.store.defer(self.job["id"], self.worker)
                result["reservations"] = sorted(keys)
        self.event(
            "panorama_discovered",
            templates=len(result.get("templates", [])),
            firewalls=sum(row["status"] == "pending" for row in result.get("firewalls", {}).values()),
        )

    def rotate_templates(self):
        r = self.request
        changed = [s for s in self.result.get("templates", []) if s["status"] == "pending"]
        if not changed:
            return
        accounts = self.local()
        baseline = self.config()
        self.result["templates_change"] = "changing"
        self.intent("panorama_templates")

        def not_accepted(reason):
            accounts.unlock()
            self.result["mutations"].remove("panorama_templates")
            self.result["templates_change"] = "not_accepted"
            for s in changed:
                s.update(status="not_accepted", reason=reason)
            self.event("panorama_templates_not_accepted")

        def nothing_staged():
            try:
                return canonical(self.config()) == canonical(baseline)
            except (DeviceError, PanosError):
                return False

        try:
            accounts.lock("netops-password-" + uuid.uuid4().hex)
        except DeviceError:
            if nothing_staged():
                return not_accepted("Panorama locks could not be taken; nothing was changed")
            raise
        if canonical(self.config()) != canonical(baseline) or canonical(
            self.config(running=True)
        ) != canonical(baseline):
            return not_accepted("Panorama configuration changed before the lock; nothing was changed")
        cmd = ET.Element("request")
        phash = ET.SubElement(cmd, "password-hash")
        ET.SubElement(phash, "password").text = self.password
        ET.SubElement(phash, "username").text = r.username
        try:
            encoded = text(
                self.panorama.op(ET.tostring(cmd, encoding="unicode"), timeout=r.command_timeout), "phash"
            )
            if not crypt_matches(self.password, encoded):
                raise DeviceError("Panorama generated password hash did not verify")
            self.panorama.selector.secrets.add(encoded)
            for s in changed:
                accounts.safe(
                    self.panorama.request,
                    {
                        "type": "config",
                        "action": "set",
                        "xpath": users_path(s["kind"], s["name"], r.username),
                        "element": "<phash>" + encoded + "</phash>",
                    },
                    timeout=r.command_timeout,
                )
        except (DeviceError, PanosError) as exc:
            reason = (
                "Panorama refused the change for this login's admin role (permission denied)"
                if isinstance(exc, PermissionRefused)
                else "Panorama rejected the template change"
            )
            if nothing_staged():
                return not_accepted(reason + "; nothing was changed")
            try:
                accounts.revert()
                reverted = canonical(self.config()) == canonical(self.config(running=True))
            except (DeviceError, PanosError):
                reverted = False
            if reverted:
                return not_accepted(reason + "; the staged changes were reverted")
            raise DeviceError(reason + " part-way; Panorama's candidate holds a partial change") from None
        staged = self.config()
        for s in changed:
            node = staged.find(
                users_path(s["kind"], s["name"], r.username).removeprefix("/config/") + "/phash"
            )
            if node is None or not crypt_matches(self.password, node.text or ""):
                raise DeviceError("Panorama did not stage the new hash in every template; inspect it")
        if without_hashes(staged, changed, r.username) != without_hashes(baseline, changed, r.username):
            raise DeviceError("Panorama candidate includes unrelated changes; commit refused")
        try:
            accounts.commit()
        except CommitRefused as exc:
            if canonical(self.config(running=True)) != canonical(baseline):
                raise DeviceError(
                    "Panorama commit was refused but its running configuration changed"
                ) from None
            accounts.revert()
            if canonical(self.config()) != canonical(baseline):
                raise DeviceError(
                    "Panorama refused the commit and the staged change could not be reverted"
                ) from None
            return not_accepted(str(exc) + "; the staged change was reverted")
        running = self.config(running=True)
        if without_hashes(running, changed, r.username) != without_hashes(baseline, changed, r.username):
            raise DeviceError("Panorama running configuration changed unexpectedly after commit")
        for s in changed:
            node = running.find(
                users_path(s["kind"], s["name"], r.username).removeprefix("/config/") + "/phash"
            )
            if node is None or not crypt_matches(self.password, node.text or ""):
                raise DeviceError("Panorama committed configuration does not hold the new hash")
            s["status"] = "committed"
        accounts.unlock()
        self.result["templates_change"] = "committed"
        self.event("panorama_templates_committed", push_required=len(self.result.get("push_required", [])))

    def firewall_request(self, serial, address):
        return PasswordRotationOptions.model_validate(
            {
                "device": address or "panorama",
                "device_type": "paloalto_panos",
                "username": self.request.username,
                "panorama": self.request.panorama,
                "serial": serial or "000000000000",
                "http_credential_profiles": self.request.http_credential_profiles,
                "create_if_missing": False,
                "verification": "local_hash",
                "command_timeout": self.request.command_timeout,
                "commit_timeout": self.request.commit_timeout,
            }
        )

    def rotate_firewalls(self):
        rows = self.result.get("firewalls", {})
        for serial, row in rows.items():
            if row["status"] in ("changing", "recovery_required"):
                # A previous attempt stopped mid-change: never replay it.
                raise DeviceError("firewall " + serial + " was left mid-change; inspect it before recovery")
            if row["status"] != "pending":
                continue
            self.checkpoint()
            request = self.firewall_request(serial, row["address"])
            try:
                device = Device(id=serial, host=row["address"], device_type="paloalto_panos")
                client = PanosAccountDevice(
                    self.settings,
                    self.store,
                    device,
                    request,
                    self.password,
                    self.guard,
                    self.audit,
                    backend=PanoramaAccounts(
                        self.settings,
                        self.store,
                        device,
                        request,
                        self.password,
                        self.guard,
                        self.audit,
                        panorama=self.panorama,
                    ),
                )
                client.preflight()
            except (DeviceError, PanosError, ValueError) as exc:
                row.update(
                    status="skipped", reason=str(exc) if isinstance(exc, DeviceError) else "unusable address"
                )
                self.event("firewall_skipped", serial=serial)
                continue
            row["status"] = "changing"
            self.intent("firewall:" + serial)
            try:
                client.apply()
                client.save()
                client.verify()
            except ChangeNotAccepted as exc:
                self.result["mutations"].remove("firewall:" + serial)
                row.update(status="not_accepted", reason=str(exc))
                self.event("firewall_not_accepted", serial=serial)
                continue
            except (DeviceError, PanosError) as exc:
                row.update(
                    status="recovery_required",
                    reason=str(exc) if isinstance(exc, DeviceError) else "PAN-OS API operation failed",
                )
                if isinstance(exc, PasswordRejected):
                    row["reason"] = "the committed hash does not match the requested password"
                raise DeviceError(
                    "firewall " + serial + ": " + row["reason"] + "; the remaining firewalls were not changed"
                ) from None
            row.update(status="rotated", confirmed=client.report.get("confirmed", []))
            self.event("firewall_rotated", serial=serial)

    def summary(self):
        rows = self.result.get("firewalls", {}).values()
        counts = {}
        for row in [*rows, *self.result.get("templates", [])]:
            counts[row["status"]] = counts.get(row["status"], 0) + 1
        self.result["summary"] = counts

    def warnings(self):
        rows = [*self.result.get("firewalls", {}).values(), *self.result.get("templates", [])]
        return any(row["status"] in ("skipped", "not_accepted") for row in rows)

    def upgrade(self):
        r = self.request = PanoramaRotationOptions.model_validate(self.job["request"])
        keys = [self.job["lock_key"], *self.result.get("reservations", [])]
        if not self.store.reserve(self.job["id"], self.worker, keys):
            if self.result.get("mutations"):
                raise DeviceError("reservation changed during password rotation")
            self.store.defer(self.job["id"], self.worker)
        self.checkpoint()
        self.password = Vault(self.store, self.settings.credential_key_file).job_password(self.job["id"])
        if self.panorama is None:
            self.panorama = Panorama(
                self.settings, self.store, r.panorama, r.http_credential_profiles, self.guard, self.audit
            )
        self.panorama.selector.secrets.add(self.password)
        self.result.update(username=r.username, panorama=r.panorama)
        self.result.setdefault("progress", {})["steps_total"] = 3
        try:
            self.step("discover", self.discover)
            if r.templates:
                self.step("templates", self.rotate_templates)
            if r.firewalls:
                self.step("firewalls", self.rotate_firewalls)
        except PanosUnavailable:
            raise DeviceError("Panorama did not answer; outcome may be unknown") from None
        except PanosError:
            raise DeviceError("Panorama API operation failed; device output omitted") from None
        finally:
            self.summary()

    def unsafe(self):
        rows = self.result.get("firewalls", {}).values()
        return self.result.get("templates_change") == "changing" or any(
            row["status"] in ("changing", "recovery_required") for row in rows
        )

    def close(self):
        if self.panorama:
            self.panorama.close()
