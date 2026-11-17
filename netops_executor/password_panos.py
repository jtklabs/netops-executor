"""Firewall-local administrator rotation over direct SSH or Panorama's serial proxy.

Candidate configuration and hashes stay in memory. A commit is allowed only when
the target account is the sole change to a previously clean candidate.

Acceptance is proved, not assumed: a login whose admin role (often a TACACS+ role) may not
edit administrators or commit can get an error, or an acknowledgement for a change that was
never staged. After a refused write the candidate is read again; after a refused commit the
running configuration is read and the staged change reverted. Only when that proves the
account unchanged does the job end as "not accepted" (nothing to recover); anything else
stays a recovery case. Locks this job took are released whenever the outcome is known.
"""

import copy
import re
import time
import uuid
import xml.etree.ElementTree as ET
from ipaddress import ip_address

from .network_ssh import CLI_ERROR, NetworkSSH
from .panos import SYSTEM_INFO, Firewall, Panorama, PanosError, PanosUnavailable, text
from .password_devices import (
    PERMISSION,
    ChangeNotAccepted,
    PasswordRejected,
    PermissionRefused,
    crypt_matches,
    verify_login,
)
from .password_models import AccountCreation
from .ssh import DeviceError

# CLI output settings belong to one SSH session, so every new session needs them again.
SESSION_SETTINGS = ("set cli scripting-mode off", "set cli config-output-format xml")


class CommitRefused(DeviceError):
    """PAN-OS definitively refused the commit (no job was created, or the job failed)."""


def permission(detail, code=None):
    return code == "403" or "HTTP 403" in (detail or "") or bool(PERMISSION.search(detail or ""))


def refused(detail, code=None, default="PAN-OS API operation failed; device output omitted"):
    if permission(detail, code):
        return PermissionRefused(
            "PAN-OS refused the operation for this login's admin role (permission denied)"
        )
    return DeviceError(default)


def template_users(value):
    """Administrator names in a pushed-template configuration; None when it cannot be read."""
    if isinstance(value, str):
        start, end = value.find("<"), value.rfind(">")
        if start < 0 or end < start:
            return None
        try:
            value = ET.fromstring("<root>" + value[start : end + 1] + "</root>")
        except ET.ParseError:
            return None
    return {node.get("name") for node in value.iter("users") for node in node.findall("entry")}


def config_xml(value):
    if isinstance(value, str):
        start, end = value.find("<config"), value.rfind("</config>")
        if start < 0 or end < start:
            raise DeviceError("PAN-OS configuration is not readable XML")
        try:
            value = ET.fromstring(value[start : end + len("</config>")])
        except ET.ParseError:
            raise DeviceError("PAN-OS configuration XML is malformed") from None
    if value.tag != "config":
        value = value.find("config")
    if value is None or value.find("mgt-config/users") is None:
        raise DeviceError("PAN-OS administrator configuration is unavailable")
    return value


def canonical(node):
    """Ignore candidate edit annotations and formatting, retaining order and real settings."""
    if node is None:
        return None
    return (
        node.tag,
        tuple(sorted((k, v) for k, v in node.attrib.items() if k not in ("admin", "dirtyId", "time"))),
        (node.text or "").strip(),
        tuple(canonical(child) for child in node),
    )


def account(config, username):
    matches = [node for node in config.findall("mgt-config/users/entry") if node.get("name") == username]
    if len(matches) > 1:
        raise DeviceError("PAN-OS configuration contains duplicate administrators")
    return matches[0] if matches else None


def outside_account(config, username):
    config = copy.deepcopy(config)
    users = config.find("mgt-config/users")
    for node in list(users):
        if node.tag == "entry" and node.get("name") == username:
            users.remove(node)
    return canonical(config)


def access(node):
    return tuple(
        canonical(node.find(name))
        for name in ("permissions", "authentication-profile", "client-certificate-only", "public-key")
    )


class SshAccounts:
    def __init__(self, settings, device, request, password, guard, audit):
        self.request = request
        self.ssh = NetworkSSH(
            settings, device, guard, request.credential_profiles, audit, device_type="paloalto_panos"
        )
        self.ssh.selector.secrets.add(password)
        self.session = None
        # Locks this job verified as its own; only these are ever removed.
        self.held = []

    def ready(self):
        # A review continuation, or a reconnect after any failed command, opens a new CLI session
        # that would otherwise print configuration in the default text format.
        driver = self.ssh.connect()
        if self.session is not driver:
            for command in SESSION_SETTINGS:
                self.run(command)
            self.session = driver

    def run(self, command, config=False):
        result = self.ssh.execute(
            command, timeout=self.request.command_timeout, mode="config" if config else "exec"
        )
        if result["cli_error"] or CLI_ERROR.search(result["stdout"]) or PERMISSION.search(result["stdout"]):
            raise refused(result["stdout"], default="PAN-OS account command rejected; output omitted")
        return result["stdout"]

    def cli(self, command, config=False):
        self.ready()
        return self.run(command, config)

    def prepare(self):
        matches = re.findall(r"(?m)^serial:\s*([A-Za-z0-9]{6,32})\s*$", self.cli("show system info"))
        if len(matches) != 1:
            raise DeviceError("PAN-OS serial could not be determined")
        return matches[0]

    def config(self, running=False):
        return config_xml(self.cli("show config running") if running else self.cli("show", config=True))

    def lock(self, marker):
        for kind in ("config", "commit"):
            self.cli("request " + kind + "-lock add comment " + marker)
            if marker not in self.cli("show " + kind + "-locks"):
                raise DeviceError("PAN-OS " + kind + " lock could not be verified")
            self.held.append(kind)

    def set_password(self, username, password, creation):
        self.ready()
        result, disconnected = self.ssh.dialogue(
            "set mgt-config users " + username + " password",
            [(re.compile(r"(?i)(?:enter|confirm|new|retype) password\s*:\s*$"), password)],
            self.request.command_timeout,
            mode="config",
            max_replies=2,
        )
        if disconnected or CLI_ERROR.search(result) or PERMISSION.search(result):
            raise refused(result, default="PAN-OS password dialogue failed")
        if creation:
            self.cli(
                "set mgt-config users " + username + " permissions role-based " + creation.role + " yes",
                config=True,
            )

    def commit(self):
        self.ready()
        result, disconnected = self.ssh.dialogue(
            "commit", [], self.request.commit_timeout, mode="config", max_replies=0
        )
        if disconnected:
            raise DeviceError("PAN-OS commit was not confirmed; inspect before recovery")
        if "configuration committed successfully" in result.lower() and not CLI_ERROR.search(result):
            return
        # The CLI returned to its prompt: the commit finished, and did not succeed.
        if re.search(r"(?i)commit failed|validation error", result) or PERMISSION.search(result):
            raise CommitRefused(
                "PAN-OS refused the commit for this login's admin role (permission denied)"
                if PERMISSION.search(result)
                else "PAN-OS commit failed"
            )
        raise DeviceError("PAN-OS commit was not confirmed; inspect before recovery")

    def revert(self):
        """Replace the candidate with the running configuration (this job's change only)."""
        self.cli("load config from running-config.xml", config=True)

    def unlock(self):
        while self.held:
            try:
                self.cli("request " + self.held.pop() + "-lock remove")
            except DeviceError:
                pass  # already released (a commit can release its commit lock)

    def template_users(self):
        try:
            return template_users(self.cli("show config pushed-template"))
        except DeviceError:
            return None

    def close(self):
        self.ssh.close()


class PanoramaAccounts:
    def __init__(self, settings, store, device, request, password, guard, audit, panorama=None):
        self.device, self.request, self.guard = device, request, guard
        # A fleet job shares one Panorama session across firewalls and closes it itself.
        self.shared = panorama is not None
        self.panorama = panorama or Panorama(
            settings, store, request.panorama, request.http_credential_profiles, guard, audit
        )
        self.panorama.selector.secrets.add(password)
        self.fw = Firewall(self.panorama, request.serial)
        self.held = []

    def safe(self, operation, *args, **kwargs):
        try:
            return operation(*args, **kwargs)
        except PanosUnavailable:
            raise DeviceError("PAN-OS API operation failed; device output omitted") from None
        except PanosError as exc:
            # API errors can include a submitted XML fragment or generated hash: classify only.
            raise refused(str(exc), getattr(exc, "code", None)) from None

    def prepare(self):
        info = self.safe(self.panorama.device, self.request.serial)
        if not info or not info["connected"]:
            raise DeviceError("firewall is not connected to the configured Panorama")
        try:
            same = ip_address(info["address"]) == ip_address(self.device.host)
        except ValueError:
            same = False
        if not same:
            raise DeviceError("device must match the management IP Panorama reports for this serial")
        result = self.safe(self.fw.op, SYSTEM_INFO, timeout=self.request.command_timeout)
        serial = text(result, "system/serial")
        if serial != self.request.serial:
            raise DeviceError("proxied firewall serial does not match the request")
        return serial

    def config(self, running=False):
        result = self.safe(
            self.fw.request,
            {"type": "config", "action": "show" if running else "get", "xpath": "/config"},
            timeout=self.request.command_timeout,
        )
        return config_xml(result)

    def lock(self, marker):
        for kind in ("config", "commit"):
            self.safe(
                self.fw.op,
                "<request><"
                + kind
                + "-lock><add><comment>"
                + marker
                + "</comment></add></"
                + kind
                + "-lock></request>",
                timeout=self.request.command_timeout,
            )
            result = self.safe(
                self.fw.op,
                "<show><" + kind + "-locks></" + kind + "-locks></show>",
                timeout=self.request.command_timeout,
            )
            if marker not in ET.tostring(result, encoding="unicode"):
                raise DeviceError("PAN-OS " + kind + " lock could not be verified")
            self.held.append(kind)

    def set_password(self, username, password, creation):
        cmd = ET.Element("request")
        phash = ET.SubElement(cmd, "password-hash")
        ET.SubElement(phash, "password").text = password
        ET.SubElement(phash, "username").text = username
        result = self.safe(
            self.fw.op, ET.tostring(cmd, encoding="unicode"), timeout=self.request.command_timeout
        )
        encoded = text(result, "phash")
        if not crypt_matches(password, encoded):
            raise DeviceError("PAN-OS generated password hash did not verify")
        self.panorama.selector.secrets.add(encoded)
        entry = ET.Element("entry", name=username)
        ET.SubElement(entry, "phash").text = encoded
        if creation:
            roles = ET.SubElement(ET.SubElement(entry, "permissions"), "role-based")
            ET.SubElement(roles, creation.role).text = "yes"
        self.safe(
            self.fw.request,
            {
                "type": "config",
                "action": "set",
                "xpath": "/config/mgt-config/users",
                "element": ET.tostring(entry, encoding="unicode"),
            },
            timeout=self.request.command_timeout,
        )

    def commit(self):
        deadline = time.monotonic() + self.request.commit_timeout
        try:
            result = self.fw.request(
                {"type": "commit", "cmd": "<commit></commit>"},
                timeout=min(self.request.command_timeout, self.request.commit_timeout),
            )
        except PanosUnavailable:
            raise DeviceError("PAN-OS commit was not confirmed; inspect before recovery") from None
        except PanosError as exc:
            # An error response: the firewall created no commit job.
            raise CommitRefused(
                "PAN-OS refused the commit for this login's admin role (permission denied)"
                if permission(str(exc), getattr(exc, "code", None))
                else "PAN-OS refused the commit"
            ) from None
        job_id = text(result, "job")
        if not job_id.isdigit():
            raise DeviceError("PAN-OS commit returned no job ID; inspect before recovery")
        while True:
            self.guard()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise DeviceError("PAN-OS commit timed out; inspect before recovery")
            try:
                result = self.fw.op(
                    "<show><jobs><id>" + job_id + "</id></jobs></show>",
                    timeout=min(self.request.command_timeout, remaining),
                )
            except PanosUnavailable:
                # The commit job is already running; a lost status response does not change its
                # outcome. Keep reading it until the commit deadline.
                time.sleep(min(2, max(0, deadline - time.monotonic())))
                continue
            except PanosError:
                raise DeviceError("PAN-OS API operation failed; device output omitted") from None
            if text(result, "job/id") != job_id:
                raise DeviceError("PAN-OS commit job identity could not be verified")
            if text(result, "job/status").upper() == "FIN":
                if text(result, "job/result").upper() != "OK":
                    details = " ".join(t for t in result.find("job").itertext()) if result.find("job") else ""
                    raise CommitRefused(
                        "PAN-OS commit failed for this login's admin role (permission denied)"
                        if PERMISSION.search(details)
                        else "PAN-OS commit failed"
                    )
                return
            time.sleep(min(2, max(0, deadline - time.monotonic())))

    def revert(self):
        self.safe(
            self.fw.op,
            "<load><config><from>running-config.xml</from></config></load>",
            timeout=self.request.command_timeout,
        )

    def unlock(self):
        while self.held:
            kind = self.held.pop()
            try:
                self.fw.op(
                    "<request><" + kind + "-lock><remove></remove></" + kind + "-lock></request>",
                    timeout=self.request.command_timeout,
                )
            except PanosError:
                pass  # already released (a commit can release its commit lock)

    def template_users(self):
        try:
            return template_users(
                self.fw.op(
                    "<show><config><pushed-template></pushed-template></config></show>",
                    timeout=self.request.command_timeout,
                )
            )
        except PanosError:
            return None

    def close(self):
        if not self.shared:
            self.panorama.close()


class PanosAccountDevice:
    def __init__(self, settings, store, device, request, password, guard, audit, backend=None):
        self.settings, self.device, self.request, self.password, self.guard = (
            settings,
            device,
            request,
            password,
            guard,
        )
        self.backend = backend or (
            PanoramaAccounts(settings, store, device, request, password, guard, audit)
            if request.panorama
            else SshAccounts(settings, device, request, password, guard, audit)
        )
        self.serial = None
        self.baseline = self.before = self.after = None
        self.creation = request.new_account or AccountCreation.administrator("paloalto_panos")
        self.report, self.locked = {}, False

    def clean(self):
        running, candidate = self.backend.config(running=True), self.backend.config()
        if canonical(running) != canonical(candidate):
            raise DeviceError("PAN-OS has pending configuration changes; resolve them before rotation")
        return running

    def preflight(self):
        self.serial = self.backend.prepare()
        if self.request.serial and self.request.serial != self.serial:
            raise DeviceError("PAN-OS serial does not match the request")
        self.baseline = self.clean()
        self.before = account(self.baseline, self.request.username)
        if self.before is None and not self.request.create_if_missing:
            raise DeviceError("local account is missing and create_if_missing is false")
        if self.before is None and self.request.username in (self.backend.template_users() or ()):
            # A local entry would silently override the template's account on this firewall.
            raise DeviceError(
                "the account comes from a Panorama template on this firewall; rotate the template "
                "with POST /api/v1/password-rotation/panorama/jobs instead of creating a local override"
            )
        if self.before is not None and (
            text(self.before, "authentication-profile") not in ("", "None", "none")
            or text(self.before, "client-certificate-only") == "yes"
        ):
            raise DeviceError("PAN-OS administrator uses external or certificate-only authentication")
        return self.before is not None

    def release(self):
        if self.locked:
            self.backend.unlock()
            self.locked = False

    def staged_nothing(self):
        """The candidate still equals the clean baseline: nothing of this job was staged."""
        try:
            return canonical(self.backend.config()) == canonical(self.baseline)
        except DeviceError:
            return False

    def apply(self):
        self.locked = True
        try:
            self.backend.lock("netops-password-" + uuid.uuid4().hex)
        except DeviceError:
            # Another administrator's lock, or a role that may not lock: nothing was staged.
            if self.staged_nothing():
                self.release()
                raise ChangeNotAccepted(
                    "PAN-OS configuration and commit locks could not be taken (another administrator "
                    "holds one, or this login's admin role may not lock); nothing was changed"
                ) from None
            raise
        if canonical(self.clean()) != canonical(self.baseline):
            self.release()
            raise ChangeNotAccepted("PAN-OS configuration changed since precheck; nothing was changed")
        try:
            self.backend.set_password(
                self.request.username, self.password, self.creation if self.before is None else None
            )
        except DeviceError as exc:
            if self.staged_nothing():
                self.release()
                raise ChangeNotAccepted(
                    (
                        "PAN-OS refused the password change for this login's admin role (permission denied); "
                        if isinstance(exc, PermissionRefused)
                        else str(exc) + "; "
                    )
                    + "the candidate configuration is unchanged"
                ) from None
            raise
        candidate = self.backend.config()
        self.after = account(candidate, self.request.username)
        if canonical(candidate) == canonical(self.baseline):
            # Acknowledged, but never staged: typical of a role without administrator access.
            self.release()
            raise ChangeNotAccepted(
                "PAN-OS acknowledged the password change but did not stage it; check that this "
                "login's admin role may edit administrators"
            )
        if self.after is None:
            raise DeviceError("PAN-OS administrator is missing after the write")
        if not crypt_matches(self.password, text(self.after, "phash")):
            raise DeviceError("PAN-OS candidate password hash does not match; commit refused")
        if self.before is not None and access(self.before) != access(self.after):
            raise DeviceError("PAN-OS administrator privileges changed unexpectedly")
        if self.before is None and text(self.after, "permissions/role-based/" + self.creation.role) != "yes":
            raise DeviceError("PAN-OS administrator role was not applied")
        if outside_account(candidate, self.request.username) != outside_account(
            self.baseline, self.request.username
        ):
            raise DeviceError("PAN-OS candidate includes unrelated changes; commit refused")
        self.report["confirmed"] = ["candidate_hash"]

    def refused_commit(self, error):
        """Prove a refused commit changed nothing, then put the candidate back."""
        try:
            running = self.backend.config(running=True)
        except DeviceError:
            raise DeviceError(
                "PAN-OS commit was refused and the running configuration could not be read; "
                "inspect before recovery"
            ) from None
        if canonical(running) != canonical(self.baseline):
            raise DeviceError("PAN-OS commit was refused but the running configuration changed; inspect it")
        try:
            self.backend.revert()
            reverted = canonical(self.backend.config()) == canonical(running)
        except DeviceError:
            reverted = False
        if not reverted:
            raise DeviceError(
                "PAN-OS refused the commit and the staged password change could not be reverted; "
                "the candidate configuration still holds it"
            )
        self.release()
        raise ChangeNotAccepted(
            str(error) + "; the staged change was reverted and the running account is unchanged"
        )

    def save(self):
        candidate = self.backend.config()
        if (
            canonical(account(candidate, self.request.username)) != canonical(self.after)
            or outside_account(candidate, self.request.username)
            != outside_account(self.baseline, self.request.username)
            or canonical(self.backend.config(running=True)) != canonical(self.baseline)
        ):
            raise DeviceError("PAN-OS configuration changed before commit; inspect before recovery")
        try:
            self.backend.commit()
        except CommitRefused as exc:
            self.refused_commit(exc)
        self.report["confirmed"].append("commit")
        running = self.backend.config(running=True)
        saved = account(running, self.request.username)
        if saved is None or canonical(saved) != canonical(self.after):
            raise DeviceError("PAN-OS committed account does not match the staged account")
        if outside_account(running, self.request.username) != outside_account(
            self.baseline, self.request.username
        ):
            raise DeviceError("PAN-OS running configuration changed unexpectedly after commit")
        self.report["confirmed"].append("running_hash")
        self.release()

    def verify(self):
        if self.request.verification == "ssh_login":
            verify_login(self.settings, self.device, self.request.username, self.password, self.guard)
            self.report.setdefault("confirmed", []).append("login")
        else:
            node = account(self.backend.config(running=True), self.request.username)
            if not crypt_matches(self.password, text(node, "phash")):
                raise PasswordRejected("PAN-OS running password hash does not match the requested password")

    def close(self):
        self.backend.close()
