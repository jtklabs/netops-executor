"""Firewall-local administrator rotation over direct SSH or Panorama's serial proxy.

Candidate configuration and hashes stay in memory. A commit is allowed only when
the target account is the sole change to a previously clean candidate.
"""

import copy
import re
import time
import uuid
import xml.etree.ElementTree as ET
from ipaddress import ip_address

from .network_ssh import CLI_ERROR, NetworkSSH
from .panos import SYSTEM_INFO, Firewall, Panorama, PanosError, text
from .password_devices import crypt_matches, verify_login
from .password_models import AccountCreation
from .ssh import DeviceError


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

    def cli(self, command, config=False):
        result = self.ssh.execute(
            command, timeout=self.request.command_timeout, mode="config" if config else "exec"
        )
        if result["cli_error"] or CLI_ERROR.search(result["stdout"]):
            raise DeviceError("PAN-OS account command rejected; output omitted")
        return result["stdout"]

    def prepare(self):
        self.cli("set cli scripting-mode off")
        self.cli("set cli config-output-format xml")
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

    def set_password(self, username, password, creation):
        result, disconnected = self.ssh.dialogue(
            "set mgt-config users " + username + " password",
            [(re.compile(r"(?i)(?:enter|confirm|new|retype) password\s*:\s*$"), password)],
            self.request.command_timeout,
            mode="config",
            max_replies=2,
        )
        if disconnected or CLI_ERROR.search(result):
            raise DeviceError("PAN-OS password dialogue failed")
        if creation:
            self.cli(
                "set mgt-config users " + username + " permissions role-based " + creation.role + " yes",
                config=True,
            )

    def commit(self):
        result, disconnected = self.ssh.dialogue(
            "commit", [], self.request.commit_timeout, mode="config", max_replies=0
        )
        if (
            disconnected
            or CLI_ERROR.search(result)
            or "configuration committed successfully" not in result.lower()
        ):
            raise DeviceError("PAN-OS commit was not confirmed; inspect before recovery")

    def close(self):
        self.ssh.close()


class PanoramaAccounts:
    def __init__(self, settings, store, device, request, password, guard, audit):
        self.device, self.request, self.guard = device, request, guard
        self.panorama = Panorama(
            settings, store, request.panorama, request.http_credential_profiles, guard, audit
        )
        self.panorama.selector.secrets.add(password)
        self.fw = Firewall(self.panorama, request.serial)

    def safe(self, operation, *args, **kwargs):
        try:
            return operation(*args, **kwargs)
        except PanosError:
            # API errors can include a submitted XML fragment or generated hash.
            raise DeviceError("PAN-OS API operation failed; device output omitted") from None

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
        result = self.safe(
            self.fw.request,
            {"type": "commit", "cmd": "<commit></commit>"},
            timeout=min(self.request.command_timeout, self.request.commit_timeout),
        )
        job_id = text(result, "job")
        if not job_id.isdigit():
            raise DeviceError("PAN-OS commit returned no job ID; inspect before recovery")
        while True:
            self.guard()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise DeviceError("PAN-OS commit timed out; inspect before recovery")
            result = self.safe(
                self.fw.op,
                "<show><jobs><id>" + job_id + "</id></jobs></show>",
                timeout=min(self.request.command_timeout, remaining),
            )
            if text(result, "job/id") != job_id:
                raise DeviceError("PAN-OS commit job identity could not be verified")
            if text(result, "job/status").upper() == "FIN":
                if text(result, "job/result").upper() != "OK":
                    raise DeviceError("PAN-OS commit failed; inspect before recovery")
                return
            time.sleep(min(2, max(0, deadline - time.monotonic())))

    def close(self):
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
        if self.before is not None and (
            text(self.before, "authentication-profile") not in ("", "None", "none")
            or text(self.before, "client-certificate-only") == "yes"
        ):
            raise DeviceError("PAN-OS administrator uses external or certificate-only authentication")
        return self.before is not None

    def apply(self):
        self.backend.lock("netops-password-" + uuid.uuid4().hex)
        if canonical(self.clean()) != canonical(self.baseline):
            raise DeviceError("PAN-OS configuration changed since precheck")
        self.backend.set_password(
            self.request.username, self.password, self.creation if self.before is None else None
        )
        candidate = self.backend.config()
        self.after = account(candidate, self.request.username)
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

    def save(self):
        candidate = self.backend.config()
        if (
            canonical(account(candidate, self.request.username)) != canonical(self.after)
            or outside_account(candidate, self.request.username)
            != outside_account(self.baseline, self.request.username)
            or canonical(self.backend.config(running=True)) != canonical(self.baseline)
        ):
            raise DeviceError("PAN-OS configuration changed before commit; inspect before recovery")
        self.backend.commit()
        running = self.backend.config(running=True)
        saved = account(running, self.request.username)
        if saved is None or canonical(saved) != canonical(self.after):
            raise DeviceError("PAN-OS committed account does not match the staged account")
        if outside_account(running, self.request.username) != outside_account(
            self.baseline, self.request.username
        ):
            raise DeviceError("PAN-OS running configuration changed unexpectedly after commit")

    def verify(self):
        if self.request.verification == "ssh_login":
            verify_login(self.settings, self.device, self.request.username, self.password, self.guard)
        else:
            node = account(self.backend.config(running=True), self.request.username)
            if not crypt_matches(self.password, text(node, "phash")):
                raise DeviceError("PAN-OS running password hash does not match the requested password")

    def close(self):
        self.backend.close()
