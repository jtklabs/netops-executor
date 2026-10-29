"""FortiGate (FortiOS 7.4) over the executor's audited SSH session, and FortiManager JSON-RPC.

Every reader parses fixed CLI output and refuses what it does not recognize. Firmware is
staged with FortiOS's controlled upgrade (`execute restore secondary-image ftp`) from a
one-time FTP server on the executor, and activated with `execute set-next-reboot` and a
reboot; an FGCP cluster upgrades itself from its primary (`execute restore image ftp`).
Netmiko switches `config system console` output to `standard` for its session; the original
setting is reported so the job can put it back.
"""

import re
import ssl

import httpx

from .credentials import AuthenticationRejected, Selector, Vault
from .execution import credential_options
from .iosxe import Iosxe
from .iosxe_config import compare
from .iosxe_models import IosxeConfigPolicy
from .network_ssh import CLI_ERROR, NetworkSSH
from .pins import PinnedContext, tls_key
from .ssh import DeviceError

# A rejected command; operations (staging, restore) also fail on any reported failure line.
REJECTED = re.compile(r"(?im)^\s*(?:Command fail\b|Unknown action\b|command parse error)")
FAILURE = re.compile(
    r"(?im)^\s*(?:Command fail\b|Unknown action\b|command parse error|.*\bfail(?:ed|ure)?\b)"
)
STAGE = re.compile(r"(?is)replace the current secondary firmware.*Do you want to continue\?\s*\(y/n\)\s*$")
RESTORE = re.compile(r"(?is)replace the current firmware.*Do you want to continue\?\s*\(y/n\)\s*$")
REBOOT = re.compile(r"(?is)This operation will reboot the system.*Do you want to continue\?\s*\(y/n\)\s*$")
UNITS = {"day": 86400, "hour": 3600, "minute": 60, "second": 1}

# FortiOS `show` prints only non-default settings. These rules compare two of them.
ORDERED = (
    r"^config firewall (?:policy|policy6|proxy-policy|security-policy|multicast-policy|local-in-policy|shaping-policy)$",
    r"^config router (?:access-list6?|prefix-list6?|route-map|aspath-list|community-list)$",
    r"^edit ",
)
REWRITES = (
    # Encrypted secrets are re-encrypted with a new salt; compare their presence only.
    ("encrypted-secrets", r"\bENC \S+", None, "ENC <encrypted>"),
)
IGNORES = (("config-header", r"^#"), ("next", r"^next$"))


def status(text):
    version = re.search(r"(?m)^Version:\s*(\S+)\s+v(\d+\.\d+\.\d+),build(\d+)", text)
    serial = re.search(r"(?m)^Serial-Number:\s*(\S+)", text)
    if not version or not serial:
        raise DeviceError("get system status: no version, build or serial")
    ha = re.search(r"(?m)^Current HA mode:\s*(.+?)\s*$", text)
    vdom = re.search(r"(?m)^Virtual domain configuration:\s*(\S+)", text)
    hostname = re.search(r"(?m)^Hostname:\s*(\S+)", text)
    mode = (ha[1] if ha else "standalone").lower()
    return {
        "model": version[1],
        "version": version[2],
        "build": int(version[3]),
        "serial": serial[1],
        "hostname": hostname[1] if hostname else None,
        "ha": "standalone" if mode.startswith("standalone") else mode.split(",")[0].strip(),
        "vdoms": bool(vdom and vdom[1].lower() in ("multiple", "enable", "split-task")),
    }


def ha_status(text):
    health = re.search(r"(?m)^HA Health Status:\s*(.+?)\s*$", text)
    if not health:
        raise DeviceError("get system ha status: no health status")
    members = {
        m[2]: {"name": m[1], "role": m[0].lower().replace("master", "primary").replace("slave", "secondary")}
        for m in re.findall(
            r"(?m)^(Primary|Secondary|Master|Slave)\s*:\s*(\S+)\s*,\s*(\S+?)\s*,\s*HA cluster index", text
        )
    }
    sync = dict(re.findall(r"(?m)^\s*(\S+?)\(updated [^)]*\):\s*(in-sync|out-of-sync)", text))
    if not members:
        raise DeviceError("get system ha status: no cluster members")
    return {"healthy": health[1].upper() == "OK", "members": members, "sync": sync}


def partitions(text):
    """Firmware partitions from `diagnose sys flash list`: number, image, build and whether active."""
    rows = re.findall(r"(?m)^\s*(\d+)\s+(\S+-FW-build(\d+)\S*)\s+\d+\s+\d+\s+\d+%\s+(Yes|No)\s*$", text)
    if not rows:
        raise DeviceError("diagnose sys flash list: no firmware partitions")
    found = []
    for number, image, build, active in rows:
        train = re.search(r"-(\d+)\.(\d+)-FW-", image)
        found.append(
            {
                "partition": int(number),
                "image": image,
                "build": int(build),
                "train": (int(train[1]), int(train[2])) if train else None,
                "active": active == "Yes",
            }
        )
    if sum(p["active"] for p in found) != 1:
        raise DeviceError("diagnose sys flash list: not exactly one active firmware partition")
    return found


def uptime_seconds(text):
    match = re.search(r"(?m)^Uptime:\s*(.+)$", text)
    if not match:
        return None
    return sum(int(n) * UNITS[u] for n, u in re.findall(r"(\d+)\s+(day|hour|minute|second)s?", match[1]))


def config_policy(policy):
    """The request's rules plus the FortiOS built-ins, in the form the comparison takes."""
    builtin = policy.builtin_rules
    return IosxeConfigPolicy(
        builtin_rules=False,
        ignore=([{"name": n, "line": line} for n, line in IGNORES] if builtin else []) + policy.ignore,
        rewrite=(
            [{"name": n, "line": line, "parent": parent, "replace": r} for n, line, parent, r in REWRITES]
            if builtin
            else []
        )
        + policy.rewrite,
        ordered_sections=(list(ORDERED) if builtin else []) + policy.ordered_sections,
        added=policy.added,
        removed=policy.removed,
    )


def logical(text):
    """Join quoted values that span lines (certificates, scripts, messages) into one line."""
    lines, pending = [], None
    for line in text.splitlines():
        if pending is not None:
            pending += "\\n" + line
            if line.replace('\\"', "").count('"') % 2:
                lines.append(pending)
                pending = None
            continue
        if line.replace('\\"', "").count('"') % 2:
            pending = line
            continue
        lines.append(line)
    if pending is not None:
        lines.append(pending)
    return "\n".join(lines)


def compare_configs(before, after, policy, limit=500):
    return compare(logical(before), logical(after), config_policy(policy), limit)


class Fortigate:
    def __init__(self, settings, device, guard, profiles, audit, ssh=None):
        self.ssh = ssh or NetworkSSH(settings, device, guard, profiles, audit, device_type="fortinet")
        self.vdoms = None

    def text(self, command, timeout=120, check=True, scope="global"):
        """One command; with VDOMs enabled, global commands run inside `config global`."""
        wrap = self.vdoms and scope == "global"
        if wrap:
            self.ssh.execute("config global", 30)
        try:
            result = self.ssh.execute(command, timeout)
        finally:
            if wrap:
                self.ssh.execute("end", 30)
        output = result["stdout"]
        if check and (result["cli_error"] or REJECTED.search(output)):
            first = next((line.strip() for line in output.splitlines() if line.strip()), "")
            raise DeviceError(" ".join(command.split()[:3]) + " was rejected: " + first[:200])
        return output

    def status(self):
        info = status(self.text("get system status", scope="vdom"))
        self.vdoms = info["vdoms"]
        uptime = uptime_seconds(self.text("get system performance status", check=False))
        return {**info, "uptime_seconds": uptime}

    def console_output(self):
        """The output mode Netmiko found before switching it to standard for its session."""
        driver = self.ssh.connect()
        return getattr(driver, "_original_output_mode", None)

    def restore_console(self, mode):
        self.ssh.connect()
        if self.vdoms:
            self.ssh.execute("config global", 30)
        for command in ("config system console", "set output " + mode, "end"):
            self.ssh.execute(command, 30)
        if self.vdoms:
            self.ssh.execute("end", 30)

    def ha(self):
        return ha_status(self.text("get system ha status"))

    def partitions(self):
        return partitions(self.text("diagnose sys flash list"))

    def config(self):
        output = self.text("show", timeout=600, check=False, scope="vdom")
        if not re.search(r"(?m)^config system global$|^config global$", output):
            raise DeviceError("show returned an incomplete configuration")
        return output

    def stage(self, name, server, user, password, timeout, poll):
        """Pull the image into the alternate partition; the running firmware is untouched."""
        output = self.dialogue(
            f"execute restore secondary-image ftp {name} {server} {user} {password}",
            STAGE,
            timeout,
            poll,
            False,
        )
        if FAILURE.search(output) or CLI_ERROR.search(output):
            raise DeviceError("execute restore secondary-image reported a failure")

    def restore(self, name, server, user, password, timeout, poll):
        """FGCP cluster upgrade from the primary: secondaries first, then the primary reboots."""
        output = self.dialogue(
            f"execute restore image ftp {name} {server} {user} {password}", RESTORE, timeout, poll, True
        )
        if FAILURE.search(output) or CLI_ERROR.search(output):
            raise DeviceError("execute restore image reported a failure")

    def set_next_reboot(self, which):
        self.text("execute set-next-reboot " + which)

    def reboot(self):
        self.dialogue("execute reboot", REBOOT, 120, None, True)

    def dialogue(self, command, question, timeout, poll, reboots):
        if self.vdoms:
            self.ssh.execute("config global", 30)
        output, disconnected = self.ssh.dialogue(
            command, [(question, "y")], timeout, poll=poll, disconnect_ok=reboots
        )
        if self.vdoms and not disconnected:
            self.ssh.execute("end", 30)
        return output

    def traffic(self):
        """State that must survive the upgrade, each category an explicit gap when unreadable."""
        readers = {
            "interfaces": lambda: {
                m[0]: m[1].lower()
                for m in re.findall(
                    r"==\[(\S+?)\]\s*\n(?:[ \t]+\S.*\n)*?[ \t]+status:\s*(\w+)",
                    self.text("get system interface physical") + "\n",
                )
            },
            "ipsec_tunnels": lambda: {
                m[0]: "up" if int(m[1]) and m[1] == m[2] else "down"
                for m in re.findall(
                    r"(?m)^'([^']+)'\s+\S+\s+selectors\(total,up\):\s*(\d+)/(\d+)",
                    self.text("get vpn ipsec tunnel summary", scope="vdom"),
                )
            },
            "bgp_peers": lambda: Iosxe.bgp(
                self.text("get router info bgp summary", scope="vdom", check=False)
            ),
            "ospf_neighbors": lambda: {
                m[0] + "|" + m[2]: m[1].split("/")[0].lower()
                for m in re.findall(
                    r"(?m)^(\d+\.\d+\.\d+\.\d+)\s+\d+\s+(\S+?)(?:\s+-)?\s+\S+\s+\d+\.\d+\.\d+\.\d+\s+(\S+)\s*$",
                    self.text("get router info ospf neighbor", scope="vdom", check=False),
                )
            },
            "routes": lambda: len(
                re.findall(
                    r"(?m)^[A-Z][A-Z0-9 *]{0,6}\s+\d+\.\d+\.\d+\.\d+/\d+",
                    self.text("get router info routing-table all", timeout=300, scope="vdom"),
                )
            ),
            "sessions": lambda: int(
                re.search(
                    r"total number of sessions[^:]*:\s*(\d+)",
                    self.text("get system session status", scope="vdom"),
                )[1]
            ),
        }
        data, gaps = {}, []
        for category, read in readers.items():
            try:
                data[category] = read()
            except (DeviceError, KeyError, TypeError, ValueError, AttributeError):
                gaps.append(category)
        data["gaps"] = gaps
        return data

    def close(self):
        self.ssh.close()


class FortiManagerError(DeviceError):
    pass


class FortiManager:
    """FortiManager JSON-RPC with an API key (`Authorization: Bearer`) from a credential profile."""

    def __init__(self, settings, store, target, profiles, guard, audit):
        self.target = settings.http_targets[target]
        self.store, self.guard = store, guard
        self.selector = Selector(
            Vault(store, settings.credential_key_file),
            "http",
            self.target.id,
            profiles if profiles is not None else self.target.credential_profiles,
            audit,
        )
        self.client = self.auth = None

    def connect(self):
        if self.client is None:
            verify = (
                PinnedContext(self.store, tls_key(self.target.base_url))
                if self.target.tls == "pin"
                else ssl.create_default_context(cafile=self.target.ca_file)
                if self.target.ca_file
                else True
            )
            self.client = httpx.Client(
                base_url=self.target.base_url, verify=verify, follow_redirects=False, trust_env=False
            )
        if self.auth is None:

            def authenticate(c):
                options = credential_options(self.selector, c, self.client)
                self.post("get", "/sys/status", options=options)
                return options

            try:
                self.auth = self.selector.run(authenticate)
            except httpx.HTTPError as exc:
                raise FortiManagerError("FortiManager is unreachable (" + type(exc).__name__ + ")") from None
            except AuthenticationRejected:
                raise FortiManagerError("FortiManager rejected every eligible HTTP credential") from None
        return self.auth

    def post(self, method, url, options=None, **params):
        self.guard()
        body = {"id": 1, "method": method, "params": [{"url": url, **params}]}
        response = self.client.post("/jsonrpc", json=body, timeout=120, **(options or self.connect()))
        if response.status_code in (401, 403):
            raise AuthenticationRejected()
        try:
            result = response.json()["result"][0]
            code = result["status"]["code"]
        except (ValueError, KeyError, IndexError, TypeError):
            raise FortiManagerError("FortiManager returned an unrecognized response") from None
        if code == -11:
            raise AuthenticationRejected()
        if code != 0:
            raise FortiManagerError(f"FortiManager {url} failed: {result['status'].get('message', code)}")
        return result.get("data")

    def device(self, adom, serial):
        rows = self.post(
            "get",
            f"/dvmdb/adom/{adom}/device",
            filter=["sn", "==", serial],
            fields=["name", "sn", "os_ver", "mr", "patch", "build", "platform_str", "conn_status", "ha_mode"],
        )
        if not rows:
            raise FortiManagerError("FortiManager does not manage " + serial + " in ADOM " + adom)
        return rows[0]

    def preview(self, adom, device, version, build):
        """Check FortiManager holds the image and can upgrade this device to it; changes nothing."""
        data = self.upgrade_call(adom, device, version, build, "f_preview")
        if str(build) not in str(data):
            raise FortiManagerError("FortiManager's upgrade preview does not reach build " + str(build))
        return data

    def upgrade(self, adom, device, version, build):
        data = self.upgrade_call(adom, device, version, build, None)
        task = (data or {}).get("taskid") or (data or {}).get("task")
        if not task:
            raise FortiManagerError("FortiManager did not start an upgrade task")
        return task

    def upgrade_call(self, adom, device, version, build, flags):
        return self.post(
            "exec",
            "/um/image/upgrade",
            data={
                "adom": adom,
                "device": [{"name": device, "vdom": "root"}],
                "image": {"release": version, "build": str(build)},
                "create_task": "disable" if flags else "enable",
                **({"flags": flags} if flags else {}),
            },
        )

    def task(self, task):
        data = self.post("get", f"/task/task/{task}")
        return {
            "percent": data.get("percent", 0),
            "state": str(data.get("state", "")).lower(),
            "errors": int(data.get("num_err", 0) or 0),
        }

    def retrieve(self, adom, device):
        """Ask FortiManager to read the device configuration again after a reboot it did not run."""
        self.post(
            "exec",
            "/dvm/cmd/reload/dev-list",
            data={
                "adom": adom,
                "reload-dev-member-list": [{"name": device, "vdom": "root"}],
                "flags": ["create_task"],
            },
        )

    def close(self):
        if self.client is not None:
            self.client.close()
