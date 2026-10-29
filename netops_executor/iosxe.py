"""Cisco IOS XE (Catalyst 9300, 9350, 3650 and 3850) over the executor's audited SSH session.

IOS XE has no structured CLI output, so every reader parses fixed tables and refuses output
it does not recognize. Images are copied with SCP over the job's own transport, or pulled by
the switch from a URL. Install commands run through a bounded dialogue that answers only
the reload, save and packages.conf questions IOS XE asks.
"""

import re

import paramiko
from scp import SCPClient, SCPException

from .iosxe_config import normalized
from .iosxe_models import release
from .network_ssh import NetworkSSH
from .ssh import DeviceError

MAC = r"[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}"
# Installer failures where IOS XE prints them: at the start of a line or after an install
# operation name. A syslog line that merely contains "failed" is not a failure.
INSTALL_FAILURE = re.compile(
    r"(?im)(?:^\s*(?:FAILED|ERROR|ABORTED)\b|^\s*%\s*Error\b"
    r"|\binstall_[a-z_]+:\s*(?:FAIL(?:ED|URE)?|ERROR|ABORT(?:ED)?)\b)"
)
RELOAD = re.compile(
    r"(?is)(?:Do you want to proceed|proceed with reload|reload of the system).*?\[y/n\]\s*[:?]?\s*$"
)
SAVE = re.compile(r"(?is)System configuration has been modified\..*Press Quit\(q\) to exit.*\[y/n/q\]\s*$")
PACKAGES_CONF = re.compile(
    r"(?i)Please confirm you have changed boot config to flash:packages\.conf\s*\[y/n\]\s*$"
)
REMOVE = re.compile(r"(?i)Do you want to remove the above files\?\s*\[y/n\]\s*$")
DESTINATION = re.compile(r"(?i)Destination filename\s*\[[^\]\r\n]*\]\?\s*$")
BOOT_COMMANDS = ("no boot system", "boot system flash:packages.conf", "no boot manual")
SECONDS = {"year": 31536000, "week": 604800, "day": 86400, "hour": 3600, "minute": 60, "second": 1}


def release_in(value, target):
    match = re.match(r"(\d+\.\d+\.\d+[a-z]?)", value or "")
    return bool(match and release(match[1]) == release(target))


def family(model):
    if re.fullmatch(r"WS-C3650-[A-Z0-9]+(?:-[LSE])?", model):
        return "C3650"
    if re.fullmatch(r"WS-C3850-[A-Z0-9]+(?:-[LSE])?", model):
        return "C3850"
    if re.fullmatch(r"C9350-[A-Z0-9-]+", model):
        return "C9350"
    if re.fullmatch(r"C9300[LX]?-[A-Z0-9-]+", model):
        return "C9300"
    return None


def uptime_seconds(text):
    match = re.search(r"(?m)^\S+ uptime is (.+)$", text)
    if not match:
        return None
    return sum(
        int(n) * SECONDS[unit]
        for n, unit in re.findall(r"(\d+) (year|week|day|hour|minute|second)s?", match[1])
    )


def members(text):
    """Per-member model, release and boot mode from the `show version` switch table."""
    rows = re.findall(
        r"(?m)^[ \t]*\*?[ \t]*(\d+)[ \t]+\d+[ \t]+((?:WS-)?C\S+)[ \t]+(\d+\.\d+\.\d+[a-z]?)"
        r"[ \t]+\S+[ \t]+(INSTALL|BUNDLE)[ \t]*\r?$",
        text,
    )
    if not rows:
        raise DeviceError("show version: no per-member model, release and mode table")
    candidates = re.findall(r"(?m)^[ \t]*\*?[ \t]*(\d+)[ \t]+\d+[ \t]+\S+", text)
    if len({r[0] for r in rows}) != len(rows) or sorted(candidates) != sorted(r[0] for r in rows):
        raise DeviceError("show version: duplicate or unrecognized member rows")
    return {n: {"model": model, "version": version, "mode": mode} for n, model, version, mode in rows}


def stack(text):
    rows = re.findall(
        r"(?m)^\s*(\*?)\s*(\d+)\s+(Active|Standby|Member)\s+(" + MAC + r")\s+\d+\s+\S+\s+(\S+)\s*$", text
    )
    if not rows:
        raise DeviceError("show switch: no recognized members")
    return {n: {"role": role, "mac": mac.lower(), "state": state} for _, n, role, mac, state in rows}


def install_summary(text):
    """Committed image per member, and whether anything is uncommitted, inactive or timing out."""
    current, committed, ambiguous = [], {}, False
    for line in text.splitlines():
        header = re.search(r"\[\s*Switch\s+([\d\s]+)\]", line)
        if header:
            current = header[1].split()
        image = re.match(r"\s*IMG\s+C\s+(\S+)", line)
        if image:
            for member in current:
                ambiguous = ambiguous or member in committed
                committed[member] = image[1]
    return {
        "committed": {} if ambiguous else committed,
        "pending": bool(re.search(r"(?m)^\s*IMG\s+[UAD]\s+", text)),
        "inactive": bool(re.search(r"(?m)^\s*IMG\s+I\s+", text)),
        "abort_timer": bool(re.search(r"Auto abort timer:\s*active\b", text, re.I)),
    }


def listing(text, name):
    free = re.search(r"\((\d+) bytes free\)", text)
    if not free:
        raise DeviceError("dir did not report free space")
    size = re.search(r"(?m)^\s*\d+\s+-[rwx-]+\s+(\d+)\s+.*\s" + re.escape(name) + r"\s*$", text)
    return int(free[1]), int(size[1]) if size else None


def boot_ok(config):
    boot = re.findall(r"(?m)^boot system (.+)$", config)
    return boot in (["flash:packages.conf"], ["switch all flash:packages.conf"]) and not re.search(
        r"(?m)^boot manual", config
    )


def neighbors(text, start, local, remote, device):
    """Local port -> neighbor|port from `show cdp|lldp neighbors detail` blocks."""
    found = {}
    for block in re.split(start, text)[1:]:
        port = re.search(local, block)
        name = re.search(device, block)
        peer = re.search(remote, block)
        if port:
            found[port[1].strip()] = (
                (name[1].strip() if name else "") + "|" + (peer[1].strip() if peer else "")
            )
    return found


class Iosxe:
    def __init__(self, settings, device, guard, profiles, audit, ssh=None):
        self.ssh = ssh or NetworkSSH(settings, device, guard, profiles, audit, device_type="cisco_xe")

    def text(self, command, timeout=120, check=True):
        result = self.ssh.execute(command, timeout, enable=True)
        if check and result["cli_error"]:
            first = next((line.strip() for line in result["stdout"].splitlines() if line.strip()), "")
            raise DeviceError(command + " was rejected: " + first[:200])
        return result["stdout"]

    def version(self):
        output = self.text("show version")
        running = re.search(r"Cisco IOS XE Software, Version (\S+)", output)
        return {
            "version": running[1] if running else None,
            "members": members(output),
            "serials": sorted(set(re.findall(r"(?m)^System Serial Number\s*:\s*(\S+)", output))),
            "uptime_seconds": uptime_seconds(output),
        }

    def stack(self):
        return stack(self.text("show switch"))

    def install_summary(self):
        return install_summary(self.text("show install summary"))

    def config(self, which):
        # A banner can contain text that looks like a CLI error, so completeness is checked instead.
        output = self.text("show " + which, timeout=300, check=False)
        if not re.search(r"(?m)^hostname \S+", output):
            raise DeviceError("show " + which + " returned an incomplete configuration")
        return output

    def unsaved(self):
        return normalized(self.config("running-config")) != normalized(self.config("startup-config"))

    def save(self):
        if "[OK]" not in self.text("write memory", timeout=300):
            raise DeviceError("write memory was not acknowledged")

    def flash(self, member, name):
        return listing(self.text(f"dir flash-{member}:"), name)

    def verify(self, name, algorithm):
        output = self.text(f"verify /{algorithm} flash:{name}", timeout=1800)
        match = re.search(r"=\s*([a-fA-F0-9]{%d})\b" % (128 if algorithm == "sha512" else 32), output)
        if not match:
            raise DeviceError(f"verify /{algorithm} returned no checksum for {name}")
        return match[1].lower()

    def upload(self, local, name, progress):
        """SCP the image to flash over the job's own authenticated SSH transport."""
        self.ssh.connect()
        try:
            with SCPClient(
                self.ssh.client.get_transport(),
                progress=lambda filename, size, sent: progress(sent, size),
                socket_timeout=120,
            ) as scp:
                scp.put(str(local), remote_path="flash:/" + name)
        except (SCPException, OSError, paramiko.SSHException) as exc:
            raise DeviceError("image copy to flash failed (" + type(exc).__name__ + ")") from None

    def device_copy(self, url, name, timeout, progress):
        output, _ = self.ssh.dialogue(
            f"copy {url} flash:{name}", [(DESTINATION, "")], timeout, progress=progress
        )
        if INSTALL_FAILURE.search(output) or not re.search(r"\d+ bytes copied", output):
            raise DeviceError("switch copy of " + name + " failed")

    def delete(self, name):
        self.text(f"delete /force flash:{name}")

    def remove_inactive(self, timeout, progress):
        output, _ = self.ssh.dialogue("install remove inactive", [(REMOVE, "y")], timeout, progress=progress)
        if INSTALL_FAILURE.search(output) or "SUCCESS" not in output:
            raise DeviceError("install remove inactive did not report success")

    def configure_boot(self):
        for command in BOOT_COMMANDS:
            result = self.ssh.execute(command, 60, mode="config")
            if result["cli_error"]:
                raise DeviceError(command + " was rejected")

    def install(self, name, timeout, progress):
        """`install add file ... activate commit`: sent once; the reload ends the session."""
        output, disconnected = self.ssh.dialogue(
            f"install add file flash:{name} activate commit",
            [(SAVE, "y"), (PACKAGES_CONF, "y"), (RELOAD, "y")],
            timeout,
            progress=progress,
            disconnect_ok=True,
        )
        if INSTALL_FAILURE.search(output):
            raise DeviceError("install add reported a failure: " + INSTALL_FAILURE.search(output)[0].strip())
        if not disconnected and not re.search(r"SUCCESS|Install will reload|Reloading", output, re.I):
            raise DeviceError("install returned to the prompt without success or a reload")
        return output

    def tech_support(self):
        return self.text("show tech-support", timeout=1800, check=False)

    def traffic(self):
        """State that must survive a reload, each category an explicit gap when unreadable."""
        readers = {
            "interfaces": lambda: {
                m[0]: m[1] + "/" + m[2]
                for m in re.findall(
                    r"(?m)^(\S+)\s+\S+\s+(?:YES|NO)\s+\S+\s+(up|down|administratively down|deleted)\s+(up|down)\s*$",
                    self.text("show ip interface brief"),
                )
            },
            "cdp": lambda: neighbors(
                self.text("show cdp neighbors detail"),
                r"(?m)^-{5,}\s*$",
                r"Interface:\s*([^,]+),",
                r"Port ID \(outgoing port\):\s*(\S+)",
                r"Device ID:\s*(\S+)",
            ),
            "lldp": lambda: neighbors(
                self.text("show lldp neighbors detail"),
                r"(?m)^-{5,}\s*$",
                r"Local Intf:\s*(\S+)",
                r"Port id:\s*(\S+)",
                r"System Name:\s*(\S+)",
            ),
            "port_channels": lambda: self.port_channels(self.text("show etherchannel summary")),
            "bgp_peers": lambda: self.bgp(self.text("show bgp all summary")),
            "ospf_neighbors": lambda: {
                m[0] + "|" + m[2]: m[1].split("/")[0].lower()
                for m in re.findall(
                    r"(?m)^(\d+\.\d+\.\d+\.\d+)\s+\d+\s+(\S+?)(?:\s+-)?\s+\S+\s+\d+\.\d+\.\d+\.\d+\s+(\S+)\s*$",
                    self.text("show ip ospf neighbor"),
                )
            },
            "hsrp": lambda: {
                m[0] + "|" + m[1]: m[2].lower()
                for m in re.findall(
                    r"(?m)^(\S+)\s+(\d+)\s+\d+\s+P?\s*(Active|Standby|Listen|Speak|Init)\s+",
                    self.text("show standby brief"),
                )
            },
            "routes": lambda: self.route_count(),
            "mac": lambda: len(re.findall(MAC, self.text("show mac address-table dynamic", timeout=300))),
            "arp": lambda: int(re.search(r"(\d+) IP ARP entries", self.text("show ip arp summary"))[1]),
            "access_sessions": lambda: self.access_sessions(),
        }
        data, gaps = {}, []
        for category, read in readers.items():
            try:
                data[category] = read()
            except (DeviceError, KeyError, TypeError, ValueError, AttributeError):
                gaps.append(category)
        data["gaps"] = gaps
        return data

    @staticmethod
    def port_channels(text):
        if not re.search(r"Number of channel-groups in use", text):
            raise DeviceError("show etherchannel summary: unrecognized output")
        members, channel = {}, None
        for line in text.splitlines():
            group = re.match(r"^\s*\d+\s+(Po\d+)\(\w+\)\s+\S+\s*(.*)$", line)
            if group:
                channel, rest = group[1], group[2]
            elif channel and re.match(r"^\s+\S+\(\w+\)", line):
                rest = line
            else:
                channel = None if line.strip() and not line[0].isspace() else channel
                continue
            for port, flags in re.findall(r"(\S+)\((\w+)\)", rest):
                members[channel + "|" + port] = "bundled" if "P" in flags else flags.lower()
        return members

    @staticmethod
    def bgp(text):
        if re.search(r"BGP not active|% BGP not active", text, re.I) or not text.strip():
            return {}
        if "BGP router identifier" not in text:
            raise DeviceError("show bgp all summary: unrecognized output")
        peers, family = {}, "default"
        for line in text.splitlines():
            if line.startswith("For address family:"):
                family = line.split(":", 1)[1].strip()
            row = re.match(r"^([0-9a-fA-F:.]+)\s+4\s+\S+(?:\s+\S+){6}\s+(\S+(?: \S+)?)\s*$", line)
            if row:
                state = row[2]
                peers[family + "|" + row[1]] = "established" if state.isdigit() else state.lower()
        return peers

    def route_count(self):
        def total(command):
            # Total networks plus subnets.
            match = re.search(r"(?m)^Total\s+(\d+)\s+(\d+)", self.text(command))
            if not match:
                raise DeviceError(command + ": no total")
            return int(match[1]) + int(match[2])

        count = total("show ip route summary")
        for name in re.findall(
            r"(?m)^\s+(\S+)\s+(?:<not set>|\S+)\s+(?:ipv4|ipv4,ipv6)\b", self.text("show vrf")
        ):
            if re.fullmatch(r"[\w.-]+", name):
                count += total(f"show ip route vrf {name} summary")
        return count

    def access_sessions(self):
        output = self.text("show access-session")
        match = re.search(r"Session count\s*=\s*(\d+)", output)
        if match:
            return int(match[1])
        if re.search(r"No sessions", output, re.I):
            return 0
        raise DeviceError("show access-session: unrecognized output")

    def close(self):
        self.ssh.close()
