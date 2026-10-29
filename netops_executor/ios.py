"""Cisco Catalyst 2960-X and 2960-XR on classic IOS 15.2 over the executor's audited SSH session.

Classic IOS upgrades with `archive download-sw`, which extracts a .tar image onto every stack
member's flash and points their boot path at it; a separate `reload` starts it. Tables,
copies and dialogues that classic IOS shares with IOS XE come from the IOS XE client.
"""

import re

from .iosxe import INSTALL_FAILURE, Iosxe, listing, uptime_seconds
from .network_ssh import CLI_ERROR, NetworkSSH
from .ssh import DeviceError

CONFIRM = re.compile(r"(?i)Proceed with reload\?\s*\[confirm\]\s*$")


def members(text):
    """Per-member model and release from the classic `show version` switch table."""
    rows = re.findall(
        r"(?m)^[ \t]*\*?[ \t]*(\d+)[ \t]+\d+[ \t]+(WS-C\S+)[ \t]+(\d+\.\d+\(\d+[a-z]?\)\S*)[ \t]+\S+[ \t]*\r?$",
        text,
    )
    if not rows:
        raise DeviceError("show version: no per-member model and release table")
    candidates = re.findall(r"(?m)^[ \t]*\*?[ \t]*(\d+)[ \t]+\d+[ \t]+\S+", text)
    if len({r[0] for r in rows}) != len(rows) or sorted(candidates) != sorted(r[0] for r in rows):
        raise DeviceError("show version: duplicate or unrecognized member rows")
    return {n: {"model": model, "version": version, "mode": None} for n, model, version in rows}


class Ios(Iosxe):
    def __init__(self, settings, device, guard, profiles, audit, ssh=None):
        super().__init__(
            settings,
            device,
            guard,
            profiles,
            audit,
            ssh=ssh or NetworkSSH(settings, device, guard, profiles, audit, device_type="cisco_ios"),
        )

    def version(self):
        output = self.text("show version")
        running = re.search(r"Cisco IOS Software, .*?Version ([^,\s]+)", output)
        image = re.search(r'System image file is "([^"]+)"', output)
        return {
            "version": running[1] if running else None,
            "members": members(output),
            "serials": sorted(set(re.findall(r"(?im)^System Serial Number\s*:\s*(\S+)", output))),
            "uptime_seconds": uptime_seconds(output),
            "image": image[1] if image else None,
        }

    def flash(self, member, name, active=False):
        # Stack members' flash is flash<member>:; the master's is flash:.
        return listing(self.text("dir flash:" if active else f"dir flash{member}:"), name)

    def has_directory(self, name):
        return bool(
            re.search(r"(?m)^\s*\d+\s+d[rwx-]+\s+.*\s" + re.escape(name) + r"\s*$", self.text("dir flash:"))
        )

    def boot_paths(self):
        paths = re.findall(r"(?im)^BOOT path-list\s*:\s*(\S*)", self.text("show boot"))
        if not paths:
            raise DeviceError("show boot reported no BOOT path-list")
        return paths

    def archive(self, source, timeout, progress):
        """`archive download-sw /imageonly /safe`: keeps the running image until the new one is in place."""
        output, _ = self.ssh.dialogue(
            "archive download-sw /imageonly /safe " + source, [], timeout, progress=progress
        )
        failure = INSTALL_FAILURE.search(output) or CLI_ERROR.search(output)
        if failure:
            raise DeviceError("archive download-sw reported a failure: " + failure[0].strip())
        return output

    def reload(self, timeout):
        """Sent once; the reload ends the session."""
        output, disconnected = self.ssh.dialogue("reload", [(CONFIRM, "")], timeout, disconnect_ok=True)
        if not disconnected:
            raise DeviceError("reload returned to the prompt")
        return output

    def install_summary(self):
        raise DeviceError("classic IOS has no install summary")
