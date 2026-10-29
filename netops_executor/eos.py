"""Arista EOS over the executor's authenticated, audited SSH session.

Reads use EOS's structured `| json` output; only flash listings, checksums and saves are text.
Images are copied with SCP over the same session, so credentials and host-key trust are the
ones the job already established.
"""

import json
import re

import paramiko
from scp import SCPClient, SCPException

from .network_ssh import NetworkSSH
from .ssh import DeviceError

# EOS keeps metadata in single-bang comments that differ between running and startup
# configuration and across reboots; operator "!!" comments are configuration.
COMMENT = re.compile(r"^\s*!(?!!)")


def parse_json(output):
    start = output.find("{")
    if start < 0:
        return None
    try:
        return json.loads(output[start:])
    except ValueError:
        return None


def normalized(config):
    return "\n".join(
        line.rstrip() for line in config.splitlines() if line.strip() and not COMMENT.match(line)
    )


def image_name(software_image):
    """`flash:/EOS-4.32.2F.swi` or `flash:EOS-4.32.2F.swi` -> `EOS-4.32.2F.swi`."""
    return re.sub(r"^flash:/?", "", software_image or "")


def flash_free(listing):
    match = re.search(r"\((\d+) bytes free\)", listing)
    if not match:
        raise DeviceError("dir flash: did not report free space")
    return int(match[1])


def flash_size(listing, name):
    match = re.search(r"(?m)^\s*[-d][rwx-]+\s+(\d+)\s+.*\s" + re.escape(name) + r"\s*$", listing)
    return int(match[1]) if match else None


class Eos:
    def __init__(self, settings, device, guard, profiles, audit, ssh=None):
        self.ssh = ssh or NetworkSSH(settings, device, guard, profiles, audit, device_type="arista_eos")

    def text(self, command, timeout=120):
        result = self.ssh.execute(command, timeout, enable=True)
        if result["cli_error"]:
            first = next((line.strip() for line in result["stdout"].splitlines() if line.strip()), "")
            raise DeviceError(command + " was rejected: " + first[:200])
        return result["stdout"]

    def json(self, command, timeout=120):
        data = parse_json(self.text(command + " | json", timeout))
        if not isinstance(data, dict):
            raise DeviceError(command + " returned no JSON")
        return data

    def version(self):
        data = self.json("show version")
        if not data.get("version") or not data.get("modelName"):
            raise DeviceError("show version returned no version or model")
        return {
            "model": data["modelName"],
            "version": data["version"],
            "serial": data.get("serialNumber", ""),
            "mac": data.get("systemMacAddress", ""),
            "uptime_seconds": int(data["uptime"]) if isinstance(data.get("uptime"), (int, float)) else None,
            "boot_time": data.get("bootupTimestamp"),
        }

    def boot_image(self):
        image = self.json("show boot-config").get("softwareImage")
        if not image:
            raise DeviceError("show boot-config returned no software image")
        return image_name(image)

    def mlag(self):
        data = self.json("show mlag")
        if not data.get("state"):
            raise DeviceError("show mlag returned no state")
        return {
            "state": data["state"].lower(),
            "neg_status": str(data.get("negStatus", "")).lower(),
            "peer_link": str(data.get("peerLinkStatus", "")).lower(),
            "local_interface": str(data.get("localIntfStatus", "")).lower(),
            "config_sanity": str(data.get("configSanity", "")).lower(),
            "peer_address": data.get("peerAddress", ""),
        }

    def unsaved(self):
        return bool(self.text("show running-config diffs").strip())

    def running_config(self):
        return self.text("show running-config", timeout=300)

    def save(self):
        if "Copy completed successfully" not in self.text("write memory", timeout=300):
            raise DeviceError("write memory was not acknowledged")

    def flash(self, name):
        listing = self.text("dir flash:")
        return flash_free(listing), flash_size(listing, name)

    def sha512(self, name):
        output = self.text("verify /sha512 flash:" + name, timeout=900)
        match = re.search(r"\b[a-fA-F0-9]{128}\b", output)
        if not match:
            raise DeviceError("verify /sha512 returned no checksum for " + name)
        return match[0].lower()

    def upload(self, local, name, progress):
        """SCP the image to flash over the job's own authenticated SSH transport."""
        self.ssh.connect()
        try:
            with SCPClient(
                self.ssh.client.get_transport(),
                progress=lambda filename, size, sent: progress(sent, size),
                socket_timeout=60,
            ) as scp:
                scp.put(str(local), remote_path="/mnt/flash/" + name)
        except (SCPException, OSError, paramiko.SSHException) as exc:
            raise DeviceError("image copy to flash failed (" + type(exc).__name__ + ")") from None

    def install_reload(self, name, timeout):
        # Native install mode: EOS points boot-config at the image and reloads; `now` skips prompts.
        self.ssh.execute("install source flash:" + name + " now reload", timeout, enable=True)

    def tech_support(self):
        return self.text("show tech-support", timeout=900)

    def reload_cause(self):
        causes = self.json("show reload cause").get("resetCauses") or []
        return " ".join(str(c.get("description", "")) for c in causes).strip()

    def traffic(self):
        """State that must survive a reload, each category an explicit gap when unreadable."""
        data, gaps = {}, []
        readers = {
            "interfaces": lambda: {
                name: str(v.get("linkStatus", "")).lower()
                for name, v in self.json("show interfaces status")["interfaceStatuses"].items()
            },
            "lldp": lambda: {
                n["port"]: str(n.get("neighborDevice", "")) + "|" + str(n.get("neighborPort", ""))
                for n in self.json("show lldp neighbors")["lldpNeighbors"]
            },
            "bgp_peers": lambda: {
                vrf + "|" + peer: str(state.get("peerState", "")).lower()
                for vrf, body in self.json("show ip bgp summary vrf all")["vrfs"].items()
                for peer, state in (body.get("peers") or {}).items()
            },
            "ospf_neighbors": lambda: {
                "|".join((vrf, inst, str(n.get("routerId", "")), str(n.get("interfaceName", "")))): str(
                    n.get("adjacencyState", "")
                ).lower()
                for vrf, body in self.json("show ip ospf neighbor vrf all")["vrfs"].items()
                for inst, entries in (body.get("instList") or {}).items()
                for n in entries.get("ospfNeighborEntries") or []
            },
            "port_channels": lambda: {
                channel + "|" + member: status
                for channel, body in self.json("show port-channel")["portChannels"].items()
                for status, key in (("active", "activePorts"), ("inactive", "inactivePorts"))
                for member in (body.get(key) or {})
            },
            "routes": lambda: sum(
                int(body.get("totalRoutes", 0))
                for body in self.json("show ip route vrf all summary")["vrfs"].values()
            ),
            "mac": lambda: len(self.json("show mac address-table")["unicastTable"]["tableEntries"]),
            "arp": lambda: self.arp_count(self.json("show ip arp vrf all")),
        }
        for category, read in readers.items():
            try:
                data[category] = read()
            except (DeviceError, KeyError, TypeError, ValueError, AttributeError):
                gaps.append(category)
        data["gaps"] = gaps
        return data

    @staticmethod
    def arp_count(data):
        if "vrfs" in data:
            return sum(len(body.get("ipV4Neighbors") or []) for body in data["vrfs"].values())
        return len(data["ipV4Neighbors"])

    def close(self):
        self.ssh.close()
