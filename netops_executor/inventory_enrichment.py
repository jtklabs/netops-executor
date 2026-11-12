"""Read-only optional enrichment through the executor's audited SSH transport."""

import hashlib
import json
import os
import re
from types import SimpleNamespace

from .config import Device
from .credentials import Vault
from .f5_operations import topology
from .fortinet import ha_status
from .inventory_licenses import parse_licenses
from .network_ssh import NetworkSSH
from .ssh import SSH, DeviceError
from .store import CancelRequested, LostOwnership

DRIVERS = {
    "Arista": "arista_eos",
    "Cisco": "cisco_ios",
    "Juniper": "juniper_junos",
    "Palo Alto Networks": "paloalto_panos",
    "Fortinet": "fortinet",
    "HPE": "aruba_os",
    "Infoblox": "terminal_server",
}
LICENSE_COMMANDS = {
    "Cisco": ("show license summary", "show license"),
    "Juniper": ("show system license",),
    "Palo Alto Networks": ("request license info",),
    "Arista": ("show license",),
    "Fortinet": ("diagnose autoupdate versions", "get system status"),
    "HPE": ("show license summary",),
    "Infoblox": ("show license",),
}


def target_for(settings, store, address, vendor, platform):
    expected = {
        "F5": "f5",
        "Arista": "arista_eos",
        "Cisco": "cisco_nxos" if "NX-OS" in platform else "cisco_ios",
        "Palo Alto Networks": "paloalto_panos",
        "Fortinet": "fortinet",
        "Opengear": "opengear",
    }.get(vendor, "linux")
    matches = [d for d in settings.devices.values() if d.host == address and d.device_type == expected]
    if len(matches) > 1:
        raise DeviceError("Multiple inventory entries match the discovered SSH target")
    if matches:
        return matches[0]
    candidates = Vault(store, settings.credential_key_file).candidates("ssh", targets=(address,))
    if not candidates:
        return None
    return Device(
        id=address, host=address, device_type=expected, credential_profiles=[row["id"] for row in candidates]
    )


def parse_ha(vendor, output, serial=""):
    if vendor == "Arista":
        data = json.loads(output[output.index("{") :])
        state = str(data.get("state", "")).lower()
        if state == "disabled":
            return [], {"status": "not_applicable", "reason": "MLAG disabled"}
        if not state:
            raise ValueError("MLAG state absent")
        peer = data.get("peerAddress")
        if not peer:
            raise ValueError("MLAG peer absent")
        healthy = state == "active" and str(data.get("peerLinkStatus", "")).lower() == "up"
        return [
            {
                "kind": "mlag",
                "peer_name": str(peer),
                "peer_address": str(peer),
                "group": str(data.get("domainId", "")),
                "state": state,
            }
        ], {"status": "passed" if healthy else "failed", "reason": "MLAG " + state}
    if vendor == "Fortinet":
        if re.search(r"(?im)^Current HA mode:\s*standalone", output):
            return [], {"status": "not_applicable", "reason": "Standalone"}
        data = ha_status(output)
        peers = [
            {
                "kind": "ha",
                "peer_name": row["name"],
                "role": row["role"],
                "state": data["sync"].get(key, "unknown"),
            }
            for key, row in data["members"].items()
            if key != serial
        ]
        healthy = (
            data["healthy"] and bool(data["sync"]) and all(s == "in-sync" for s in data["sync"].values())
        )
        return peers, {"status": "passed" if healthy else "failed", "reason": "FortiGate HA health and sync"}
    if vendor == "Palo Alto Networks":
        # CLI text field names are scoped by their Local/Peer information sections.
        if re.search(r"(?im)^\s*Enabled:\s*no\b", output):
            return [], {"status": "not_applicable", "reason": "HA disabled"}
        peer = re.search(r"(?is)Peer Information:(.*?)(?:^\S|\Z)", output, re.M)
        if not peer:
            raise ValueError("Peer information absent")
        name = re.search(r"(?im)^\s*Hostname:\s*(\S+)", peer[1])
        address = re.search(r"(?im)^\s*Management IPv4 Address:\s*([\d.]+)", peer[1])
        state = re.search(r"(?im)^\s*State:\s*(\S+)", peer[1])
        sync = re.search(r"(?im)^\s*Running Configuration:\s*(.+)$", output)
        if not (name or address):
            raise ValueError("Peer identity absent")
        healthy = bool(
            state
            and state[1].lower() in ("active", "passive")
            and sync
            and sync[1].strip().lower() == "synchronized"
        )
        return [
            {
                "kind": "ha",
                "peer_name": name[1] if name else address[1],
                "peer_address": address[1] if address else "",
                "state": state[1] if state else "unknown",
            }
        ], {"status": "passed" if healthy else "unknown", "reason": "PAN-OS HA peer and configuration sync"}
    raise ValueError("No HA parser")


def collect_enrichment(
    settings, store, address, facts, job_id, checkpoint, audit, *, backup=False, target_image=None
):
    vendor = facts["manufacturer"]
    output = {"components": {}, "readiness": {}, "relationships": [], "licenses": []}
    if vendor not in DRIVERS and vendor != "F5":
        output["components"] = {
            name: {"status": "unsupported", "reason": "No device CLI adapter for this platform"}
            for name in ("licenses", "ha", "readiness")
        }
        return output
    ssh = None
    try:
        target = target_for(settings, store, address, vendor, facts.get("platform", ""))
        if target is None:
            output["components"] = {
                name: {"status": "skipped", "reason": "No eligible saved SSH profile"}
                for name in ("licenses", "ha", "readiness")
            }
            return output
        driver = DRIVERS.get(vendor)
        if vendor == "Cisco" and "NX-OS" in facts.get("platform", ""):
            driver = "cisco_nxos"
        if vendor == "HPE" and facts.get("platform") != "ArubaOS":
            output["components"]["licenses"] = {
                "status": "unsupported",
                "reason": "License CLI adapter supports ArubaOS controllers",
            }
            return output
        ssh = (
            SSH(settings, target, guard=checkpoint, audit=audit)
            if vendor == "F5"
            else NetworkSSH(settings, target, guard=checkpoint, audit=audit, device_type=driver)
        )

        def read(command):
            checkpoint()
            if vendor == "F5":
                return ssh.tmsh(command, timeout=30)
            result = ssh.execute(command, timeout=30)
            if result.get("cli_error") or re.search(
                r"(?im)^\s*(?:Command fail|Unknown action|command parse error)", result["stdout"]
            ):
                raise DeviceError("Read-only collection command rejected: " + command)
            return result["stdout"]

        def attempt(component, operation):
            try:
                operation()
            except (CancelRequested, LostOwnership):
                raise
            except Exception:
                # Vendor output can contain activation keys. Never put exception text in reports.
                output["components"][component] = {
                    "status": "failed",
                    "reason": "Read-only CLI collection failed or output was not recognized",
                }
            else:
                output["components"].setdefault(component, {"status": "success"})

        def licenses():
            if vendor == "F5":
                # Existing F5 license path already collects the full key and modules.
                output["components"]["licenses"] = {
                    "status": "skipped",
                    "reason": "Collected through F5 license adapter",
                }
                return
            commands = LICENSE_COMMANDS[vendor]
            for command in commands:
                try:
                    text = read(command)
                except DeviceError:
                    continue
                found = parse_licenses(vendor, text)
                if found:
                    output["licenses"] = found
                    return
            output["components"]["licenses"] = {
                "status": "partial",
                "reason": "No recognized device-observed license records; portal coverage unverified",
            }

        def ha():
            if vendor == "F5":
                data = topology(SimpleNamespace(ssh=ssh))
                output["relationships"] = [
                    {
                        "kind": "ha",
                        "peer_name": m["name"].rsplit("/", 1)[-1],
                        "peer_address": m["host"],
                        "group": ",".join(data["groups"])[:200],
                        "role": data["role"],
                        "state": data["sync"],
                    }
                    for m in data["members"]
                    if m["name"] != data["self"]
                ]
                output["readiness"]["ha"] = {
                    "status": "not_applicable"
                    if not data["groups"]
                    else "passed"
                    if data["sync"] == "in sync" and data["role"] in ("active", "standby")
                    else "failed",
                    "reason": data["sync"],
                }
                return
            command = {
                "Arista": "show mlag | json",
                "Fortinet": "get system ha status",
                "Palo Alto Networks": "show high-availability all",
            }.get(vendor)
            if not command:
                output["components"]["ha"] = {
                    "status": "unsupported",
                    "reason": "HA readiness requires a platform-specific precheck",
                }
                return
            text = read(command)
            if vendor == "Fortinet":
                text = read("get system status") + "\n" + text
            output["relationships"], output["readiness"]["ha"] = parse_ha(
                vendor, text, facts.get("serial", "")
            )

        def readiness():
            ssh.connect()
            for name in ("ssh", "credentials", "trust"):
                output["readiness"][name] = {
                    "status": "passed",
                    "reason": "Authenticated SSH with verified or pinned host key",
                }
            commands = {
                "Arista": "dir flash:",
                "Cisco": "dir bootflash:" if driver == "cisco_nxos" else "dir flash:",
                "Juniper": "show system storage",
                "Palo Alto Networks": "show system disk-space",
            }
            if vendor in commands:
                text = read(commands[vendor])
                match = re.search(r"(\d+)\s+bytes\s+(?:free|available)", text)
                size = (target_image or {}).get("size")
                if match and size:
                    enough = int(match[1]) >= int(size) * 2
                    output["readiness"]["storage"] = {
                        "status": "passed" if enough else "failed",
                        "reason": f"{int(match[1])} bytes free; requires twice preferred image size ({size} bytes)",
                    }
                else:
                    output["readiness"]["storage"] = {
                        "status": "unknown",
                        "reason": "Comparable free bytes or preferred image size unavailable",
                    }
            if backup:
                command = {
                    "Arista": "show running-config",
                    "Cisco": "show running-config",
                    "Juniper": "show configuration | display set",
                    "Palo Alto Networks": "show config running",
                    "Fortinet": "show full-configuration",
                }.get(vendor)
                if command:
                    config = read(command)
                    if len(config.strip()) < 20:
                        raise DeviceError("Configuration output too short to verify a backup")
                    directory = (
                        settings.backup_root / "discovery" / hashlib.sha256(address.encode()).hexdigest()[:20]
                    )
                    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
                    path = directory / (job_id + ".cfg")
                    with path.open("x", encoding="utf-8") as handle:
                        os.chmod(path, 0o600)
                        handle.write(config)
                    output["readiness"]["backup"] = {
                        "status": "passed",
                        "reason": "Private configuration snapshot saved on collecting executor",
                    }
                else:
                    output["readiness"]["backup"] = {
                        "status": "unknown",
                        "reason": "Use platform backup workflow to verify a recoverable backup",
                    }
            else:
                output["readiness"]["backup"] = {
                    "status": "unknown",
                    "reason": "Backup not requested; set backup_config or run platform backup workflow",
                }

        attempt("licenses", licenses)
        attempt("ha", ha)
        attempt("readiness", readiness)
        return output
    except (CancelRequested, LostOwnership):
        raise
    except Exception:
        output["components"]["readiness"] = {
            "status": "failed",
            "reason": "SSH target or credential store unavailable",
        }
        return output
    finally:
        if ssh:
            ssh.close()
