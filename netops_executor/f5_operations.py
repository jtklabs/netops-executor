"""SSH-only platform checks, configuration copy, and HA observations."""

import hashlib
import re
import shlex
from ipaddress import ip_address

from .device import blocks, field, name, required
from .ssh import DeviceError


def status(text, choices):
    for line in text.splitlines():
        value = (
            re.sub(r"^\s*(?:status(?:\.description)?|Status)\s*:?\s*", "", line).strip().strip('"').lower()
        )
        if value in choices:
            return value
    raise DeviceError("unrecognized device status")


def children(tokens, key):
    try:
        start = tokens.index(key)
        if tokens[start + 1] != "{":
            raise ValueError()
        depth, result = 0, []
        for i in range(start + 1, len(tokens)):
            value = tokens[i]
            if value == "{":
                depth += 1
            elif value == "}":
                depth -= 1
                if depth == 0:
                    return result
            elif depth == 1 and i + 1 < len(tokens) and tokens[i + 1] == "{":
                result.append(value)
    except (ValueError, IndexError):
        pass
    raise DeviceError("device group membership could not be parsed")


def qualified(value):
    return value if value.startswith("/") else "/Common/" + value


def topology(device):
    ssh = device.ssh
    records = {
        qualified(k): v for k, v in blocks(ssh.tmsh("list /cm device all-properties"), "cm device").items()
    }
    local = [key for key, row in records.items() if field(row, "self-device") in ("true", "yes")]
    if len(local) != 1:
        raise DeviceError("cannot identify local HA device")
    me = local[0]
    groups = blocks(ssh.tmsh("list /cm device-group all-properties"), "cm device-group")
    failover = {
        key: row
        for key, row in groups.items()
        if field(row, "type") == "sync-failover"
        and me in [qualified(member) for member in children(row, "devices")]
    }
    role = status(
        ssh.tmsh("show /cm failover-status field-fmt"), ("active", "standby", "offline", "forced offline")
    )
    if not failover:
        return {
            "self": me,
            "members": [{"name": me, "host": str(ip_address(required(records[me], "management-ip")))}],
            "groups": [],
            "role": role,
            "cluster": None,
            "auto_sync": False,
            "sync": "standalone",
        }
    members = sorted(
        set(qualified(member) for row in failover.values() for member in children(row, "devices"))
    )
    if len(members) != 2 or any(member not in records for member in members):
        raise DeviceError("only verified two-member active/standby HA pairs are supported")
    addresses = [
        {"name": member, "host": str(ip_address(required(records[member], "management-ip")))}
        for member in members
    ]
    key = hashlib.sha256("|".join(sorted(m["host"] for m in addresses)).encode()).hexdigest()
    return {
        "self": me,
        "members": addresses,
        "groups": sorted(failover),
        "role": role,
        "cluster": "ha:" + key,
        "auto_sync": any(field(row, "auto-sync") == "enabled" for row in failover.values()),
        "sync": status(
            ssh.tmsh("show /cm sync-status field-fmt"),
            ("in sync", "changes pending", "awaiting initial sync", "disconnected", "sync failure"),
        ),
    }


def owners(device):
    text = device.ssh.tmsh("show /cm traffic-group field-fmt")
    try:
        # BIG-IP 17.5 prints "cm traffic-group <group>:<device>" rows.
        rows = blocks(text, "cm traffic-group")
    except DeviceError:
        rows = blocks(text, "cm traffic-group-device")
    groups = {}
    for _, row in rows.items():
        group = qualified(required(row, "traffic-group"))
        if group.endswith("/traffic-group-local-only"):
            continue
        member = qualified(required(row, "device-name"))
        state = required(row, "failover-state")
        if member in groups.setdefault(group, {}):
            raise DeviceError("duplicate traffic-group device status")
        groups[group][member] = state
    result = {}
    for group, members in groups.items():
        if sorted(members.values()) != ["active", "standby"]:
            raise DeviceError("traffic group requires one active and one healthy standby")
        result[group] = next(member for member, state in members.items() if state == "active")
    if not result:
        raise DeviceError("no floating traffic-group ownership was reported")
    return result


def details(device):
    ssh = device.ssh
    specs = {
        "vlans": ("net vlan", "tag"),
        "self_ips": ("net self", "address vlan traffic-group"),
        # BIG-IP 17.5 rejects "gw" as a list property; all-properties includes it.
        "routes": ("net route", "all-properties"),
        "management_routes": ("sys management-route", "network gateway"),
        "management_ip": ("sys management-ip", ""),
        "trunks": ("net trunk", "interfaces"),
        "provisioning": ("sys provision", "level"),
        "certificates": ("sys file ssl-cert", "expiration-string"),
    }
    result, errors = {}, {}
    for label, (kind, properties) in specs.items():
        try:
            recursive = (
                "recursive "
                if kind not in ("sys provision", "sys management-ip", "sys management-route", "net trunk")
                else ""
            )
            result[label] = blocks(ssh.tmsh(f"cd /; list /{kind} {recursive}{properties}".strip()), kind)
        except DeviceError:
            errors[label] = "collection unavailable"
    # iRule names only: rule bodies are arbitrary Tcl, and 17.5 rejects "one-line" for rules.
    for label, command, kind in [("irules", "cd /; list /ltm rule recursive app-service", "ltm rule")]:
        try:
            result[label] = sorted(blocks(ssh.tmsh(command), kind))
        except DeviceError:
            errors[label] = "collection unavailable"
    try:
        result["interfaces"] = blocks(ssh.tmsh("show /net interface field-fmt"), "net interface")
        # Retain status only, not continually changing packet counters.
        result["interfaces"] = {
            key: field(row, "status", field(row, "status.description"))
            for key, row in result["interfaces"].items()
        }
    except DeviceError:
        errors["interfaces"] = "collection unavailable"
    return result, errors


def readiness(device):
    output = device.ssh.shell("perl -MF5::ASMReady -e 'print F5::ASMReady::is_asm_ready() ? 1 : 0'").strip()
    if output not in ("0", "1"):
        raise DeviceError("ASM readiness signal is unavailable")
    return output == "1"


def platform(device):
    rows = blocks(device.ssh.tmsh("list /cm device marketing-name platform-id self-device"), "cm device")
    me = next((v for v in rows.values() if field(v, "self-device") in ("true", "yes")), None)
    if not me:
        raise DeviceError("hardware platform could not be read")
    return [field(me, "marketing-name"), field(me, "platform-id")]


def license_date(device):
    text = device.ssh.tmsh("show /sys license")
    match = re.search(r"(?im)^\s*Service Check Date\s+([0-9]{4})[/.-]([0-9]{2})[/.-]([0-9]{2})", text)
    if not match:
        raise DeviceError("license service-check date unavailable")
    return "-".join(match.groups())


def free_bytes(device):
    rows = device.ssh.shell("df -Pk /shared/images").splitlines()
    try:
        return int(rows[-1].split()[3]) * 1024
    except (ValueError, IndexError):
        raise DeviceError("image filesystem free space unavailable") from None


def start_copy(device, source, target, job_id):
    # Persist the intent in the job before launching. No retry after a lost acknowledgement.
    directory = "/var/tmp/netops-executor-" + job_id
    script = f"/sbin/cpcfg --source={name(source)} {name(target)} > {directory}/output.log 2>&1; rc=$?; printf '%s' \"$rc\" > {directory}/exit.tmp; mv {directory}/exit.tmp {directory}/exit"
    device.ssh.shell(
        "umask 077; mkdir "
        + directory
        + " && nohup sh -c "
        + shlex.quote(script)
        + " </dev/null >/dev/null 2>&1 &",
        timeout=30,
    )
    return directory


def copy_status(device, directory):
    output = device.ssh.shell(
        "if test -f "
        + name(directory)
        + "/exit; then cat "
        + name(directory)
        + "/exit; else printf running; fi"
    ).strip()
    if output == "running":
        return None
    if output != "0":
        raise DeviceError("configuration copy failed; inspect its recorded device log")
    return True
