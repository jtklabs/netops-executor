#!/usr/bin/env python3
"""Poll a simulated multi-vendor SNMP fleet with NetOps Executor and check NetBox.

    ./lab.py                    # up, discover all, rediscover all, then stack failover and hardware changes
    ./lab.py up                 # build and start the lab only
    ./lab.py poll [ADDRESS]     # submit one discovery job and print its result (default: the stack)
    ./lab.py down               # stop the lab and delete its volumes

The full run expects an empty NetBox: run ./lab.py down before running it again.

One agent container answers SNMPv3 for every device in FLEET plus a
four-member Catalyst 9300 stack, each on its own 10.93.0.x address, from walks
built by make_walks.py. The lab also runs a throwaway NetBox 4.7.4 with the
repo's netbox-refresh plugin, and the executor API and a worker. It binds only
to 127.0.0.1: NetBox on port 18080 and the executor on 18081. Secrets are
generated into lab.env on first run; it is gitignored.

Only the Python standard library is required on the host, plus Docker.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import string
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import NamedTuple

HERE = os.path.dirname(os.path.abspath(__file__))
ENV_FILE = os.path.join(HERE, "lab.env")
NETBOX = "http://127.0.0.1:" + os.environ.get("LAB_NETBOX_PORT", "18080")
EXECUTOR = "http://127.0.0.1:" + os.environ.get("LAB_EXECUTOR_PORT", "18081")
SITE = "SNMP Lab"
POLLER = "snmp-lab"
# Software report results that mean netbox-refresh stored the running version.
REPORTED = {"created", "changed", "updated", "unchanged"}


class Device(NamedTuple):
    name: str
    manufacturer: str
    model: str
    serial: str
    software: str
    platform: str
    role: str
    interface: str


# Address -> what discovery must record. Addresses match make_walks.FLEET.
FLEET = {
    "10.93.0.11": Device(
        "bld-b-acc-01",
        "Cisco",
        "WS-C2960X-48FPD-L",
        "FOC1934X0AB",
        "15.2(7)E3",
        "Cisco IOS",
        "Switch",
        "Vlan1",
    ),
    "10.93.0.12": Device(
        "dc1-spine-01",
        "Arista",
        "DCS-7050SX-72Q",
        "JPE17240001",
        "4.29.2F",
        "Arista EOS",
        "Switch",
        "Management1",
    ),
    "10.93.0.13": Device(
        "dal-wlc-01", "HPE", "Aruba7010", "CX0011234", "8.10.0.4", "ArubaOS", "Wireless Controller", "GE0/0/1"
    ),
    "10.93.0.14": Device(
        "dal-cppm-01",
        "HPE",
        "C2000",
        "CNC2K2310042",
        "6.11.5.253053",
        "Aruba ClearPass",
        "Network Access Control",
        "eth0",
    ),
    "10.93.0.15": Device(
        "dal-ltm-01",
        "F5",
        "BIG-IP i5800",
        "f5-chs-01234567",
        "17.1.1.3-0.0.5",
        "F5 TMOS",
        "Load Balancer",
        "mgmt",
    ),
    "10.93.0.16": Device(
        "dal-fw-01",
        "Palo Alto Networks",
        "PA-3220",
        "013101011234",
        "11.1.4-h7",
        "PAN-OS",
        "Firewall",
        "management",
    ),
    "10.93.0.17": Device(
        "dal-fgt-01", "Fortinet", "FortiGate-600E", "FG600ETK21901234", "7.2.8", "FortiOS", "Firewall", "mgmt"
    ),
    "10.93.0.18": Device(
        "dal-cp-01",
        "Check Point",
        "Check Point 6200",
        "1811B00234",
        "R81.20 Take 89",
        "Check Point Gaia",
        "Firewall",
        "eth0",
    ),
    "10.93.0.19": Device(
        "dal-ddi-01",
        "Infoblox",
        "IB-1420",
        "422900123456789",
        "9.0.4-50212",
        "Infoblox NIOS",
        "DNS/DHCP",
        "MGMT",
    ),
    "10.93.0.20": Device(
        "dal-acc-01", "Juniper", "EX4300-48T", "PE3714AF0123", "21.4R3-S4.9", "Junos", "Switch", "me0"
    ),
    "10.93.0.21": Device(
        "dal-con-01",
        "Opengear",
        "CM7148-2-DAC",
        "71482763250042",
        "4.13.0",
        "Opengear",
        "Console Server",
        "eth0",
    ),
    "10.93.0.22": Device(
        "dal-srx-01", "Juniper", "SRX1500", "DK2919AF0042", "21.4R3-S5.4", "Junos", "Firewall", "fxp0"
    ),
    "10.93.0.23": Device(
        "dal-proxy-01", "Blue Coat", "SG-S400", "0723160042", "6.6.5.2", "SGOS", "Proxy", "0:0"
    ),
}

CONTROLLER = "10.93.0.13"
# APs dal-wlc-01 terminates: name -> (model, serial, version). dal-ap-102 has
# no wlanAPSwVersion row, so it inherits the controller's version.
ACCESS_POINTS = {
    "dal-ap-101": ("AP-515", "CNJPJ0A001", "8.10.0.4_87457"),
    "dal-ap-102": ("AP-515", "CNJPJ0A002", "8.10.0.4"),
    "dal-ap-103": ("AP-535", "CNJPJ0B003", "8.10.0.4_87457"),
}

STACK_IP = "10.93.0.10"
HOSTNAME = "lab-c9300-stk01"
# Stack records: name -> (vc_position, model, serial).
STACK = {
    HOSTNAME: (1, "C9300-48P", "FOC2741L1AA"),
    f"{HOSTNAME}-2": (2, "C9300-48U", "FOC2741L2BB"),
    f"{HOSTNAME}-3": (3, "C9300-24T", "FOC2742L3CC"),
    f"{HOSTNAME}-4": (4, "C9300-48P", "FOC2742L4DD"),
}
STACK_VERSION = "17.09.05"
# The stack after each hardware change in make_walks.CHANGES, and the records
# each change retires: name -> serial.
REPLACED = {**STACK, f"{HOSTNAME}-3": (3, "C9300-24P", "FOC2750L3ZZ")}
RENUMBERED = {
    **REPLACED,
    f"{HOSTNAME}-2": (2, "C9300-48P", "FOC2742L4DD"),
    f"{HOSTNAME}-4": (4, "C9300-48U", "FOC2741L2BB"),
}
NEW_MASTER = {**RENUMBERED, HOSTNAME: (1, "C9300-48P", "FOC2751L1EE")}
RETIRED_3 = {f"{HOSTNAME}-3-decom-FOC2742L3CC": "FOC2742L3CC"}
RETIRED_1 = {**RETIRED_3, f"{HOSTNAME}-decom-FOC2741L1AA": "FOC2741L1AA"}

failures: list[str] = []


def token(length: int, alphabet: str = string.ascii_letters + string.digits) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(length))


def write_env() -> None:
    if os.path.exists(ENV_FILE):
        return
    db_password = token(32)
    key, value = token(12), token(40)
    values = {
        # NetBox and PostgreSQL
        "DB_PASSWORD": db_password,
        "POSTGRES_PASSWORD": db_password,
        "SECRET_KEY": token(64),
        "API_TOKEN_PEPPER_1": token(64),
        "SUPERUSER_PASSWORD": token(24),
        "SUPERUSER_API_KEY": key,
        "SUPERUSER_API_TOKEN": value,
        # NetOps Executor
        "NETOPS_API_TOKEN": token(48),
        "NETOPS_NETBOX_TOKEN": f"nbt_{key}.{value}",
        # The emulator's fixed lab credentials (scripts/snmp-inventory/tests/emulator/emulator.py).
        "LAB_SNMP_AUTH_PASSWORD": "labauthpass123",
        "LAB_SNMP_PRIV_PASSWORD": "labprivpass123",
    }
    with open(ENV_FILE, "w") as handle:
        handle.writelines(f"{name}={item}\n" for name, item in values.items())
    os.chmod(ENV_FILE, 0o600)


def env() -> dict[str, str]:
    with open(ENV_FILE) as handle:
        return dict(line.rstrip("\n").split("=", 1) for line in handle if "=" in line)


def compose(*args: str, walk: str | None = None) -> None:
    environment = dict(os.environ)
    if walk:
        environment["STACK_WALK"] = walk
    subprocess.run(["docker", "compose", *args], cwd=HERE, env=environment, check=True)


def http(method: str, url: str, auth: str, body: dict | None = None):
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Authorization": auth,
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read() or b"null")


def netbox(path: str, **params):
    query = urllib.parse.urlencode(params)
    return http("GET", f"{NETBOX}/api/{path}?{query}", "Bearer " + env()["NETOPS_NETBOX_TOKEN"])


def wait(description: str, check, timeout: float) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if check():
                return
        except (urllib.error.URLError, ConnectionError, OSError):
            pass
        time.sleep(3)
    sys.exit(f"timed out waiting for {description}")


def up(walk: str = "c9300-stack") -> None:
    write_env()
    subprocess.run([sys.executable, os.path.join(HERE, "make_walks.py")], check=True)
    compose("up", "-d", "--build", walk=walk)
    print("waiting for NetBox migrations and superuser token (first boot takes a few minutes)...")
    wait("NetBox", lambda: netbox("status/").get("netbox-version"), 900)
    wait(
        "NetOps Executor", lambda: urllib.request.urlopen(f"{EXECUTOR}/healthz", timeout=5).status == 200, 120
    )
    print(
        f"NetBox {netbox('status/')['netbox-version']} at {NETBOX}  (admin / SUPERUSER_PASSWORD in lab.env)"
    )


def poll(address: str, show: bool = False) -> dict:
    auth = "Bearer " + env()["NETOPS_API_TOKEN"]
    job = http(
        "POST",
        f"{EXECUTOR}/api/v1/snmp/walks",
        auth,
        {"device_ip": address, "site": SITE, "poller_instance": POLLER, "queue": "priority"},
    )
    deadline = time.time() + 180
    while time.time() < deadline:
        job = http("GET", f"{EXECUTOR}/api/v1/snmp/walks/{job['id']}", auth)
        if job["status"] not in ("queued", "running"):
            break
        time.sleep(1)
    print(f"\njob {job['id']} for {address} finished: {job['status']}")
    if show:
        print(json.dumps((job.get("result") or {}).get("discovery") or {}, indent=2, sort_keys=True))
    return job


def check(condition: bool, message: str) -> None:
    print(("  ok    " if condition else "  FAIL  ") + message)
    if not condition:
        failures.append(message)


def discovery(job: dict) -> dict:
    return (job.get("result") or {}).get("discovery") or {}


def site_id() -> int | None:
    sites = netbox("dcim/sites/", name=SITE)["results"]
    return sites[0]["id"] if len(sites) == 1 else None


def device_record(name: str) -> dict:
    rows = netbox("dcim/devices/", name=name, site_id=site_id())["results"]
    check(len(rows) == 1, f"{name}: exactly one NetBox device (got {len(rows)})")
    return rows[0] if rows else {}


def stored_software(device_id: int | None) -> str | None:
    rows = netbox("plugins/refresh/device-software/", device_id=device_id)["results"] if device_id else []
    return rows[0].get("raw_version") if len(rows) == 1 else None


def verify_job(job: dict, name: str, expect_action: str) -> dict:
    facts = discovery(job)
    check(job["status"] == "succeeded", f"{name}: job succeeded (got {job['status']})")
    action = (facts.get("netbox") or {}).get("status")
    check(action == expect_action, f"{name}: NetBox device {expect_action} (got {action})")
    check(facts.get("missing") == [], f"{name}: no missing identity fields (got {facts.get('missing')})")
    status = (facts.get("software_inventory") or {}).get("status")
    check(status in REPORTED, f"{name}: software report accepted (got {status})")
    return facts


def verify_device(job: dict, address: str, spec: Device, expect_action: str) -> None:
    print(f"\n== {spec.name} ({spec.manufacturer} {spec.model}, {address})")
    facts = verify_job(job, spec.name, expect_action)
    for field, wanted in (
        ("name", spec.name),
        ("manufacturer", spec.manufacturer),
        ("model", spec.model),
        ("serial", spec.serial),
        ("software_version", spec.software),
        ("platform", spec.platform),
    ):
        check(facts.get(field) == wanted, f"{spec.name}: SNMP {field} {wanted!r} (got {facts.get(field)!r})")

    row = device_record(spec.name)
    if not row:
        return
    model = row["device_type"]["model"]
    manufacturer = row["device_type"].get("manufacturer", {}).get("name")
    check(
        (manufacturer, model) == (spec.manufacturer, spec.model),
        f"{spec.name}: device type {spec.manufacturer} {spec.model} (got {manufacturer} {model})",
    )
    check(row["serial"] == spec.serial, f"{spec.name}: serial {spec.serial} (got {row['serial']})")
    check(row["role"]["name"] == spec.role, f"{spec.name}: role {spec.role} (got {row['role']['name']})")
    platform = (row.get("platform") or {}).get("name")
    check(platform == spec.platform, f"{spec.name}: platform {spec.platform} (got {platform})")
    fields = row["custom_fields"]
    check(
        fields.get("software_version") == spec.software,
        f"{spec.name}: software_version {spec.software} (got {fields.get('software_version')})",
    )
    check(
        fields.get("snmp_discovery_ip") == address,
        f"{spec.name}: snmp_discovery_ip {address} (got {fields.get('snmp_discovery_ip')})",
    )
    tags = {tag["name"] for tag in row["tags"]}
    check({POLLER, "discovered"} <= tags, f"{spec.name}: tags {POLLER}, discovered (got {sorted(tags)})")
    primary = (row.get("primary_ip4") or {}).get("address")
    check(primary == f"{address}/24", f"{spec.name}: primary IPv4 {address}/24 (got {primary})")
    addresses = netbox("ipam/ip-addresses/", address=address)["results"]
    interfaces = [(item.get("assigned_object") or {}).get("name") for item in addresses]
    check(interfaces == [spec.interface], f"{spec.name}: {address} on {spec.interface} (got {interfaces})")
    stored = stored_software(row["id"])
    check(stored == spec.software, f"{spec.name}: netbox-refresh running {spec.software} (got {stored})")


def verify_access_points(job: dict, expect_action: str) -> None:
    print("\n== access points reported by dal-wlc-01")
    inventory = discovery(job).get("access_point_inventory") or {}
    check(inventory.get("status") == "synced", f"AP inventory synced (got {inventory.get('status')})")
    check(
        (inventory.get("reported"), inventory.get("skipped")) == (len(ACCESS_POINTS), 0),
        f"controller reported {len(ACCESS_POINTS)} APs, none skipped "
        f"(got {inventory.get('reported')}, {inventory.get('skipped')})",
    )
    results = {row["name"]: row for row in inventory.get("access_points") or []}
    controller = device_record(FLEET[CONTROLLER].name).get("id")
    for name, (model, serial, version) in ACCESS_POINTS.items():
        result = results.get(name, {})
        check(result.get("status") == expect_action, f"{name}: {expect_action} (got {result.get('status')})")
        status = (result.get("software_inventory") or {}).get("status")
        check(status in REPORTED, f"{name}: software report accepted (got {status})")
        row = device_record(name)
        if not row:
            continue
        check(
            row["device_type"]["model"] == model, f"{name}: model {model} (got {row['device_type']['model']})"
        )
        check(row["serial"] == serial, f"{name}: serial {serial} (got {row['serial']})")
        check(row["role"]["name"] == "Wireless AP", f"{name}: role Wireless AP (got {row['role']['name']})")
        platform = (row.get("platform") or {}).get("name")
        check(platform == "ArubaOS", f"{name}: platform ArubaOS (got {platform})")
        check(row["status"]["value"] == "active", f"{name}: status active (got {row['status']['value']})")
        check(
            row["description"] == "AP group dallas-floor-1",
            f"{name}: description 'AP group dallas-floor-1' (got {row['description']!r})",
        )
        fields = row["custom_fields"]
        linked = (fields.get("wireless_controller") or {}).get("id")
        check(linked == controller, f"{name}: wireless_controller is dal-wlc-01 (got {linked})")
        check(
            fields.get("software_version") == version,
            f"{name}: software_version {version} (got {fields.get('software_version')})",
        )
        tags = {tag["name"] for tag in row["tags"]}
        check({POLLER, "discovered"} <= tags, f"{name}: tags {POLLER}, discovered (got {sorted(tags)})")
        stored = stored_software(row["id"])
        check(stored == version, f"{name}: netbox-refresh running {version} (got {stored})")


def verify_stack(
    job: dict,
    step: str,
    expect_action: str,
    expected: dict = STACK,
    retired: dict | None = None,
    changes: tuple[int, int] = (0, 0),
    before: dict | None = None,
) -> dict:
    """Check the stack; return serial -> NetBox device id for the next step."""
    print(f"\n== {HOSTNAME} stack: {step}")
    facts = verify_job(job, HOSTNAME, expect_action)
    stack = facts.get("stack_inventory") or {}
    check(stack.get("status") == "synced", f"stack inventory synced (got {stack.get('status')})")
    counts = (len(stack.get("retired") or []), len(stack.get("renumbered") or []))
    check(counts == changes, f"retired, renumbered this poll: {changes} (got {counts})")
    for member in stack.get("members") or []:
        status = (member.get("software_inventory") or {}).get("status")
        check(status in REPORTED, f"{member.get('name')}: software report accepted (got {status})")

    # The 2960X answers a one-row StackWise table; it must not become a chassis.
    chassis = netbox("dcim/virtual-chassis/", limit=100)["results"]
    check(len(chassis) == 1, f"one virtual chassis (got {len(chassis)})")
    members = (
        netbox("dcim/devices/", virtual_chassis_id=chassis[0]["id"], limit=100)["results"] if chassis else []
    )
    devices = {row["name"]: row for row in members}
    check(set(devices) == set(expected), f"chassis members are {sorted(expected)} (got {sorted(devices)})")
    if chassis:
        check(
            (chassis[0].get("master") or {}).get("id") == devices.get(HOSTNAME, {}).get("id"),
            "virtual chassis master is the hostname record",
        )
    for name, (position, model, serial) in expected.items():
        row = devices.get(name)
        if not row:
            continue
        check(
            row.get("vc_position") == position,
            f"{name}: vc_position {position} (got {row.get('vc_position')})",
        )
        check(
            row["device_type"]["model"] == model, f"{name}: model {model} (got {row['device_type']['model']})"
        )
        check(row["serial"] == serial, f"{name}: serial {serial} (got {row['serial']})")
        version = row["custom_fields"].get("software_version")
        check(version == STACK_VERSION, f"{name}: software_version {STACK_VERSION} (got {version})")
        check(row["role"]["name"] == "Switch", f"{name}: role Switch (got {row['role']['name']})")
        platform = (row.get("platform") or {}).get("name")
        check(platform == "Cisco IOS-XE", f"{name}: platform Cisco IOS-XE (got {platform})")
        primary = (row.get("primary_ip4") or {}).get("address")
        wanted = f"{STACK_IP}/24" if name == HOSTNAME else None
        check(primary == wanted, f"{name}: primary IPv4 {wanted} (got {primary})")
        stored = stored_software(row["id"])
        check(stored == STACK_VERSION, f"{name}: netbox-refresh running {STACK_VERSION} (got {stored})")
    addresses = netbox("ipam/ip-addresses/", address=STACK_IP)["results"]
    owners = [((item.get("assigned_object") or {}).get("device") or {}).get("id") for item in addresses]
    check(
        owners == [devices.get(HOSTNAME, {}).get("id")],
        f"{STACK_IP} assigned once, to the hostname record (got devices {owners})",
    )

    for name, serial in (retired or {}).items():
        rows = netbox("dcim/devices/", name=name, site_id=site_id())["results"]
        check(len(rows) == 1, f"{name}: retired record exists (got {len(rows)})")
        if not rows:
            continue
        row = rows[0]
        check(row["serial"] == serial, f"{name}: serial {serial} (got {row['serial']})")
        check(
            row["status"]["value"] == "decommissioning",
            f"{name}: status decommissioning (got {row['status']['value']})",
        )
        check(row["virtual_chassis"] is None, f"{name}: out of the chassis (got {row['virtual_chassis']})")
        check(row["primary_ip4"] is None, f"{name}: no primary IP (got {row['primary_ip4']})")
        found = row["custom_fields"].get("snmp_discovery_ip")
        check(found in (None, ""), f"{name}: no snmp_discovery_ip (got {found})")

    ids = {row["serial"]: row["id"] for row in devices.values()}
    for serial, device_id in (before or {}).items():
        if serial in ids:
            check(ids[serial] == device_id, f"{serial}: keeps NetBox record {device_id} (got {ids[serial]})")
    return ids


def discover_all(expect_action: str) -> None:
    verify_stack(poll(STACK_IP), "discovery", expect_action)
    for address, spec in FLEET.items():
        job = poll(address)
        verify_device(job, address, spec, expect_action)
        if address == CONTROLLER:
            verify_access_points(job, expect_action)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("command", nargs="?", default="all", choices=("all", "up", "poll", "down"))
    parser.add_argument("address", nargs="?", default=STACK_IP, help="device to poll (poll only)")
    args = parser.parse_args()
    if args.command == "down":
        compose("down", "-v")
        return 0
    if args.command == "up":
        up()
        return 0
    if args.command == "poll":
        poll(args.address, show=True)
        return 0

    up()
    print("\n#### first discovery creates every device")
    discover_all("created")
    print("\n#### rediscovery changes nothing")
    discover_all("unchanged")
    print("\n#### failover: switch 2 becomes active, switch 1 rejoins as standby")
    compose("up", "-d", "--force-recreate", "agents", walk="c9300-stack-failover")
    time.sleep(5)
    ids = verify_stack(poll(STACK_IP), "an election keeps the management record and IP", "unchanged")

    def change(walk: str, step: str, *args, **kwargs) -> dict:
        print(f"\n#### {step}")
        compose("up", "-d", "--force-recreate", "agents", walk=walk)
        time.sleep(5)
        return verify_stack(poll(STACK_IP), step, *args, **kwargs)

    ids = change(
        "c9300-stack-replaced",
        "switch 3 swapped: new record, old one decommissioning",
        "unchanged",
        REPLACED,
        RETIRED_3,
        (1, 0),
        ids,
    )
    ids = verify_stack(
        poll(STACK_IP), "rediscovery after the swap", "unchanged", REPLACED, RETIRED_3, before=ids
    )
    ids = change(
        "c9300-stack-renumbered",
        "switches 2 and 4 swap numbers: records renamed and moved",
        "unchanged",
        RENUMBERED,
        RETIRED_3,
        (0, 2),
        ids,
    )
    ids = verify_stack(
        poll(STACK_IP), "rediscovery after renumbering", "unchanged", RENUMBERED, RETIRED_3, before=ids
    )
    ids = change(
        "c9300-stack-new-master",
        "switch 1 swapped: new hostname record takes the IP and chassis",
        "created",
        NEW_MASTER,
        RETIRED_1,
        (1, 0),
        ids,
    )
    verify_stack(
        poll(STACK_IP), "rediscovery after the new master", "unchanged", NEW_MASTER, RETIRED_1, before=ids
    )
    print(f"\n{len(failures)} failure(s)" if failures else "\nall checks passed")
    for failure in failures:
        print(f"  {failure}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
