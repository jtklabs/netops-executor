#!/usr/bin/env python3
"""Generate the recorded walks the lab's SNMP agents serve.

Every snmp-inventory fixture except its three-member stack is served at its
own lab address, rewritten so the device's management interface carries that
address (discovery can then assign it as the primary IP). FLEET lists them.

The lab's own 9300 stack replaces the fixture stack. It has four present
switches and one provisioned slot:

    switch 1  C9300-48P  active    entPhysicalIndex 1000
    switch 2  C9300-48U  standby   entPhysicalIndex 2000
    switch 3  C9300-24T  member    entPhysicalIndex 3000
    switch 4  C9300-48P  member    entPhysicalIndex 4000
    switch 5  (provisioned, no hardware)

It is built with the same helpers as the snmp-inventory fixtures, so the
format is exactly `snmpwalk -On -Oe -Ot` output. Two walks are written:

    c9300-stack.walk           switch 1 is the active switch
    c9300-stack-failover.walk  switch 1 has failed over: switch 2 is active
                               and switch 1 has rejoined as standby

The management SVI (Vlan10) carries the stack's lab address.

walks/fleet.json maps each walk to the address the agent serves it on.

Usage:
    ./make_walks.py [--output-dir walks]
"""

from __future__ import annotations

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
EMULATOR = os.path.join(HERE, "..", "..", "..", "..", "..", "scripts", "snmp-inventory", "tests", "emulator")
sys.path.insert(0, os.path.abspath(EMULATOR))

from make_fixtures import (  # noqa: E402
    CLASS_CHASSIS,
    CLASS_CONTAINER,
    CLASS_MODULE,
    CLASS_POWER,
    CSW,
    DEVICES,
    IPADDR,
    entity,
    format_walk,
    hexs,
    i,
    interface,
    ip_address,
    s,
    system_group,
)

STACK_ADDRESS = "10.93.0.10"
# Fixture name -> lab address. The stack is served at STACK_ADDRESS.
FLEET = {
    "cisco-2960x": "10.93.0.11",
    "arista-7050sx": "10.93.0.12",
    "aruba-7010-wlc": "10.93.0.13",
    "aruba-clearpass": "10.93.0.14",
    "f5-bigip": "10.93.0.15",
    "palo-pa3220": "10.93.0.16",
    "fortigate-600e": "10.93.0.17",
    "checkpoint-gaia": "10.93.0.18",
    "infoblox-nios": "10.93.0.19",
    "juniper-ex4300": "10.93.0.20",
    "opengear-cm7148": "10.93.0.21",
    "juniper-srx1500-cluster": "10.93.0.22",
    "bluecoat-sg-s400": "10.93.0.23",
}
# Objects the shared fixtures leave out that the executor reads. The
# snmp-inventory scanner reads Opengear from sysDescr only, so its fixture has
# no ogSerialNumber; the executor reads it, as on the real IM7248 in netbox47.
EXTRAS = {"opengear-cm7148": [s("1.3.6.1.4.1.25049.17.1.2.0", "71482763250042")]}

HOSTNAME = "lab-c9300-stk01"
VERSION = "17.09.05"
IMAGE = "cat9k_iosxe.17.09.05.SPA.bin"

ACTIVE, MEMBER, NOT_MEMBER, STANDBY = 1, 2, 3, 4
READY, PROVISIONED = 4, 9

# (switch number, model, serial, base MAC, uplink module or "")
MEMBERS = (
    (1, "C9300-48P", "FOC2741L1AA", "70:B3:17:A1:00:00", "C9300-NM-8X"),
    (2, "C9300-48U", "FOC2741L2BB", "70:B3:17:A2:00:00", "C9300-NM-8X"),
    (3, "C9300-24T", "FOC2742L3CC", "70:B3:17:A3:00:00", "C9300-NM-4G"),
    (4, "C9300-48P", "FOC2742L4DD", "70:B3:17:A4:00:00", ""),
)
PROVISIONED_SWITCH = 5


def stack_row(entity_index: int, number: int, role: int, state: int, mac: str, priority: int) -> list:
    """One cswSwitchInfoEntry, indexed by the member's entPhysicalIndex."""
    return [
        i(f"{CSW}.1.{entity_index}", number),  # cswSwitchNumCurrent
        i(f"{CSW}.2.{entity_index}", number),  # cswSwitchNumNextReload
        i(f"{CSW}.3.{entity_index}", role),  # cswSwitchRole
        i(f"{CSW}.4.{entity_index}", priority),  # cswSwitchSwPriority
        i(f"{CSW}.5.{entity_index}", 0),  # cswSwitchHwPriority
        i(f"{CSW}.6.{entity_index}", state),  # cswSwitchState
        hexs(f"{CSW}.7.{entity_index}", mac),  # cswSwitchMacAddress
        s(f"{CSW}.8.{entity_index}", IMAGE if state == READY else ""),
    ]


def build(address: str, active: int, standby: int) -> list:
    """The whole stack, with `active` and `standby` holding those roles."""
    out = system_group(
        "Cisco IOS Software [Cupertino], Catalyst L3 Switch Software "
        f"(CAT9K_IOSXE), Version {VERSION}, RELEASE SOFTWARE (fc1)\n"
        "Technical Support: http://www.cisco.com/techsupport\n"
        "Copyright (c) 1986-2024 by Cisco Systems, Inc.\n"
        "Compiled Thu 09-May-24 10:41 by mcpre",
        "1.3.6.1.4.1.9.1.2494",  # cat9300-48P, the product of the original active switch
        HOSTNAME,
        location="Lab / Rack 1",
    )
    out += entity(1, "c93xx Stack", 11, 0, -1, "c93xx Stack", "", "", "Cisco")

    for number, model, serial, mac, uplink in MEMBERS:
        base = number * 1000
        out += entity(
            base,
            f"Cisco Catalyst 9300 Switch Stack Member {number}",
            CLASS_CHASSIS,
            contained_in=1,
            rel_pos=number,
            name=f"Switch {number}",
            model=model,
            serial=serial,
            mfg="Cisco",
            hw="V02",
            sw=VERSION,
        )
        out += entity(
            base + 1,
            f"Uplink Module Container Switch {number}",
            CLASS_CONTAINER,
            contained_in=base,
            rel_pos=1,
            name=f"Switch {number} FRU Uplink Module Container",
            mfg="Cisco",
        )
        if uplink:
            out += entity(
                base + 2,
                f"Cisco Catalyst 9300 Uplink Module {uplink}",
                CLASS_MODULE,
                contained_in=base + 1,
                rel_pos=1,
                name=f"Switch {number} Uplink Module",
                model=uplink,
                serial=f"FOC2741U{number:02d}M",
                mfg="Cisco",
                hw="V01",
            )
        out += entity(
            base + 3,
            f"Switch {number} Power Supply A",
            CLASS_POWER,
            contained_in=base,
            rel_pos=1,
            name=f"Switch {number} Power Supply A",
            model="PWR-C1-715WAC",
            serial=f"DTN2741P{number:02d}A",
            mfg="Cisco",
        )
        role = ACTIVE if number == active else STANDBY if number == standby else MEMBER
        priority = 15 if number == active else 14 if number == standby else 1
        out += stack_row(base, number, role, READY, mac, priority)

    # A provisioned switch has a StackWise row but no hardware behind it.
    out += stack_row(
        PROVISIONED_SWITCH * 1000, PROVISIONED_SWITCH, NOT_MEMBER, PROVISIONED, "00:00:00:00:00:00", 1
    )

    if_index = 1
    for number, model, _serial, _mac, uplink in MEMBERS:
        ports = 24 if model.startswith("C9300-24") else 48
        for port in (1, 2, ports):
            out += interface(
                if_index,
                f"GigabitEthernet{number}/0/{port}",
                6,
                1000,
                mac=f"70:B3:17:A{number}:00:{port:02X}",
                alias=f"access {number}/0/{port}",
            )
            if_index += 1
        if uplink:
            speed, prefix = (
                (10000, "TenGigabitEthernet") if uplink == "C9300-NM-8X" else (1000, "GigabitEthernet")
            )
            for port in (1, 2):
                out += interface(
                    if_index,
                    f"{prefix}{number}/1/{port}",
                    6,
                    speed,
                    mac=f"70:B3:17:A{number}:01:{port:02X}",
                    alias=f"uplink {number}/1/{port}",
                )
                if_index += 1
    out += interface(if_index, "Port-channel1", 161, 20000, alias="uplink to distribution")
    if_index += 1
    management = if_index
    out += interface(management, "Vlan10", 53, 0, mac="70:B3:17:A1:00:01", alias="management")
    if_index += 1
    out += interface(if_index, "GigabitEthernet0/0", 6, 1000, mac="70:B3:17:A1:00:0F", alias="oob management")
    out += ip_address(address, 24, management)
    return out


def relocate(varbinds: list, address: str) -> list:
    """Move the fixture's first (management) address to `address` on the same interface."""
    rows = [v for v in varbinds if v.oid.startswith(f"{IPADDR}.3.1.4.")]
    if not rows:
        raise SystemExit("fixture has no IPv4 ipAddressTable row to relocate")
    if_index = int(rows[0].value)
    kept = [v for v in varbinds if not v.oid.startswith(IPADDR + ".")]
    return kept + ip_address(address, 24, if_index)


def write(output_dir: str, name: str, varbinds: list) -> None:
    path = os.path.join(output_dir, f"{name}.walk")
    with open(path, "w") as handle:
        handle.write(f"# {name} — synthetic walk, generated by make_walks.py\n")
        handle.write(format_walk(varbinds))
    print(f"{name:24s} {len(varbinds):4d} varbinds -> {os.path.relpath(path)}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--output-dir", default=os.path.join(HERE, "walks"))
    args = parser.parse_args()
    os.makedirs(args.output_dir, exist_ok=True)
    for name, active, standby in (("c9300-stack", 1, 2), ("c9300-stack-failover", 2, 1)):
        write(args.output_dir, name, build(STACK_ADDRESS, active, standby))
    for name, address in FLEET.items():
        write(args.output_dir, name, relocate(DEVICES[name](), address) + EXTRAS.get(name, []))
    with open(os.path.join(args.output_dir, "fleet.json"), "w") as handle:
        json.dump({"c9300-stack": STACK_ADDRESS, **FLEET}, handle, indent=2)
        handle.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
