#!/usr/bin/env python3
"""Generate the recorded-walk fixtures the emulator serves.

The fixtures are synthetic. There are no real devices of these families
reachable from the lab, so each one is built from the structure the vendor's
published MIB defines and the values that family is documented to return —
model strings, serial formats, sysDescr wording, which tables are populated and
which are empty.

Being explicit about that: these fixtures prove the scanner handles the shapes
correctly. They cannot prove a particular firmware populates a particular
table. When a real device of one of these families is available, capture it
with `record_walk.py` and drop the file in over the generated one — the format
is identical, and the tests will then be running against ground truth.

The most important shapes encoded here:

    cisco-c9300-stack   three chassis rows in ENTITY-MIB plus a populated
                        CISCO-STACKWISE-MIB, interfaces named Gi<member>/0/<n>,
                        uplink modules with their own serials
    arista-7050sx       ENTITY-MIB populated, model reported plainly as
                        DCS-7050SX-72Q — the case orb-agent turns into
                        "aristaDCS7050SX272Q"
    aruba-7010-wlc      a controller with an AP table, which is the only way
                        the APs get inventoried
    firewalls/LBs       ENTITY-MIB deliberately near-empty, so model and serial
                        have to come from the vendor's own scalars
    neighbor tables     the stack, the 2960X and the Arista carry CDP/LLDP
                        adjacency data describing the SAME links from both
                        ends — Cisco-to-Cisco seen twice (CDP long names, LLDP
                        short names), the Arista LLDP-only, one link landing
                        on stack member 2, and a phone, an AP and an unknown
                        switch that exercise the neighbor-class filter and the
                        report-don't-guess paths

Usage:
    ./make_fixtures.py [--output-dir ../fixtures]
"""

from __future__ import annotations

import argparse
import ipaddress
import os

from walkfile import Varbind, format_walk

# --- OIDs, repeated here so a fixture bug cannot be masked by a mibs.py bug ---

SYS = "1.3.6.1.2.1.1"
ENT = "1.3.6.1.2.1.47.1.1.1.1"
IFT = "1.3.6.1.2.1.2.2.1"
IFX = "1.3.6.1.2.1.31.1.1.1"
IPADDR = "1.3.6.1.2.1.4.34.1"
IPPFX = "1.3.6.1.2.1.4.32.1.5"
CSW = "1.3.6.1.4.1.9.9.500.1.2.1.1"
ARUBA_AP = "1.3.6.1.4.1.14823.2.2.1.5.2.1.4.1"
# LLDP-MIB is an IEEE MIB: its root is 1.0.8802, OUTSIDE 1.3.6.1. The
# emulator registers a second pass_persist subtree for it, and --save-walk
# captures it separately, both because of exactly this.
LLDP_REM = "1.0.8802.1.1.2.1.4.1.1"  # lldpRemEntry, columns .N.<t>.<port>.<idx>
LLDP_LOC = "1.0.8802.1.1.2.1.3.7.1"  # lldpLocPortEntry, columns .N.<port>
CDP = "1.3.6.1.4.1.9.9.23.1.2.1.1"  # cdpCacheEntry, columns .N.<ifIndex>.<devIdx>

CLASS_CHASSIS = 3
CLASS_CONTAINER = 5
CLASS_MODULE = 9
CLASS_POWER = 6
CLASS_PORT = 10


def s(oid: str, value: str) -> Varbind:
    return Varbind(oid, "STRING", value)


def i(oid: str, value: int) -> Varbind:
    return Varbind(oid, "INTEGER", str(value))


def g(oid: str, value: int) -> Varbind:
    return Varbind(oid, "Gauge32", str(value))


def hexs(oid: str, mac: str) -> Varbind:
    return Varbind(oid, "Hex-STRING", " ".join(mac.split(":")))


def ticks(oid: str, value: int) -> Varbind:
    return Varbind(oid, "Timeticks", f"({value}) 0:00:00.00")


def objid(oid: str, value: str) -> Varbind:
    return Varbind(oid, "OID", value)


def system_group(
    descr: str,
    object_id: str,
    name: str,
    location: str = "Lab",
    contact: str = "netops@example.com",
    uptime: int = 123456700,
) -> list[Varbind]:
    return [
        s(f"{SYS}.1.0", descr),
        objid(f"{SYS}.2.0", object_id),
        ticks(f"{SYS}.3.0", uptime),
        s(f"{SYS}.4.0", contact),
        s(f"{SYS}.5.0", name),
        s(f"{SYS}.6.0", location),
    ]


def entity(
    index: int,
    descr: str,
    entity_class: int,
    contained_in: int = 0,
    rel_pos: int = -1,
    name: str = "",
    model: str = "",
    serial: str = "",
    mfg: str = "",
    hw: str = "",
    fw: str = "",
    sw: str = "",
) -> list[Varbind]:
    rows = [
        s(f"{ENT}.2.{index}", descr),
        i(f"{ENT}.4.{index}", contained_in),
        i(f"{ENT}.5.{index}", entity_class),
        i(f"{ENT}.6.{index}", rel_pos),
        s(f"{ENT}.7.{index}", name),
    ]
    for column, value in ((8, hw), (9, fw), (10, sw), (11, serial), (12, mfg), (13, model)):
        rows.append(s(f"{ENT}.{column}.{index}", value))
    return rows


def interface(
    index: int,
    name: str,
    if_type: int,
    speed_mbps: int,
    mac: str = "",
    alias: str = "",
    mtu: int = 1500,
    admin: int = 1,
    oper: int = 1,
    descr: str = "",
) -> list[Varbind]:
    rows = [
        i(f"{IFT}.1.{index}", index),
        s(f"{IFT}.2.{index}", descr or name),
        i(f"{IFT}.3.{index}", if_type),
        i(f"{IFT}.4.{index}", mtu),
        # ifSpeed saturates at 4294967295; real agents report that for >4Gbps.
        g(f"{IFT}.5.{index}", min(speed_mbps * 1_000_000, 4294967295)),
        hexs(f"{IFT}.6.{index}", mac) if mac else s(f"{IFT}.6.{index}", ""),
        i(f"{IFT}.7.{index}", admin),
        i(f"{IFT}.8.{index}", oper),
        s(f"{IFX}.1.{index}", name),
        g(f"{IFX}.15.{index}", speed_mbps),
        s(f"{IFX}.18.{index}", alias),
    ]
    return rows


def ip_address(address: str, prefix_len: int, if_index: int) -> list[Varbind]:
    """An ipAddressTable row, including the RowPointer that carries the mask.

    The prefix length is not a column of its own: it is the last sub-identifier
    of the pointer in ipAddressPrefix. Encoding it properly here is what makes
    the fixture exercise the scanner's decoding of it.
    """
    addr = ipaddress.ip_address(address)
    octets = ".".join(str(b) for b in addr.packed)
    index = f"1.{len(addr.packed)}.{octets}"
    network = ipaddress.ip_network(f"{address}/{prefix_len}", strict=False)
    net_octets = ".".join(str(b) for b in network.network_address.packed)
    pointer = f"{IPPFX}.{if_index}.1.{len(addr.packed)}.{net_octets}.{prefix_len}"
    return [
        i(f"{IPADDR}.3.{index}", if_index),
        i(f"{IPADDR}.4.{index}", 1),  # unicast
        objid(f"{IPADDR}.5.{index}", pointer),
        i(f"{IPADDR}.6.{index}", 2),  # manual
        i(f"{IPADDR}.7.{index}", 1),  # preferred
    ]


def stack_member(entity_index: int, number: int, role: int, state: int, mac: str) -> list[Varbind]:
    return [
        i(f"{CSW}.1.{entity_index}", number),
        i(f"{CSW}.2.{entity_index}", number),
        i(f"{CSW}.3.{entity_index}", role),
        i(f"{CSW}.4.{entity_index}", 1),
        i(f"{CSW}.5.{entity_index}", 1),
        i(f"{CSW}.6.{entity_index}", state),
        hexs(f"{CSW}.7.{entity_index}", mac),
        s(f"{CSW}.8.{entity_index}", "cat9k_iosxe.17.03.04a.SPA.bin"),
    ]


def lldp_loc_port(port_num: int, name: str, subtype: int = 5) -> list[Varbind]:
    """One lldpLocPortTable row: what lldpRemLocalPortNum actually indexes.

    subtype 5 is interfaceName. The row exists so the scanner can resolve the
    local port through the table the MIB prescribes instead of assuming the
    port number is an ifIndex.
    """
    return [
        i(f"{LLDP_LOC}.2.{port_num}", subtype),
        s(f"{LLDP_LOC}.3.{port_num}", name),
        s(f"{LLDP_LOC}.4.{port_num}", name),
    ]


def lldp_neighbor(
    port_num: int,
    rem_index: int,
    chassis: str,
    port_id: str,
    sys_name: str,
    caps_hex: str,
    chassis_subtype: int = 4,
    port_subtype: int = 5,
    sys_desc: str = "",
    port_desc: str = "",
) -> list[Varbind]:
    """One lldpRemTable row. Index is <timeMark>.<localPortNum>.<remIndex>.

    `chassis` and `port_id` are rendered per their subtype: colon-hex strings
    become Hex-STRING octets (a MAC under chassis subtype 4, an
    address-family-prefixed address under subtype 5), anything else a plain
    STRING. Capability BITS go over as octets too — 0x28 (bridge+router) is a
    printable "(", which is exactly the case the collector must survive.
    """
    idx = f"0.{port_num}.{rem_index}"

    def rendered(oid: str, value: str) -> Varbind:
        if ":" in value and all(len(p) == 2 for p in value.split(":")):
            return hexs(oid, value)
        return s(oid, value)

    rows = [
        i(f"{LLDP_REM}.4.{idx}", chassis_subtype),
        rendered(f"{LLDP_REM}.5.{idx}", chassis),
        i(f"{LLDP_REM}.6.{idx}", port_subtype),
        rendered(f"{LLDP_REM}.7.{idx}", port_id),
        s(f"{LLDP_REM}.8.{idx}", port_desc),
        s(f"{LLDP_REM}.9.{idx}", sys_name),
        s(f"{LLDP_REM}.10.{idx}", sys_desc),
        hexs(f"{LLDP_REM}.11.{idx}", caps_hex),
        hexs(f"{LLDP_REM}.12.{idx}", caps_hex),
    ]
    return rows


def cdp_neighbor(
    if_index: int,
    device_index: int,
    device_id: str,
    port: str,
    platform: str,
    caps_hex: str,
    address: str = "",
    version: str = "",
) -> list[Varbind]:
    """One cdpCacheTable row. Index is <local ifIndex>.<deviceIndex>."""
    idx = f"{if_index}.{device_index}"
    rows = []
    if address:
        packed = ipaddress.ip_address(address).packed
        rows += [
            i(f"{CDP}.3.{idx}", 1),  # CiscoNetworkProtocol ip(1)
            hexs(f"{CDP}.4.{idx}", ":".join(f"{b:02X}" for b in packed)),
        ]
    rows += [
        s(f"{CDP}.5.{idx}", version or f"Cisco IOS Software running on {device_id}"),
        s(f"{CDP}.6.{idx}", device_id),
        s(f"{CDP}.7.{idx}", port),
        s(f"{CDP}.8.{idx}", platform),
        hexs(f"{CDP}.9.{idx}", caps_hex),
    ]
    return rows


def bitmap(positions, length: int, first: int = 0) -> str:
    """Set bits as printed hex, most significant bit first, counted from `first`.

    Cisco's VLAN bitmaps open at VLAN 0; a Q-BRIDGE PortList at bridge port 1.
    """
    data = bytearray(length)
    for position in positions:
        offset = position - first
        data[offset // 8] |= 0x80 >> (offset % 8)
    return " ".join(f"{octet:02X}" for octet in data)


CISCO_VTP_VLAN = "1.3.6.1.4.1.9.9.46.1.3.1.1"
CISCO_TRUNK_PORT = "1.3.6.1.4.1.9.9.46.1.6.1.1"
CISCO_VM_VLAN = "1.3.6.1.4.1.9.9.68.1.2.2.1.2"


def cisco_vlan(vid: int, name: str, vlan_type: int = 1) -> list[Varbind]:
    """One vtpVlanTable row, in management domain 1."""
    return [
        i(f"{CISCO_VTP_VLAN}.2.1.{vid}", 1),  # vtpVlanState operational
        i(f"{CISCO_VTP_VLAN}.3.1.{vid}", vlan_type),  # vtpVlanType
        s(f"{CISCO_VTP_VLAN}.4.1.{vid}", name),  # vtpVlanName
    ]


def cisco_access_port(if_index: int, vid: int) -> list[Varbind]:
    # Every switchport has a trunk row too, and an access port's says so.
    return [
        i(f"{CISCO_VM_VLAN}.{if_index}", vid),
        i(f"{CISCO_TRUNK_PORT}.14.{if_index}", 2),  # notTrunking
    ]


def cisco_trunk_port(if_index: int, allowed, native: int = 1) -> list[Varbind]:
    """A trunking vlanTrunkPortTable row; `allowed` is the VLAN ids, or "all"."""
    vids = range(0, 4096) if allowed == "all" else allowed
    rows = [
        i(f"{CISCO_TRUNK_PORT}.5.{if_index}", native),
        i(f"{CISCO_TRUNK_PORT}.14.{if_index}", 1),  # trunking
    ]
    for position, column in enumerate((4, 17, 18, 19)):
        low = position * 1024
        rows.append(
            Varbind(
                f"{CISCO_TRUNK_PORT}.{column}.{if_index}",
                "Hex-STRING",
                bitmap([v for v in vids if low <= v < low + 1024], 128, first=low),
            )
        )
    return rows


DOT1D_BASE_PORT_IF_INDEX = "1.3.6.1.2.1.17.1.4.1.2"
DOT1Q_VLAN = "1.3.6.1.2.1.17.7.1.4"


def qbridge_port(port: int, if_index: int, pvid: int = 1) -> list[Varbind]:
    return [
        i(f"{DOT1D_BASE_PORT_IF_INDEX}.{port}", if_index),
        g(f"{DOT1Q_VLAN}.5.1.1.{port}", pvid),  # dot1qPvid
    ]


def qbridge_vlan(vid: int, name: str, egress, untagged, octets: int = 4) -> list[Varbind]:
    """A VLAN in both the static table and the current one (time mark 0)."""
    return [
        s(f"{DOT1Q_VLAN}.3.1.1.{vid}", name),
        Varbind(f"{DOT1Q_VLAN}.2.1.4.0.{vid}", "Hex-STRING", bitmap(egress, octets, first=1)),
        Varbind(f"{DOT1Q_VLAN}.2.1.5.0.{vid}", "Hex-STRING", bitmap(untagged, octets, first=1)),
    ]


def aruba_ap(
    mac: str,
    name: str,
    model: str,
    serial: str,
    address: str,
    group: str = "default",
    status: int = 1,
    sw_version: str = "",
) -> list[Varbind]:
    index = ".".join(str(int(part, 16)) for part in mac.split(":"))
    out = [
        Varbind(f"{ARUBA_AP}.2.{index}", "IpAddress", address),
        s(f"{ARUBA_AP}.3.{index}", name),
        s(f"{ARUBA_AP}.4.{index}", group),
        s(f"{ARUBA_AP}.6.{index}", serial),
        s(f"{ARUBA_AP}.13.{index}", model),
        i(f"{ARUBA_AP}.19.{index}", status),
    ]
    # wlanAPSwVersion — emitted only when set, because that is how the sparse
    # case looks on the wire: the row is simply absent from the walk, not an
    # empty string.
    if sw_version:
        out.append(s(f"{ARUBA_AP}.34.{index}", sw_version))
    return out


# --- device definitions ------------------------------------------------------


def cisco_c9300_stack() -> list[Varbind]:
    """A three-member Catalyst 9300 stack — the case that matters most.

    Each member is its own chassis entity with its own serial and model, the
    stackwise table gives the switch numbers and which one is master, and the
    interface names carry the member number in their first path component.
    """
    out = system_group(
        "Cisco IOS Software [Amsterdam], Catalyst L3 Switch Software "
        "(CAT9K_IOSXE), Version 17.03.04a, RELEASE SOFTWARE (fc3)\n"
        "Technical Support: http://www.cisco.com/techsupport\n"
        "Copyright (c) 1986-2021 by Cisco Systems, Inc.\n"
        "Compiled Tue 04-May-21 05:22 by mcpre",
        "1.3.6.1.4.1.9.1.2494",
        "bld-a-core-01",
        location="Building A / IDF 1",
    )

    # Stack container, then one chassis per member. Real 9300s number the
    # chassis entities 1000, 2000, 3000 with the stack itself at 1.
    out += entity(1, "c93xx Stack", 11, 0, -1, "c93xx Stack", "", "", "Cisco")
    members = [
        (1000, 1, "C9300-48P", "FOC2530L0AB", "AC:F2:C5:11:22:01", 1),  # master
        (2000, 2, "C9300-48P", "FOC2530L0CD", "AC:F2:C5:11:22:02", 2),
        (3000, 3, "C9300-24P", "FOC2531L0EF", "AC:F2:C5:11:22:03", 2),
    ]
    for entity_index, number, model, serial, mac, role in members:
        out += entity(
            entity_index,
            f"Cisco Catalyst 9300 Switch Stack Member {number}",
            CLASS_CHASSIS,
            contained_in=1,
            rel_pos=number,
            name=f"Switch {number}",
            model=model,
            serial=serial,
            mfg="Cisco",
            hw="V03",
            sw="17.03.04a",
        )
        # Each member has an uplink module bay with a network module in it.
        out += entity(
            entity_index + 1,
            f"Uplink Module Container Switch {number}",
            CLASS_CONTAINER,
            contained_in=entity_index,
            rel_pos=1,
            name=f"Switch {number} FRU Uplink Module Container",
            mfg="Cisco",
        )
        out += entity(
            entity_index + 2,
            "Cisco Catalyst 9300 8x10G Uplink Module",
            CLASS_MODULE,
            contained_in=entity_index + 1,
            rel_pos=1,
            name=f"Switch {number} Uplink Module",
            model="C9300-NM-8X",
            serial=f"FOC2530U{number:02d}X",
            mfg="Cisco",
            hw="V02",
        )
        out += entity(
            entity_index + 3,
            f"Switch {number} Power Supply A",
            CLASS_POWER,
            contained_in=entity_index,
            rel_pos=1,
            name=f"Switch {number} Power Supply A",
            model="PWR-C1-715WAC",
            serial=f"DTM2530P{number:02d}A",
            mfg="Cisco",
        )
        out += stack_member(entity_index, number, role, 4, mac)

    # Interfaces: a few access ports per member plus the shared logical ones.
    if_index = 1
    for number, _model in ((1, "48P"), (2, "48P"), (3, "24P")):
        for port in range(1, 4):
            out += interface(
                if_index,
                f"GigabitEthernet{number}/0/{port}",
                6,
                1000,
                mac=f"AC:F2:C5:{number:02X}:0{port}:01",
                alias=f"access port {number}/0/{port}",
            )
            if_index += 1
        for port in range(1, 3):
            out += interface(
                if_index,
                f"TenGigabitEthernet{number}/1/{port}",
                6,
                10000,
                mac=f"AC:F2:C5:{number:02X}:1{port}:01",
                alias=f"uplink {number}/1/{port}",
            )
            if_index += 1

    out += interface(if_index, "Port-channel1", 161, 20000, alias="uplink to distribution")
    if_index += 1
    out += interface(if_index, "Vlan10", 53, 0, mac="AC:F2:C5:11:22:01", alias="management", mtu=1500)
    management_index = if_index
    if_index += 1
    out += interface(
        if_index,
        "GigabitEthernet0/0",
        6,
        1000,
        mac="AC:F2:C5:11:22:0F",
        alias="oob management",
        descr="GigabitEthernet0/0",
    )

    out += ip_address("10.10.1.5", 24, management_index)

    # --- CDP/LLDP neighbors. The links here are the other half of the ones
    # the arista-7050sx and cisco-2960x fixtures report, so a sync of both
    # sides must converge on one cable per link.
    #
    # lldpLocPortNum == ifIndex on this fixture (what IOS-XE does), but the
    # table is still present and the scanner still resolves through it.
    for port_num, name in (
        (1, "GigabitEthernet1/0/1"),
        (2, "GigabitEthernet1/0/2"),
        (3, "GigabitEthernet1/0/3"),
        (4, "TenGigabitEthernet1/1/1"),
        (6, "GigabitEthernet2/0/1"),
        (11, "GigabitEthernet3/0/1"),
    ):
        out += lldp_loc_port(port_num, name)

    # The Arista spine, LLDP only — EOS speaks no CDP, so no cdpCache row for
    # it anywhere. Its sysName carries a domain suffix while the NetBox device
    # is the short name, which is the matching problem, not an accident.
    out += lldp_neighbor(
        4,
        1,
        "00:1C:73:AA:BB:01",
        "Ethernet1",
        "dc1-spine-01.example.net",
        "28",
        sys_desc="Arista Networks EOS version 4.29.2F",
    )
    # The 2960X access switch, on STACK MEMBER 2's port — the cable must land
    # on the member device, not the master. A Cisco-to-Cisco link shows up in
    # both protocols: LLDP names the remote port in short form, CDP in long
    # form, and the two sightings are one adjacency.
    out += lldp_neighbor(6, 1, "00:1E:14:11:22:01", "Gi1/0/1", "bld-b-acc-01", "28")
    out += cdp_neighbor(
        6,
        1,
        "bld-b-acc-01.example.net",
        "GigabitEthernet1/0/1",
        "cisco WS-C2960X-48FPD-L",
        "00:00:00:28",
        address="10.10.2.5",
    )
    # An IP phone. CDP names the platform outright; the LLDP-MED sighting
    # carries the telephone capability bit, a network-address chassis id and a
    # MAC port id. The default neighbor filter must exclude it.
    out += cdp_neighbor(
        2,
        1,
        "SEP0011223344AA",
        "Port 1",
        "Cisco IP Phone 7962",
        "00:00:04:90",
        address="10.10.20.31",
        version="SCCP42.9-4-2SR3-1S",
    )
    out += lldp_neighbor(
        2,
        2,
        "01:0A:0A:14:1F",
        "00:11:22:33:44:AA",
        "SEP0011223344AA",
        "24",
        chassis_subtype=5,
        port_subtype=3,
        port_desc="SW PORT",
    )
    # A wireless AP, LLDP only, wlanAccessPoint capability set — also
    # filtered by default (APs are inventoried from their controller).
    out += lldp_neighbor(
        11,
        1,
        "20:4C:03:BB:01:01",
        "20:4C:03:BB:01:01",
        "bld-a-ap-01",
        "30",
        port_subtype=3,
        sys_desc="ArubaOS (MODEL: 515), Version 8.10.0.4",
    )
    # A switch NetBox has never heard of: stays a reported one-sided
    # sighting, never a fabricated device.
    out += lldp_neighbor(3, 1, "AA:BB:CC:00:99:01", "ge-0/0/7", "unknown-sw-99", "28")
    return out


def arista_7050sx() -> list[Varbind]:
    """Arista reports DCS-7050SX-72Q plainly; orb-agent renders it aristaDCS7050SX272Q."""
    out = system_group(
        "Arista Networks EOS version 4.29.2F running on an Arista Networks DCS-7050SX-72Q",
        "1.3.6.1.4.1.30065.1.3011.7050",
        "dc1-spine-01",
        location="DC1 / Row 3",
    )
    out += entity(
        1,
        "Arista Networks DCS-7050SX-72Q",
        CLASS_CHASSIS,
        0,
        -1,
        name="DCS-7050SX-72Q",
        model="DCS-7050SX-72Q",
        serial="JPE17240001",
        mfg="Arista Networks",
        hw="02.03",
        sw="4.29.2F",
    )
    out += entity(
        2,
        "Arista Networks Power Supply",
        CLASS_POWER,
        1,
        1,
        name="PowerSupply1",
        model="PWR-460AC-F",
        serial="K192KL00012",
        mfg="Arista Networks",
    )
    for index in range(1, 5):
        out += interface(
            index,
            f"Ethernet{index}",
            6,
            10000,
            mac=f"00:1C:73:AA:BB:{index:02X}",
            alias=f"spine uplink {index}",
        )
    out += interface(5, "Management1", 6, 1000, mac="00:1C:73:AA:BB:FF", alias="oob")
    out += interface(6, "Port-Channel10", 161, 40000, alias="mlag peer link")
    out += ip_address("10.30.0.11", 24, 5)
    out += interface(7, "Vlan100", 136, 0, mac="00:1C:73:AA:BB:FE", alias="servers gateway")
    out += ip_address("10.30.100.2", 24, 7)

    # Q-BRIDGE numbers ports by bridge port, and here that is DELIBERATELY not
    # the ifIndex (Ethernet1 is bridge port 11), for the reason the LLDP
    # numbering below is not either. Ethernet1 is an access port, Ethernet2 a
    # trunk with a native VLAN, the port channel a trunk with none, and
    # Ethernet3-4 are routed: bridge ports in no VLAN, whose PVID of 1 must
    # not be read as membership.
    for port, if_index in ((11, 1), (12, 2), (13, 3), (14, 4), (20, 6)):
        out += qbridge_port(port, if_index, pvid=100 if if_index == 1 else 1)
    out += qbridge_vlan(1, "default", egress=[12], untagged=[12])
    out += qbridge_vlan(100, "SERVERS", egress=[11, 12, 20], untagged=[11])
    out += qbridge_vlan(200, "STORAGE", egress=[12, 20], untagged=[])

    # LLDP only — the other side of the stack's Te1/1/1 sighting. The local
    # port numbering here is DELIBERATELY not the ifIndex (Ethernet1 is LLDP
    # port 101): the MIB never promises the two are equal, some platforms
    # genuinely diverge, and this fixture is what keeps the
    # lldpLocPortTable-resolution path exercised. Real EOS happens to use the
    # ifIndex; a capture from real hardware can replace this whole file.
    out += lldp_loc_port(101, "Ethernet1")
    out += lldp_loc_port(102, "Ethernet2")
    # The remote port arrives in Cisco short form ("Te1/1/1") while the stack
    # fixture's ifName is the long form — the canonicalisation problem, from
    # the expanding side.
    out += lldp_neighbor(
        101,
        1,
        "AC:F2:C5:11:22:01",
        "Te1/1/1",
        "bld-a-core-01",
        "28",
        sys_desc="Cisco IOS Software [Amsterdam], Catalyst L3 Switch Software (CAT9K_IOSXE)",
    )
    return out


def aruba_7010_wlc() -> list[Varbind]:
    """An ArubaOS controller, including the AP table it terminates."""
    out = system_group(
        "ArubaOS (MODEL: Aruba7010), Version 8.10.0.4",
        "1.3.6.1.4.1.14823.1.1.1",
        "dal-wlc-01",
        location="Dallas / MDF",
    )
    out += entity(
        1,
        "Aruba7010",
        CLASS_CHASSIS,
        0,
        -1,
        name="Aruba7010",
        model="Aruba7010",
        serial="CX0011234",
        mfg="Aruba Networks",
        sw="8.10.0.4",
    )
    # ArubaOS controller scalars (WLSX-SYSTEMEXT-MIB).
    out += [
        s("1.3.6.1.4.1.14823.2.2.1.2.1.2.0", "dal-wlc-01"),
        s("1.3.6.1.4.1.14823.2.2.1.2.1.3.0", "Aruba7010"),
        i("1.3.6.1.4.1.14823.2.2.1.2.1.4.0", 1),
        s("1.3.6.1.4.1.14823.2.2.1.2.1.11.0", "CX0011234"),
    ]
    for index in range(1, 3):
        out += interface(
            index, f"GE0/0/{index}", 6, 1000, mac=f"20:4C:03:11:22:{index:02X}", alias=f"ap uplink {index}"
        )
    out += ip_address("10.20.0.9", 24, 1)

    # Two APs report their own image via wlanAPSwVersion (the AP build carries
    # a suffix the controller's version lacks); dal-ap-102 has no version row
    # at all, which is how some builds leave the column — it must inherit the
    # controller's 8.10.0.4 rather than land blank.
    aps = [
        ("20:4C:03:AA:01:01", "dal-ap-101", "AP-515", "CNJPJ0A001", "10.20.10.11", "8.10.0.4_87457"),
        ("20:4C:03:AA:01:02", "dal-ap-102", "AP-515", "CNJPJ0A002", "10.20.10.12", ""),
        ("20:4C:03:AA:01:03", "dal-ap-103", "AP-535", "CNJPJ0B003", "10.20.10.13", "8.10.0.4_87457"),
    ]
    for mac, name, model, serial, address, sw_version in aps:
        out += aruba_ap(mac, name, model, serial, address, group="dallas-floor-1", sw_version=sw_version)
    return out


def aruba_clearpass() -> list[Varbind]:
    """A ClearPass appliance, as the fleet's actually answer.

    The sysDescr shape is verbatim from a production box ("ClearPass Policy
    Manager 6.10.6.186545, Model: C1000, FIPS Mode: Disabled" — values here
    are synthetic, the shape is not); there is NO ENTITY-MIB and NO WLSX
    object. What it does serve is its own CPPM-MIB cppmSystemTable: one row,
    model/serial/version in columns 1-3, index 18 (see vendors.py).
    """
    out = system_group(
        "ClearPass Policy Manager 6.11.5.253053, Model: C2000, FIPS Mode: Disabled",
        "1.3.6.1.4.1.14823.1.6.1",
        "dal-cppm-01",
        location="Dallas / MDF",
    )
    cppm = "1.3.6.1.4.1.14823.1.6.1.1.1.1.1"
    out += [
        s(f"{cppm}.1.1", "C2000"),  # cppmSystemModel
        s(f"{cppm}.2.1", "CNC2K2310042"),  # cppmSystemSerialNumber
        s(f"{cppm}.3.1", "6.11.5.253053"),  # cppmSystemVersion
        s(f"{cppm}.4.1", "dal-cppm-01"),  # cppmSystemHostname
        i(f"{cppm}.18.1", 1),  # cppmSystemIdx
    ]
    out += interface(1, "eth0", 6, 1000, mac="00:50:56:AA:10:01", alias="management")
    out += ip_address("10.20.0.10", 24, 1)
    return out


def f5_bigip() -> list[Varbind]:
    """ENTITY-MIB is left empty on purpose — BIG-IPs do not populate it usefully."""
    out = system_group(
        "Linux dal-ltm-01.example.net 3.10.0-1160.el7.x86_64 #1 SMP x86_64",
        "1.3.6.1.4.1.3375.2.1.3.4.43",
        "dal-ltm-01",
        location="Dallas / Row 2",
    )
    out += [
        s("1.3.6.1.4.1.3375.2.1.4.1.0", "BIG-IP"),
        s("1.3.6.1.4.1.3375.2.1.4.2.0", "17.1.1.3"),
        # sysProductBuild — the walk previously carried this line as a HAND
        # EDIT that this generator did not know about, so regenerating the
        # fixtures silently deleted it and broke the two F5 build tests. The
        # generator is the source of truth; real captures replace whole files.
        s("1.3.6.1.4.1.3375.2.1.4.3.0", "0.0.5"),
        s("1.3.6.1.4.1.3375.2.1.3.3.3.0", "f5-chs-01234567"),
        s("1.3.6.1.4.1.3375.2.1.3.5.2.0", "BIG-IP i5800"),
    ]
    out += interface(1, "mgmt", 6, 1000, mac="00:94:A1:11:22:01", alias="management")
    out += interface(2, "1.1", 6, 10000, mac="00:94:A1:11:22:02", alias="to core")
    out += interface(3, "1.2", 6, 10000, mac="00:94:A1:11:22:03", alias="to core")
    out += ip_address("10.40.0.20", 24, 1)
    return out


def palo_pa3220() -> list[Varbind]:
    out = system_group(
        "Palo Alto Networks PA-3220 series firewall",
        "1.3.6.1.4.1.25461.2.3.35",
        "dal-fw-01",
        location="Dallas / DMZ",
    )
    out += [
        s("1.3.6.1.4.1.25461.2.1.2.1.1.0", "11.1.4-h7"),
        s("1.3.6.1.4.1.25461.2.1.2.1.2.0", "PA-3220"),
        s("1.3.6.1.4.1.25461.2.1.2.1.3.0", "013101011234"),
    ]
    out += interface(1, "ethernet1/1", 6, 1000, mac="00:1B:17:11:22:01", alias="untrust")
    out += interface(2, "ethernet1/2", 6, 1000, mac="00:1B:17:11:22:02", alias="trust")
    out += interface(3, "management", 6, 1000, mac="00:1B:17:11:22:0F", alias="mgmt")
    out += ip_address("10.10.1.20", 24, 3)
    return out


def fortigate_600e() -> list[Varbind]:
    out = system_group(
        "FortiGate-600E v7.2.8,build1639,240110 (GA)",
        "1.3.6.1.4.1.12356.101.1.6001",
        "dal-fgt-01",
        location="Dallas / Edge",
    )
    out += [
        s("1.3.6.1.4.1.12356.101.4.1.1.0", "v7.2.8,build1639,240110 (GA)"),
        s("1.3.6.1.4.1.12356.100.1.1.1.0", "FG600ETK21901234"),
    ]
    out += interface(1, "port1", 6, 1000, mac="00:09:0F:11:22:01", alias="wan1")
    out += interface(2, "port2", 6, 1000, mac="00:09:0F:11:22:02", alias="lan")
    out += interface(3, "mgmt", 6, 1000, mac="00:09:0F:11:22:0F", alias="management")
    out += ip_address("10.40.0.30", 24, 3)
    return out


def checkpoint_gaia() -> list[Varbind]:
    out = system_group(
        "Linux dal-cp-01 3.10.0-957.21.3cpx86_64 #1 SMP x86_64 GNU/Linux",
        "1.3.6.1.4.1.2620.1.6.123.1.62",
        "dal-cp-01",
        location="Dallas / Edge",
    )
    out += [
        s("1.3.6.1.4.1.2620.1.6.4.1.0", "R81.20"),
        # svnServicePack: the installed Jumbo Hotfix take, Gauge32 on the wire.
        g("1.3.6.1.4.1.2620.1.6.999.0", 89),
        s("1.3.6.1.4.1.2620.1.6.16.3.0", "1811B00234"),
        s("1.3.6.1.4.1.2620.1.6.16.7.0", "Check Point 6200"),
        s("1.3.6.1.4.1.2620.1.6.16.9.0", "Check Point"),
    ]
    out += interface(1, "eth0", 6, 1000, mac="00:1C:7F:11:22:01", alias="external")
    out += interface(2, "eth1", 6, 1000, mac="00:1C:7F:11:22:02", alias="internal")
    out += ip_address("10.40.0.40", 24, 1)
    return out


def infoblox_nios() -> list[Varbind]:
    out = system_group(
        "Infoblox NIOS Release 9.0.4-50212 running on IB-1420",
        "1.3.6.1.4.1.7779.1.1420",
        "dal-ddi-01",
        location="Dallas / MDF",
    )
    out += [
        s("1.3.6.1.4.1.7779.3.1.1.2.1.4.0", "IB-1420"),
        s("1.3.6.1.4.1.7779.3.1.1.2.1.6.0", "422900123456789"),
        s("1.3.6.1.4.1.7779.3.1.1.2.1.7.0", "9.0.4-50212"),
    ]
    out += interface(1, "LAN1", 6, 1000, mac="00:1B:C0:11:22:01", alias="service")
    out += interface(2, "MGMT", 6, 1000, mac="00:1B:C0:11:22:0F", alias="management")
    out += ip_address("10.40.0.50", 24, 2)
    return out


def juniper_ex4300() -> list[Varbind]:
    out = system_group(
        "Juniper Networks, Inc. ex4300-48t Ethernet Switch, kernel JUNOS 21.4R3-S4.9, "
        "Build date: 2023-05-11 04:32:15 UTC Copyright (c) 1996-2023 Juniper Networks, Inc.",
        "1.3.6.1.4.1.2636.1.1.1.2.82",
        "dal-acc-01",
        location="Dallas / IDF 2",
    )
    out += entity(
        1,
        "Juniper EX4300-48T Ethernet Switch",
        CLASS_CHASSIS,
        0,
        -1,
        name="Chassis",
        model="EX4300-48T",
        serial="PE3714AF0123",
        mfg="Juniper Networks",
        hw="REV 12",
        sw="21.4R3-S4.9",
    )
    out += [
        s("1.3.6.1.4.1.2636.3.1.2.0", "Juniper EX4300-48T Ethernet Switch"),
        s("1.3.6.1.4.1.2636.3.1.3.0", "PE3714AF0123"),
        s("1.3.6.1.4.1.2636.3.1.8.1.14.1.1.0.0", "EX4300-48T"),  # jnxContentsModel
    ]
    for index in range(1, 4):
        out += interface(
            index, f"ge-0/0/{index - 1}", 6, 1000, mac=f"54:E0:32:11:22:{index:02X}", alias=f"access {index}"
        )
    out += interface(4, "me0", 6, 1000, mac="54:E0:32:11:22:FF", alias="management")
    out += interface(5, "ae0", 161, 20000, alias="uplink lag")
    out += ip_address("10.50.0.10", 24, 4)
    return out


def opengear_console() -> list[Varbind]:
    out = system_group(
        "Opengear CM7148-2-DAC console server version 4.13.0",
        "1.3.6.1.4.1.25049.1.1",
        "dal-con-01",
        location="Dallas / Row 1",
    )
    out += interface(1, "eth0", 6, 1000, mac="00:13:C6:11:22:01", alias="management")
    out += interface(2, "eth1", 6, 1000, mac="00:13:C6:11:22:02", alias="failover")
    out += ip_address("10.60.0.10", 24, 1)
    return out


def cisco_single_2960() -> list[Varbind]:
    """A standalone switch, to prove a single chassis does NOT become a stack."""
    out = system_group(
        "Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E3, "
        "RELEASE SOFTWARE (fc2)",
        "1.3.6.1.4.1.9.1.1745",
        "bld-b-acc-01",
        location="Building B / IDF 2",
    )
    out += entity(
        1001,
        "WS-C2960X-48FPD-L",
        CLASS_CHASSIS,
        0,
        -1,
        name="1",
        model="WS-C2960X-48FPD-L",
        serial="FOC1934X0AB",
        mfg="Cisco",
        hw="V04",
        sw="15.2(7)E3",
    )
    # A single-member stackwise table: present on 2960X, and the scanner must
    # treat one member as a standalone device rather than a chassis of one.
    out += stack_member(1001, 1, 1, 4, "00:1E:14:11:22:01")
    for index in range(1, 4):
        out += interface(
            index,
            f"GigabitEthernet1/0/{index}",
            6,
            1000,
            mac=f"00:1E:14:11:22:{index:02X}",
            alias=f"access {index}",
        )
    out += interface(10, "Vlan1", 53, 0, mac="00:1E:14:11:22:FE", alias="management")
    out += ip_address("10.10.2.5", 24, 10)

    # The VLAN database with the token ring relics every Catalyst carries, an
    # uplink pruned to three VLANs with a non-default native, and two access
    # ports. VOICE is allowed on the uplink but 30 is not defined here at all,
    # which is the case the allowed list alone gets wrong.
    out += cisco_vlan(1, "default")
    out += cisco_vlan(10, "USERS")
    out += cisco_vlan(20, "VOICE")
    out += cisco_vlan(99, "MGMT")
    out += cisco_vlan(1002, "fddi-default", vlan_type=2)
    out += cisco_vlan(1003, "token-ring-default", vlan_type=3)
    out += cisco_trunk_port(1, [10, 20, 30, 99], native=99)
    out += cisco_access_port(2, 10)
    out += cisco_access_port(3, 20)

    # The uplink to the 9300 stack, seen from this side — the stack fixture
    # reports the same link from member 2's port. Both protocols again, and
    # again LLDP short-form vs CDP long-form for the same remote port.
    out += lldp_loc_port(1, "GigabitEthernet1/0/1")
    out += lldp_neighbor(1, 1, "AC:F2:C5:11:22:01", "Gi2/0/1", "bld-a-core-01", "28")
    out += cdp_neighbor(
        1, 1, "bld-a-core-01", "GigabitEthernet2/0/1", "cisco C9300-48P", "00:00:00:29", address="10.10.1.5"
    )
    return out


def juniper_srx1500_cluster() -> list[Varbind]:
    """An SRX1500 chassis cluster primary — the two reported failure shapes.

    Field reports from the fleet, encoded here so the fixes stay fixed:
    jnxBoxSerialNo answers EMPTY (the "no serials" report), and every
    descriptive string carries the cluster node prefix — "node0 Juniper
    SRX1500 Internet Router" (the "node number in the model" report). The
    real serial and the clean model live on the jnxContentsTable chassis row
    (index 1.1.0.0), which is where the profile's fallback OIDs look.
    """
    out = system_group(
        "Juniper Networks, Inc. srx1500 internet router, kernel JUNOS 21.4R3-S5.4, "
        "Build date: 2023-09-15 06:12:01 UTC Copyright (c) 1996-2023 Juniper Networks, Inc.",
        # Product arc under 2636.1.1.1.2; only the enterprise number (2636) is
        # read, the leaf is immaterial to the scanner by design.
        "1.3.6.1.4.1.2636.1.1.1.2.134",
        "dal-srx-01",
        location="Dallas / Edge",
    )
    # Chassis clusters prefix ENTITY strings with the node, and leave the
    # model and serial columns empty on the chassis row.
    out += entity(
        1,
        "node0 Juniper SRX1500 Internet Router",
        CLASS_CHASSIS,
        0,
        -1,
        name="node0 Chassis",
        model="",
        serial="",
        mfg="Juniper Networks",
        hw="REV 08",
        sw="21.4R3-S5.4",
    )
    out += [
        s("1.3.6.1.4.1.2636.3.1.2.0", "node0 Juniper SRX1500 Internet Router"),
        s("1.3.6.1.4.1.2636.3.1.3.0", ""),  # empty — the report
        s("1.3.6.1.4.1.2636.3.1.8.1.6.1.1.0.0", "node0 Juniper SRX1500 Internet Router"),
        s("1.3.6.1.4.1.2636.3.1.8.1.7.1.1.0.0", "DK2919AF0042"),  # jnxContentsSerialNo
        # jnxContentsModel is the FRU model name, not the product name — the
        # fleet reported a raw-looking identifier here; this value is synthetic
        # but that shape, so the tests prove it lands in part_number and never
        # in the model name.
        s("1.3.6.1.4.1.2636.3.1.8.1.14.1.1.0.0", "SRX1500-SYS-JB"),
    ]
    out += interface(1, "ge-0/0/0", 6, 1000, mac="4C:6D:58:11:22:01", alias="untrust")
    out += interface(2, "ge-0/0/1", 6, 1000, mac="4C:6D:58:11:22:02", alias="trust")
    out += interface(3, "fxp0", 6, 1000, mac="4C:6D:58:11:22:0F", alias="management")
    out += interface(4, "reth0", 161, 2000, alias="cluster reth")
    out += ip_address("10.60.0.40", 24, 3)
    return out


def bluecoat_sg_s400() -> list[Varbind]:
    """A ProxySG — the "nothing but a name" report.

    sysDescr and sysObjectID are verbatim from a real captured walk (librenms
    test corpus, tests/snmpsim/sgos.snmprec). ENTITY-MIB is absent on SGOS, so
    identity comes entirely from the BLUECOAT-SG-PROXY-MIB scalars and the
    sysDescr words; without the vendor profile the scanner could record
    nothing beyond the hostname, which is exactly what the fleet saw.
    """
    out = system_group(
        "Blue Coat SG-S400 Series, Version: SGOS 6.6.5.2, Release id: 193348 Proxy Edition",
        "1.3.6.1.4.1.3417.1.1.37",
        "dal-proxy-01",
        location="Dallas / DMZ",
    )
    out += [
        s("1.3.6.1.4.1.3417.2.11.1.2.0", "SGOS"),  # sgProxySoftware
        s("1.3.6.1.4.1.3417.2.11.1.3.0", "6.6.5.2"),  # sgProxyVersion
        s("1.3.6.1.4.1.3417.2.11.1.4.0", "0723160042"),  # sgProxySerialNumber
    ]
    out += interface(1, "0:0", 6, 1000, mac="00:D0:83:11:22:01", alias="inside")
    out += interface(2, "0:1", 6, 1000, mac="00:D0:83:11:22:02", alias="outside")
    out += ip_address("10.70.0.50", 24, 1)
    return out


DEVICES = {
    "cisco-c9300-stack": cisco_c9300_stack,
    "cisco-2960x": cisco_single_2960,
    "arista-7050sx": arista_7050sx,
    "aruba-7010-wlc": aruba_7010_wlc,
    "aruba-clearpass": aruba_clearpass,
    "f5-bigip": f5_bigip,
    "palo-pa3220": palo_pa3220,
    "fortigate-600e": fortigate_600e,
    "checkpoint-gaia": checkpoint_gaia,
    "infoblox-nios": infoblox_nios,
    "juniper-ex4300": juniper_ex4300,
    "opengear-cm7148": opengear_console,
    "juniper-srx1500-cluster": juniper_srx1500_cluster,
    "bluecoat-sg-s400": bluecoat_sg_s400,
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    default_output = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "fixtures")
    parser.add_argument("--output-dir", default=default_output)
    args = parser.parse_args()

    output_dir = os.path.abspath(args.output_dir)
    os.makedirs(output_dir, exist_ok=True)
    for name, builder in sorted(DEVICES.items()):
        varbinds = builder()
        path = os.path.join(output_dir, f"{name}.walk")
        header = (
            f"# {name} — synthetic recorded walk, generated by "
            f"tests/emulator/make_fixtures.py\n"
            "# Format is exactly `snmpwalk -On -Oe -Ot` output, so a capture from a real\n"
            "# device of this family can replace this file with no conversion.\n"
        )
        with open(path, "w") as handle:
            handle.write(header)
            handle.write(format_walk(varbinds))
        print(f"{name:22s} {len(varbinds):5d} varbinds -> {os.path.relpath(path)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
