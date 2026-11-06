"""Resolve the SNMP target to its reported interface and subnet."""

from ipaddress import IPv4Network, ip_address, ip_network

IP_ADDRESS_ENTRY = "1.3.6.1.2.1.4.34.1"
IP_PREFIX_ENTRY = "1.3.6.1.2.1.4.32.1."
IPV4_ENTRY = "1.3.6.1.2.1.4.20.1"
IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
IF_DESCR = "1.3.6.1.2.1.2.2.1.2"


def reported_prefix(pointer, address, interface_index, address_type):
    if not pointer.lstrip(".").startswith(IP_PREFIX_ENTRY):
        return None
    try:
        _, index, kind, size, *prefix, length = map(
            int, pointer.lstrip(".").removeprefix(IP_PREFIX_ENTRY).split(".")
        )
        if (index, kind, size) != (interface_index, address_type, len(address.packed)) or len(prefix) != size:
            return None
        network = ip_network((ip_address(bytes(prefix)), length))
    except ValueError:
        return None
    return network.prefixlen if address in network else None


async def collect_polled_address(get, address):
    address_type = 1 if address.version == 4 else 2
    suffix = ".".join(map(str, (address_type, len(address.packed), *address.packed)))
    index_oid, type_oid, prefix_oid, origin_oid = (
        f"{IP_ADDRESS_ENTRY}.{col}.{suffix}" for col in (3, 4, 5, 6)
    )
    row = await get([index_oid, type_oid, prefix_oid, origin_oid])
    if row.get(type_oid) not in (None, "", "1"):
        return None
    reported_index = row.get(index_oid, "")
    index = int(reported_index) if reported_index.isdecimal() else 0
    prefix = reported_prefix(row.get(prefix_oid, ""), address, index, address_type)
    if address.version == 4 and (not index or prefix is None):
        legacy_index, mask_oid = (f"{IPV4_ENTRY}.{col}.{address}" for col in (2, 3))
        legacy = await get([legacy_index, mask_oid])
        value = legacy.get(legacy_index, "")
        legacy_index = int(value) if value.isdecimal() else 0
        if not legacy_index or index not in (0, legacy_index):
            return None
        try:
            network = IPv4Network((0, legacy.get(mask_oid, "")))
        except ValueError:
            return None
        if str(network.netmask) != legacy.get(mask_oid):
            return None
        index, prefix = legacy_index, network.prefixlen
    if not index or prefix is None:
        return None
    name_oid, descr_oid = f"{IF_NAME}.{index}", f"{IF_DESCR}.{index}"
    interface = await get([name_oid, descr_oid])
    name = interface.get(name_oid) or interface.get(descr_oid)
    if not name or any(ord(char) < 32 or ord(char) == 127 for char in name):
        return None
    return {"interface": name, "address": f"{address}/{prefix}", "dhcp": row.get(origin_oid) == "4"}
