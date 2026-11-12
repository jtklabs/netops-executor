"""Bounded LLDP/CDP inventory. LLDP local port numbers are not assumed to be ifIndex."""

LLDP_LOCAL = "1.0.8802.1.1.2.1.3.7.1"
LLDP_REMOTE = "1.0.8802.1.1.2.1.4.1.1"
CDP = "1.3.6.1.4.1.9.9.23.1.2.1.1"


async def collect_neighbors(walk_column, cisco=False):
    async def column(root):
        return {index: value.strip() async for index, value in walk_column(root, bulk=True, limit=2000)}

    names = await column(LLDP_REMOTE + ".9")
    local = await column(LLDP_LOCAL + ".3") if names else {}
    ports = await column(LLDP_REMOTE + ".7") if names else {}
    result = []
    for index, peer in names.items():
        parts = index.split(".")
        if peer and len(parts) == 3 and all(p.isdecimal() for p in parts):
            result.append(
                {
                    "kind": "lldp",
                    "peer_name": peer[:255],
                    "local_interface": local.get(parts[1], "")[:100],
                    "peer_interface": ports.get(index, "")[:100],
                }
            )
    if cisco:
        devices = await column(CDP + ".6")
        remote_ports = await column(CDP + ".7") if devices else {}
        # CDP index is ifIndex.cdpCacheDeviceIndex, unlike LLDP.
        ifnames = await column("1.3.6.1.2.1.31.1.1.1.1") if devices else {}
        for index, peer in devices.items():
            parts = index.split(".")
            if peer and len(parts) == 2:
                result.append(
                    {
                        "kind": "cdp",
                        "peer_name": peer[:255],
                        "local_interface": ifnames.get(parts[0], "")[:100],
                        "peer_interface": remote_ports.get(index, "")[:100],
                    }
                )
    return result
