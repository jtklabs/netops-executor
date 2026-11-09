"""Read the access points an ArubaOS controller terminates.

APs tunnel to their controller and usually sit on networks the poller cannot
reach, so the controller's WLSX-WLAN-MIB wlsxWlanAPTable is the inventory. Its
INDEX is wlanAPMacAddress, so each AP's MAC is the row suffix; the OIDs mirror
the snmp-inventory scanner in jtklabs/Netbox (scripts/snmp-inventory/snmpinv/vendors.py).
"""

AP_ENTRY = "1.3.6.1.4.1.14823.2.2.1.5.2.1.4.1"
COLUMNS = {
    "address": 2,  # wlanAPIpAddress
    "name": 3,  # wlanAPName
    "group": 4,  # wlanAPGroupName
    "serial": 6,  # wlanAPSerialNumber
    "model": 13,  # wlanAPModelName
    "status": 19,  # wlanAPStatus: 1 up, 2 down
    "software_version": 34,  # wlanAPSwVersion; some builds leave it out
}
STATUS_UP = "1"
# Larger than any single controller or Mobility Conductor's AP limit.
MAX_ACCESS_POINTS = 16384


class AccessPointInventoryError(Exception):
    pass


def mac_from_index(index):
    octets = index.split(".")
    if len(octets) != 6 or not all(o.isascii() and o.isdecimal() and int(o) < 256 for o in octets):
        return None
    return ":".join(f"{int(o):02x}" for o in octets)


async def collect_access_points(walk_column):
    rows = {}
    for field, column in COLUMNS.items():
        async for index, value in walk_column(f"{AP_ENTRY}.{column}", bulk=True, limit=MAX_ACCESS_POINTS):
            mac = mac_from_index(index)
            if mac is None:
                raise AccessPointInventoryError("Aruba returned an invalid access point index")
            rows.setdefault(mac, {})[field] = value
    return [
        {
            "mac_address": mac,
            "name": row.get("name", ""),
            "model": row.get("model", ""),
            "serial": row.get("serial", ""),
            "address": row.get("address", ""),
            "group": row.get("group", ""),
            "up": row.get("status") == STATUS_UP,
            "software_version": row.get("software_version", ""),
        }
        for mac, row in sorted(rows.items())
    ]
