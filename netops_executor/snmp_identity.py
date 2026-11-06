"""Read the small set of SNMP facts needed to create a NetBox device."""

import re
from dataclasses import dataclass

from pysnmp.proto.rfc1902 import OctetString

SYSTEM = "1.3.6.1.2.1.1"
SYS_DESCR, SYS_OBJECT_ID, SYS_NAME = (f"{SYSTEM}.{oid}.0" for oid in (1, 2, 5))
ENTITY = "1.3.6.1.2.1.47.1.1.1.1"
ENTITY_CLASS = f"{ENTITY}.5"
ENTERPRISE = "1.3.6.1.4.1."
VERSION = r"\bversion[:\s]+([0-9][\w.()/-]*)|\bv([0-9]+\.[0-9][\w.()/-]*)"


@dataclass(frozen=True)
class Vendor:
    manufacturer: str
    serial: tuple[str, ...] = ()
    model: tuple[str, ...] = ()
    version: tuple[str, ...] = ()
    build: str = ""
    model_pattern: str = ""
    version_pattern: str = ""


# Enterprise scalars mirror the verified OIDs in scripts/snmp-inventory/snmpinv/vendors.py.
VENDORS = {
    9: Vendor("Cisco"),
    11: Vendor("HPE"),
    14179: Vendor("Cisco"),
    30065: Vendor("Arista"),
    14823: Vendor(
        "HPE",
        serial=("14823.2.2.1.2.1.11.0",),
        model=("14823.2.2.1.2.1.3.0",),
        model_pattern=r"\bmodel:\s*([\w-]+)",
        version_pattern=r"ClearPass Policy Manager\s+([0-9][\w.-]*)",
    ),
    2636: Vendor(
        "Juniper",
        serial=("2636.3.1.3.0", "2636.3.1.8.1.7.1.1.0.0", "2636.3.1.8.1.7.1.0.0.0"),
        model=("2636.3.1.2.0",),
        version_pattern=r"\bJUNOS\s+([0-9][\w.-]*)",
    ),
    25461: Vendor(
        "Palo Alto Networks",
        serial=("25461.2.1.2.1.3.0",),
        version=("25461.2.1.2.1.1.0",),
        model_pattern=r"\b((?:PA|VM|M)-[\w-]+)",
        version_pattern=r"\bPAN-OS\s+([0-9][\w.-]*)",
    ),
    3375: Vendor(
        "F5",
        serial=("3375.2.1.3.3.3.0",),
        model=("3375.2.1.3.5.2.0",),
        version=("3375.2.1.4.2.0",),
        build="3375.2.1.4.3.0",
    ),
    12356: Vendor(
        "Fortinet",
        serial=("12356.100.1.1.1.0",),
        version=("12356.101.4.1.1.0", "12356.103.2.1.7.0"),
        model_pattern=r"\b(Forti\w+-[\w-]+)",
    ),
    7779: Vendor(
        "Infoblox",
        serial=("7779.3.1.1.2.1.6.0",),
        model=("7779.3.1.1.2.1.4.0",),
        version=("7779.3.1.1.2.1.7.0",),
        version_pattern=r"\bNIOS Release\s+([0-9][\w.-]*)",
    ),
    25049: Vendor(
        "Opengear",
        serial=("25049.17.1.2.0",),  # OG-STATUSv2-MIB::ogSerialNumber
        model_pattern=r"\bOpengear(?:\s+Inc\.?)?\s+([A-Z]{2}\d[\w-]*)",
        version_pattern=r"\b([0-9]+\.[0-9]+\.[0-9]+)\b",
    ),
}


def text(value):
    if value is None:
        return ""
    if isinstance(value, OctetString):
        value = value.asOctets().decode("utf-8", errors="replace")
    else:
        value = value.prettyPrint()
    value = value.strip(" \t\r\n\x00")
    return "" if value.casefold() in {"n/a", "na", "none", "unknown", "not available"} else value


def extract(pattern, description):
    match = re.search(pattern, description, re.IGNORECASE) if pattern else None
    return next((value.rstrip(",.") for value in match.groups() if value), "") if match else ""


async def collect_identity(get, chassis_index, first_value):
    system = await get([SYS_NAME, SYS_DESCR, SYS_OBJECT_ID])
    description = system.get(SYS_DESCR, "")
    enterprise = system.get(SYS_OBJECT_ID, "").removeprefix(ENTERPRISE).split(".", 1)[0]
    vendor = (
        VENDORS.get(int(enterprise), Vendor(""))
        if enterprise.isascii() and enterprise.isdecimal()
        else Vendor("")
    )
    chassis = {}
    if index := await chassis_index():
        oids = {
            field: f"{ENTITY}.{column}.{index}"
            for field, column in (
                ("serial", 11),
                ("manufacturer", 12),
                ("model", 13),
                ("software_version", 10),
            )
        }
        values = await get(list(oids.values()))
        chassis = {field: values.get(oid, "") for field, oid in oids.items()}
    vendor_oids = vendor.serial + vendor.model + vendor.version
    if vendor.build:
        vendor_oids += (vendor.build,)
    fallback = await get([ENTERPRISE + oid for oid in vendor_oids])

    def first(oids):
        return next((fallback[ENTERPRISE + oid] for oid in oids if fallback.get(ENTERPRISE + oid)), "")

    model = chassis.get("model") or first(vendor.model) or extract(vendor.model_pattern, description)
    if vendor.manufacturer == "Juniper":
        model = re.sub(r"^(?:node\d+[ :]+)?Juniper(?: Networks(?:,? Inc\.?)?)?\s+", "", model, flags=re.I)
        model = re.sub(
            r"\s+(?:internet (?:backbone )?router|services gateway|ethernet switch)$", "", model, flags=re.I
        )
    serial = chassis.get("serial") or first(vendor.serial)
    version = first(vendor.version) or extract(vendor.version_pattern, description)
    build = fallback.get(ENTERPRISE + vendor.build)
    if version and build and build != "0":
        version = f"{version}-{build}"
    if vendor.manufacturer == "Fortinet" and version:
        version = extract(VERSION, version) or version
    if enterprise == "14823" and "clearpass" in description.casefold():
        entry = ENTERPRISE + "14823.1.6.1.1.1.1.1"
        model = model or await first_value(f"{entry}.1")
        serial = serial or await first_value(f"{entry}.2")
        version = await first_value(f"{entry}.3") or version
    return {
        "name": system.get(SYS_NAME, "").rstrip("."),
        "manufacturer": vendor.manufacturer or chassis.get("manufacturer", ""),
        "model": model,
        "serial": serial,
        "software_version": version or extract(VERSION, description) or chassis.get("software_version", ""),
    }
