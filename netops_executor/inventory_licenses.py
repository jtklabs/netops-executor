"""Normalize device-observed entitlements without retaining raw CLI output."""

import re
from datetime import datetime


def date_value(value):
    value = value.strip()
    for pattern in ("%Y-%m-%d", "%m/%d/%Y", "%B %d, %Y", "%b %d %Y", "%b %d, %Y"):
        try:
            return (
                datetime.strptime(value[:10] if pattern == "%Y-%m-%d" else value, pattern).date().isoformat()
            )
        except ValueError:
            pass
    return None


def entry(product, expiration="", reference="", modules=None):
    return {
        "product": product[:150],
        "reference": reference[:100],
        "reported_expiration": date_value(expiration),
        "installed_modules": modules or [product[:200]],
        "service_check_date": None,
    }


def parse_licenses(vendor, output):
    """Only documented product/date columns enter inventory; keys stay out of reports."""
    found = []
    if vendor == "Palo Alto Networks":
        for block in re.split(r"(?m)^License entry:", output)[1:]:
            fields = dict(re.findall(r"(?m)^\s*(Feature|Description|Expires|Serial):\s*(.*?)\s*$", block))
            if fields.get("Feature"):
                found.append(entry(fields["Feature"], fields.get("Expires", "")))
    elif vendor == "Arista":
        for block in re.split(r"(?m)^License feature:\s*", output)[1:]:
            product = block.splitlines()[0].strip()
            expiry = re.search(r"(?m)^Expiration:\s*(.+)$", block)
            found.append(entry(product, expiry[1] if expiry else ""))
    elif vendor == "Cisco":
        # Smart Licensing summary: name, entitlement tag, count, status.
        for name, tag, count, state in re.findall(
            r"(?m)^\s*(.+?)\s+\(([^)]+)\)\s+(\d+)\s+([A-Z][A-Z ]+)\s*$", output
        ):
            if int(count) > 0:
                found.append(
                    entry(name.strip(), modules=[f"{name.strip()}: {state.strip()} (count {count})"])
                )
        if not found:
            # Classic IOS indexed license detail.
            for block in re.split(r"(?m)^Index\s+\d+\s+Feature:\s*", output)[1:]:
                product = block.splitlines()[0].strip()
                state = re.search(r"(?m)^\s*License State:\s*(.+)$", block)
                found.append(entry(product, modules=[f"{product}: {state[1].strip()}" if state else product]))
        if not found:
            # NX-OS legacy usage, including unlicensed use (status preserved).
            for feature, installed, count, state in re.findall(
                r"(?m)^\s*(\S+)\s+(Yes|No)\s+(\d+|-)\s+(In use|Unused|Not in use)\b", output
            ):
                if installed == "Yes" or state == "In use":
                    found.append(
                        entry(feature, modules=[f"{feature}: installed={installed}, {state}, count={count}"])
                    )
    elif vendor == "Juniper":
        for feature, used, installed, needed, expiry in re.findall(
            r"(?m)^\s*(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(permanent|\d{4}-\d{2}-\d{2}(?: \d{2}:\d{2}:\d{2})?|invalid|expired)\s*$",
            output,
            re.I,
        ):
            if int(installed) or int(used):
                found.append(
                    entry(
                        feature,
                        expiry,
                        modules=[
                            f"{feature}: installed={installed}, used={used}, needed={needed}, expiry={expiry}"
                        ],
                    )
                )
    elif vendor == "Fortinet":
        # `diagnose autoupdate versions`: each service has its own contract date.
        for block in re.split(r"\n\s*\n", output):
            expiration = re.search(r"(?im)^\s*Contract Expiry Date:\s*(.+)$", block)
            if expiration:
                product = next((line.strip().rstrip(":") for line in block.splitlines() if line.strip()), "")
                if product:
                    found.append(entry(product, expiration[1]))
        status = re.search(r"(?im)^License Status:\s*(.+)$", output)
        if status and not found:
            expiry = re.search(r"(?im)^(?:License Expiration|Expiration Date|Expiry Date):\s*(.+)$", output)
            found.append(
                entry(
                    "FortiGate VM",
                    expiry[1] if expiry else "",
                    modules=["License status: " + status[1].strip()],
                )
            )
    elif vendor == "Infoblox":
        for block in re.split(r"(?m)^License Type\s*:\s*", output)[1:]:
            product = block.splitlines()[0].strip()
            expiry = re.search(r"(?m)^Expiration Date\s*:\s*(.+)$", block)
            found.append(entry(product, expiry[1] if expiry else ""))
    elif vendor == "HPE":
        # ArubaOS summary does not expose activation keys.
        for license_type, description, state, expiration, total in re.findall(
            r"(?m)^\s*(\S+)\s{2,}(.+?)\s{2,}(Enabled|Disabled|Active|Expired)\s+(Never|Permanent|\d{4}-\d{2}-\d{2}|\d{2}/\d{2}/\d{4})\s+(\d+)\s*$",
            output,
            re.I,
        ):
            found.append(entry(description, expiration, modules=[f"{license_type}: {state}, count={total}"]))
    return found
