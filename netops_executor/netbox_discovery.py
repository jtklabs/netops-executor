"""Write basic SNMP inventory through the configured NetBox REST API."""

import re
import ssl
import unicodedata
from hashlib import sha256
from ipaddress import ip_interface

import httpx

DISCOVERY_IP = "snmp_discovery_ip"
SOFTWARE_VERSION = "software_version"
SOFTWARE_REPORT = "plugins/refresh/device-software/report/"
DISCOVERED_TAG = "discovered"
LEGACY_DISCOVERY_ROLE = "snmp-discovered"
WIRELESS_CONTROLLER = "wireless_controller"
ACCESS_POINT_ROLE = "Wireless AP"

# Platforms that only ever run one kind of appliance.
ROLE_PLATFORMS = {
    "aruba clearpass": "Network Access Control",
    "infoblox nios": "DNS/DHCP",
    "sgos": "Proxy",
}
# Only infer a role for product families that identify a device function.
ROLE_MODELS = {
    "arista": ((r"DCS-", "Switch"),),
    # Quantum and numbered appliances are gateways; Smart-1 management servers are not.
    "check point": (
        (r"(?:Check Point\s+)?(?:Quantum\s+(?:Spark|Force|Lightspeed)?\s*)?\d{4,5}\b", "Firewall"),
    ),
    "cisco": (
        (r"(?:WS-C|C(?:atalyst[ -]+)?9[23456]\d{2}|N[235679]K-|Nexus\b)", "Switch"),
        (r"(?:ASR|ISR|CSR)\b|(?:ASR|ISR|CSR)\d|C(?:atalyst[ -]+)?8[235]\d{2}", "Router"),
        (r"(?:ASA|FPR)[ -]?\d", "Firewall"),
    ),
    "f5": ((r"BIG[- ]?IP\b", "Load Balancer"),),
    "fortinet": ((r"FortiGate\b|FG-", "Firewall"), (r"FortiSwitch\b|FS-", "Switch")),
    # Aruba Mobility controllers (70xx, 72xx, 90xx, 92xx) and Mobility Conductors.
    "hpe": (
        (r"(?:Aruba\s*|A)?(?:7[02]\d{2}|9[0-2]\d{2})(?:XM)?\b|MM-(?:HW|VA)", "Wireless Controller"),
        (r"(?:Aruba\s*)?AP-\d", ACCESS_POINT_ROLE),
    ),
    "juniper": (
        (r"(?:EX|QFX)[ -]?\d", "Switch"),
        (r"(?:MX|PTX|ACX)[ -]?\d", "Router"),
        (r"SRX[ -]?\d", "Firewall"),
    ),
    "opengear": ((r"(?:ACM|CM|IM|OM)\d", "Console Server"),),
    "palo alto networks": ((r"(?:PA|VM)-\d", "Firewall"),),
}


class SyncError(Exception):
    """A safe, actionable error for the job result."""


def slugify(value):
    value = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode().lower()
    return re.sub(r"[^a-z0-9]+", "-", value).strip("-")


def model_key(value):
    return slugify(value).replace("-", "")


def discovery_role(facts):
    if role := ROLE_PLATFORMS.get((facts.get("platform") or "").casefold()):
        return role
    for pattern, role in ROLE_MODELS.get(facts["manufacturer"].casefold(), ()):
        if re.match(pattern, facts["model"], re.IGNORECASE):
            return role
    return "Unclassified"


def sync_device(settings, site, poller, address, facts, checkpoint):
    token = settings.netbox_token
    scheme = "Bearer" if token.startswith("nbt_") else "Token"
    verify = (
        ssl.create_default_context(cafile=str(settings.netbox_ca_file)) if settings.netbox_ca_file else True
    )
    with httpx.Client(
        base_url=settings.netbox_url.rstrip("/") + "/api/",
        headers={"Authorization": f"{scheme} {token}", "Accept": "application/json"},
        timeout=10,
        verify=verify,
        trust_env=False,
    ) as http:
        return NetBoxDiscovery(http, checkpoint).sync(site, poller, address, facts)


class NetBoxDiscovery:
    def __init__(self, http, checkpoint):
        self.http = http
        self.checkpoint = checkpoint

    def request(self, method, path, **kwargs):
        self.checkpoint()
        response = self.http.request(method, path, **kwargs)
        response.raise_for_status()
        return response.json()

    def records(self, path, **filters):
        offset = 0
        while True:
            page = self.request("GET", path, params={**filters, "limit": 100, "offset": offset})
            yield from page["results"]
            if not page["next"] or not page["results"]:
                return
            offset += len(page["results"])

    def named(self, path, name):
        return next(
            (row for row in self.records(path, name__ie=name) if row["name"].casefold() == name.casefold()),
            None,
        )

    def ensure(self, path, lookup, data):
        if existing := lookup():
            return existing
        try:
            return self.request("POST", path, json=data)
        except httpx.HTTPStatusError as error:
            # Other executors can create the same site, tag, or type concurrently.
            if error.response.status_code in (400, 409) and (existing := lookup()):
                return existing
            raise

    def named_object(self, path, name, slug=None):
        slug = (slug or slugify(name))[:100].rstrip("-")
        if path == "dcim/sites/":
            # Distinct names may slugify identically, including names using non-Latin scripts.
            suffix = sha256(name.casefold().encode()).hexdigest()[:12]
            if not slug or any(
                site["name"].casefold() != name.casefold() for site in self.records(path, slug=slug)
            ):
                slug = f"{slug[:87].rstrip('-') or 'site'}-{suffix}"
        if not slug:
            raise SyncError("NetBox names need at least one letter or digit usable in a slug")
        return self.ensure(path, lambda: self.named(path, name), {"name": name, "slug": slug})

    def custom_field(self, name, label, description, kind="text"):
        path = "extras/custom-fields/"
        data = {
            "object_types": ["dcim.device"],
            "name": name,
            "label": label,
            "type": kind,
            "description": description,
        }
        if kind == "object":
            data["related_object_type"] = "dcim.device"
        field = self.ensure(
            path,
            lambda: next((row for row in self.records(path, name=name) if row["name"] == name), None),
            data,
        )
        if (
            field["type"]["value"] != kind
            or "dcim.device" not in field["object_types"]
            or (kind == "object" and field.get("related_object_type") != "dcim.device")
        ):
            noun = "device object" if kind == "object" else "device text"
            raise SyncError(f"NetBox custom field {name} must be a {noun} field")

    def device_type(self, manufacturer, model):
        path = "dcim/device-types/"
        slug = slugify(f"{manufacturer['slug']}-{model}")[:100].rstrip("-")
        key = model_key(model)
        if not key:
            raise SyncError("The reported model has no usable NetBox slug")
        # The HPE catalog spells models like Aruba7010 as Aruba 7010.
        query = re.sub(r"^aruba[- ]*", "", model, flags=re.I) if key.startswith("aruba") else model

        def match(search, exact_key):
            rows = list(self.records(path, manufacturer_id=manufacturer["id"], q=search))
            for field in ("model", "part_number"):
                matches = [row for row in rows if model_key(row.get(field) or "") == exact_key]
                if len(matches) == 1:
                    return matches[0]
                if len(matches) > 1:
                    raise SyncError("The reported model matches multiple NetBox device types")
            return None

        def lookup():
            if exact := match(query or model, key):
                return exact
            # Catalog punctuation can differ from the device's response, e.g. FortiGate-600E.
            fragments = re.findall(r"[a-z0-9]+", query or model, re.I)
            if len(fragments) > 1 and (exact := match(fragments[-1], key)):
                return exact
            # Infoblox NIOS can report IB-1420 for the Trinzic TE-1420.
            # Restrict aliases to numeric hardware models, leaving VM and other series alone.
            if manufacturer["slug"] == "infoblox" and (number := re.fullmatch(r"ib-([0-9]+)", model, re.I)):
                alias = "TE-" + number[1]
                return match(alias, model_key(alias))
            return None

        return self.ensure(
            path,
            lookup,
            {"manufacturer": manufacturer["id"], "model": model, "slug": slug},
        )

    def device(self, name, address, poller_tag, discovered_tag):
        """The device this poller discovered at this address.

        A polled IP is unique per poller, but pollers in other networks can reach other
        devices at the same IP, so NetBox can hold the address more than once. The poller
        tag and discovery IP identify the device, whatever its name.
        """
        path = "dcim/devices/"

        def tagged(device, tag):
            return any(existing["id"] == tag["id"] for existing in device["tags"])

        matches = [
            device
            for device in self.records(path, tag=poller_tag["slug"], **{f"cf_{DISCOVERY_IP}": address})
            if device["custom_fields"].get(DISCOVERY_IP) == address and tagged(device, poller_tag)
        ]
        if len(matches) > 1:
            raise SyncError("Multiple NetBox devices from this poller share the polled address")
        if matches:
            return matches[0]
        # A device recorded outside discovery, by name and address. A device another
        # poller discovered carries the discovered tag and is never taken over.
        for device in self.records(path, name__ie=name):
            if (device["name"] or "").casefold() != name.casefold() or tagged(device, discovered_tag):
                continue
            fields = device["custom_fields"]
            primary = device.get("primary_ip6" if ":" in address else "primary_ip4")
            if fields.get(DISCOVERY_IP) == address or (
                not fields.get(DISCOVERY_IP)
                and primary
                and str(ip_interface(primary["address"]).ip) == address
            ):
                matches.append(device)
        if len(matches) > 1:
            raise SyncError("Multiple NetBox devices already share this name and address")
        return matches[0] if matches else None

    def sync(self, site_name, poller, address, facts):
        action, device = self.sync_inventory(site_name, poller, address, facts)
        if (management_ip := facts.get("management_ip")) and self.assign_primary_ip(
            device, management_ip, self.named_object("extras/tags/", poller, poller)
        ):
            if action == "unchanged":
                action = "updated"
        if facts.get("stack_member_id"):
            try:
                facts["stack_inventory"] = self.sync_stack(device, poller, facts)
            except SyncError as error:
                facts["stack_inventory"] = {"status": "failed", "error": str(error)}
            except httpx.HTTPStatusError as error:
                facts["stack_inventory"] = {
                    "status": "failed",
                    "error": f"NetBox stack sync returned HTTP {error.response.status_code}",
                }
            except (httpx.RequestError, OSError, ValueError, TypeError, KeyError):
                facts["stack_inventory"] = {"status": "failed", "error": "Could not sync the NetBox stack"}
        if facts["software_version"] and (device.get("platform") or facts.get("platform")):
            facts["software_inventory"] = self.report_software(device["id"], facts)
        if facts.get("access_points") is not None:
            try:
                facts["access_point_inventory"] = self.sync_access_points(device, poller, facts)
            except SyncError as error:
                facts["access_point_inventory"] = {"status": "failed", "error": str(error)}
            except httpx.HTTPStatusError as error:
                facts["access_point_inventory"] = {
                    "status": "failed",
                    "error": f"NetBox access point sync returned HTTP {error.response.status_code}",
                }
            except (httpx.RequestError, OSError, ValueError, TypeError, KeyError):
                facts["access_point_inventory"] = {
                    "status": "failed",
                    "error": "Could not sync the controller's access points",
                }
        return action, device["id"]

    def sync_access_points(self, controller, poller, facts):
        """Create or update one device per AP the controller reports.

        A new AP starts at the controller's site, because nothing in the AP
        table says where it hangs; a later move by hand is kept. APs the
        controller stops reporting are left alone, like stack members.
        """
        self.custom_field(
            WIRELESS_CONTROLLER,
            "Wireless controller",
            "Controller that last reported this access point to NetOps Executor.",
            kind="object",
        )
        manufacturer = self.named_object("dcim/manufacturers/", facts["manufacturer"])
        platform = (controller.get("platform") or {}).get("id")
        if not platform and facts.get("platform"):
            platform = self.named_object("dcim/platforms/", facts["platform"])["id"]
        defaults = {
            "site": controller["site"]["id"],
            "tenant": (controller.get("tenant") or {}).get("id"),
            "role": self.named_object("dcim/device-roles/", ACCESS_POINT_ROLE)["id"],
            "platform": platform,
            "tags": [
                self.named_object("extras/tags/", poller, poller)["id"],
                self.named_object("extras/tags/", DISCOVERED_TAG)["id"],
            ],
        }
        device_types = {}
        results, skipped = [], 0
        for access_point in facts["access_points"]:
            if not access_point["up"] and not access_point["serial"]:
                # Down and never reported a serial: a stale controller entry, not hardware.
                skipped += 1
                continue
            name = (access_point["name"] or access_point["mac_address"].replace(":", ""))[:64]
            try:
                if not access_point["model"]:
                    raise SyncError(f"Access point {name} has no model in the controller table")
                if access_point["model"] not in device_types:
                    device_types[access_point["model"]] = self.device_type(
                        manufacturer, access_point["model"]
                    )
                results.append(
                    self.sync_access_point(
                        controller, facts, access_point, name, device_types[access_point["model"]], defaults
                    )
                )
            except SyncError as error:
                results.append({"name": name, "status": "failed", "error": str(error)})
            except httpx.HTTPStatusError as error:
                results.append(
                    {
                        "name": name,
                        "status": "failed",
                        "error": f"NetBox returned HTTP {error.response.status_code} for this access point",
                    }
                )
        failed = any(
            row["status"] == "failed" or row.get("software_inventory", {}).get("status") == "failed"
            for row in results
        )
        return {
            "status": "warning" if failed else "synced",
            "controller_id": controller["id"],
            "reported": len(facts["access_points"]),
            "skipped": skipped,
            "access_points": results,
        }

    def sync_access_point(self, controller, facts, access_point, name, device_type, defaults):
        path = "dcim/devices/"
        serial = access_point["serial"]
        version = access_point["software_version"] or facts["software_version"]

        def by_serial():
            if not serial:
                return None
            matches = [
                row
                for row in self.records(path, serial=serial)
                if (row["serial"] or "").casefold() == serial.casefold()
            ]
            if len(matches) > 1:
                raise SyncError(f"Access point {name} serial matches multiple NetBox devices")
            return matches[0] if matches else None

        def by_name():
            for row in self.records(path, name__ie=name, site_id=defaults["site"]):
                if (row["name"] or "").casefold() != name.casefold() or (
                    (row.get("tenant") or {}).get("id") != defaults["tenant"]
                ):
                    continue
                if serial and row["serial"] and row["serial"].casefold() != serial.casefold():
                    raise SyncError(f"Access point {name} has a different serial in NetBox")
                return row
            return None

        fields = {WIRELESS_CONTROLLER: controller["id"]}
        if version:
            fields[SOFTWARE_VERSION] = version
        description = f"AP group {access_point['group']}" if access_point["group"] else ""
        current = by_serial() or by_name()
        if current is None:
            current = self.ensure(
                path,
                lambda: by_serial() or by_name(),
                {
                    **defaults,
                    "name": name,
                    "device_type": device_type["id"],
                    "serial": serial,
                    "status": "active" if access_point["up"] else "offline",
                    "description": description,
                    "custom_fields": fields,
                },
            )
            action = "created"
        else:
            changes = {}
            if current["name"] != name:
                changes["name"] = name
            if current["device_type"]["id"] != device_type["id"]:
                changes["device_type"] = device_type["id"]
            if serial and current["serial"] != serial:
                changes["serial"] = serial
            if defaults["platform"] and not current.get("platform"):
                changes["platform"] = defaults["platform"]
            current_fields = current["custom_fields"]
            if (current_fields.get(WIRELESS_CONTROLLER) or {}).get("id") != controller["id"] or (
                version and current_fields.get(SOFTWARE_VERSION) != version
            ):
                changes["custom_fields"] = fields
            # Keep a description someone wrote; only maintain the one discovery writes.
            if current["description"] != description and (
                not current["description"] or current["description"].startswith("AP group ")
            ):
                changes["description"] = description
            if defaults["tags"][0] not in {tag["id"] for tag in current["tags"]}:
                changes["add_tags"] = [defaults["tags"][0]]
            if changes:
                current = self.request("PATCH", f"{path}{current['id']}/", json=changes)
            action = "updated" if changes else "unchanged"
        result = {
            "name": name,
            "device_id": current["id"],
            "serial": serial,
            "up": access_point["up"],
            "status": action,
        }
        if version and (current.get("platform") or defaults["platform"]):
            result["software_inventory"] = self.report_software(
                current["id"],
                {"software_version": version, "collected_at": facts.get("collected_at")},
            )
        return result

    def sync_stack(self, device, poller, facts):
        path = "dcim/virtual-chassis/"
        devices_path = "dcim/devices/"
        anchor = facts["stack_member_id"]
        suffix = f"-{device['id']}"
        chassis_name = facts["name"][: 64 - len(suffix)] + suffix
        # A replaced management switch is a new record joining the existing chassis.
        if existing := device.get("virtual_chassis") or (
            {"id": facts["stack_chassis_id"]} if facts.get("stack_chassis_id") else None
        ):
            chassis = self.request("GET", f"{path}{existing['id']}/")
        else:
            chassis = self.ensure(path, lambda: self.named(path, chassis_name), {"name": chassis_name})
        chassis_id = chassis["id"]
        master = (chassis.get("master") or {}).get("id")
        if master not in (None, device["id"]):
            raise SyncError("The polled device is not the management member of its NetBox virtual chassis")
        positions = {
            row["vc_position"]: row for row in self.records(devices_path, virtual_chassis_id=chassis_id)
        }
        if anchor in positions and positions[anchor]["id"] != device["id"]:
            raise SyncError("The management member's position is already in use in NetBox")
        if not device.get("virtual_chassis"):
            self.request(
                "PATCH",
                f"{devices_path}{device['id']}/",
                json={"virtual_chassis": chassis_id, "vc_position": anchor},
            )
        if master is None:
            self.request("PATCH", f"{path}{chassis_id}/", json={"master": device["id"]})
        manufacturer = self.named_object("dcim/manufacturers/", facts["manufacturer"])
        tag = self.named_object("extras/tags/", poller, poller)
        discovered = self.named_object("extras/tags/", DISCOVERED_TAG)
        role = self.named_object("dcim/device-roles/", "Switch")
        defaults = {
            "site": device["site"]["id"],
            "tenant": (device.get("tenant") or {}).get("id"),
            "role": role["id"],
            "platform": (device.get("platform") or {}).get("id"),
            "virtual_chassis": chassis_id,
            "status": "active",
            "tags": [tag["id"], discovered["id"]],
        }
        results = [
            self.sync_stack_member(facts, member, positions.get(member["member_id"]), manufacturer, defaults)
            for member in facts["stack_members"]
            if member["member_id"] != anchor
        ]
        incomplete = any(
            row.get("software_inventory", {}).get("status") == "failed" for row in results
        ) or any(not member["serial"] or not member["software_version"] for member in facts["stack_members"])
        changes = facts.get("stack_changes") or {}
        return {
            "status": "warning" if incomplete else "synced",
            "virtual_chassis_id": chassis_id,
            "members": results,
            "retired": changes.get("retired", []),
            "renumbered": changes.get("renumbered", []),
        }

    def reconcile_stack(self, current, members, facts):
        """Line NetBox's stack records up with the switches SNMP reports, by serial.

        A switch that now reports another member number is renamed and moved to
        that position. A record whose switch is gone while its member number is
        in use by other hardware is retired: renamed <name>-decom-<serial>, set
        to decommissioning and taken out of the chassis, so the new switch can
        take its name and position. NetBox needs device names unique per site
        and tenant, whatever the status, hence the rename. A record whose switch
        is gone and whose number nobody uses is kept, as before.

        Returns the management record, or None when its switch was replaced,
        and the reported member it now stands for.
        """
        path = "dcim/devices/"
        chassis = self.request("GET", f"dcim/virtual-chassis/{current['virtual_chassis']['id']}/")
        facts["stack_chassis_id"] = chassis["id"]
        records = list(self.records(path, virtual_chassis_id=chassis["id"]))
        reported = {member["member_id"]: member for member in members}
        by_serial = {member["serial"].casefold(): member for member in members if member["serial"]}

        def switch(row):
            return by_serial.get(row["serial"].casefold()) if row["serial"] else None

        anchor, replaced = switch(current), False
        if anchor is None:
            anchor = reported.get(current["vc_position"])
            if current["serial"]:
                # The management switch is gone. New hardware in its slot takes over.
                held = {row["serial"].casefold() for row in records if row["serial"]}
                if anchor is None or not anchor["serial"] or anchor["serial"].casefold() in held:
                    raise SyncError("The management switch left the stack; check the NetBox stack")
                replaced = True
            elif anchor is None:
                raise SyncError("The management chassis changed or disappeared; check the NetBox stack")

        hostname = facts["name"]

        def target_name(member):
            if member is anchor:
                return hostname
            suffix = f"-{member['member_id']}"
            return hostname[: 64 - len(suffix)] + suffix

        retire, moves = [], []
        for row in records:
            member = switch(row)
            if row["id"] == current["id"] and replaced:
                retire.append(row)
            elif member is None:
                if row["serial"] and row["vc_position"] in reported:
                    retire.append(row)
            elif (row["vc_position"], row["name"]) != (member["member_id"], target_name(member)):
                moves.append((row, member["member_id"], target_name(member)))

        changes = {"retired": [], "renumbered": []}
        master = (chassis.get("master") or {}).get("id")
        for row in retire:
            if row["id"] == master:
                self.request("PATCH", f"dcim/virtual-chassis/{chassis['id']}/", json={"master": None})
                master = None
            changes["retired"].append(self.retire_stack_member(row, management=row["id"] == current["id"]))

        retired = {row["id"] for row in retire}
        remaining = [row for row in records if row["id"] not in retired]
        occupied = {row["vc_position"]: row["id"] for row in remaining}
        names = {(row["name"] or "").casefold(): row["id"] for row in remaining}
        if any(
            occupied.get(position, row["id"]) != row["id"]
            or names.get(name.casefold(), row["id"]) != row["id"]
            for row, position, name in moves
        ):
            # Swapped member numbers: park every moving record first. NetBox
            # positions run to 255; stacks use the low numbers.
            targets = {position for _, position, _ in moves}
            spare = (n for n in range(255, 0, -1) if n not in occupied and n not in targets)
            for row, _, _ in moves:
                suffix = f"-renumbering-{row['id']}"
                self.request(
                    "PATCH",
                    f"{path}{row['id']}/",
                    json={"vc_position": next(spare), "name": hostname[: 64 - len(suffix)] + suffix},
                )
        for row, position, name in moves:
            updated = self.request(
                "PATCH", f"{path}{row['id']}/", json={"vc_position": position, "name": name}
            )
            changes["renumbered"].append(
                {
                    "device_id": row["id"],
                    "serial": row["serial"],
                    "from": row["vc_position"],
                    "to": position,
                    "name": name,
                }
            )
            if row["id"] == current["id"]:
                current = updated
        facts["stack_changes"] = changes
        return (None if replaced else current), anchor

    def retire_stack_member(self, row, management):
        path = "dcim/devices/"
        site, tenant = row["site"]["id"], (row.get("tenant") or {}).get("id")

        def taken(name):
            return any(
                (other["name"] or "").casefold() == name.casefold()
                and (other.get("tenant") or {}).get("id") == tenant
                and other["id"] != row["id"]
                for other in self.records(path, name__ie=name, site_id=site)
            )

        name = ""
        for suffix in (f"-decom-{row['serial']}", f"-decom-{row['serial']}-{row['id']}"):
            name = (row["name"] or "")[: 64 - len(suffix)] + suffix
            if not taken(name):
                break
        data = {"name": name, "status": "decommissioning", "virtual_chassis": None, "vc_position": None}
        addresses = []
        if management:
            # Free the management address and discovery match for the replacement switch.
            addresses = [row[field]["id"] for field in ("primary_ip4", "primary_ip6") if row.get(field)]
            data.update({"primary_ip4": None, "primary_ip6": None, "custom_fields": {DISCOVERY_IP: None}})
        self.request("PATCH", f"{path}{row['id']}/", json=data)
        for address in addresses:
            self.request(
                "PATCH",
                f"ipam/ip-addresses/{address}/",
                json={"assigned_object_type": None, "assigned_object_id": None},
            )
        return {
            "device_id": row["id"],
            "serial": row["serial"],
            "position": row["vc_position"],
            "name": name,
        }

    def sync_stack_member(self, facts, member, current, manufacturer, defaults):
        path = "dcim/devices/"
        position = member["member_id"]
        suffix = f"-{position}"
        name = facts["name"][: 64 - len(suffix)] + suffix
        site_id, tenant_id = defaults["site"], defaults["tenant"]

        def lookup():
            for row in self.records(path, name__ie=name, site_id=site_id):
                if (row["name"] or "").casefold() != name.casefold() or (
                    (row.get("tenant") or {}).get("id") != tenant_id
                ):
                    continue
                chassis = (row.get("virtual_chassis") or {}).get("id")
                if chassis == defaults["virtual_chassis"] and row["vc_position"] == position:
                    return row
                raise SyncError(f"Stack member {name} conflicts with an existing NetBox device")
            return None

        # Check the name even when a member was found by slot; renaming must not collide.
        named = lookup()
        current = current or named
        if current and any(current.get(field) for field in ("primary_ip4", "primary_ip6", "oob_ip")):
            raise SyncError(f"Stack member {name} has a management IP in NetBox")
        if (
            current
            and member["serial"]
            and current["serial"]
            and (member["serial"].casefold() != current["serial"].casefold())
        ):
            raise SyncError(f"Stack member {name} has a different chassis serial in NetBox")
        device_type = self.device_type(manufacturer, member["model"])
        fields = {SOFTWARE_VERSION: member["software_version"]} if member["software_version"] else {}
        platform = defaults["platform"]
        if not current:
            current = self.ensure(
                path,
                lookup,
                {
                    **defaults,
                    "name": name,
                    "device_type": device_type["id"],
                    "serial": member["serial"],
                    "vc_position": position,
                    "custom_fields": fields,
                },
            )
        else:
            changes = {}
            if current["name"] != name:
                changes["name"] = name
            if current["device_type"]["id"] != device_type["id"]:
                changes["device_type"] = device_type["id"]
            if member["serial"] and current["serial"] != member["serial"]:
                changes["serial"] = member["serial"]
            if platform and not current.get("platform"):
                changes["platform"] = platform
            if fields and current["custom_fields"].get(SOFTWARE_VERSION) != member["software_version"]:
                changes["custom_fields"] = fields
            poller_tag = defaults["tags"][0]
            if poller_tag not in {item["id"] for item in current["tags"]}:
                changes["add_tags"] = [poller_tag]
            if changes:
                self.request("PATCH", f"{path}{current['id']}/", json=changes)
        result = {"member_id": position, "device_id": current["id"], "name": name}
        if member["software_version"] and (current.get("platform") or platform):
            result["software_inventory"] = self.report_software(
                current["id"],
                {**member, "collected_at": facts.get("collected_at")},
            )
        return result

    def report_software(self, device_id, facts):
        data = {"device": device_id, "version": facts["software_version"], "source": "snmp"}
        if collected_at := facts.get("collected_at"):
            data["collected_at"] = collected_at
        try:
            (entry,) = self.request("POST", SOFTWARE_REPORT, json=data)["results"]
            if entry["result"] in {"created", "changed", "updated", "unchanged", "stale"}:
                return {"status": entry["result"], "id": entry["id"]}
        except httpx.HTTPStatusError as error:
            if error.response.status_code == 404:
                return {"status": "unavailable"}
            return {
                "status": "failed",
                "error": f"Software report returned HTTP {error.response.status_code}",
            }
        except (httpx.RequestError, ValueError, KeyError, TypeError):
            pass
        return {"status": "failed", "error": "NetBox did not accept the running software observation"}

    def assign_primary_ip(self, device, management_ip, poller_tag):
        interface_path = "dcim/interfaces/"
        address_path = "ipam/ip-addresses/"
        name = management_ip["interface"]
        cidr = ip_interface(management_ip["address"])
        device_id = device["id"]

        def find_interface():
            matches = [
                row
                for row in self.records(interface_path, device_id=device_id, name__ie=name)
                if row["name"].casefold() == name.casefold()
            ]
            if len(matches) > 1:
                raise SyncError("Multiple NetBox interfaces match the interface reported by SNMP")
            return matches[0] if matches else None

        interface = self.ensure(
            interface_path, find_interface, {"device": device_id, "name": name, "type": "other"}
        )
        vrf_id = (interface.get("vrf") or {}).get("id")
        assignment = {"assigned_object_type": "dcim.interface", "assigned_object_id": interface["id"]}

        rows = [
            row
            for row in self.records(address_path, address=str(cidr.ip))
            if (row.get("vrf") or {}).get("id") == vrf_id and ip_interface(row["address"]).ip == cidr.ip
        ]

        def assigned_device(row):
            if row.get("assigned_object_type") != "dcim.interface" or row.get("assigned_object_id") is None:
                return None
            return ((row.get("assigned_object") or {}).get("device") or {}).get("id")

        def tagged(row):
            return any(tag["id"] == poller_tag["id"] for tag in row.get("tags") or [])

        # The same address can be recorded for devices behind other pollers: records assigned
        # to other devices are theirs and stay untouched. This device's own record is reused,
        # even from another of its interfaces after a rename.
        own = [row for row in rows if row["assigned_object_id"] == interface["id"]] or [
            row for row in rows if assigned_device(row) == device_id
        ]
        # An unassigned record is claimed when it is this poller's, or the address's only record.
        free = [row for row in rows if row["assigned_object_id"] is None and (tagged(row) or len(rows) == 1)]
        candidates = own or free
        if len(candidates) > 1:
            raise SyncError("Multiple NetBox IP records for this device or poller match the polled address")
        if candidates:
            address = candidates[0]
        else:
            try:
                address = self.request(
                    "POST",
                    address_path,
                    json={
                        **assignment,
                        "address": str(cidr),
                        "vrf": vrf_id,
                        "status": "dhcp" if management_ip["dhcp"] else "active",
                        "tags": [poller_tag["id"]],
                    },
                )
            except httpx.HTTPStatusError as error:
                if error.response.status_code != 400:
                    raise
                raise SyncError(
                    "NetBox refused another IP record for the polled address; it may enforce unique "
                    "IPs in this VRF, so give each poller's network its own VRF"
                ) from None
        ip_data = {}
        if any(address.get(key) != value for key, value in assignment.items()):
            ip_data.update(assignment)
        if ip_interface(address["address"]) != cidr:
            ip_data["address"] = str(cidr)
        if not tagged(address):
            ip_data["add_tags"] = [poller_tag["id"]]
        if ip_data:
            self.request("PATCH", f"{address_path}{address['id']}/", json=ip_data)

        primary_field = f"primary_ip{cidr.version}"
        set_primary = (device.get(primary_field) or {}).get("id") != address["id"]
        if set_primary:
            self.request("PATCH", f"dcim/devices/{device_id}/", json={primary_field: address["id"]})
        return bool(ip_data or set_primary)

    def sync_inventory(self, site_name, poller, address, facts):
        if poller == DISCOVERED_TAG:
            raise SyncError("The poller instance cannot use the reserved discovered tag")
        self.custom_field(DISCOVERY_IP, "SNMP discovery IP", "Address polled by NetOps Executor.")
        self.custom_field(SOFTWARE_VERSION, "Software version", "Running software version reported by SNMP.")
        site = self.named_object("dcim/sites/", site_name)
        tag = self.named_object("extras/tags/", poller, poller)
        discovered = self.named_object("extras/tags/", DISCOVERED_TAG)
        path = "dcim/devices/"
        name = facts["name"]
        current = self.device(name, address, tag, discovered)
        members = facts.get("stack_members")
        existing_stack = current and current.get("virtual_chassis") and facts["manufacturer"] == "Cisco"
        if members:
            if existing_stack:
                # The hostname and IP are the stack's stable management record.
                # An active/standby election alone does not move physical records.
                current, anchor = self.reconcile_stack(current, members, facts)
                existing_stack = bool(current)
            else:
                anchor = next(row for row in members if row["role"] == "active")
            facts["stack_member_id"] = anchor["member_id"]
            facts["model"] = anchor["model"]
            facts["serial"] = anchor["serial"]
            if anchor["role"] != "active":
                facts["software_version"] = anchor["software_version"]
        if existing_stack and not members:
            # Without StackWise membership, the first ENTITY-MIB chassis might
            # be another switch. Keep the established hardware identity.
            device_type = current["device_type"]
        else:
            manufacturer = self.named_object("dcim/manufacturers/", facts["manufacturer"])
            device_type = self.device_type(manufacturer, facts["model"])
        fields = {DISCOVERY_IP: address}
        data = {"device_type": device_type["id"], "site": site["id"]}
        if facts["serial"] and (not existing_stack or members):
            data["serial"] = facts["serial"]
        if facts["software_version"]:
            fields[SOFTWARE_VERSION] = facts["software_version"]
        if (current is None or not current.get("platform")) and (platform := facts.get("platform")):
            data["platform"] = self.named_object("dcim/platforms/", platform)["id"]
        if current is None:
            role = self.named_object("dcim/device-roles/", discovery_role(facts))
            try:
                created = self.request(
                    "POST",
                    path,
                    json={
                        **data,
                        "name": name,
                        "role": role["id"],
                        "status": "active",
                        "tags": [tag["id"], discovered["id"]],
                        "custom_fields": fields,
                    },
                )
                return "created", created
            except httpx.HTTPStatusError as error:
                if error.response.status_code not in (400, 409):
                    raise
                current = self.device(name, address, tag, discovered)
                if current is None:
                    if any(
                        (row["name"] or "").casefold() == name.casefold() and row["tenant"] is None
                        for row in self.records(path, site_id=site["id"], name__ie=name)
                    ):
                        raise SyncError(
                            "NetBox already has this name at the site for another poller or address"
                        ) from None
                    raise
        if current.get("platform"):
            data.pop("platform", None)
        for field in ("device_type", "site"):
            if data[field] == current[field]["id"]:
                del data[field]
        if data.get("serial") == current["serial"]:
            data.pop("serial", None)
        if facts.get("serial_source") == "snmp" and current["serial"]:
            # A VE whose license could not be read this time keeps the serial NetBox
            # already has, so a license serial is not swapped for the SNMP chassis serial.
            data.pop("serial", None)
        if any(current["custom_fields"].get(key) != value for key, value in fields.items()):
            data["custom_fields"] = fields
        tag_ids = [tag["id"]]
        if current["role"]["slug"] == LEGACY_DISCOVERY_ROLE:
            data["role"] = self.named_object("dcim/device-roles/", discovery_role(facts))["id"]
            tag_ids.append(self.named_object("extras/tags/", DISCOVERED_TAG)["id"])
        existing_tags = {existing["id"] for existing in current["tags"]}
        if missing_tags := [tag_id for tag_id in tag_ids if tag_id not in existing_tags]:
            data["add_tags"] = missing_tags
        if data:
            current = self.request("PATCH", f"{path}{current['id']}/", json=data)
        return ("updated" if data else "unchanged"), current
