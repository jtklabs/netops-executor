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

    def device(self, name, address):
        matches = []
        for device in self.records("dcim/devices/", name__ie=name):
            if (device["name"] or "").casefold() != name.casefold():
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
        if (management_ip := facts.get("management_ip")) and self.assign_primary_ip(device, management_ip):
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
        if existing := device.get("virtual_chassis"):
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
        return {
            "status": "warning" if incomplete else "synced",
            "virtual_chassis_id": chassis_id,
            "members": results,
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

    def assign_primary_ip(self, device, management_ip):
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

        def find_address():
            matches = [
                row
                for row in self.records(address_path, address=str(cidr.ip))
                if (row.get("vrf") or {}).get("id") == vrf_id and ip_interface(row["address"]).ip == cidr.ip
            ]
            if len(matches) > 1:
                raise SyncError("Multiple NetBox IP records match the polled address in the interface VRF")
            return matches[0] if matches else None

        address = self.ensure(
            address_path,
            find_address,
            {
                **assignment,
                "address": str(cidr),
                "vrf": vrf_id,
                "status": "dhcp" if management_ip["dhcp"] else "active",
            },
        )
        ip_data = {}
        if address["assigned_object_id"] is None:
            ip_data.update(assignment)
        elif any(address[key] != value for key, value in assignment.items()):
            raise SyncError("The polled IP is already assigned to another NetBox object in the interface VRF")
        if ip_interface(address["address"]) != cidr:
            ip_data["address"] = str(cidr)
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
        path = "dcim/devices/"
        name = facts["name"]
        current = self.device(name, address)
        members = facts.get("stack_members")
        existing_stack = current and current.get("virtual_chassis") and facts["manufacturer"] == "Cisco"
        if members:
            if existing_stack:
                # The hostname and IP are the stack's stable management record.
                # An active/standby election alone does not move physical records.
                anchor = next((row for row in members if row["member_id"] == current["vc_position"]), None)
                if anchor is None or (
                    current["serial"]
                    and anchor["serial"]
                    and current["serial"].casefold() != anchor["serial"].casefold()
                ):
                    raise SyncError("The management chassis changed or disappeared; check the NetBox stack")
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
            discovered = self.named_object("extras/tags/", DISCOVERED_TAG)
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
                current = self.device(name, address)
                if current is None:
                    if any(
                        (row["name"] or "").casefold() == name.casefold() and row["tenant"] is None
                        for row in self.records(path, site_id=site["id"], name__ie=name)
                    ):
                        raise SyncError(
                            "NetBox already has this name at the site with a different address"
                        ) from None
                    raise
        if current.get("platform"):
            data.pop("platform", None)
        for field in ("device_type", "site"):
            if data[field] == current[field]["id"]:
                del data[field]
        if data.get("serial") == current["serial"]:
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
