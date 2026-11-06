"""Write basic SNMP inventory through the configured NetBox REST API."""

import re
import ssl
import unicodedata
from hashlib import sha256
from ipaddress import ip_interface

import httpx

DISCOVERY_IP = "snmp_discovery_ip"
SOFTWARE_VERSION = "software_version"


class SyncError(Exception):
    """A safe, actionable error for the job result."""


def slugify(value):
    value = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode().lower()
    return re.sub(r"[^a-z0-9]+", "-", value).strip("-")


def model_key(value):
    return slugify(value).replace("-", "")


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

    def custom_field(self, name, label, description):
        path = "extras/custom-fields/"
        field = self.ensure(
            path,
            lambda: next((row for row in self.records(path, name=name) if row["name"] == name), None),
            {
                "object_types": ["dcim.device"],
                "name": name,
                "label": label,
                "type": "text",
                "description": description,
            },
        )
        if field["type"]["value"] != "text" or "dcim.device" not in field["object_types"]:
            raise SyncError(f"NetBox custom field {name} must be a device text field")

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
        self.custom_field(DISCOVERY_IP, "SNMP discovery IP", "Address polled by NetOps Executor.")
        self.custom_field(SOFTWARE_VERSION, "Software version", "Running software version reported by SNMP.")
        site = self.named_object("dcim/sites/", site_name)
        tag = self.named_object("extras/tags/", poller, poller)
        manufacturer = self.named_object("dcim/manufacturers/", facts["manufacturer"])
        device_type = self.device_type(manufacturer, facts["model"])

        path = "dcim/devices/"
        name = facts["name"]
        current = self.device(name, address)
        fields = {DISCOVERY_IP: address}
        data = {"device_type": device_type["id"], "site": site["id"]}
        if facts["serial"]:
            data["serial"] = facts["serial"]
        if facts["software_version"]:
            fields[SOFTWARE_VERSION] = facts["software_version"]
        if current is None:
            role = self.named_object("dcim/device-roles/", "SNMP discovered")
            try:
                created = self.request(
                    "POST",
                    path,
                    json={
                        **data,
                        "name": name,
                        "role": role["id"],
                        "status": "active",
                        "tags": [tag["id"]],
                        "custom_fields": fields,
                    },
                )
                return "created", created["id"]
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
        for field in ("device_type", "site"):
            if data[field] == current[field]["id"]:
                del data[field]
        if data.get("serial") == current["serial"]:
            data.pop("serial", None)
        if any(current["custom_fields"].get(key) != value for key, value in fields.items()):
            data["custom_fields"] = fields
        if all(existing["id"] != tag["id"] for existing in current["tags"]):
            data["add_tags"] = [tag["id"]]
        if data:
            self.request("PATCH", f"{path}{current['id']}/", json=data)
        return ("updated" if data else "unchanged"), current["id"]
