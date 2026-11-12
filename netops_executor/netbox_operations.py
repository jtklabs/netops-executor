"""Send safe collection evidence to Lifecycle and query the preferred image."""

from datetime import datetime, timezone
from hashlib import sha256

import httpx

from . import __version__
from .netbox_discovery import NetBoxDiscovery, SyncError, netbox_client


def preferred_image(settings, device_id, checkpoint):
    try:
        checkpoint()
        with netbox_client(settings) as http:
            response = http.get("plugins/refresh/readiness/", params={"device": device_id, "limit": 1})
            response.raise_for_status()
            rows = response.json()["results"]
            return rows[0].get("preferred_version") if rows else None
    except (httpx.HTTPError, ValueError, KeyError, TypeError):
        return None


def sync_observed_licenses(settings, device_id, poller, vendor, entries, checkpoint):
    try:
        results = []
        with netbox_client(settings) as http:
            writer = NetBoxDiscovery(http, checkpoint)
            for item in entries:
                info = {**item, "serial": "", "verified_at": datetime.now(timezone.utc).isoformat()}
                # A device-observed product is not a vendor contract or activation key.
                info["reference"] = (
                    item.get("reference")
                    or f"observed-device-{device_id}-" + sha256(item["product"].encode()).hexdigest()[:20]
                )
                results.append(writer.sync_f5_license(device_id, poller, info, manufacturer_name=vendor))
        return {"status": "success", "records": results}
    except httpx.HTTPStatusError as error:
        return {"status": "failed", "reason": f"License inventory returned HTTP {error.response.status_code}"}
    except (httpx.RequestError, SyncError, OSError, ValueError, KeyError, TypeError):
        return {"status": "failed", "reason": "Could not synchronize device-observed licenses"}


def report_observation(settings, job_id, device_id, discovery, enrichment, checkpoint):
    facts = {
        key: str(discovery[key])[:500]
        for key in ("serial", "model", "platform", "software_version")
        if discovery.get(key)
    }
    facts["hostname"] = discovery["name"][:500]
    sources = {key: "observed" for key in facts}
    for key, source in discovery.get("field_sources", {}).items():
        field = "hostname" if key == "name" else key
        if field in facts:
            sources[field] = source
    components = {
        "identity": {
            "status": "partial"
            if any(not discovery.get(k) for k in ("serial", "model", "name"))
            else "success"
        },
        "netbox": {"status": "success"},
    }
    if not discovery.get("polled", True):
        components["identity"] = {
            "status": "failed",
            "reason": "SNMP failed; inventory seeded from manual fallback",
        }
    elif any(source == "manual" for source in sources.values()):
        components["identity"] = {"status": "partial", "reason": "Blank readings filled from manual fallback"}
    ip = discovery.get("management_ip")
    if ip:
        facts.update(
            management_ip=ip["address"],
            management_interface=ip["interface"],
            prefix_source=ip.get("prefix_source", "snmp"),
            interface_source=ip.get("interface_source", "snmp"),
        )
        sources.update(
            management_ip="inferred" if ip.get("prefix_source") == "host" else "observed",
            management_interface="inferred"
            if ip.get("interface_source") == "placeholder"
            else "netbox-existing"
            if ip.get("interface_source") == "netbox"
            else "observed",
        )
        components["address"] = {
            "status": "partial"
            if "inferred" in (sources["management_ip"], sources["management_interface"])
            else "success",
            "reason": "Host prefix or placeholder interface used" if "inferred" in sources.values() else "",
        }
    else:
        components["address"] = {"status": "failed", "reason": "No usable management address"}
    components["software"] = {
        "status": "success"
        if discovery.get("software_version") and sources.get("software_version") == "observed"
        else "partial"
    }
    components.update(enrichment.get("components", {}))
    neighbors = discovery.get("neighbor_inventory", {"status": "skipped"})
    components["neighbors"] = {key: value for key, value in neighbors.items() if key in ("status", "reason")}
    inventory = discovery.get("license_inventory", {})
    if inventory:
        components["licenses"] = {"status": "failed" if inventory.get("status") == "failed" else "success"}
    elif discovery.get("license_lookup"):
        lookup = discovery["license_lookup"]
        components["licenses"] = {
            "status": {"succeeded": "success"}.get(lookup["status"], lookup["status"]),
            "reason": lookup.get("reason", ""),
        }
    if enrichment.get("licenses"):
        facts["license_products"] = sorted({row["product"] for row in enrichment["licenses"]})[:100]
        sources["license_products"] = "observed"
    if enrichment.get("license_products"):
        facts["license_products"] = sorted(set(enrichment["license_products"]))[:100]
        sources["license_products"] = "observed"
    expiration = enrichment.get("license_expiration") or min(
        (
            row["reported_expiration"]
            for row in enrichment.get("licenses", [])
            if row.get("reported_expiration")
        ),
        default=None,
    )
    if expiration:
        facts["license_expiration"] = expiration
        sources["license_expiration"] = "observed"
    if discovery.get("software_inventory", {}).get("status") == "failed":
        components["software"] = {
            "status": "failed",
            "reason": "Running software inventory synchronization failed",
        }
    relationships = [*discovery.get("neighbors", []), *enrichment.get("relationships", [])]
    ha = enrichment.get("readiness", {}).get("ha", {})
    if ha.get("reason"):
        facts["ha_state"] = ha["reason"][:500]
        sources["ha_state"] = "observed"
    payload = {
        "device": device_id,
        "job_id": job_id,
        "poller": discovery["poller_instance"],
        "executor_version": __version__,
        "observed_at": discovery["collected_at"],
        "components": components,
        "facts": facts,
        "field_sources": sources,
        "readiness": enrichment.get("readiness", {}),
        "relationships": relationships,
    }
    try:
        checkpoint()
        with netbox_client(settings) as http:
            response = http.post("plugins/refresh/observations/report/", json=payload)
            response.raise_for_status()
            data = response.json()
            return {**data, "collection_status": data.get("status"), "status": "success"}
    except httpx.HTTPStatusError as error:
        return {
            "status": "unavailable" if error.response.status_code == 404 else "failed",
            "reason": f"Lifecycle observation report returned HTTP {error.response.status_code}",
        }
    except (httpx.RequestError, ValueError, KeyError, TypeError):
        return {"status": "failed", "reason": "Could not publish collection evidence to Lifecycle"}
