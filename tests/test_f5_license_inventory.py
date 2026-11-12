import json

import httpx
import pytest

from netops_executor.f5_operations import license_details
from netops_executor.netbox_discovery import NetBoxDiscovery, sync_licenses

KEY = "ABCDE-FGHIJ-KLMNO-PQRST-UVW1234"
OUTPUT = f"""Sys::License
Registration key    {KEY}
License End Date    2026/11/14
Service Check Date  2026/10/14

Active Modules
  BIG-IP, VE Trial (AAAAAAA-BBBBBBB)
    DNS (1K QPS), VE
    Advanced Web Application Firewall, VE
"""


@pytest.fixture(autouse=True)
def lifecycle_operations_backend(monkeypatch):
    from netops_executor import snmp

    monkeypatch.setattr(snmp, "preferred_image", lambda *args: None)
    monkeypatch.setattr(snmp, "report_observation", lambda *args: {"status": "success"})
    monkeypatch.setattr(
        snmp,
        "collect_enrichment",
        lambda *args, **kwargs: {"components": {}, "readiness": {}, "relationships": []},
    )


def observation(output=OUTPUT):
    class Device:
        def tmsh(self, command, timeout):
            assert command == "show /sys license"
            return output

    details = license_details(Device())
    details["verified_at"] = "2026-11-11T18:00:00+00:00"
    return details


def test_license_metadata_includes_full_reference_and_cleans_module_codes():
    details = observation()
    assert details["reference"] == KEY
    assert details["serial"] == "UVW1234"
    assert details["product"] == "BIG-IP, VE Trial"
    assert details["installed_modules"] == [
        "BIG-IP, VE Trial",
        "DNS (1K QPS), VE",
        "Advanced Web Application Firewall, VE",
    ]
    assert details["reported_expiration"] == "2026-11-14"
    assert details["service_check_date"] == "2026-10-14"


def test_missing_or_invalid_optional_dates_do_not_fail_license_collection():
    details = observation(f"Registration key {KEY}\nLicense End Date 2026/02/31\n")
    assert details["reported_expiration"] is None
    assert details["service_check_date"] is None
    assert details["installed_modules"] == []


class LicenseAPI:
    def __init__(self):
        self.entitlements = []
        self.assignments = []
        self.writes = []
        self.reject_assignment = False

    def handle(self, request):
        path = request.url.path.removeprefix("/api/").strip("/")
        if request.method == "GET":
            if path == "dcim/manufacturers":
                rows = [{"id": 3, "name": "F5"}]
            elif path == "extras/tags":
                rows = [{"id": 7, "name": "checkmk-us"}, {"id": 8, "name": "discovered"}]
            elif path == "plugins/refresh/license-entitlements":
                rows = self.entitlements
            else:
                assert path == "plugins/refresh/license-assignments"
                rows = self.assignments
            return httpx.Response(200, json={"results": rows, "next": None})
        body = json.loads(request.content)
        self.writes.append((request.method, path, body))
        entitlement = "license-entitlements" in path
        collection = self.entitlements if entitlement else self.assignments
        if request.method == "POST":
            if not entitlement and self.reject_assignment:
                self.reject_assignment = False
                return httpx.Response(403, json={"detail": "Forbidden"})
            row = {"id": 11 if entitlement else 21, **body}
            row["tags"] = [{"id": tag} for tag in row.get("tags", [])]
            collection.append(row)
            return httpx.Response(201, json=row)
        assert request.method == "PATCH"
        row = next(row for row in collection if row["id"] == int(path.rsplit("/", 1)[1]))
        additions = body.pop("add_tags", [])
        row.update(body)
        row.setdefault("tags", []).extend({"id": tag} for tag in additions)
        return httpx.Response(200, json=row)

    def client(self):
        return httpx.Client(
            base_url="https://netbox.example/api/", transport=httpx.MockTransport(self.handle)
        )


def test_license_sync_creates_records_and_updates_observations_without_duplicates():
    api = LicenseAPI()
    with api.client() as client:
        sync = NetBoxDiscovery(client, lambda: None)
        report = sync.sync_f5_license(10, "checkmk-us", observation())
        assert report == {
            "status": "created",
            "entitlement_id": 11,
            "assignment_id": 21,
            "module_count": 3,
            "reported_expiration": "2026-11-14",
        }
        assert KEY not in json.dumps(report)
        assert api.entitlements[0]["reference"] == KEY
        assert api.assignments[0]["device"] == 10
        api.entitlements[0].update(seats=5, vault_reference="existing vault item")
        api.assignments[0]["seats"] = 2
        updated = observation()
        updated.update(reported_expiration="2027-11-14", verified_at="2026-11-12T18:00:00+00:00")
        updated["installed_modules"].append("SSL, VE")
        sync.sync_f5_license(10, "checkmk-us", updated)
        assert len(api.entitlements) == len(api.assignments) == 1
        assert api.entitlements[0]["expires_on"] == "2027-11-14"
        assert api.entitlements[0]["seats"] == 5
        assert api.entitlements[0]["vault_reference"] == "existing vault item"
        assert api.assignments[0]["seats"] == 2
        assert "SSL, VE" in api.assignments[0]["installed_modules"]


def test_license_sync_upgrades_a_linked_support_serial_reference_and_skips_stale_data():
    api = LicenseAPI()
    api.entitlements.append(
        {"id": 11, "manufacturer": 3, "reference": "UVW1234", "product": "BIG-IP", "tags": []}
    )
    api.assignments.append({"id": 21, "device": 10, "entitlement": 11, "tags": []})
    with api.client() as client:
        sync = NetBoxDiscovery(client, lambda: None)
        sync.sync_f5_license(10, "checkmk-us", observation())
        assert api.entitlements[0]["reference"] == KEY
        assert len(api.entitlements) == len(api.assignments) == 1
        api.writes.clear()
        older = observation()
        older["verified_at"] = "2026-11-10T18:00:00+00:00"
        older["reported_expiration"] = "2025-01-01"
        assert sync.sync_f5_license(10, "checkmk-us", older)["status"] == "stale"
        assert not api.writes


def test_partial_license_sync_failure_is_safe_to_retry():
    api = LicenseAPI()
    api.reject_assignment = True
    with api.client() as client:
        sync = NetBoxDiscovery(client, lambda: None)
        with pytest.raises(httpx.HTTPStatusError):
            sync.sync_f5_license(10, "checkmk-us", observation())
        assert len(api.entitlements) == 1 and not api.assignments
        assert sync.sync_f5_license(10, "checkmk-us", observation())["status"] == "created"
        assert len(api.entitlements) == len(api.assignments) == 1


@pytest.mark.parametrize("code", [403, 404, 500])
def test_license_report_errors_are_actionable_and_do_not_include_registration_keys(
    settings, monkeypatch, code
):
    import netops_executor.netbox_discovery as module

    monkeypatch.setattr(
        module,
        "netbox_client",
        lambda _: httpx.Client(
            base_url="https://netbox.example/api/",
            transport=httpx.MockTransport(lambda request: httpx.Response(code, json={"detail": KEY})),
        ),
    )
    report = sync_licenses(settings, 10, "checkmk-us", observation(), lambda: None)
    assert report["status"] == "failed"
    assert f"HTTP {code}" in report["error"]
    assert KEY not in json.dumps(report)


@pytest.mark.parametrize("write_status", ["created", "failed"])
def test_discovery_distinguishes_license_read_and_plugin_write(settings, store, monkeypatch, write_status):
    from netops_executor import snmp
    from netops_executor.config import Device

    settings.devices["bigip"] = Device(id="bigip", host="192.0.2.15", device_type="f5")

    class LicenseSSH:
        def __init__(self, settings, device, guard, audit):
            guard()

        def tmsh(self, command, timeout):
            return OUTPUT

        def close(self):
            pass

    monkeypatch.setattr(snmp, "SSH", LicenseSSH)
    monkeypatch.setattr(snmp, "sync_device", lambda *args: ("created", 10))
    reports = []

    def report(settings, device, poller, info, checkpoint):
        checkpoint()
        assert device == 10 and info["reference"] == KEY
        reports.append(info)
        return {"status": write_status}

    monkeypatch.setattr(snmp, "sync_licenses", report)
    store.submit(
        {"device_ip": "192.0.2.15", "site": "Lab", "poller_instance": "checkmk-us"},
        "license-test",
        kind="snmp_walk",
    )
    job = store.claim("worker")
    runner = snmp.SnmpRunner(settings, store, job, "worker")
    runner.result["discovery"] = {
        "name": "bigip",
        "manufacturer": "F5",
        "model": "BIG-IP Virtual Edition",
        "serial": "SNMP-SERIAL",
        "software_version": "17.5.1",
        "site": "Lab",
        "poller_instance": "checkmk-us",
        "address": "192.0.2.15",
    }
    assert runner.sync_inventory() == (
        "succeeded" if write_status == "created" else "completed_with_warnings"
    )
    facts = runner.result["discovery"]
    assert facts["license_lookup"]["status"] == "succeeded"
    assert facts["license_inventory"]["status"] == write_status
    assert facts["serial"] == "UVW1234"
    assert len(reports) == 1
    assert KEY not in json.dumps(runner.result)
