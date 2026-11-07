import json

import httpx
import pytest

from netops_executor.netbox_discovery import NetBoxDiscovery


@pytest.mark.parametrize("previous_role", [None, "core-switch", "snmp-discovered"])
def test_discovery_marks_new_and_legacy_devices_but_preserves_manual_provenance(previous_role):
    calls = []
    rows = {
        "extras/custom-fields": [
            {"name": field, "object_types": ["dcim.device"], "type": {"value": "text"}}
            for field in ("software_version", "snmp_discovery_ip")
        ],
        "dcim/sites": [{"id": 1, "name": "Lab", "slug": "lab"}],
        "extras/tags": [
            {"id": 7, "name": "checkmk-au", "slug": "checkmk-au"},
            {"id": 8, "name": "discovered", "slug": "discovered"},
        ],
        "dcim/manufacturers": [{"id": 3, "name": "Cisco", "slug": "cisco"}],
        "dcim/device-types": [{"id": 4, "model": "Catalyst 9300-48P", "part_number": "C9300-48P"}],
        "dcim/device-roles": [{"id": 5, "name": "Switch", "slug": "switch"}],
        "dcim/platforms": [{"id": 9, "name": "Cisco IOS-XE", "slug": "cisco-ios-xe"}],
        "dcim/devices": [
            {
                "id": id_,
                "name": "switch",
                "serial": "existing",
                "site": {"id": 1},
                "device_type": {"id": 4},
                "role": {"slug": previous_role},
                "platform": {"id": 12} if previous_role == "core-switch" else None,
                "custom_fields": {
                    "snmp_discovery_ip": address,
                    "software_version": "17.9.5",
                    "other": "keep",
                },
                "tags": [{"id": 6}],
            }
            for id_, address in [(10, "192.0.2.2"), (11, "192.0.2.1")]
            if id_ != 11 or previous_role is not None
        ],
    }

    def handle(request):
        path = request.url.path.removeprefix("/api/").strip("/")
        if request.method == "GET":
            return httpx.Response(200, json={"results": rows[path], "next": None})
        calls.append((request.method, path, json.loads(request.content)))
        return httpx.Response(200, json={"id": 11})

    facts = {
        "name": "Switch",
        "manufacturer": "Cisco",
        "model": "C9300-48P",
        "platform": "Cisco IOS-XE",
        "serial": "",
        "software_version": "",
    }
    with httpx.Client(
        base_url="https://netbox.example/api/", transport=httpx.MockTransport(handle)
    ) as client:
        result = NetBoxDiscovery(client, lambda: None).sync("Lab", "checkmk-au", "192.0.2.1", facts)
    if previous_role is None:
        assert result == ("created", 11)
        method, path, data = calls.pop()
        assert (method, path) == ("POST", "dcim/devices")
        assert data["role"] == 5 and data["platform"] == 9 and data["tags"] == [7, 8]
        assert not calls
    else:
        assert result == ("updated", 11)
        expected = (
            {"role": 5, "platform": 9, "add_tags": [7, 8]}
            if previous_role == "snmp-discovered"
            else {"add_tags": [7]}
        )
        assert calls == [("PATCH", "dcim/devices/11", expected)]


def test_device_type_lookup_uses_exact_normalized_model_after_punctuation_search():
    def handle(request):
        assert request.method == "GET"
        query = request.url.params["q"]
        rows = (
            [
                {"id": 1, "model": "FortiGate 600E", "part_number": "FG-600E"},
                {"id": 2, "model": "FortiGate 3600E", "part_number": "FG-3600E"},
            ]
            if query == "600E"
            else []
        )
        return httpx.Response(200, json={"results": rows, "next": None})

    with httpx.Client(
        base_url="https://netbox.example/api/", transport=httpx.MockTransport(handle)
    ) as client:
        match = NetBoxDiscovery(client, lambda: None).device_type(
            {"id": 3, "slug": "fortinet"}, "FortiGate-600E"
        )
    assert match["id"] == 1


@pytest.mark.parametrize("foreign", [False, True])
def test_primary_ip_uses_the_interface_vrf_and_preserves_other_assignments(foreign):
    from netops_executor.netbox_discovery import SyncError

    calls = []

    def handle(request):
        path = request.url.path.removeprefix("/api/").strip("/")
        if request.method == "GET":
            if path == "dcim/interfaces":
                assert request.url.params["device_id"] == "6"
                rows = [{"id": 147, "name": "eth0", "vrf": {"id": 10}}]
            else:
                assert path == "ipam/ip-addresses"
                assert request.url.params["address"] == "192.0.2.15"
                rows = [
                    {"id": 1, "vrf": None, "address": "192.0.2.15/24", "assigned_object_id": 208},
                    {
                        "id": 2,
                        "vrf": {"id": 10},
                        "address": "192.0.2.15/24",
                        "assigned_object_id": 207 if foreign else None,
                        "assigned_object_type": "dcim.interface" if foreign else None,
                    },
                ]
            return httpx.Response(200, json={"results": rows, "next": None})
        calls.append((request.method, path, json.loads(request.content)))
        return httpx.Response(200, json={})

    with httpx.Client(
        base_url="https://netbox.example/api/", transport=httpx.MockTransport(handle)
    ) as client:
        discovery = NetBoxDiscovery(client, lambda: None)
        management_ip = {"interface": "eth0", "address": "192.0.2.15/24", "dhcp": False}
        if foreign:
            with pytest.raises(SyncError, match="already assigned"):
                discovery.assign_primary_ip({"id": 6}, management_ip)
            assert calls == []
        else:
            assert discovery.assign_primary_ip({"id": 6}, management_ip)
            assert calls == [
                (
                    "PATCH",
                    "ipam/ip-addresses/2",
                    {"assigned_object_type": "dcim.interface", "assigned_object_id": 147},
                ),
                ("PATCH", "dcim/devices/6", {"primary_ip4": 2}),
            ]


@pytest.mark.parametrize(
    ("http_status", "response", "expected"),
    [
        (200, {"results": [{"result": "created", "id": 27}]}, {"status": "created", "id": 27}),
        (404, {}, {"status": "unavailable"}),
        (403, {}, {"status": "failed", "error": "Software report returned HTTP 403"}),
    ],
)
def test_discovery_reports_running_software_for_the_matched_device(
    monkeypatch, http_status, response, expected
):
    def handle(request):
        assert request.method == "POST"
        assert request.url.path == "/api/plugins/refresh/device-software/report/"
        assert json.loads(request.content) == {
            "device": 10,
            "version": "17.5.1.10-0.0.35",
            "source": "snmp",
            "collected_at": "2026-11-07T00:00:00+00:00",
        }
        return httpx.Response(http_status, json=response)

    facts = {"software_version": "17.5.1.10-0.0.35", "collected_at": "2026-11-07T00:00:00+00:00"}
    with httpx.Client(
        base_url="https://netbox.example/api/", transport=httpx.MockTransport(handle)
    ) as client:
        discovery = NetBoxDiscovery(client, lambda: None)
        monkeypatch.setattr(
            discovery, "sync_inventory", lambda *_: ("unchanged", {"id": 10, "platform": {"id": 9}})
        )
        assert discovery.sync("Lab", "checkmk-au", "192.0.2.1", facts) == ("unchanged", 10)
    assert facts["software_inventory"] == expected
