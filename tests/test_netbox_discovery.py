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
