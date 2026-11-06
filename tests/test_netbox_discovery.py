import json

import httpx

from netops_executor.netbox_discovery import NetBoxDiscovery


def test_repeat_poll_uses_name_and_ip_and_adds_only_its_tag():
    calls = []
    rows = {
        "extras/custom-fields": [
            {"name": field, "object_types": ["dcim.device"], "type": {"value": "text"}}
            for field in ("software_version", "snmp_discovery_ip")
        ],
        "dcim/sites": [{"id": 1, "name": "Lab", "slug": "lab"}],
        "extras/tags": [{"id": 7, "name": "checkmk-au", "slug": "checkmk-au"}],
        "dcim/manufacturers": [{"id": 3, "name": "Cisco", "slug": "cisco"}],
        "dcim/device-types": [{"id": 4, "model": "Catalyst 9300-48P", "part_number": "C9300-48P"}],
        "dcim/devices": [
            {
                "id": id_,
                "name": "switch",
                "serial": "existing",
                "site": {"id": 1},
                "device_type": {"id": 4},
                "custom_fields": {
                    "snmp_discovery_ip": address,
                    "software_version": "17.9.5",
                    "other": "keep",
                },
                "tags": [{"id": 6}],
            }
            for id_, address in [(10, "192.0.2.2"), (11, "192.0.2.1")]
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
        "serial": "",
        "software_version": "",
    }
    with httpx.Client(
        base_url="https://netbox.example/api/", transport=httpx.MockTransport(handle)
    ) as client:
        result = NetBoxDiscovery(client, lambda: None).sync("Lab", "checkmk-au", "192.0.2.1", facts)
    assert result == ("updated", 11)
    assert calls == [("PATCH", "dcim/devices/11", {"add_tags": [7]})]


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
