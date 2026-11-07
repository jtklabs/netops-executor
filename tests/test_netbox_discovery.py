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


@pytest.mark.parametrize(
    ("manufacturer", "model", "platform", "role"),
    [
        ("Check Point", "Check Point 6200", "Check Point Gaia", "Firewall"),
        ("Check Point", "Check Point Quantum Spark 1600", "Check Point Gaia", "Firewall"),
        ("Check Point", "Smart-1 6000-L", "Check Point Gaia", "Unclassified"),
        ("Blue Coat", "SG-S400", "SGOS", "Proxy"),
        ("Infoblox", "IB-1420", "Infoblox NIOS", "DNS/DHCP"),
        ("HPE", "C2000", "Aruba ClearPass", "Network Access Control"),
        ("HPE", "Aruba7010", "ArubaOS", "Wireless Controller"),
        ("HPE", "Aruba 9240", "ArubaOS", "Wireless Controller"),
        ("HPE", "MM-VA-500", "ArubaOS", "Wireless Controller"),
        ("HPE", "AP-515", "ArubaOS", "Wireless AP"),
        ("HPE", "Aruba 9300-32D", "ArubaOS-CX", "Unclassified"),
        ("Juniper", "SRX1500", "Junos", "Firewall"),
        ("Palo Alto Networks", "PA-3220", "PAN-OS", "Firewall"),
    ],
)
def test_discovery_role_covers_appliance_families(manufacturer, model, platform, role):
    from netops_executor.netbox_discovery import discovery_role

    assert discovery_role({"manufacturer": manufacturer, "model": model, "platform": platform}) == role


class FakeNetBox:
    """Enough of the NetBox REST API for the access point sync: filtered GETs, POST and PATCH."""

    def __init__(self, devices):
        self.rows = {
            "extras/custom-fields": [
                {
                    "name": "wireless_controller",
                    "object_types": ["dcim.device"],
                    "type": {"value": "object"},
                    "related_object_type": "dcim.device",
                }
            ],
            "dcim/manufacturers": [{"id": 3, "name": "HPE", "slug": "hpe"}],
            "dcim/device-types": [
                {"id": 41, "model": "AP-515", "part_number": ""},
                {"id": 42, "model": "AP-535", "part_number": ""},
            ],
            "dcim/device-roles": [{"id": 5, "name": "Wireless AP", "slug": "wireless-ap"}],
            "extras/tags": [
                {"id": 7, "name": "lab", "slug": "lab"},
                {"id": 8, "name": "discovered", "slug": "discovered"},
            ],
            "dcim/devices": devices,
        }
        self.calls = []

    def handle(self, request):
        path = request.url.path.removeprefix("/api/").strip("/")
        params = request.url.params
        if request.method == "GET":
            rows = self.rows[path]
            if path == "dcim/device-types":
                rows = [row for row in rows if params["q"].casefold() in row["model"].casefold()]
            if path == "dcim/devices":
                if "serial" in params:
                    rows = [row for row in rows if row["serial"].casefold() == params["serial"].casefold()]
                if "name__ie" in params:
                    rows = [row for row in rows if row["name"].casefold() == params["name__ie"].casefold()]
                if "site_id" in params:
                    rows = [row for row in rows if str(row["site"]["id"]) == params["site_id"]]
            return httpx.Response(200, json={"results": rows, "next": None})
        data = json.loads(request.content)
        self.calls.append((request.method, path, data))
        if path == "plugins/refresh/device-software/report":
            return httpx.Response(200, json={"results": [{"result": "created", "id": data["device"] + 1000}]})
        if request.method == "POST":
            return httpx.Response(
                201, json={"id": 500 + len(self.calls), "platform": {"id": data["platform"]}}
            )
        return httpx.Response(200, json={"id": int(path.rsplit("/", 1)[1]), "platform": {"id": 9}})


def test_controller_access_points_become_devices_matched_by_serial():
    renamed = {
        "id": 61,
        "name": "old-name",
        "serial": "CNJPJ0A001",
        "site": {"id": 2},  # Moved by hand to the floor's real site; kept.
        "tenant": None,
        "device_type": {"id": 41},
        "platform": {"id": 9},
        "description": "",
        "custom_fields": {"software_version": "8.10.0.3", "wireless_controller": None},
        "tags": [{"id": 8}],
    }
    unchanged = {
        "id": 62,
        "name": "dal-ap-102",
        "serial": "CNJPJ0A002",
        "site": {"id": 1},
        "tenant": None,
        "device_type": {"id": 41},
        "platform": {"id": 9},
        "description": "AP group floor-1",
        "custom_fields": {"software_version": "8.10.0.4", "wireless_controller": {"id": 40}},
        "tags": [{"id": 7}, {"id": 8}],
    }
    conflict = {**unchanged, "id": 63, "name": "dal-ap-104", "serial": "OTHER-SERIAL"}
    netbox = FakeNetBox([renamed, unchanged, conflict])

    def ap(name, serial, model="AP-515", up=True, version=""):
        return {
            "mac_address": "20:4c:03:aa:01:01",
            "name": name,
            "model": model,
            "serial": serial,
            "address": "10.20.10.11",
            "group": "floor-1",
            "up": up,
            "software_version": version,
        }

    facts = {
        "manufacturer": "HPE",
        "platform": "ArubaOS",
        "software_version": "8.10.0.4",
        "collected_at": "2026-11-07T00:00:00+00:00",
        "access_points": [
            ap("dal-ap-101", "CNJPJ0A001", version="8.10.0.4_87457"),
            ap("dal-ap-102", "CNJPJ0A002"),
            ap("dal-ap-103", "CNJPJ0B003", model="AP-535", up=False),
            ap("", "", up=False),
            ap("dal-ap-104", "CNJPJ0A004"),
        ],
    }
    controller = {"id": 40, "site": {"id": 1}, "tenant": None, "platform": {"id": 9}}
    with httpx.Client(
        base_url="https://netbox.example/api/", transport=httpx.MockTransport(netbox.handle)
    ) as client:
        result = NetBoxDiscovery(client, lambda: None).sync_access_points(controller, "lab", facts)

    assert (result["status"], result["controller_id"], result["reported"], result["skipped"]) == (
        "warning",
        40,
        5,
        1,
    )
    rows = {row["name"]: row for row in result["access_points"]}
    assert {name: row["status"] for name, row in rows.items()} == {
        "dal-ap-101": "updated",
        "dal-ap-102": "unchanged",
        "dal-ap-103": "created",
        "dal-ap-104": "failed",
    }
    assert rows["dal-ap-104"]["error"] == "Access point dal-ap-104 has a different serial in NetBox"
    writes = [call for call in netbox.calls if call[1] != "plugins/refresh/device-software/report"]
    assert writes == [
        (
            "PATCH",
            "dcim/devices/61",
            {
                "name": "dal-ap-101",
                "custom_fields": {"wireless_controller": 40, "software_version": "8.10.0.4_87457"},
                "description": "AP group floor-1",
                "add_tags": [7],
            },
        ),
        (
            "POST",
            "dcim/devices",
            {
                "site": 1,
                "tenant": None,
                "role": 5,
                "platform": 9,
                "tags": [7, 8],
                "name": "dal-ap-103",
                "device_type": 42,
                "serial": "CNJPJ0B003",
                "status": "offline",
                "description": "AP group floor-1",
                "custom_fields": {"wireless_controller": 40, "software_version": "8.10.0.4"},
            },
        ),
    ]
    reports = [call[2] for call in netbox.calls if call[1] == "plugins/refresh/device-software/report"]
    assert [(report["device"], report["version"]) for report in reports] == [
        (61, "8.10.0.4_87457"),
        (62, "8.10.0.4"),
        (rows["dal-ap-103"]["device_id"], "8.10.0.4"),
    ]
    assert rows["dal-ap-101"]["software_inventory"] == {"status": "created", "id": 1061}
