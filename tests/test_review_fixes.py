"""Regression tests for the 0.26.0 review: discovery data integrity."""

import json
from ipaddress import ip_address
from types import SimpleNamespace

import httpx

from netops_executor import netbox_operations
from netops_executor.discovery_overrides import ManualFallback
from netops_executor.inventory_licenses import date_value, parse_licenses
from netops_executor.netbox_discovery import NetBoxDiscovery, SyncError
from netops_executor.snmp import SnmpRunner

POLLER = {"id": 7, "name": "checkmk-au", "slug": "checkmk-au"}


def client(handle):
    return httpx.Client(base_url="https://netbox.example/api/", transport=httpx.MockTransport(handle))


def test_own_ip_record_in_another_vrf_is_reused_not_duplicated():
    calls = []

    def handle(request):
        path = request.url.path.removeprefix("/api/").strip("/")
        if request.method == "GET":
            if path == "dcim/interfaces":
                rows = [{"id": 147, "name": "Gi0/0", "vrf": None}]
            else:
                # The device's address is recorded in VRF 20; its interface has no VRF.
                rows = [
                    {
                        "id": 2,
                        "vrf": {"id": 20},
                        "address": "192.0.2.15/24",
                        "assigned_object_type": "dcim.interface",
                        "assigned_object_id": 147,
                        "assigned_object": {"id": 147, "device": {"id": 6}},
                        "tags": [{"id": 7}],
                    }
                ]
            return httpx.Response(200, json={"results": rows, "next": None})
        calls.append((request.method, path, json.loads(request.content)))
        return httpx.Response(200, json={})

    with client(handle) as http:
        changed = NetBoxDiscovery(http, lambda: None).assign_primary_ip(
            {"id": 6, "primary_ip4": {"id": 2}},
            {"interface": "Gi0/0", "address": "192.0.2.15/24", "dhcp": False},
            POLLER,
        )
    assert changed is False and calls == []


def test_blank_snmp_reading_kept_from_netbox_is_not_relabelled_as_observed():
    rows = {
        "extras/custom-fields": [
            {"name": name, "object_types": ["dcim.device"], "type": {"value": kind}}
            for name, kind in (
                ("software_version", "text"),
                ("snmp_discovery_ip", "text"),
                ("discovery_poller", "text"),
                ("inventory_field_sources", "json"),
                ("inventory_poll_status", "text"),
            )
        ],
        "dcim/sites": [{"id": 1, "name": "Lab", "slug": "lab"}],
        "extras/tags": [POLLER, {"id": 8, "name": "discovered", "slug": "discovered"}],
        "dcim/manufacturers": [{"id": 3, "name": "Cisco", "slug": "cisco"}],
        "dcim/device-types": [{"id": 4, "model": "Catalyst 9300-48P", "part_number": "C9300-48P"}],
        "dcim/devices": [
            {
                "id": 11,
                "name": "sw1",
                "serial": "FOC1",
                "site": {"id": 1},
                "device_type": {"id": 4},
                "role": {"slug": "switch"},
                "platform": {"id": 9},
                "status": {"value": "active"},
                "custom_fields": {
                    "snmp_discovery_ip": "192.0.2.1",
                    "discovery_poller": "checkmk-au",
                    "software_version": "17.9.1",
                    "inventory_field_sources": {"software_version": "observed"},
                    "inventory_poll_status": "polled",
                },
                "tags": [{"id": 7}, {"id": 8}],
            }
        ],
    }

    def handle(request):
        path = request.url.path.removeprefix("/api/").strip("/")
        if request.method == "GET":
            return httpx.Response(200, json={"results": rows[path], "next": None})
        return httpx.Response(200, json={"id": 11})

    # SNMP returned a blank version; manual fallback filled it.
    facts = {
        "name": "sw1",
        "manufacturer": "Cisco",
        "model": "C9300-48P",
        "serial": "FOC1",
        "software_version": "manual-version",
        "field_sources": {"software_version": "manual", "serial": "observed"},
    }
    with client(handle) as http:
        NetBoxDiscovery(http, lambda: None).sync_inventory("Lab", "checkmk-au", "192.0.2.1", facts)
    assert facts["software_version"] == "17.9.1"
    # Not "observed": it would be reported to Lifecycle as a fresh reading.
    assert facts["field_sources"]["software_version"] == "netbox-existing"


def test_ip_assignment_failure_is_reported_and_the_rest_of_the_sync_runs(monkeypatch):
    def handle(request):
        return httpx.Response(200, json={"results": [POLLER], "next": None})

    with client(handle) as http:
        discovery = NetBoxDiscovery(http, lambda: None)
        monkeypatch.setattr(discovery, "sync_inventory", lambda *args: ("created", {"id": 6}))

        def refuse(*args):
            raise SyncError("NetBox refused another IP record for the polled address")

        monkeypatch.setattr(discovery, "assign_primary_ip", refuse)
        facts = {
            "management_ip": {"interface": "eth0", "address": "192.0.2.1/24", "dhcp": False},
            "software_version": "",
        }
        assert discovery.sync("Lab", "checkmk-au", "192.0.2.1", facts) == ("created", 6)
    assert facts["management_ip_sync"] == {
        "status": "failed",
        "error": "NetBox refused another IP record for the polled address",
    }


def test_observation_omits_a_ve_chassis_serial_fallback(settings, monkeypatch):
    settings.netbox_url, settings.netbox_token = "https://netbox.example", "x" * 40
    sent = []

    def handle(request):
        sent.append(json.loads(request.content))
        return httpx.Response(201, json={"id": 1, "status": "success", "changes": []})

    monkeypatch.setattr(netbox_operations, "netbox_client", lambda s: client(handle))
    discovery = {
        "name": "bigip",
        "manufacturer": "F5",
        "model": "BIG-IP Virtual Edition",
        "serial": "chassis-uuid",
        "serial_source": "snmp",
        "software_version": "17.5.1",
        "poller_instance": "checkmk-au",
        "collected_at": "2026-11-12T00:00:00Z",
    }
    netbox_operations.report_observation(
        settings, "job-1", 1, discovery, {"components": {}, "readiness": {}}, lambda: None
    )
    assert "chassis-uuid" not in json.dumps(sent)


def test_same_product_licenses_merge_instead_of_overwriting():
    merged = netbox_operations.merge_products(
        [
            {
                "product": "IPS",
                "reference": "",
                "reported_expiration": "2026-01-01",
                "installed_modules": ["a"],
            },
            {
                "product": "IPS",
                "reference": "",
                "reported_expiration": "2027-01-01",
                "installed_modules": ["b"],
            },
            {"product": "AV", "reference": "", "reported_expiration": None, "installed_modules": ["c"]},
        ]
    )
    assert [(m["product"], m["reported_expiration"], m["installed_modules"]) for m in merged] == [
        ("IPS", "2027-01-01", ["a", "b"]),
        ("AV", None, ["c"]),
    ]


def test_fortigate_license_expiration_and_contract_dates_parse():
    found = parse_licenses("Fortinet", "License Status: Valid\nLicense Expiration Date: 2027-03-01\n")
    assert found[0]["reported_expiration"] == "2027-03-01"
    assert date_value("Mon Jan  1 2024") == "2024-01-01"


def test_seed_after_a_partial_ve_poll_never_replaces_the_license_serial():
    runner = object.__new__(SnmpRunner)
    runner.request = SimpleNamespace(
        manual_fallback=ManualFallback(name="bigip"),
        device_ip=ip_address("192.0.2.15"),
        site="Lab",
        poller_instance="checkmk-au",
    )
    # The poll timed out after identity: the VE's chassis serial was read, not its license.
    runner.result = {
        "discovery": {"manufacturer": "F5", "model": "BIG-IP Virtual Edition", "serial": "chassis-uuid"}
    }
    runner.seed_manual_inventory()
    assert runner.result["discovery"]["serial_source"] == "snmp"


def test_preferred_image_ignores_rows_for_other_devices(settings, monkeypatch):
    settings.netbox_url, settings.netbox_token = "https://netbox.example", "x" * 40
    rows = [{"device": {"id": 99}, "preferred_version": {"name": "other-device-image"}}]

    def handle(request):
        return httpx.Response(200, json={"results": rows, "next": None})

    monkeypatch.setattr(netbox_operations, "netbox_client", lambda s: client(handle))
    # A plugin that ignored the device filter returned another device's readiness row.
    assert netbox_operations.preferred_image(settings, 6, lambda: None) is None
    rows.append({"device": {"id": 6}, "preferred_version": {"name": "mine"}})
    assert netbox_operations.preferred_image(settings, 6, lambda: None) == {"name": "mine"}


def test_tmsh_login_shell_runs_writes_directly_and_refuses_secrets(settings, monkeypatch):
    import pytest

    from netops_executor.config import Device
    from netops_executor.ssh import SSH, DeviceError

    ssh = SSH(settings, Device(id="bigip", host="192.0.2.1"))
    sent = []
    monkeypatch.setattr(
        ssh, "shell", lambda command, timeout, stdin=None, diagnostics=False: sent.append(command)
    )
    ssh.f5_shell_type = "tmsh"  # detected by an earlier read on this connection
    ssh.tmsh("save /sys config")
    assert sent == ["save /sys config"]  # not wrapped in `tmsh -q -c`, which tmsh cannot run
    with pytest.raises(DeviceError, match="bash"):
        ssh.tmsh("save /sys ucs x passphrase y", secret=True)
    assert sent == ["save /sys config"]
    ssh.f5_shell_type = "bash"
    ssh.tmsh("save /sys config")
    assert sent[-1] == "tmsh -q -c 'save /sys config'"


class FakeCLI:
    def __init__(self, connect_error=None, host_key_status="pinned", outputs=None):
        self.connect_error, self.host_key_status = connect_error, host_key_status
        self.outputs, self.connects = outputs or {}, 0

    def __call__(self, *args, **kwargs):
        return self

    def connect(self):
        self.connects += 1
        if self.connect_error:
            raise self.connect_error

    def execute(self, command, timeout=30):
        from netops_executor.ssh import DeviceError

        if command not in self.outputs:
            raise DeviceError("not recognized")
        return {"stdout": self.outputs[command], "cli_error": False}

    def close(self):
        pass


def enrich(settings, store, monkeypatch, fake, vendor, backup=False):
    from netops_executor import inventory_enrichment as module
    from netops_executor.config import Device

    monkeypatch.setattr(module, "target_for", lambda *args: Device(id="a", host="192.0.2.1"))
    monkeypatch.setattr(module, "NetworkSSH", fake)
    return module.collect_enrichment(
        settings,
        store,
        "192.0.2.1",
        {"manufacturer": vendor},
        "job-1",
        lambda: None,
        lambda d: None,
        backup=backup,
    )


def test_enrichment_stops_once_at_a_changed_host_key(settings, store, monkeypatch):
    from netops_executor.ssh import HostKeyChangedError

    fake = FakeCLI(
        connect_error=HostKeyChangedError("SSH host key for 192.0.2.1:22 changed and is not trusted")
    )
    result = enrich(settings, store, monkeypatch, fake, "Arista")
    assert fake.connects == 1
    assert {c["reason"] for c in result["components"].values()} == {
        "SSH host key for 192.0.2.1:22 changed and is not trusted"
    }


def test_readiness_does_not_pass_a_key_pinned_during_this_job(settings, store, monkeypatch):
    result = enrich(settings, store, monkeypatch, FakeCLI(host_key_status="pinned_now"), "Arista")
    assert result["readiness"]["trust"]["status"] == "unknown"
    result = enrich(settings, store, monkeypatch, FakeCLI(host_key_status="known_hosts"), "Arista")
    assert result["readiness"]["trust"]["status"] == "passed"


def test_backup_with_a_redacted_credential_is_not_reported_restorable(settings, store, monkeypatch):
    config = "config system admin\n edit admin\n  set password [REDACTED]\n next\nend\n"
    fake = FakeCLI(outputs={"show full-configuration": config})
    result = enrich(settings, store, monkeypatch, fake, "Fortinet", backup=True)
    assert result["readiness"]["backup"]["status"] == "unknown"
