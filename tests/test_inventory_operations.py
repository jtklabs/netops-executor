import asyncio
import json

import httpx
import pytest

from netops_executor import netbox_operations
from netops_executor.inventory_enrichment import collect_enrichment, parse_ha
from netops_executor.inventory_licenses import date_value, parse_licenses
from netops_executor.snmp_neighbors import CDP, LLDP_LOCAL, LLDP_REMOTE, collect_neighbors


@pytest.mark.parametrize(
    "vendor,output,product,expiry",
    [
        (
            "Arista",
            "License feature: IPSec\nCount: 1\nExpiration: 2027-02-03 00:00:00\nActive: yes\n",
            "IPSec",
            "2027-02-03",
        ),
        (
            "Palo Alto Networks",
            "License entry:\nFeature: Threat Prevention\nExpires: March 08, 2027\n",
            "Threat Prevention",
            "2027-03-08",
        ),
        (
            "Cisco",
            "License Usage:\nc9300 Network Advantage (C9300-48 Network Advantage) 1 IN USE\n",
            "c9300 Network Advantage",
            None,
        ),
        ("Cisco", "Index 1 Feature: ipservices\n License State: Active, In Use\n", "ipservices", None),
        ("Cisco", "LAN_ENTERPRISE_SERVICES_PKG Yes 1 In use Never -\n", "LAN_ENTERPRISE_SERVICES_PKG", None),
        ("Juniper", "Feature name used installed needed Expiry\nbgp 0 1 0 permanent\n", "bgp", None),
        (
            "Fortinet",
            "IPS Attack Engine\nVersion: 7.0\nContract Expiry Date: 2027-01-02\n",
            "IPS Attack Engine",
            "2027-01-02",
        ),
        (
            "Infoblox",
            "License Type : DNS\nExpiration Date : 05/13/2027\nLicense String : SENSITIVE-KEY\n",
            "DNS",
            "2027-05-13",
        ),
        ("HPE", "AP  Access Points  Enabled  Never  16\n", "Access Points", None),
    ],
)
def test_license_products_and_dates_exclude_keys(vendor, output, product, expiry):
    rows = parse_licenses(vendor, output)
    assert rows[0]["product"] == product
    assert rows[0]["reported_expiration"] == expiry
    assert "SENSITIVE-KEY" not in json.dumps(rows)
    assert rows[0]["reference"] == ""


def test_license_dates_do_not_confuse_database_updates_with_contract_expiry():
    assert parse_licenses("Fortinet", "Virus-DB: 99.9 (2026-01-01)\n") == []
    assert date_value("Never") is None
    assert date_value("2027-13-01") is None


def test_lldp_local_port_number_is_not_assumed_to_be_ifindex():
    columns = {
        LLDP_REMOTE + ".9": [("100.77.1", "peer-a")],
        LLDP_LOCAL + ".3": [("77", "Ethernet3")],
        LLDP_REMOTE + ".7": [("100.77.1", "xe-0/0/2")],
        CDP + ".6": [("123.1", "peer-b")],
        CDP + ".7": [("123.1", "GigabitEthernet1/0/1")],
        "1.3.6.1.2.1.31.1.1.1.1": [("123", "Ethernet9")],
    }

    async def walk(root, **kwargs):
        assert kwargs["limit"] == 2000
        for row in columns[root]:
            yield row

    rows = asyncio.run(collect_neighbors(walk, cisco=True))
    assert rows[0] == {
        "kind": "lldp",
        "peer_name": "peer-a",
        "local_interface": "Ethernet3",
        "peer_interface": "xe-0/0/2",
    }
    assert rows[1]["local_interface"] == "Ethernet9"


def test_ha_does_not_treat_unknown_state_as_healthy():
    peers, check = parse_ha("Arista", json.dumps({"state": "active", "peerAddress": "192.0.2.2"}))
    assert peers[0]["peer_address"] == "192.0.2.2"
    assert check["status"] == "failed"
    assert parse_ha("Arista", '{"state":"disabled"}')[1]["status"] == "not_applicable"


def test_enrichment_without_eligible_credentials_is_explicitly_skipped(settings, store):
    result = collect_enrichment(
        settings,
        store,
        "192.0.2.99",
        {"manufacturer": "Arista", "platform": "Arista EOS"},
        "job-1",
        lambda: None,
        lambda data: None,
    )
    assert result["components"]["licenses"]["status"] == "skipped"
    assert result["readiness"] == {}


def test_enrichment_failure_keeps_raw_license_output_private(settings, store, monkeypatch):
    from netops_executor import inventory_enrichment as module
    from netops_executor.config import Device
    from netops_executor.ssh import DeviceError

    monkeypatch.setattr(module, "target_for", lambda *args: Device(id="a", host="192.0.2.1"))

    class BrokenSSH:
        def __init__(self, *args, **kwargs):
            pass

        def execute(self, *args, **kwargs):
            raise DeviceError("SENSITIVE-LICENSE-KEY")

        def connect(self):
            raise DeviceError("SENSITIVE-PASSWORD")

        def close(self):
            pass

    monkeypatch.setattr(module, "NetworkSSH", BrokenSSH)
    result = collect_enrichment(
        settings, store, "192.0.2.1", {"manufacturer": "Arista"}, "job-1", lambda: None, lambda data: None
    )
    assert "SENSITIVE" not in json.dumps(result)
    assert result["components"]["readiness"]["status"] == "failed"


def test_observation_publishes_manual_and_inferred_provenance_without_license_key(settings, monkeypatch):
    settings.netbox_url, settings.netbox_token = "https://netbox.example", "x" * 40
    sent = []

    def handle(request):
        assert request.url.path == "/api/plugins/refresh/observations/report/"
        sent.append(json.loads(request.content))
        return httpx.Response(
            201,
            json={
                "id": 1,
                "status": "partial",
                "changes": [{"field": "software_version", "before": "1", "after": "2"}],
            },
        )

    from netops_executor.netbox_discovery import netbox_client

    monkeypatch.setattr(
        netbox_operations,
        "netbox_client",
        lambda s: httpx.Client(base_url=s.netbox_url + "/api/", transport=httpx.MockTransport(handle)),
    )
    discovery = {
        "name": "a",
        "manufacturer": "Arista",
        "model": "DCS-7050",
        "serial": "SERIAL-A",
        "software_version": "2",
        "poller_instance": "checkmk-us",
        "collected_at": "2026-11-12T00:00:00Z",
        "field_sources": {"model": "manual"},
        "management_ip": {
            "address": "192.0.2.1/32",
            "interface": "discovery-management",
            "prefix_source": "host",
            "interface_source": "placeholder",
        },
        "license_lookup": {"status": "succeeded", "key": "SENSITIVE-KEY"},
    }
    result = netbox_operations.report_observation(
        settings, "job-1", 1, discovery, {"components": {}, "readiness": {}}, lambda: None
    )
    assert result["status"] == "success"
    assert result["collection_status"] == "partial"
    assert sent[0]["field_sources"]["model"] == "manual"
    assert sent[0]["field_sources"]["management_interface"] == "inferred"
    assert sent[0]["executor_version"]
    assert "SENSITIVE-KEY" not in json.dumps(sent)
    assert netbox_client  # Keep the production writer independently testable.
