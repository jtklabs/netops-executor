import asyncio

import pytest
from pydantic import ValidationError
from pysnmp.proto import rfc1902
from pysnmp.proto.errind import RequestTimedOut
from test_snmp import FakeAgent
from test_snmp import client as snmp_client

from netops_executor.discovery_overrides import (
    IdentityRule,
    ManualFallback,
    apply_manual_fallback,
    apply_rules,
    load_rules,
    matches,
)
from netops_executor.netbox_discovery import NetBoxDiscovery
from netops_executor.snmp_identity import SYS_DESCR, SYS_NAME, SYS_OBJECT_ID
from netops_executor.snmp_models import SnmpWalkRequest
from netops_executor.worker import process


@pytest.fixture
def client(settings):
    return snmp_client.__wrapped__(settings)


def rule(**kwargs):
    return IdentityRule.model_validate(
        {
            "id": "srx-model",
            "match": {"manufacturer": "Juniper"},
            "fields": {"model": {"oid": "1.3.6.1.4.1.2636.99.1", "regex": r"Chassis (SRX\d+)", "group": 1}},
            **kwargs,
        }
    )


def test_get_walk_regex_precedence_and_manual_blanks():
    async def get(oids):
        return {oids[0]: "Chassis SRX5800"}

    async def walk(root, **kwargs):
        assert kwargs["limit"] == 256
        for row in ("Routing Engine", "Chassis SRX5800"):
            yield "1", row

    facts = {"manufacturer": "Juniper", "model": ""}
    asyncio.run(apply_rules(facts, {}, "192.0.2.58", get, walk, [rule()]))
    assert facts["model"] == "SRX5800"
    assert facts["field_sources"]["model"] == "observed"
    assert facts["identity_rules"][0]["status"] == "applied"
    asyncio.run(apply_rules(facts, {}, "192.0.2.58", get, walk, [rule()]))
    assert facts["identity_rules"] == []  # Fallback does not replace an existing reading.
    facts["model"] = ""
    walk_rule = rule(
        fields={
            "model": {
                "oid": "1.3.6.1.4.1.2636.99",
                "walk": True,
                "regex": r"Chassis (?P<model>SRX\d+)",
                "group": "model",
            }
        }
    )
    asyncio.run(apply_rules(facts, {}, "192.0.2.58", get, walk, [walk_rule]))
    apply_manual_fallback(facts, ManualFallback(model="WRONG", serial="MANUAL-SERIAL"))
    assert facts["model"] == "SRX5800"
    assert facts["serial"] == "MANUAL-SERIAL"
    assert facts["field_sources"]["serial"] == "manual"


def test_match_conditions_use_oid_arc_boundaries_and_all_conditions():
    r = rule(
        match={
            "sys_object_id_prefix": "1.3.6.1.4.1.2636",
            "network": "192.0.2.0/24",
            "sys_descr_regex": "(?i)srx",
        }
    )
    assert matches(r, {}, {"sysObjectID": "1.3.6.1.4.1.2636.1", "sysDescr": "SRX5800"}, "192.0.2.58")
    assert not matches(r, {}, {"sysObjectID": "1.3.6.1.4.1.26360.1", "sysDescr": "SRX5800"}, "192.0.2.58")
    assert not matches(r, {}, {"sysObjectID": "1.3.6.1.4.1.2636.1", "sysDescr": "SRX5800"}, "198.51.100.1")


@pytest.mark.parametrize(
    "changes",
    [
        {"fields": {"model": {"oid": "not-an-oid"}}},
        {"match": {}},
        {"fields": {"model": {"source": "sysDescr", "regex": "("}}},
        {"fields": {"model": {"source": "sysDescr", "regex": "(SRX)", "group": "absent"}}},
        {"fields": {"password": {"value": "no"}}},
        {"fields": {"model": {"value": "SRX", "oid": "1.3.6"}}},
    ],
)
def test_invalid_rules_are_rejected(changes):
    with pytest.raises(ValidationError):
        rule(**changes)


def test_yaml_validation_reload_and_duplicate_keys(tmp_path):
    path = tmp_path / "overrides.yaml"
    path.write_text(
        "version: 1\nrules:\n  - id: juniper-model\n    match:\n      manufacturer: Juniper\n    fields:\n      model:\n        value: SRX5800\n"
    )
    rules, before = load_rules(path)
    assert rules[0].fields["model"].value == "SRX5800"
    path.write_text(path.read_text().replace("5800", "5600"))
    rules, after = load_rules(path)
    assert before != after
    assert rules[0].fields["model"].value == "SRX5600"
    path.write_text("version: 1\nversion: 1\nrules: []")
    with pytest.raises(ValueError, match="Invalid discovery overrides"):
        load_rules(path)
    path.write_text("!!python/object/apply:os.system [echo INVALID]")
    with pytest.raises(ValueError):
        load_rules(path)


def test_regex_timeout_preserves_identity():
    r = rule(fields={"model": {"source": "sysDescr", "regex": "(a+)+$", "group": 1}}, mode="replace")
    facts = {"manufacturer": "Juniper", "model": "SRX5800"}
    asyncio.run(apply_rules(facts, {"sysDescr": "a" * 8000 + "!"}, "192.0.2.58", None, None, [r]))
    assert facts["model"] == "SRX5800"
    assert facts["identity_rules"][0]["status"] == "failed"


def test_srx_oid_rule_creates_device_without_builtin_model(client, settings, store, monkeypatch):
    from netops_executor import snmp

    settings.netbox_url, settings.netbox_token, settings.poller_instance = (
        "https://netbox.example",
        "x" * 40,
        "checkmk-us",
    )
    FakeAgent(
        monkeypatch,
        {
            SYS_NAME: rfc1902.OctetString("srx-58"),
            SYS_DESCR: rfc1902.OctetString("JUNOS 23.4R2"),
            SYS_OBJECT_ID: rfc1902.ObjectName("1.3.6.1.4.1.2636.1.1"),
            "1.3.6.1.4.1.2636.99.1": rfc1902.OctetString("Chassis SRX5800"),
        },
    )
    seen = []
    monkeypatch.setattr(
        snmp,
        "sync_device",
        lambda s, site, poller, address, facts, checkpoint: seen.append(dict(facts)) or ("created", 58),
    )
    job = client.post(
        "/api/v1/snmp/walks",
        json={"device_ip": "192.0.2.58", "site": "Lab", "identity_rules": [rule().model_dump()]},
    ).json()
    process(settings, store, store.claim("worker"), "worker")
    result = store.get(job["id"])
    assert result["status"] == "completed_with_warnings"  # No serial supplied.
    assert seen[0]["model"] == "SRX5800"
    assert seen[0]["field_sources"]["model"] == "observed"
    assert seen[0]["polled"] is True


def test_failed_poll_can_seed_manual_identity_without_claiming_discovery(
    client, settings, store, monkeypatch
):
    from netops_executor import snmp

    settings.netbox_url, settings.netbox_token, settings.poller_instance = (
        "https://netbox.example",
        "x" * 40,
        "checkmk-us",
    )
    FakeAgent(monkeypatch, {}, script={i: (RequestTimedOut(), 0, 0, ()) for i in range(1, 20)})
    seen = []
    monkeypatch.setattr(
        snmp,
        "sync_device",
        lambda s, site, poller, address, facts, checkpoint: seen.append(dict(facts)) or ("created", 58),
    )
    job = client.post(
        "/api/v1/snmp/walks",
        json={
            "device_ip": "192.0.2.58",
            "site": "Lab",
            "manual_fallback": {"name": "srx-58", "manufacturer": "Juniper", "model": "SRX5800"},
        },
    ).json()
    process(settings, store, store.claim("worker"), "worker")
    result = store.get(job["id"])
    assert result["status"] == "failed"
    assert result["result"]["discovery"]["netbox"] == {"status": "created", "device_id": 58}
    assert seen[0]["polled"] is False
    assert seen[0]["field_sources"]["model"] == "manual"
    assert seen[0]["management_ip"]["address"] == "192.0.2.58/32"


def test_manual_identity_validation():
    with pytest.raises(ValidationError):
        SnmpWalkRequest(device_ip="192.0.2.58", manual_fallback={"model": "SRX5800"}, get_oids=["1.3.6.1"])
    with pytest.raises(ValidationError):
        ManualFallback(name="   ")
    with pytest.raises(ValidationError):
        ManualFallback(serial="bad\nvalue")


@pytest.mark.parametrize(
    "polled,existing,expected_discovered", [(False, False, False), (True, False, True), (True, True, True)]
)
def test_manual_seed_tag_and_later_promotion(polled, existing, expected_discovered, monkeypatch):
    writer = NetBoxDiscovery(None, lambda: None)
    monkeypatch.setattr(writer, "custom_field", lambda *a: None)
    monkeypatch.setattr(
        writer,
        "named_object",
        lambda path, name, *args: {"id": 8 if name == "discovered" else 7, "slug": name},
    )
    monkeypatch.setattr(writer, "device_type", lambda *a: {"id": 4})
    current = (
        {
            "id": 58,
            "name": "srx-58",
            "serial": "",
            "role": {"slug": "firewall"},
            "site": {"id": 7},
            "device_type": {"id": 4},
            "platform": None,
            "custom_fields": {"inventory_poll_status": "unpolled"},
            "tags": [{"id": 7}],
        }
        if existing
        else None
    )
    monkeypatch.setattr(writer, "device", lambda *a: current)
    calls = []
    monkeypatch.setattr(
        writer, "request", lambda method, path, **kwargs: calls.append(kwargs["json"]) or {"id": 58}
    )
    facts = {
        "name": "srx-58",
        "manufacturer": "Juniper",
        "model": "SRX5800",
        "platform": "",
        "serial": "",
        "software_version": "",
        "field_sources": {"model": "manual" if not polled else "observed"},
        "polled": polled,
    }
    writer.sync_inventory("Lab", "checkmk-us", "192.0.2.58", facts)
    body = calls[-1]
    assert (8 in body.get("tags", body.get("add_tags", []))) == expected_discovered
    if not polled:
        assert body["status"] == "planned"
    assert body["custom_fields"]["inventory_poll_status"] == ("polled" if polled else "unpolled")
