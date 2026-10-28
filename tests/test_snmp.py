import asyncio
import base64
import json

import pytest
from fastapi.testclient import TestClient
from pysnmp.proto import rfc1902
from pysnmp.proto.errind import RequestTimedOut

from netops_executor import snmp
from netops_executor.api import create_app
from netops_executor.snmp_models import SnmpProfile, SnmpWalkRequest
from netops_executor.store import LostOwnership
from netops_executor.worker import process

ROOT = "1.3.6.1.2.1.1"
OTHER = "1.3.6.1.2.1.2"


@pytest.fixture
def client(settings):
    settings.snmp_profiles = {
        "default": SnmpProfile(id="default", username="reader", security_level="noAuthNoPriv")
    }
    return TestClient(create_app(settings), headers={"Authorization": "Bearer " + settings.token})


def submit(client, **kwargs):
    response = client.post("/api/v1/snmp/walks", json={"device_ip": "192.0.2.15", "oids": [ROOT], **kwargs})
    assert response.status_code == 202, response.text
    return response.json()


def fake_walk(monkeypatch, results):
    roots = iter(results)

    async def walk(*args, **kwargs):
        assert kwargs == {"lookupMib": False, "lexicographicMode": False, "ignoreNonIncreasingOid": False}
        root = next(roots)
        for entry in results[root]:
            if isinstance(entry, Exception):
                raise entry
            if entry == "timeout":
                await asyncio.sleep(2)
            else:
                yield entry

    monkeypatch.setattr(snmp.snmp, "walk_cmd", walk)


def binding(root, index, value):
    return None, 0, 0, [(rfc1902.ObjectName(root + "." + str(index)), value)]


def test_submission_auth_idempotency_and_openapi(client):
    body = {"device_ip": "2001:0db8::1", "oids": ["." + ROOT]}
    path = "/api/v1/snmp/walks"
    assert client.post(path, json=body, headers={"Authorization": ""}).status_code == 401
    first = client.post(path, json=body, headers={"Idempotency-Key": "walk-1"})
    assert first.status_code == 202
    job = first.json()
    assert job["request"]["device_ip"] == "2001:db8::1"
    assert job["request"]["oids"] == [ROOT]
    assert job["kind"] == "snmp_walk" and job["status"] == "queued"
    assert client.post(path, json=body, headers={"Idempotency-Key": "walk-1"}).json()["id"] == job["id"]
    assert (
        client.post(path, json={**body, "port": 1161}, headers={"Idempotency-Key": "walk-1"}).status_code
        == 409
    )
    assert client.get(path + "/" + job["id"]).status_code == 200
    assert client.get("/api/v1/jobs").json()[0]["kind"] == "snmp_walk"
    assert client.post(f"/api/v1/jobs/{job['id']}/rollback", json={}).status_code == 409
    assert client.get(path + "/missing/results").status_code == 404
    assert client.get(path + "/" + job["id"] + "/results").json()["finished"] is False
    schema = client.get("/openapi.json").json()
    assert "SnmpWalkRequest" in schema["components"]["schemas"]


@pytest.mark.parametrize(
    "change",
    [
        {"device_ip": "hostname"},
        {"device_ip": "fe80::1%en0"},
        {"oids": []},
        {"oids": ["sysDescr"]},
        {"oids": ["1.40.1"]},
        {"oids": ["3.1"]},
        {"oids": ["1.3.4294967296"]},
        {"oids": [ROOT, "." + ROOT]},
        {"oids": ["1.3." + "1." * 127 + "1"]},
        {"oids": ["1.٣"]},
        {"oids": [ROOT] * 65},
        {"profile": "missing"},
        {"max_rows": 100001},
        {"port": 0},
        {"timeout": 0},
        {"job_timeout": 3601},
        {"community": "not-supported"},
    ],
)
def test_validation(client, change):
    assert (
        client.post(
            "/api/v1/snmp/walks", json={"device_ip": "192.0.2.1", "oids": [ROOT], **change}
        ).status_code
        == 422
    )


def test_multiple_roots_and_pagination(client, settings, store, monkeypatch):
    job = submit(client, oids=[ROOT, OTHER])
    fake_walk(
        monkeypatch,
        {
            ROOT: [
                binding(ROOT, 1, rfc1902.OctetString(b"\x00\xffhello")),
                binding(ROOT, 2, rfc1902.Counter64(2**63 + 1)),
            ],
            OTHER: [binding(OTHER, 1, rfc1902.IpAddress("192.0.2.1"))],
        },
    )
    process(settings, store, store.claim("worker"), "worker")
    state = store.get(job["id"])
    assert state["status"] == "succeeded" and not state["lock_held"]
    assert state["result"]["rows"] == 3
    url = f"/api/v1/snmp/walks/{job['id']}/results"
    page = client.get(url, params={"limit": 2}).json()
    assert page["has_more"] and page["finished"]
    assert base64.b64decode(page["rows"][0]["value"]) == b"\x00\xffhello"
    assert page["rows"][1]["value"] == str(2**63 + 1)
    second = client.get(url, params={"after": page["next_cursor"]}).json()
    assert not second["has_more"] and len(second["rows"]) == 1
    assert second["rows"][0]["value"] == "192.0.2.1"
    assert second["rows"][0]["root_oid"] == OTHER
    assert client.get(url, params={"limit": 1001}).status_code == 422
    assert client.get(url, headers={"Authorization": ""}).status_code == 401


def test_partial_error_continues_other_roots(client, settings, store, monkeypatch):
    job = submit(client, oids=[ROOT, OTHER])
    fake_walk(
        monkeypatch,
        {ROOT: [binding(ROOT, 1, rfc1902.Integer32(7)), (RequestTimedOut(), 0, 0, ())], OTHER: []},
    )
    process(settings, store, store.claim("w"), "w")
    state = store.get(job["id"])
    assert state["status"] == "failed" and state["result"]["rows"] == 1
    assert state["result"]["oids"][0]["error"] == "SNMP engine error: RequestTimedOut"
    assert state["result"]["oids"][1]["status"] == "succeeded"


@pytest.mark.parametrize("byte_limit", [False, True])
def test_result_limits_preserve_partial_data(client, settings, store, monkeypatch, byte_limit):
    job = submit(client, max_rows=1, oids=[ROOT, OTHER])
    if byte_limit:
        monkeypatch.setattr(snmp, "MAX_RESULT_BYTES", 1)
    fake_walk(monkeypatch, {ROOT: [binding(ROOT, n, rfc1902.Integer32(n)) for n in (1, 2)]})
    process(settings, store, store.claim("w"), "w")
    state = store.get(job["id"])
    assert state["status"] == "failed" and state["result"]["truncated"]
    assert state["result"]["rows"] == (0 if byte_limit else 1)
    assert state["result"]["oids"][1]["status"] == "skipped"


def test_timeout_and_secret_redaction(client, settings, store, monkeypatch):
    job = submit(client, job_timeout=1)
    fake_walk(monkeypatch, {ROOT: [binding(ROOT, 1, rfc1902.Integer32(1)), "timeout"]})
    process(settings, store, store.claim("w"), "w")
    assert store.get(job["id"])["result"]["error"] == "job timeout exceeded"
    assert len(store.snmp_results(job["id"])["rows"]) == 1
    other = submit(client)
    fake_walk(monkeypatch, {ROOT: [RuntimeError("password=must-not-be-logged")]})
    process(settings, store, store.claim("w"), "w")
    saved = json.dumps(store.get(other["id"])) + json.dumps(store.events(other["id"]))
    assert "must-not-be-logged" not in saved
    assert store.get(other["id"])["status"] == "failed"


def test_stale_walk_fenced_and_released(client, store):
    job = submit(client)
    store.claim("old")
    row = snmp.serialize(ROOT, rfc1902.ObjectName(ROOT + ".1"), rfc1902.Integer32(1))
    store.append_snmp_rows(job["id"], "old", [row], {"rows": 1})
    with store.connect() as db:
        db.execute("UPDATE jobs SET heartbeat=0 WHERE id=?", (job["id"],))
    store.reap(120)
    state = store.get(job["id"])
    assert state["status"] == "failed" and not state["lock_held"]
    with pytest.raises(LostOwnership):
        store.append_snmp_rows(job["id"], "old", [row], {})
    assert len(store.snmp_results(job["id"])["rows"]) == 1
    new = submit(client)
    assert store.claim("new")["id"] == new["id"]


def test_target_lock_and_other_workers(client, store):
    first = submit(client)
    second = submit(client)
    third = submit(client, device_ip="192.0.2.16")
    assert store.claim("a")["id"] == first["id"]
    assert store.claim("b")["id"] == third["id"]
    assert store.claim("c") is None
    store.finish(first["id"], "a", "succeeded")
    assert store.claim("c")["id"] == second["id"]


def test_v3_profiles_and_credentials(monkeypatch):
    with pytest.raises(ValueError):
        SnmpProfile(id="default", username="reader")
    profile = SnmpProfile(
        id="default", username="reader", auth_password_env="SNMP_AUTH", priv_password_env="SNMP_PRIV"
    )
    with pytest.raises(snmp.WalkError):
        snmp.credentials(profile)
    monkeypatch.setenv("SNMP_AUTH", "test-auth-password")
    monkeypatch.setenv("SNMP_PRIV", "test-priv-password")
    auth = snmp.credentials(profile)
    assert auth.security_level == "authPriv"
    assert auth.authentication_protocol == snmp.snmp.usmHMAC192SHA256AuthProtocol
    assert auth.privacy_protocol == snmp.snmp.usmAesCfb128Protocol
    assert "test-auth-password" not in profile.model_dump_json()
    assert SnmpWalkRequest(device_ip="192.0.2.1", oids=[".01.03.6"]).oids == ["1.3.6"]


def test_config_profile_file(settings, monkeypatch, tmp_path):
    from netops_executor.config import Settings

    inventory = tmp_path / "devices.json"
    inventory.write_text("[]")
    profiles = tmp_path / "profiles.json"
    profile = {"id": "default", "username": "reader", "security_level": "noAuthNoPriv"}
    profiles.write_text(json.dumps([profile]))
    monkeypatch.setenv("F5_ENV_FILE", str(tmp_path / "absent.env"))
    monkeypatch.setenv("F5_API_TOKEN", settings.token)
    monkeypatch.setenv("F5_DEVICES_FILE", str(inventory))
    monkeypatch.setenv("F5_DATA_DIR", str(settings.data_dir))
    monkeypatch.setenv("F5_BACKUP_ROOT", str(settings.backup_root))
    monkeypatch.setenv("F5_SNMP_PROFILES_FILE", str(profiles))
    assert Settings.load().snmp_profiles["default"].username == "reader"
    profiles.write_text(json.dumps([profile, profile]))
    with pytest.raises(ValueError, match="duplicate SNMP"):
        Settings.load()
    monkeypatch.delenv("F5_SNMP_PROFILES_FILE")
    assert Settings.load().snmp_profiles == {}


def test_live_pagination_isolation_and_cancel(client, store):
    first, second = submit(client), submit(client, device_ip="192.0.2.20")
    store.claim("a")
    store.claim("b")
    row = snmp.serialize(ROOT, rfc1902.ObjectName(ROOT + ".1"), rfc1902.Integer32(7))
    store.append_snmp_rows(first["id"], "a", [row], {"rows": 1})
    assert not store.snmp_results(second["id"])["rows"]
    live = store.snmp_results(first["id"])
    assert not live["finished"] and not live["has_more"]
    store.append_snmp_rows(first["id"], "a", [row], {"rows": 2})
    store.finish(first["id"], "a", "succeeded")
    last = store.snmp_results(first["id"], live["next_cursor"])
    assert last["finished"] and len(last["rows"]) == 1
    assert last["rows"][0]["seq"] > live["next_cursor"]
    third = submit(client)
    assert client.post(f"/api/v1/jobs/{third['id']}/cancel").status_code == 200
    cancelled = store.snmp_results(third["id"])
    assert cancelled["finished"] and cancelled["status"] == "cancelled"


def test_pdu_error(client, settings, store, monkeypatch):
    job = submit(client)
    fake_walk(monkeypatch, {ROOT: [(None, 5, 1, ())]})
    process(settings, store, store.claim("w"), "w")
    result = store.get(job["id"])
    assert result["status"] == "failed"
    assert result["result"]["oids"][0]["error"] == "SNMP PDU error 5 at binding 1"
