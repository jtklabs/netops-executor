import asyncio
import base64
import json

import pytest
from fastapi.testclient import TestClient
from pysnmp.proto import rfc1902, rfc1905
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


class FakeAgent:
    """In-memory SNMP agent answering the runner's GET, GETNEXT and GETBULK exchanges."""

    def __init__(self, monkeypatch, values, max_varbinds=None, drop_bulk=False, script=None):
        self.values = sorted((rfc1902.ObjectName(oid), value) for oid, value in values.items())
        self.max_varbinds, self.drop_bulk = max_varbinds, drop_bulk
        # Optional overrides by request number: a response tuple, an exception, or "sleep".
        self.script = script or {}
        self.calls = []
        monkeypatch.setattr(snmp, "request", self.request)

    def successors(self, oid, count):
        found = [(o, v) for o, v in self.values if o > oid][:count]
        return found + [(oid, rfc1905.endOfMibView)] * (count - len(found))

    def answer(self, kind, oids, repetitions):
        if kind == "bulk" and self.drop_bulk:
            return RequestTimedOut(), 0, 0, ()
        size = repetitions if kind == "bulk" else len(oids)
        if self.max_varbinds and size > self.max_varbinds:
            return None, 1, 0, ()
        if kind == "get":
            lookup = dict(self.values)
            return None, 0, 0, [(o, lookup.get(o, rfc1905.noSuchInstance)) for o in oids]
        return None, 0, 0, self.successors(oids[0], repetitions if kind == "bulk" else 1)

    async def request(self, kind, engine, auth, target, context, oids, repetitions=0):
        oids = [rfc1902.ObjectName(str(oid)) for oid in oids]
        self.calls.append((kind, repetitions if kind == "bulk" else None, [str(o) for o in oids]))
        override = self.script.get(len(self.calls))
        if override == "sleep":
            await asyncio.sleep(2)
        elif isinstance(override, Exception):
            raise override
        elif override is not None:
            return override
        return self.answer(kind, oids, repetitions)

    def kinds(self):
        return [kind for kind, _, _ in self.calls]


def rows(root, count, start=1):
    return {f"{root}.{n}": rfc1902.Integer32(n) for n in range(start, start + count)}


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
        {"get_oids": ["sysName.0"]},
        {"get_oids": [ROOT + ".5.0"] * 2},
        {"profile": "missing"},
        {"max_rows": 100001},
        {"port": 0},
        {"timeout": 0},
        {"job_timeout": 3601},
        {"walk_mode": "fast"},
        {"max_repetitions": 0},
        {"max_repetitions": 101},
        {"request_interval": 11},
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
    agent = FakeAgent(
        monkeypatch,
        {
            ROOT + ".1": rfc1902.OctetString(b"\x00\xffhello"),
            ROOT + ".2": rfc1902.Counter64(2**63 + 1),
            OTHER + ".1": rfc1902.IpAddress("192.0.2.1"),
        },
    )
    process(settings, store, store.claim("worker"), "worker")
    state = store.get(job["id"])
    assert state["status"] == "succeeded" and not state["lock_held"]
    assert state["result"]["rows"] == 3
    # One GETBULK per root; the first response runs past ROOT into OTHER and stops at the boundary.
    assert agent.calls == [("bulk", 25, [ROOT]), ("bulk", 25, [OTHER])]
    assert state["result"]["walk"] == {
        "mode": "auto",
        "method": "bulk",
        "max_repetitions": 25,
        "requests": 2,
        "fallbacks": [],
    }
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


def walked(store, job):
    oids = [row["oid"] for row in store.snmp_results(job["id"], limit=1000)["rows"]]
    assert len(oids) == len(set(oids)), "rows were duplicated"
    return oids


def test_bulk_size_shrinks_on_too_big_and_carries_to_later_roots(client, settings, store, monkeypatch):
    job = submit(client, oids=[ROOT, OTHER])
    agent = FakeAgent(monkeypatch, {**rows(ROOT, 30), **rows(OTHER, 4)}, max_varbinds=5)
    process(settings, store, store.claim("w"), "w")
    state = store.get(job["id"])
    assert state["status"] == "succeeded", state["result"]
    assert len(walked(store, job)) == 34
    walk = state["result"]["walk"]
    assert [f["max_repetitions"] for f in walk["fallbacks"]] == [12, 6, 3]
    assert {f["reason"] for f in walk["fallbacks"]} == {"tooBig"}
    assert walk["method"] == "bulk" and walk["max_repetitions"] == 3
    assert ("bulk", 3, [OTHER]) in agent.calls and ("bulk", 25, [OTHER]) not in agent.calls


def test_auto_mode_falls_back_to_getnext_when_bulk_is_dropped(client, settings, store, monkeypatch):
    job = submit(client)
    agent = FakeAgent(monkeypatch, rows(ROOT, 3), drop_bulk=True)
    process(settings, store, store.claim("w"), "w")
    state = store.get(job["id"])
    assert state["status"] == "succeeded", state["result"]
    assert len(walked(store, job)) == 3
    # One unanswered GETBULK, then GETNEXT only.
    assert agent.kinds() == ["bulk", "next", "next", "next", "next"]
    assert state["result"]["walk"]["method"] == "next"
    assert state["result"]["walk"]["fallbacks"] == [
        {"reason": "timeout", "oid": ROOT, "max_repetitions": None}
    ]


def test_unreachable_agent_fails_after_one_getnext_attempt(client, settings, store, monkeypatch):
    job = submit(client)
    agent = FakeAgent(monkeypatch, {}, script={n: (RequestTimedOut(), 0, 0, ()) for n in range(1, 10)})
    process(settings, store, store.claim("w"), "w")
    state = store.get(job["id"])
    assert state["status"] == "failed"
    assert state["result"]["oids"][0]["error"] == "SNMP engine error: RequestTimedOut"
    assert agent.kinds() == ["bulk", "next"]


def test_bulk_mode_never_switches_to_getnext(client, settings, store, monkeypatch):
    job = submit(client, walk_mode="bulk")
    agent = FakeAgent(monkeypatch, rows(ROOT, 3), drop_bulk=True)
    process(settings, store, store.claim("w"), "w")
    assert store.get(job["id"])["status"] == "failed"
    assert agent.kinds() == ["bulk"]


def test_next_mode_uses_getnext_only(client, settings, store, monkeypatch):
    job = submit(client, walk_mode="next", max_repetitions=50)
    agent = FakeAgent(monkeypatch, rows(ROOT, 2))
    process(settings, store, store.claim("w"), "w")
    state = store.get(job["id"])
    assert state["status"] == "succeeded" and len(walked(store, job)) == 2
    assert set(agent.kinds()) == {"next"}
    assert state["result"]["walk"]["method"] == "next" and state["result"]["walk"]["max_repetitions"] is None


def test_mid_walk_timeout_halves_and_resumes_without_duplicates(client, settings, store, monkeypatch):
    job = submit(client, max_repetitions=4)
    agent = FakeAgent(monkeypatch, rows(ROOT, 10), script={2: (RequestTimedOut(), 0, 0, ())})
    process(settings, store, store.claim("w"), "w")
    state = store.get(job["id"])
    assert state["status"] == "succeeded", state["result"]
    assert walked(store, job) == [f"{ROOT}.{n}" for n in range(1, 11)]
    assert state["result"]["walk"]["fallbacks"] == [{"reason": "timeout", "oid": ROOT, "max_repetitions": 2}]
    # The retry resumes after the last committed row rather than restarting the subtree.
    assert agent.calls[1:3] == [("bulk", 4, [ROOT + ".4"]), ("bulk", 2, [ROOT + ".4"])]


def test_scalar_root_and_batched_gets(client, settings, store, monkeypatch):
    scalar = ROOT + ".5.0"
    gets = [f"{OTHER}.{n}.0" for n in range(1, 13)]
    job = submit(client, oids=[scalar], get_oids=gets)
    values = {scalar: rfc1902.OctetString(b"lab-switch"), **{oid: rfc1902.Integer32(1) for oid in gets[:11]}}
    agent = FakeAgent(monkeypatch, values, max_varbinds=6)
    process(settings, store, store.claim("w"), "w")
    state = store.get(job["id"])
    assert state["status"] == "succeeded", state["result"]
    statuses = [g["status"] for g in state["result"]["gets"]]
    assert statuses == ["succeeded"] * 11 + ["missing"]
    # Batches of 10 split once on tooBig; the second batch of 2 fits.
    assert [(k, len(o)) for k, _, o in agent.calls[:4]] == [("get", 10), ("get", 5), ("get", 5), ("get", 2)]
    root = state["result"]["oids"][0]
    assert root["status"] == "succeeded" and root["rows"] == 1 and root["scalar"]
    results = store.snmp_results(job["id"])["rows"]
    assert results[-1]["oid"] == scalar and base64.b64decode(results[-1]["value"]) == b"lab-switch"
    assert {r["root_oid"] for r in results[:11]} == set(gets[:11])


def test_failed_scalar_probe_keeps_empty_walk(client, settings, store, monkeypatch):
    job = submit(client)
    FakeAgent(monkeypatch, {}, script={2: (RequestTimedOut(), 0, 0, ())})
    process(settings, store, store.claim("w"), "w")
    state = store.get(job["id"])
    root = state["result"]["oids"][0]
    assert state["status"] == "succeeded" and root["rows"] == 0
    assert root["scalar_probe_error"] == "SNMP engine error: RequestTimedOut"


def test_get_only_request(client, settings, store, monkeypatch):
    response = client.post(
        "/api/v1/snmp/walks", json={"device_ip": "192.0.2.15", "get_oids": [ROOT + ".3.0"]}
    )
    assert response.status_code == 202, response.text
    FakeAgent(monkeypatch, {ROOT + ".3.0": rfc1902.TimeTicks(42)})
    process(settings, store, store.claim("w"), "w")
    state = store.get(response.json()["id"])
    assert state["status"] == "succeeded" and state["result"]["oids"] == []
    assert store.snmp_results(state["id"])["rows"][0]["value"] == "42"


def test_request_interval_paces_requests(client, settings, store, monkeypatch):
    job = submit(client, max_repetitions=1, request_interval=0.5)
    FakeAgent(monkeypatch, rows(ROOT, 2))
    pauses = []
    original = asyncio.sleep

    async def sleep(seconds):
        pauses.append(seconds)
        await original(0)

    monkeypatch.setattr(snmp.asyncio, "sleep", sleep)
    process(settings, store, store.claim("w"), "w")
    assert store.get(job["id"])["status"] == "succeeded"
    # Three requests (two rows, then the subtree boundary); no pause before the first.
    assert pauses == [0.5, 0.5]


def test_partial_error_continues_other_roots(client, settings, store, monkeypatch):
    job = submit(client, oids=[ROOT, OTHER], walk_mode="next")
    FakeAgent(monkeypatch, rows(ROOT, 3), script={2: (RequestTimedOut(), 0, 0, ())})
    process(settings, store, store.claim("w"), "w")
    state = store.get(job["id"])
    assert state["status"] == "failed" and state["result"]["rows"] == 1
    assert state["result"]["oids"][0]["error"] == "SNMP engine error: RequestTimedOut"
    assert state["result"]["oids"][1]["status"] == "succeeded"


def test_non_increasing_oid_fails_the_root(client, settings, store, monkeypatch):
    job = submit(client)
    back = [
        (rfc1902.ObjectName(ROOT + ".2"), rfc1902.Integer32(2)),
        (rfc1902.ObjectName(ROOT + ".1"), rfc1902.Integer32(1)),
    ]
    FakeAgent(monkeypatch, {}, script={1: (None, 0, 0, back)})
    process(settings, store, store.claim("w"), "w")
    state = store.get(job["id"])
    assert state["status"] == "failed"
    assert state["result"]["oids"][0]["error"] == "SNMP agent returned a non-increasing OID"


@pytest.mark.parametrize("byte_limit", [False, True])
def test_result_limits_preserve_partial_data(client, settings, store, monkeypatch, byte_limit):
    job = submit(client, max_rows=1, oids=[ROOT, OTHER])
    if byte_limit:
        monkeypatch.setattr(snmp, "MAX_RESULT_BYTES", 1)
    FakeAgent(monkeypatch, rows(ROOT, 2))
    process(settings, store, store.claim("w"), "w")
    state = store.get(job["id"])
    assert state["status"] == "failed" and state["result"]["truncated"]
    assert state["result"]["rows"] == (0 if byte_limit else 1)
    assert state["result"]["oids"][0]["rows"] == state["result"]["rows"]
    assert state["result"]["oids"][1]["status"] == "skipped"


def test_timeout_and_secret_redaction(client, settings, store, monkeypatch):
    job = submit(client, job_timeout=1, max_repetitions=1)
    FakeAgent(monkeypatch, rows(ROOT, 3), script={2: "sleep"})
    process(settings, store, store.claim("w"), "w")
    assert store.get(job["id"])["result"]["error"] == "job timeout exceeded"
    assert len(store.snmp_results(job["id"])["rows"]) == 1
    other = submit(client)
    FakeAgent(monkeypatch, {}, script={1: RuntimeError("password=must-not-be-logged")})
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
    # A GETBULK error gets one GETNEXT retry in auto mode; the same error then fails the root.
    agent = FakeAgent(monkeypatch, {}, script={1: (None, 5, 1, ()), 2: (None, 5, 1, ())})
    process(settings, store, store.claim("w"), "w")
    result = store.get(job["id"])
    assert result["status"] == "failed"
    assert result["result"]["oids"][0]["error"] == "SNMP PDU error 5 at binding 1"
    assert agent.kinds() == ["bulk", "next"]
    assert result["result"]["walk"]["fallbacks"][0]["reason"] == "error"


def test_bulk_rejected_by_report_falls_back(client, settings, store, monkeypatch):
    from pysnmp.proto.errind import ReportPduReceived

    job = submit(client)
    agent = FakeAgent(monkeypatch, rows(ROOT, 2), script={1: (ReportPduReceived(), 0, 0, ())})
    process(settings, store, store.claim("w"), "w")
    state = store.get(job["id"])
    assert state["status"] == "succeeded" and len(walked(store, job)) == 2
    assert agent.kinds() == ["bulk", "next", "next", "next"]
    assert state["result"]["walk"]["fallbacks"][0]["reason"] == "unsupported"
