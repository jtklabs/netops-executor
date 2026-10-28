import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from netops_executor import store as store_module
from netops_executor.api import create_app
from netops_executor.cli import parser
from netops_executor.config import HTTPTarget
from netops_executor.execution_models import Batch, ManualCompletion, ValidationDecision
from netops_executor.models import ScheduledRequest
from netops_executor.store import Deferred, NeedsReview, Store

NOW = 1800000000


def stamp(seconds=0):
    return datetime.fromtimestamp(NOW + seconds, timezone.utc).isoformat().replace("+00:00", "Z")


@pytest.fixture
def clock(monkeypatch):
    clock = SimpleNamespace(now=NOW)
    monkeypatch.setattr(store_module, "time", SimpleNamespace(time=lambda: clock.now))
    return clock


@pytest.fixture
def client(settings, clock):
    settings.http_targets["pan"] = HTTPTarget(id="pan", base_url="https://pan.example")
    return TestClient(create_app(settings), headers={"Authorization": "Bearer " + settings.token})


@pytest.mark.parametrize(
    "path,body",
    [
        ("jobs", {"device": "lab"}),
        ("ssh/jobs", {"device": "lab", "commands": [{"command": "date"}]}),
        ("http/jobs", {"target": "pan", "requests": [{"path": "/"}]}),
        ("snmp/walks", {"device_ip": "192.0.2.9", "oids": ["1.3.6.1"]}),
        ("cipher-scans", {"device_ip": "192.0.2.9", "protocol": "https"}),
    ],
)
def test_all_submission_kinds_schedule_and_expire(client, clock, path, body):
    store = client.app.state.store
    response = client.post(
        "/api/v1/" + path, json={**body, "start_at": stamp(10), "latest_start_at": stamp(20)}
    )
    assert response.status_code == 202, response.text
    job = response.json()
    assert job["status"] == "queued" and job["started_at"] is None
    assert job["start_at"] == stamp(10) and job["request"]["latest_start_at"] == stamp(20)
    assert store.claim("worker") is None
    with store.connect() as db:
        assert db.execute("SELECT count(*) FROM locks").fetchone()[0] == 0
    clock.now += 21
    result = client.get("/api/v1/jobs/" + job["id"]).json()
    assert result["status"] == "expired" and not result["lock_held"]
    assert result["result"]["error_code"] == "start_window_expired"
    assert store.claim("worker") is None
    assert store.events(job["id"])[-1]["step"] == "start_window_expired"
    if path == "cipher-scans":
        assert client.get("/api/v1/cipher-scans/" + job["id"]).json()["status"] == "expired"
    if path == "snmp/walks":
        assert client.get("/api/v1/snmp/walks/" + job["id"] + "/results").json()["finished"] is True


def test_future_jobs_do_not_block_ready_jobs_and_start_boundary(store, clock):
    future = store.submit(
        {"device": "lab", "start_at": stamp(10), "latest_start_at": stamp(10)}, "device:lab"
    )
    ready = store.submit({"device": "lab", "start_at": stamp(-100)}, "device:lab")
    claimed = store.claim("one")
    assert claimed["id"] == ready["id"] and claimed["started_at"] == NOW
    store.finish(ready["id"], "one", "succeeded")
    assert store.claim("two") is None
    clock.now += 10
    claimed = store.claim("two")
    assert claimed["id"] == future["id"] and claimed["started_at"] == NOW + 10
    clock.now += 1
    store.reap(100)
    assert store.get(future["id"])["status"] == "running"
    store.finish(future["id"], "two", "succeeded")
    assert store.get(future["id"])["started_at"] == NOW + 10


@pytest.mark.parametrize("window", [{}, {"start_at": None, "latest_start_at": None}, {"start_at": stamp(-1)}])
def test_immediate_start_is_backwards_compatible(store, clock, window):
    job = store.submit({"device": "lab", **window}, "device:lab")
    assert store.claim("worker")["id"] == job["id"]


def test_expired_at_submission_and_idempotency(client):
    body = {"device": "lab", "latest_start_at": stamp(-1)}
    headers = {"Idempotency-Key": "expired-request"}
    first = client.post("/api/v1/jobs", json=body, headers=headers).json()
    assert first["status"] == "expired" and first["started_at"] is None
    assert client.post("/api/v1/jobs", json=body, headers=headers).json()["id"] == first["id"]
    assert (
        client.post("/api/v1/jobs", json={**body, "latest_start_at": stamp(60)}, headers=headers).status_code
        == 409
    )
    assert len(client.app.state.store.events(first["id"])) == 1


def test_offsets_normalize_and_legacy_unscheduled_idempotency(client):
    body = {"device": "lab", "start_at": "2027-01-15T03:00:00-05:00"}
    headers = {"Idempotency-Key": "offset-job"}
    first = client.post("/api/v1/jobs", json=body, headers=headers).json()
    assert first["start_at"] == "2027-01-15T08:00:00Z"
    assert (
        client.post(
            "/api/v1/jobs", json={**body, "start_at": "2027-01-15T08:00:00Z"}, headers=headers
        ).json()["id"]
        == first["id"]
    )
    headers = {"Idempotency-Key": "legacy-job"}
    first = client.post("/api/v1/jobs", json={"device": "lab"}, headers=headers).json()
    with client.app.state.store.connect() as db:
        old = json.loads(db.execute("SELECT request FROM jobs WHERE id=?", (first["id"],)).fetchone()[0])
        old.pop("start_at", None)
        old.pop("latest_start_at", None)
        db.execute("UPDATE jobs SET request=? WHERE id=?", (json.dumps(old, sort_keys=True), first["id"]))
    assert (
        client.post("/api/v1/jobs", json={"device": "lab", "start_at": None}, headers=headers).json()["id"]
        == first["id"]
    )


@pytest.mark.parametrize(
    "window",
    [
        {"start_at": "2027-01-01T12:00:00"},
        {"latest_start_at": "2027-01-01"},
        {"start_at": 1800000000},
        {"latest_start_at": "1800000000"},
        {"start_at": "tomorrow"},
        {"start_at": stamp(20), "latest_start_at": stamp(10)},
    ],
)
def test_invalid_windows_rejected(client, window):
    assert client.post("/api/v1/jobs", json={"device": "lab", **window}).status_code == 422


def test_busy_lock_expiry_does_not_release_owner(store, clock):
    owner = store.submit({"device": "lab"}, "device:lab")
    store.claim("owner")
    waiting = store.submit({"device": "lab", "latest_start_at": stamp(10)}, "device:lab")
    assert store.claim("other") is None
    clock.now += 11
    assert store.claim("other") is None
    assert store.get(waiting["id"])["status"] == "expired"
    assert store.get(owner["id"])["lock_held"]


def test_resource_deferral_still_obeys_deadline(store, clock):
    job = store.submit({"device": "lab", "latest_start_at": stamp(10)}, "device:lab")
    store.claim("worker")
    with pytest.raises(Deferred):
        store.defer(job["id"], "worker")
    assert store.get(job["id"])["started_at"] is None
    clock.now += 11
    assert store.claim("worker") is None
    assert store.get(job["id"])["status"] == "expired"


def test_validation_continuation_keeps_original_start_and_can_resume_after_deadline(store, clock):
    job = store.submit({"device": "lab", "latest_start_at": stamp(10)}, "device:lab")
    store.claim("worker")
    with pytest.raises(NeedsReview):
        store.open_gate(job["id"], "worker", "post_validation", {"critical": ["review"]}, {})
    gate = store.get(job["id"])["validation_gates"][0]
    clock.now += 20
    store.reap(100)
    assert store.get(job["id"])["status"] == "needs_review"
    store.decide(
        job["id"],
        ValidationDecision(
            action="accept",
            gate_id=gate["id"],
            validation_revision=1,
            operator="operator",
            reason="checked manually",
        ),
    )
    assert store.claim("resumed")["id"] == job["id"]
    assert store.get(job["id"])["started_at"] == NOW
    with pytest.raises(Deferred):
        store.defer(job["id"], "resumed")
    assert store.get(job["id"])["started_at"] == NOW
    clock.now += 10
    assert store.claim("resumed-again")["id"] == job["id"]


def test_upgrade_waves_keep_barriers_and_expired_items_need_manual_completion(store, clock):
    batch = Batch(
        name="window",
        start_at=stamp(10),
        waves=[
            {"wave": 1, "upgrade_at_a_time": 1, "ips": ["192.0.2.1", "192.0.2.2"]},
            {"wave": 2, "ips": ["192.0.2.3"]},
        ],
        overrides={"192.0.2.2": {"latest_start_at": stamp(20)}},
    )
    result = store.create_batch(batch, None, lambda ip: "device:" + ip)
    assert store.claim("one") is None
    clock.now += 10
    first = store.claim("one")
    assert first["device"] == "192.0.2.1"
    assert store.claim("two") is None
    clock.now += 11
    store.reap(100)
    assert store.batch(result["id"])["status"] == "needs_attention"
    second = store.batch(result["id"])["jobs"][1]
    assert second["status"] == "expired"
    assert store.get(first["id"])["status"] == "running"
    store.finish(first["id"], "one", "succeeded")
    assert store.claim("two") is None
    store.mark_done(second["id"], ManualCompletion(operator="operator", reason="skip expired unit"))
    assert store.claim("two")["device"] == "192.0.2.3"


def test_batch_windows_cannot_be_widened_by_overrides(client):
    body = {
        "name": "night",
        "start_at": stamp(10),
        "latest_start_at": stamp(100),
        "waves": [{"wave": 1, "ips": ["192.0.2.1", "192.0.2.2"]}],
        "defaults": {"start_at": stamp(5)},
        "overrides": {
            "192.0.2.1": {"latest_start_at": stamp(150)},
            "192.0.2.2": {"start_at": stamp(30), "latest_start_at": stamp(90)},
        },
    }
    response = client.post("/api/v1/upgrade-batches", json=body)
    assert response.status_code == 202, response.text
    batch = response.json()
    assert batch["start_at"] == stamp(10)
    assert batch["jobs"][0]["start_at"] == stamp(10)
    assert batch["jobs"][0]["latest_start_at"] == stamp(100)
    assert batch["jobs"][1]["start_at"] == stamp(30)
    assert batch["jobs"][1]["latest_start_at"] == stamp(90)
    body["overrides"]["192.0.2.2"]["start_at"] = stamp(200)
    assert client.post("/api/v1/upgrade-batches", json=body).status_code == 422


def test_scheduled_rollback_leaves_parent_recovery_lock_until_eligible(client, clock):
    store = client.app.state.store
    source = store.submit({"device": "lab"}, "device:lab")
    store.claim("original")
    store.record(source["id"], "original", "rollback_recorded", result={"rollback": {"volume": "HD1.1"}})
    store.finish(source["id"], "original", "recovery_required")
    path = "/api/v1/jobs/" + source["id"] + "/rollback"
    response = client.post(
        path, json={"worker_stopped": True, "start_at": stamp(10), "latest_start_at": stamp(20)}
    )
    assert response.status_code == 202
    assert store.claim("rollback-worker") is None
    assert store.get(source["id"])["lock_held"]
    clock.now += 21
    store.reap(100)
    assert store.get(response.json()["id"])["status"] == "expired"
    assert store.get(source["id"])["lock_held"]


def test_concurrent_workers_claim_due_job_once(store, clock):
    job = store.submit({"device": "lab", "start_at": stamp(10)}, "device:lab")
    clock.now += 10
    with ThreadPoolExecutor(4) as pool:
        results = list(pool.map(store.claim, ["one", "two", "three", "four"]))
    assert [item["id"] for item in results if item] == [job["id"]]


def test_legacy_database_migration_is_additive_and_concurrent(tmp_path):
    path = tmp_path / "legacy.sqlite3"
    with sqlite3.connect(path) as db:
        # The prior release already initialized persisted databases in WAL mode.
        db.execute("PRAGMA journal_mode=WAL")
        db.executescript("""CREATE TABLE jobs (
            id TEXT PRIMARY KEY, device TEXT NOT NULL, lock_key TEXT NOT NULL,
            kind TEXT NOT NULL, parent TEXT, request TEXT NOT NULL, status TEXT NOT NULL,
            created REAL NOT NULL, updated REAL NOT NULL, worker TEXT, heartbeat REAL,
            result TEXT NOT NULL DEFAULT '{}', idempotency_key TEXT UNIQUE);
            INSERT INTO jobs(id,device,lock_key,kind,request,status,created,updated)
            VALUES ('old','lab','device:lab','upgrade','{"device":"lab"}','queued',1,1),
                   ('review','other','device:other','upgrade','{"device":"other"}','needs_review',2,2);""")
    with ThreadPoolExecutor(4) as pool:
        stores = list(pool.map(lambda _: Store(path), range(4)))
    store = stores[0]
    assert store.get("old")["started_at"] is None
    assert store.get("review")["started_at"] == 2
    assert store.claim("worker")["id"] == "old"
    assert Store(path).get("old")["status"] == "running"


def test_swagger_and_cli_expose_schedule(client):
    schemas = client.get("/openapi.json").json()["components"]["schemas"]
    for name in (
        "JobRequest",
        "SSHJob",
        "HTTPJob",
        "SnmpWalkRequest",
        "CipherScanRequest",
        "RollbackRequest",
        "Batch",
    ):
        for field in ("start_at", "latest_start_at"):
            assert {"format": "date-time", "type": "string"} in schemas[name]["properties"][field]["anyOf"]
    args = parser().parse_args(
        ["submit", "--device", "lab", "--start-at", stamp(10), "--latest-start-at", stamp(20)]
    )
    assert args.start_at == stamp(10) and args.latest_start_at == stamp(20)
    assert parser().parse_args(["rollback", "id", "--start-at", stamp(10)]).start_at == stamp(10)
    assert ScheduledRequest(start_at=stamp(10)).model_dump()["start_at"] == stamp(10)


def test_schedule_persists_across_store_restart_and_can_be_cancelled(store, clock):
    job = store.submit({"device": "lab", "start_at": stamp(10), "latest_start_at": stamp(30)}, "device:lab")
    reopened = Store(store.path)
    assert reopened.get(job["id"])["start_at"] == stamp(10)
    assert reopened.claim("early") is None
    reopened.cancel(job["id"])
    clock.now += 31
    reopened.reap(100)
    assert reopened.claim("late") is None
    assert reopened.get(job["id"])["status"] == "cancelled"
