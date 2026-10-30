import json
import sqlite3
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from netops_executor import store as store_module
from netops_executor.api import create_app
from netops_executor.cli import parser
from netops_executor.config import HTTPTarget
from netops_executor.execution_models import Batch, ValidationDecision
from netops_executor.store import Conflict, Store
from netops_executor.worker import worker_queues

NOW = 1800000000


@pytest.fixture
def clock(monkeypatch):
    clock = SimpleNamespace(now=NOW)
    monkeypatch.setattr(store_module, "time", SimpleNamespace(time=lambda: clock.now))
    return clock


@pytest.fixture
def client(settings, clock):
    settings.http_targets["pan"] = HTTPTarget(id="pan", base_url="https://pan.example")
    return TestClient(create_app(settings), headers={"Authorization": "Bearer " + settings.token})


def walk(store, n, queue=None):
    request = {"device_ip": f"192.0.2.{n % 250 + 1}", "oids": ["1.3.6.1"]}
    if queue:
        request["queue"] = queue
    return store.submit(request, f"snmp:{n}", kind="snmp_walk")


@pytest.mark.parametrize(
    "path,body,queue",
    [
        ("jobs", {"device": "lab"}, "upgrade"),
        ("ssh/jobs", {"device": "lab", "commands": [{"command": "date"}]}, "scheduled"),
        ("http/jobs", {"target": "pan", "requests": [{"path": "/"}]}, "scheduled"),
        ("snmp/walks", {"device_ip": "192.0.2.9", "oids": ["1.3.6.1"]}, "scheduled"),
        ("cipher-scans", {"device_ip": "192.0.2.9", "protocol": "https"}, "scheduled"),
    ],
)
def test_default_and_explicit_queue_per_kind(client, path, body, queue):
    default = client.post("/api/v1/" + path, json=body)
    assert default.status_code == 202, default.text
    assert default.json()["queue"] == queue and default.json()["request"].get("queue") is None
    explicit = client.post("/api/v1/" + path, json={**body, "queue": "priority"})
    assert explicit.status_code == 202, explicit.text
    assert explicit.json()["queue"] == "priority" and explicit.json()["request"]["queue"] == "priority"
    assert client.post("/api/v1/" + path, json={**body, "queue": "urgent"}).status_code == 422


def test_priority_job_runs_before_a_large_scheduled_backlog(store):
    backlog = [walk(store, n) for n in range(2000)]
    urgent = walk(store, 5000, "priority")
    upgrade = store.submit({"device": "lab"}, "device:lab")
    # A worker without a pool takes priority, then upgrades, then the oldest scheduled job.
    assert store.claim("all")["id"] == urgent["id"]
    assert store.claim("all")["id"] == upgrade["id"]
    assert store.claim("all")["id"] == backlog[0]["id"]


def test_pools_claim_their_queue_first_then_fall_back(store):
    priority, upgrade = worker_queues(pool="priority"), worker_queues(pool="upgrade")
    # Scheduled work has no pool: every worker takes it once both other queues are empty.
    assert priority == ("priority", "upgrade", "scheduled")
    assert upgrade == ("upgrade", "priority", "scheduled")
    backlog = [walk(store, n) for n in range(3)]
    urgent = walk(store, 10, "priority")
    firmware = store.submit({"device": "lab"}, "device:lab")
    assert store.claim("upgrade-1", upgrade)["id"] == firmware["id"]
    assert store.claim("priority-1", priority)["id"] == urgent["id"]
    # With its own queue empty, a worker takes the next queue in its order instead of idling.
    second = walk(store, 11, "priority")
    other = store.submit({"device": "other"}, "device:other")
    assert store.claim("upgrade-2", upgrade)["id"] == other["id"]
    assert store.claim("upgrade-3", upgrade)["id"] == second["id"]
    assert store.claim("upgrade-4", upgrade)["id"] == backlog[0]["id"]
    third = walk(store, 12, "priority")
    last = store.submit({"device": "third"}, "device:third")
    assert store.claim("priority-2", priority)["id"] == third["id"]
    assert store.claim("priority-3", priority)["id"] == last["id"]
    assert store.claim("priority-4", priority)["id"] == backlog[1]["id"]
    assert store.claim("priority-5", priority)["id"] == backlog[2]["id"]
    assert store.claim("priority-6", priority) is None


def test_exact_queue_lists_exclude_other_queues(store):
    scheduled = walk(store, 1)
    assert store.claim("priority-1", ("priority",)) is None
    assert store.claim("upgrade-1", ("upgrade",)) is None
    urgent = walk(store, 2, "priority")
    upgrade = store.submit({"device": "lab"}, "device:lab")
    assert store.claim("scheduled-1", ("scheduled",))["id"] == scheduled["id"]
    assert store.claim("scheduled-2", ("scheduled",)) is None
    assert store.claim("upgrade-1", ("upgrade",))["id"] == upgrade["id"]
    assert store.claim("priority-1", ("priority",))["id"] == urgent["id"]
    with pytest.raises(ValueError):
        store.claim("bad", ("urgent",))
    with pytest.raises(ValueError):
        store.claim("bad", ())


def test_worker_queue_order_is_honored(store):
    urgent = walk(store, 1, "priority")
    scheduled = walk(store, 2)
    assert store.claim("borrower", ("scheduled", "priority"))["id"] == scheduled["id"]
    assert store.claim("borrower", ("scheduled", "priority"))["id"] == urgent["id"]


def test_locks_still_apply_across_queues(store):
    running = store.submit({"device": "lab"}, "device:lab")
    assert store.claim("upgrade-1", ("upgrade",))["id"] == running["id"]
    urgent = store.submit(
        {"device": "lab", "commands": [{"command": "date"}], "queue": "priority"}, "device:lab", kind="ssh"
    )
    assert store.claim("priority-1", ("priority",)) is None
    store.finish(running["id"], "upgrade-1", "succeeded")
    assert store.claim("priority-1", ("priority",))["id"] == urgent["id"]


def test_deferred_job_keeps_its_queue(store):
    urgent = walk(store, 1, "priority")
    store.claim("priority-1", ("priority",))
    with pytest.raises(store_module.Deferred):
        store.defer(urgent["id"], "priority-1")
    assert store.get(urgent["id"])["queue"] == "priority"


def test_rollback_defaults_to_priority(client):
    store = client.app.state.store
    source = store.submit({"device": "lab"}, "device:lab")
    store.claim("upgrade-1", ("upgrade",))
    store.record(source["id"], "upgrade-1", "rollback_recorded", result={"rollback": {"volume": "HD1.1"}})
    store.finish(source["id"], "upgrade-1", "failed")
    path = "/api/v1/jobs/" + source["id"] + "/rollback"
    rollback = client.post(path, json={})
    assert rollback.status_code == 202, rollback.text
    assert rollback.json()["queue"] == "priority"
    assert store.claim("upgrade-1", ("upgrade",)) is None
    assert store.claim("priority-1", ("priority",))["id"] == rollback.json()["id"]
    assert client.post(path, json={"queue": "upgrade"}).json()["queue"] == "upgrade"


def test_batch_members_use_upgrade_or_batch_queue(store):
    waves = [{"wave": 1, "upgrade_at_a_time": 2, "ips": ["192.0.2.1", "192.0.2.2"]}]
    plain = store.create_batch(Batch(name="plain", waves=waves), "plain", lambda ip: "device:" + ip)
    assert [j["queue"] for j in plain["jobs"]] == ["upgrade", "upgrade"]
    urgent = store.create_batch(
        Batch(name="urgent", queue="priority", waves=waves, overrides={"192.0.2.2": {"queue": "upgrade"}}),
        "urgent",
        lambda ip: "urgent:" + ip,
    )
    assert [j["queue"] for j in urgent["jobs"]] == ["priority", "upgrade"]
    # A batch without a queue stores the same idempotent payload as before queues existed.
    with store.connect() as db:
        assert '"queue"' not in db.execute("SELECT request FROM batches WHERE key='plain'").fetchone()[0]


def test_idempotency_includes_queue_only_when_given(store):
    first = walk(store, 1)
    with store.connect() as db:
        assert (
            '"queue"' not in db.execute("SELECT request FROM jobs WHERE id=?", (first["id"],)).fetchone()[0]
        )
    request = {"device_ip": "192.0.2.9", "oids": ["1.3.6.1"]}
    job = store.submit(request, "snmp:9", key="k", kind="snmp_walk")
    assert store.submit({**request, "queue": None}, "snmp:9", key="k", kind="snmp_walk")["id"] == job["id"]
    with pytest.raises(Conflict):
        store.submit({**request, "queue": "priority"}, "snmp:9", key="k", kind="snmp_walk")


def test_legacy_database_backfills_queues(tmp_path):
    path = tmp_path / "legacy.sqlite3"
    with sqlite3.connect(path) as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.executescript("""CREATE TABLE jobs (
            id TEXT PRIMARY KEY, device TEXT NOT NULL, lock_key TEXT NOT NULL,
            kind TEXT NOT NULL, parent TEXT, request TEXT NOT NULL, status TEXT NOT NULL,
            created REAL NOT NULL, updated REAL NOT NULL, worker TEXT, heartbeat REAL,
            result TEXT NOT NULL DEFAULT '{}', idempotency_key TEXT UNIQUE);
            CREATE TABLE workers (id TEXT PRIMARY KEY, heartbeat REAL, job TEXT, state TEXT);
            INSERT INTO workers VALUES ('old-worker', 1, NULL, 'available');
            INSERT INTO jobs(id,device,lock_key,kind,request,status,created,updated) VALUES
            ('f5','lab','device:lab','upgrade','{"device":"lab"}','queued',1,1),
            ('eos','sw','device:sw','eos_upgrade','{"device":"sw"}','queued',2,2),
            ('back','lab','device:lab','rollback','{"device":"lab"}','queued',3,3),
            ('walk','192.0.2.1','snmp:1','snmp_walk','{"device_ip":"192.0.2.1"}','queued',4,4);""")
    store = Store(path)
    assert {j: store.get(j)["queue"] for j in ("f5", "eos", "back", "walk")} == {
        "f5": "upgrade",
        "eos": "upgrade",
        "back": "priority",
        "walk": "scheduled",
    }
    legacy = store.worker_list(10**10)[0]
    assert legacy["queues"] == ["priority", "upgrade", "scheduled"] and legacy["version"] is None
    assert store.claim("scheduled-1", ("scheduled",))["id"] == "walk"


def test_queue_summary_reports_backlog_and_workers(client, clock):
    store = client.app.state.store
    walk(store, 1)
    clock.now += 30
    walk(store, 2)
    walk(store, 3, "priority")
    store.submit({"device": "lab", "start_at": "2030-01-01T00:00:00Z"}, "device:lab")
    store.worker_seen("p1", queues=worker_queues(pool="priority"))
    store.worker_seen("u1", queues=worker_queues(pool="upgrade"))
    store.worker_seen("all")
    store.claim("p1", worker_queues(pool="priority"))
    store.worker_seen("p1", "job", "busy")
    summary = {q["queue"]: q for q in client.get("/api/v1/queues").json()}
    assert summary["scheduled"] == {
        "queue": "scheduled",
        "queued": 2,
        "due": 2,
        "running": 0,
        "oldest_due_wait_seconds": 30.0,
        "workers": 0,
        "busy_workers": 0,
        "fallback_workers": 3,
    }
    assert summary["priority"] == {
        "queue": "priority",
        "queued": 0,
        "due": 0,
        "running": 1,
        "oldest_due_wait_seconds": None,
        "workers": 2,
        "busy_workers": 1,
        "fallback_workers": 1,
    }
    assert summary["upgrade"]["queued"] == 1 and summary["upgrade"]["due"] == 0
    assert summary["upgrade"]["oldest_due_wait_seconds"] is None
    assert summary["upgrade"]["workers"] == 1 and summary["upgrade"]["fallback_workers"] == 2
    workers = {w["id"]: w for w in client.get("/api/v1/workers").json()}
    assert (
        workers["p1"]["queues"] == ["priority", "upgrade", "scheduled"] and workers["p1"]["state"] == "busy"
    )


@pytest.mark.parametrize(
    "queue,pool,instance,expected",
    [
        (None, None, None, ("priority", "upgrade", "scheduled")),
        (None, None, "3", ("priority", "upgrade", "scheduled")),
        (None, None, "priority-1", ("priority", "upgrade", "scheduled")),
        (None, None, "upgrade-2", ("upgrade", "priority", "scheduled")),
        (None, "upgrade", None, ("upgrade", "priority", "scheduled")),
        ("priority, scheduled", None, "upgrade-1", ("priority", "scheduled")),
    ],
)
def test_worker_queue_selection(queue, pool, instance, expected):
    assert worker_queues(queue, pool, instance) == expected


@pytest.mark.parametrize(
    "queue,pool,instance",
    [
        ("urgent", None, None),
        ("priority,priority", None, None),
        ("", None, "urgent-1"),
        (None, None, "bulk"),
        (None, "bulk", None),
        (None, "scheduled", None),
        (None, None, "scheduled-3"),
    ],
)
def test_worker_queue_selection_rejects_unknown_queues(queue, pool, instance):
    with pytest.raises(ValueError):
        worker_queues(queue, pool, instance)


def test_cli_exposes_queues():
    assert parser().parse_args(["worker", "--queue", "priority"]).queue == "priority"
    assert parser().parse_args(["worker", "--pool", "upgrade"]).pool == "upgrade"
    with pytest.raises(SystemExit):
        parser().parse_args(["worker", "--pool", "upgrade", "--queue", "upgrade"])
    assert parser().parse_args(["worker", "--instance", "upgrade-2"]).instance == "upgrade-2"
    with pytest.raises(SystemExit):
        parser().parse_args(["worker", "--pool", "scheduled"])
    assert parser().parse_args(["submit", "--device", "lab", "--queue", "priority"]).queue == "priority"
    assert parser().parse_args(["rollback", "id", "--queue", "upgrade"]).queue == "upgrade"
    assert parser().parse_args(["queues"]).command == "queues"
    with pytest.raises(SystemExit):
        parser().parse_args(["submit", "--device", "lab", "--queue", "urgent"])


def test_every_job_submission_accepts_a_queue(client):
    # Anything that creates or resumes a job must take a queue, including endpoints added later.
    spec = client.get("/openapi.json").json()
    schemas = spec["components"]["schemas"]
    jobs = {"JobResponse", "CipherScanJobResponse", "BatchResponse"}
    checked = []
    for path, operations in spec["paths"].items():
        operation = operations.get("post")
        if not operation or "requestBody" not in operation:
            continue
        responses = json.dumps(operation["responses"])
        if not any(name in responses for name in jobs) and not path.endswith("/validation-decisions"):
            continue
        name = operation["requestBody"]["content"]["application/json"]["schema"]["$ref"].split("/")[-1]
        if name in ("RecoveryResolution", "ManualCompletion"):
            continue  # Resolving or completing a job never queues work.
        assert "queue" in schemas[name]["properties"], path
        checked.append(path)
    assert len(checked) == 18
    for example in schemas["CipherScanRequest"]["examples"]:
        assert example["queue"] in ("priority", "scheduled")


def decision(gate, queue=None):
    return ValidationDecision(
        action="accept",
        gate_id=gate["id"],
        validation_revision=gate["revision"],
        operator="operator",
        reason="checked manually",
        queue=queue,
    )


def gated(store, device):
    job = store.submit({"device": device}, "device:" + device)
    store.claim("upgrade-1", worker_queues(pool="upgrade"))
    with pytest.raises(store_module.NeedsReview):
        store.open_gate(job["id"], "upgrade-1", "post_validation", {"critical": ["review"]}, {})
    return job, store.get(job["id"])["validation_gates"][0]


def test_validation_decision_can_move_the_resumed_job(client):
    store = client.app.state.store
    moved, gate = gated(store, "lab")
    response = client.post(
        f"/api/v1/jobs/{moved['id']}/validation-decisions", json=decision(gate, "priority").model_dump()
    )
    assert response.status_code == 202, response.text
    assert store.get(moved["id"])["queue"] == "priority"
    assert store.claim("upgrade-only", ("upgrade",)) is None
    assert store.claim("priority-1", ("priority",))["id"] == moved["id"]

    kept, gate = gated(store, "other")
    store.decide(kept["id"], decision(gate))
    assert store.get(kept["id"])["queue"] == "upgrade"
    # A decision without a queue stores the same payload as before queues existed, so replays match.
    with store.connect() as db:
        stored = db.execute("SELECT decision FROM gates WHERE id=?", (gate["id"],)).fetchone()[0]
    assert "queue" not in json.loads(stored)
    assert store.decide(kept["id"], decision(gate)) == {"gate_id": gate["id"], "state": "pending"}
    args = parser().parse_args(
        ["validation", "id", "--operator", "o", "--reason", "fine now", "--action", "accept"]
        + ["--gate-id", "g", "--revision", "1", "--queue", "priority"]
    )
    assert args.queue == "priority"
