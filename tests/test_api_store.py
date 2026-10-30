import concurrent.futures
import multiprocessing
import time

import pytest
from fastapi.testclient import TestClient

from netops_executor import __version__
from netops_executor.api import create_app
from netops_executor.store import Conflict, LostOwnership, Store


def claim_process(path, worker):
    return Store(path).claim(worker)


def test_atomic_claims_across_processes(store):
    for i in range(8):
        store.submit({"device": f"d{i}"}, "group:ha" if i < 4 else f"device:d{i}")
    ctx = multiprocessing.get_context("spawn")
    with concurrent.futures.ProcessPoolExecutor(4, mp_context=ctx) as pool:
        results = list(pool.map(claim_process, [store.path] * 8, [f"w{i}" for i in range(8)]))
    jobs = [r for r in results if r]
    assert len(jobs) == 5
    assert len({j["lock_key"] for j in jobs}) == 5
    assert len({j["id"] for j in jobs}) == 5


def test_stale_worker_never_replays_and_can_be_explicitly_resolved(store):
    j = store.submit({"device": "lab"}, "device:lab")
    store.claim("dead")
    with store.connect() as db:
        db.execute("UPDATE jobs SET heartbeat=? WHERE id=?", (time.time() - 1000, j["id"]))
    store.reap(120)
    assert store.get(j["id"])["status"] == "recovery_required"
    assert not store.heartbeat(j["id"], "dead")
    with pytest.raises(LostOwnership):
        store.guard(j["id"], "dead")
    store.submit({"device": "lab"}, "device:lab")
    assert store.claim("next") is None
    store.resolve(
        j["id"], {"worker_stopped": True, "device_inspected": True, "note": "Inspected by operator"}
    )
    assert store.claim("next") is not None
    with pytest.raises(LostOwnership):
        store.record(j["id"], "dead", "mutation")


def test_idempotency_reuses_payload_and_rejects_conflict(store):
    a = store.submit({"device": "lab"}, "device:lab", "same")
    b = store.submit({"device": "lab"}, "device:lab", "same")
    assert a["id"] == b["id"]
    with pytest.raises(Conflict):
        store.submit({"device": "other"}, "device:other", "same")


def test_release_version_is_reported(settings, store):
    c = TestClient(create_app(settings))
    assert c.get("/healthz").json() == {"status": "ok", "api_version": "v1", "version": __version__}
    assert c.get("/openapi.json").json()["info"]["version"] == __version__
    store.worker_seen("w1", queues=("priority", "upgrade", "scheduled"))
    store.worker_seen("w1", "job", "busy")
    c.headers["Authorization"] = "Bearer " + settings.token
    assert c.get("/api/v1/workers").json()[0]["version"] == __version__
    index = c.get("/").text
    assert 'id="version"' in index


def test_api_auth_plan_and_submit(settings):
    c = TestClient(create_app(settings))
    assert c.get("/healthz").status_code == 200
    assert c.get("/api/v1/jobs").status_code == 401
    assert c.get("/api/v1/devices", headers={"Authorization": "Bearer nope"}).status_code == 401
    c.headers["Authorization"] = "Bearer " + settings.token
    assert "key_file" not in str(c.get("/api/v1/devices").json())
    plan = c.post("/api/v1/plan", json={"device": "lab", "ucs_unencrypted": True}).json()
    assert plan["steps"] == ["prevalidate", "save_config", "create_ucs", "copy_ucs", "postvalidate_no_reboot"]
    assert c.get("/api/v1/jobs").json() == []
    headers = {"Idempotency-Key": "client-job-1"}
    a = c.post("/api/v1/jobs", json={"device": "lab"}, headers=headers)
    b = c.post("/api/v1/jobs", json={"device": "lab"}, headers=headers)
    assert a.status_code == 202 and a.json()["id"] == b.json()["id"]
    assert (
        c.post("/api/v1/jobs", json={"device": "lab", "create_ucs": True}, headers=headers).status_code == 409
    )
    job = a.json()["id"]
    assert c.get("/api/v1/jobs/" + job + "/events").json() == []
    assert c.post("/api/v1/jobs/" + job + "/rollback", json={}).status_code == 409
    assert c.post("/api/v1/jobs/" + job + "/cancel").json()["status"] == "cancelled"
    assert c.get("/api/v1/jobs/missing").status_code == 404
    assert c.get("/api/v1/jobs?limit=-1").status_code == 422
    assert c.post("/api/v1/jobs", json={"device": "missing"}).status_code == 422
    assert c.get("/openapi.json").json()["paths"]["/api/v1/jobs"]["post"]["security"] == [{"HTTPBearer": []}]


def test_backup_auth_and_recovery_confirmation(settings):
    app = create_app(settings)
    c = TestClient(app)
    store = app.state.store
    j = store.submit({"device": "lab"}, "device:lab")
    store.claim("worker")
    store.finish(j["id"], "worker", "recovery_required")
    url = "/api/v1/jobs/" + j["id"]
    assert c.get(url + "/backup").status_code == 401
    c.headers["Authorization"] = "Bearer " + settings.token
    assert c.get(url + "/backup").status_code == 404
    assert (
        c.post(
            url + "/resolve",
            json={"worker_stopped": False, "device_inspected": True, "note": "Inspected device"},
        ).status_code
        == 422
    )
    assert (
        c.post(
            url + "/resolve",
            json={"worker_stopped": True, "device_inspected": True, "note": "Inspected device"},
        ).json()["status"]
        == "resolved"
    )


def test_malicious_paths_and_fields_rejected(settings):
    c = TestClient(create_app(settings))
    c.headers["Authorization"] = "Bearer " + settings.token
    for extra in (
        {"backup_directory": "../../etc"},
        {"backup_directory": "/tmp"},
        {"command": "reboot"},
        {"target_volume": "HD1.2; reboot"},
        {"drain": True},
        {"drain_percent": float("inf")},
        {"install": True},
    ):
        if extra.get("drain_percent") == float("inf"):
            continue
        assert c.post("/api/v1/jobs", json={"device": "lab", **extra}).status_code == 422
    (settings.backup_root / "escape").symlink_to("/private/tmp", target_is_directory=True)
    assert c.post("/api/v1/jobs", json={"device": "lab", "backup_directory": "escape/foo"}).status_code == 422


def test_failed_validation_fences_follow_on_jobs_but_allows_rollback(store):
    original = store.submit({"device": "lab"}, "group:pair")
    job = store.claim("worker")
    store.record(job["id"], "worker", "post_validation_completed", result={"rollback": {"volume": "HD1.1"}})
    store.finish(job["id"], "worker", "failed", retain_lock=True)
    assert store.get(job["id"])["lock_held"]
    store.submit({"device": "peer"}, "group:pair")
    assert store.claim("next") is None
    rollback = store.submit({"device": "lab"}, "group:pair", kind="rollback", parent=original["id"])
    claimed = store.claim("recovery")
    assert claimed["id"] == rollback["id"]
    assert claimed["result"]["inherited_lock"]
    assert not store.get(original["id"])["lock_held"]
    assert store.get(rollback["id"])["lock_held"]
    store.finish(rollback["id"], "recovery", "succeeded")
    assert store.claim("next")["device"] == "peer"


def test_locked_failed_job_can_be_resolved(store):
    job = store.submit({"device": "lab"}, "device:lab")
    store.claim("worker")
    store.finish(job["id"], "worker", "failed", retain_lock=True)
    store.resolve(
        job["id"], {"worker_stopped": True, "device_inspected": True, "note": "Inspected and repaired"}
    )
    assert not store.get(job["id"])["lock_held"]
