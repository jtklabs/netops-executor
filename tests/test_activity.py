"""The console's view of active work: what is held, what it blocks, and finding a device's jobs."""

import time

import pytest
from fastapi.testclient import TestClient

from netops_executor.api import create_app
from netops_executor.store import NeedsReview


@pytest.fixture
def api(settings):
    return TestClient(create_app(settings), headers={"Authorization": "Bearer " + settings.token})


def queued(store, device, lock=None, kind="ssh", **request):
    return store.submit({"device": device, **request}, lock or "device:" + device, kind=kind)


def running(store, device, worker, kind="ssh"):
    job = queued(store, device, kind=kind)
    claimed = store.claim(worker)
    assert claimed["id"] == job["id"]
    return job


def test_a_held_job_lists_the_queued_jobs_it_blocks(settings, store, api):
    # fw1 needs recovery and keeps its lock; a later job for fw1 cannot start.
    stuck = running(store, "fw1", "w1", kind="panos_upgrade")
    with store.connect() as db:
        db.execute(
            "UPDATE jobs SET result=? WHERE id=?",
            ('{"error": "PAN-OS commit was not confirmed", "progress": {"step": "commit"}}', stuck["id"]),
        )
    store.finish(stuck["id"], "w1", "recovery_required")
    blocked = queued(store, "fw1", kind="password_rotation")
    # sw2 waits for a review decision.
    review = running(store, "sw2", "w2", kind="iosxe_upgrade")
    with pytest.raises(NeedsReview):
        store.open_gate(review["id"], "w2", "post_validation", {"critical": ["BGP peer down"]}, {})
    queued(store, "sw2")
    # lb3 is running; a job elsewhere is just waiting for a worker; another is scheduled.
    running(store, "lb3", "w3")
    ready = queued(store, "rtr4")
    later = queued(store, "rtr5")
    with store.connect() as db:
        db.execute("UPDATE jobs SET start_at=? WHERE id=?", (time.time() + 3600, later["id"]))

    board = api.get("/api/v1/activity").json()
    assert board["summary"] == {
        "running": 1,
        "needs_review": 1,
        "recovery_required": 1,
        "held": 2,
        "queued": 4,
        "blocked": 2,
    }
    # Needing attention first: recovery, then review, then running.
    assert [h["state"] for h in board["held"]] == ["recovery_required", "needs_review", "running"]
    recovery, decision, run = board["held"]
    assert recovery["device"] == "fw1" and recovery["action"] == "resolve"
    assert "PAN-OS commit was not confirmed" in recovery["detail"] and "stays locked" in recovery["detail"]
    assert recovery["holds"] == ["device:fw1"]
    assert [q["id"] for q in recovery["blocking"]] == [blocked["id"]]
    assert recovery["blocking"][0]["waiting"]["detail"].startswith("Blocked by panos_upgrade job")
    assert decision["action"] == "review" and decision["gate"] == "post_validation"
    assert "post validation" in decision["detail"] and len(decision["blocking"]) == 1
    assert run["action"] is None and run["blocking"] == []
    reasons = {q["device"]: q["waiting"]["reason"] for q in board["queued"]}
    assert reasons == {"fw1": "blocked", "sw2": "blocked", "rtr4": "worker", "rtr5": "scheduled"}
    assert next(q for q in board["queued"] if q["id"] == ready["id"])["waiting"]["detail"].startswith("Ready")

    # Releasing the hold lets the blocked job run.
    store.resolve(
        stuck["id"], {"operator": "ops", "reason": "inspected, commit confirmed", "worker_stopped": True}
    )
    board = api.get("/api/v1/activity").json()
    assert all(h["job"]["id"] != stuck["id"] for h in board["held"])
    assert next(q for q in board["queued"] if q["id"] == blocked["id"])["waiting"]["reason"] == "worker"


def test_search_finds_a_device_by_ip_exactly_and_by_its_inventory_id(settings, store, api):
    by_ip = queued(store, "192.0.2.10")
    by_id = queued(store, "lab")  # the inventory ID for 192.0.2.10
    queued(store, "192.0.2.100")
    queued(store, "192.0.2.1")
    found = {j["id"] for j in api.get("/api/v1/jobs", params={"search": "192.0.2.10"}).json()}
    assert found == {by_ip["id"], by_id["id"]}
    assert {j["id"] for j in api.get("/api/v1/jobs", params={"search": "lab"}).json()} == found
    partial = api.get("/api/v1/jobs", params={"search": "192.0.2.1"}).json()
    assert [j["device"] for j in partial] == ["192.0.2.1"]  # an IP never matches 192.0.2.10 or .100
    prefix = api.get("/api/v1/jobs", params={"search": "192.0.2."}).json()
    assert len(prefix) == 3  # text that is not a full IP matches part of the device
    assert api.get("/api/v1/jobs", params={"search": by_ip["id"][:8]}).json()[0]["id"] == by_ip["id"]
    assert api.get("/api/v1/jobs", params={"search": "50%_"}).json() == []


def test_status_filter_and_active_shortcut(settings, store, api):
    done = running(store, "a", "w1")
    store.finish(done["id"], "w1", "succeeded")
    waiting = queued(store, "b")
    statuses = {j["id"]: j["status"] for j in api.get("/api/v1/jobs", params={"status": "active"}).json()}
    assert statuses == {waiting["id"]: "queued"}
    assert [j["id"] for j in api.get("/api/v1/jobs", params={"status": "succeeded"}).json()] == [done["id"]]
    assert api.get("/api/v1/jobs", params={"status": "bogus"}).status_code == 422
    combined = api.get("/api/v1/jobs", params={"status": "active", "search": "a"}).json()
    assert combined == []
