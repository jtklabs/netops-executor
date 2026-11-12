from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from prometheus_client.parser import text_string_to_metric_families

from netops_executor import __version__
from netops_executor.api import create_app
from netops_executor.metrics import render_metrics
from netops_executor.store import Deferred, Store


def samples(store, settings):
    return [
        sample
        for family in text_string_to_metric_families(render_metrics(store, settings).decode())
        for sample in family.samples
    ]


def value(observations, name, **labels):
    return sum(
        sample.value
        for sample in observations
        if sample.name == name and all(sample.labels.get(key) == wanted for key, wanted in labels.items())
    )


@pytest.fixture
def clock(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr("netops_executor.store.time.time", lambda: now[0])
    return now


def test_metrics_endpoint_is_authenticated_and_prometheus_parseable(settings):
    settings.poller_instance = "checkmk-us"
    client = TestClient(create_app(settings))
    assert client.get("/metrics").status_code == 401
    response = client.get("/metrics", headers={"Authorization": "Bearer " + settings.token})
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert response.headers["cache-control"] == "no-store"
    observations = [
        sample for family in text_string_to_metric_families(response.text) for sample in family.samples
    ]
    assert value(observations, "netops_executor_build_info", poller="checkmk-us", version=__version__) == 1
    assert value(observations, "netops_jobs_completed_total") == 0
    assert settings.token not in response.text


def test_job_counters_and_histograms_survive_restarts_repeated_finishes_and_job_deletion(
    settings, store, clock
):
    job = store.submit({"device": "private-device", "queue": "priority"}, "private-lock", kind="ssh")
    clock[0] = 1005
    assert store.claim("private-worker")["id"] == job["id"]
    store.record(job["id"], "private-worker", "read", result={"secret": "private-result"})
    clock[0] = 1020
    store.finish(job["id"], "private-worker", "succeeded")
    store.finish(job["id"], "private-worker", "failed")
    for current in (store, Store(settings.data_dir / "jobs.sqlite3")):
        observations = samples(current, settings)
        assert value(observations, "netops_jobs_submitted_total", queue="priority", job_type="ssh") == 1
        assert (
            value(
                observations, "netops_jobs_completed_total", queue="priority", job_type="ssh", result="pass"
            )
            == 1
        )
        assert value(observations, "netops_jobs_completed_total", result="fail") == 0
        assert value(observations, "netops_job_duration_seconds_sum", queue="priority", job_type="ssh") == 15
        assert value(observations, "netops_job_queue_wait_seconds_sum", queue="priority", job_type="ssh") == 5
        assert (
            value(
                observations,
                "netops_job_duration_seconds_bucket",
                queue="priority",
                job_type="ssh",
                le="10",
            )
            == 0
        )
        assert (
            value(
                observations,
                "netops_job_duration_seconds_bucket",
                queue="priority",
                job_type="ssh",
                le="30",
            )
            == 1
        )
        assert "private-device" not in render_metrics(current, settings).decode()
        assert "private-result" not in render_metrics(current, settings).decode()
    with store.connect() as db:
        db.execute("DELETE FROM jobs WHERE id=?", (job["id"],))
    observations = samples(store, settings)
    assert value(observations, "netops_jobs_completed_total", result="pass") == 1
    assert value(observations, "netops_jobs_submitted_total") == 1


def test_scheduled_delay_is_excluded_from_queue_wait_and_backlog_is_separated(settings, store, clock):
    start = datetime.fromtimestamp(1100, timezone.utc).isoformat()
    job = store.submit(
        {"device": "lab", "queue": "scheduled", "start_at": start}, "scheduled", kind="snmp_walk"
    )
    observations = samples(store, settings)
    assert value(observations, "netops_queue_jobs", queue="scheduled", state="future") == 1
    assert value(observations, "netops_queue_jobs", queue="scheduled", state="due") == 0
    assert store.claim("worker") is None
    clock[0] = 1110
    assert value(samples(store, settings), "netops_queue_oldest_due_wait_seconds", queue="scheduled") == 10
    assert store.claim("worker")["id"] == job["id"]
    clock[0] = 1130
    store.finish(job["id"], "worker", "completed_with_warnings")
    observations = samples(store, settings)
    assert value(observations, "netops_job_queue_wait_seconds_sum", job_type="snmp_walk") == 10
    assert value(observations, "netops_job_duration_seconds_sum", job_type="snmp_walk") == 20
    assert value(observations, "netops_jobs_completed_total", result="warning") == 1


def test_reservation_deferral_uses_the_actual_admitted_start(settings, store, clock):
    job = store.submit({"device": "lab"}, "deferral", kind="ssh")
    clock[0] = 1005
    store.claim("worker")
    with pytest.raises(Deferred):
        store.defer(job["id"], "worker")
    clock[0] = 1020
    store.claim("worker")
    clock[0] = 1030
    store.finish(job["id"], "worker", "succeeded")
    observations = samples(store, settings)
    assert value(observations, "netops_job_duration_seconds_sum", job_type="ssh") == 10
    assert value(observations, "netops_job_queue_wait_seconds_sum", job_type="ssh") == 20


def test_recovery_resolution_does_not_count_a_job_twice_and_unstarted_jobs_have_no_runtime(
    settings, store, clock
):
    first = store.submit({"device": "lab"}, "first", kind="ssh")
    store.claim("worker")
    clock[0] = 1010
    store.finish(first["id"], "worker", "recovery_required", retain_lock=True)
    with store.connect() as db:
        db.execute("UPDATE jobs SET status='resolved',updated=? WHERE id=?", (1020, first["id"]))
    second = store.submit({"device": "other"}, "second", kind="ssh")
    store.cancel(second["id"])
    observations = samples(store, settings)
    assert value(observations, "netops_jobs_completed_total", result="fail") == 1
    assert value(observations, "netops_jobs_completed_total", result="resolved") == 0
    assert value(observations, "netops_jobs_completed_total", result="cancelled") == 1
    assert value(observations, "netops_job_duration_seconds_count", job_type="ssh") == 1


def test_manual_completion_is_recorded_as_the_final_outcome(settings, store, clock):
    job = store.submit({"device": "lab"}, "manual", kind="ssh")
    store.claim("worker")
    with store.connect() as db:
        db.execute("INSERT INTO controls(job,waive) VALUES (?,1)", (job["id"],))
    store.finish(job["id"], "worker", "succeeded")
    observations = samples(store, settings)
    assert value(observations, "netops_jobs_completed_total", result="manual") == 1
    assert value(observations, "netops_jobs_completed_total", result="pass") == 0


def test_legacy_jobs_are_backfilled_once_and_worker_versions_are_aggregated(settings, store, clock):
    job = store.submit({"device": "lab"}, "legacy", kind="ssh")
    store.claim("worker")
    clock[0] = 1010
    store.finish(job["id"], "worker", "failed")
    with store.connect() as db:
        db.execute("DROP TRIGGER jobs_metrics_submitted")
        db.execute("DROP TRIGGER jobs_metrics_finished")
        db.execute("DROP TABLE job_metrics")
    upgraded = Store(settings.data_dir / "jobs.sqlite3")
    assert value(samples(upgraded, settings), "netops_jobs_completed_total", result="fail") == 1
    upgraded.worker_seen("private-worker-id", state="busy", queues=["priority", "scheduled"])
    observations = samples(upgraded, settings)
    assert value(observations, "netops_workers_online", queue="priority", version=__version__) == 1
    assert value(observations, "netops_workers_busy", queue="priority", version=__version__) == 1
    assert "private-worker-id" not in render_metrics(upgraded, settings).decode()
    clock[0] += settings.stale_seconds + 1
    assert value(samples(upgraded, settings), "netops_workers_online") == 0
