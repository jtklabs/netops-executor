import hashlib
import hmac
import json
import threading
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from netops_executor import __version__
from netops_executor import api as api_module
from netops_executor.api import create_app
from netops_executor.config import webhook_url
from netops_executor.execution_models import ManualCompletion
from netops_executor.store import Deferred, NeedsReview
from netops_executor.webhooks import WebhookSender

TOKEN = "central-issued-token-0123456789"
SECRET = "s" * 40
URL = "https://central.example/netops/webhook?token=hidden"


class Receiver:
    """Records webhook requests and answers with queued responses (200 by default)."""

    def __init__(self):
        self.requests, self.responses = [], []

    def __call__(self, request):
        self.requests.append(request)
        response = self.responses.pop(0) if self.responses else 200
        if isinstance(response, Exception):
            raise response
        return httpx.Response(response)

    def bodies(self):
        return [json.loads(r.content) for r in self.requests]


@pytest.fixture
def hooked(settings):
    settings.webhook_url, settings.webhook_token, settings.webhook_secret = URL, TOKEN, SECRET
    return settings


@pytest.fixture
def receiver():
    return Receiver()


@pytest.fixture
def sender(hooked, store, receiver):
    store.set_webhooks(True)
    return WebhookSender(hooked, store, httpx.Client(transport=httpx.MockTransport(receiver)))


def deliveries(store):
    with store.connect() as db:
        return [dict(r) for r in db.execute("SELECT * FROM webhook_deliveries ORDER BY seq")]


def ssh_job(store, **request):
    return store.submit(
        {"device": "lab", "commands": [{"command": "date"}], **request}, "device:lab", kind="ssh"
    )


def test_finished_job_is_posted_signed_with_its_record(store, sender, receiver):
    job = ssh_job(store)
    store.claim("w")
    store.record(job["id"], "w", "done", result={"output": "ok"})
    store.finish(job["id"], "w", "succeeded")
    assert sender.deliver_due(time.time() + 1) == 1
    [request] = receiver.requests
    assert str(request.url) == URL
    assert request.headers["Authorization"] == "Bearer " + TOKEN
    body = json.loads(request.content)
    assert body["event"] == "job.finished" and body["status"] == "succeeded"
    assert body["executor_version"] == __version__
    assert body["job"] == store.get(job["id"]) and body["job"]["result"] == {"output": "ok"}
    timestamp = request.headers["X-NetOps-Timestamp"]
    expected = hmac.new(SECRET.encode(), timestamp.encode() + b"." + request.content, hashlib.sha256)
    assert request.headers["X-NetOps-Signature"] == "sha256=" + expected.hexdigest()
    assert request.headers["X-NetOps-Event"] == "job.finished"
    assert request.headers["X-NetOps-Delivery"] == body["delivery_id"]
    assert [d["state"] for d in deliveries(store)] == ["delivered"]
    assert sender.deliver_due(time.time() + 2) == 0 and len(receiver.requests) == 1


def test_signature_is_optional(hooked, store, sender, receiver):
    hooked.webhook_secret = None
    store.cancel(ssh_job(store)["id"])
    assert sender.deliver_due(time.time() + 1) == 1
    [request] = receiver.requests
    assert request.headers["Authorization"] == "Bearer " + TOKEN
    assert "X-NetOps-Signature" not in request.headers


def finish_paths(store):
    """Each yields (job id, expected status) through a different code path."""
    queued = ssh_job(store)
    store.cancel(queued["id"])
    yield queued["id"], "cancelled"

    late = ssh_job(store, latest_start_at="2000-01-01T00:00:00Z")
    yield late["id"], "expired"

    walk = store.submit({"device_ip": "192.0.2.9", "oids": ["1.3.6.1"]}, "snmp:9", kind="snmp_walk")
    store.claim("w")
    with store.connect() as db:
        db.execute("UPDATE jobs SET heartbeat=0 WHERE id=?", (walk["id"],))
    store.reap(10)
    yield walk["id"], "failed"

    upgrade = store.submit({"device": "lab"}, "device:lab")
    store.claim("w")
    with pytest.raises(NeedsReview):
        store.open_gate(upgrade["id"], "w", "post", [], {})
    yield upgrade["id"], "needs_review"

    stuck = store.submit({"device": "other"}, "device:other")
    fixed = store.submit({"device": "fourth"}, "device:fourth")
    store.claim("w")
    store.claim("w")
    with store.connect() as db:
        db.execute("UPDATE jobs SET heartbeat=0 WHERE id IN (?,?)", (stuck["id"], fixed["id"]))
    store.reap(10)
    yield stuck["id"], "recovery_required"
    # Resolved before its recovery_required delivery was sent: that delivery reports resolved.
    store.resolve(fixed["id"], {"note": "worker stopped and device inspected"})
    yield fixed["id"], "resolved"

    skipped = store.submit({"device": "third"}, "device:third")
    store.mark_done(skipped["id"], ManualCompletion(operator="op", reason="done by hand"))
    yield skipped["id"], "manually_completed"


def test_every_finishing_path_queues_a_delivery(store, sender, receiver):
    expected = list(finish_paths(store))
    assert sender.deliver_due(time.time() + 1) == len(expected)
    sent = [(b["job"]["id"], b["status"], b["event"]) for b in receiver.bodies()]
    assert sent == [
        (job, status, "job.needs_review" if status == "needs_review" else "job.finished")
        for job, status in expected
    ]


def test_starting_and_requeueing_send_nothing(store, sender):
    job = store.submit({"device": "lab"}, "device:lab")
    store.claim("w")
    with pytest.raises(Deferred):
        store.defer(job["id"], "w")
    store.claim("w")
    assert deliveries(store) == []


def test_unsent_delivery_takes_the_newer_status(store, sender, receiver):
    job = store.submit({"device": "lab"}, "device:lab")
    store.claim("w")
    store.mark_done(job["id"], ManualCompletion(operator="op", reason="waive this run"))
    # finish() writes succeeded, then the waiver turns it into manually_completed in one transaction.
    store.finish(job["id"], "w", "succeeded")
    assert [d["status"] for d in deliveries(store)] == ["manually_completed"]
    sender.deliver_due(time.time() + 1)
    assert [b["status"] for b in receiver.bodies()] == ["manually_completed"]


def test_change_after_an_attempt_queues_another_delivery(store, sender, receiver):
    job = store.submit({"device": "lab"}, "device:lab")
    store.claim("w")
    with store.connect() as db:
        db.execute("UPDATE jobs SET heartbeat=0 WHERE id=?", (job["id"],))
    store.reap(10)
    receiver.responses = [503]
    now = time.time() + 1
    assert sender.deliver_due(now) == 0
    store.resolve(job["id"], {"note": "worker stopped and device inspected"})
    assert [(d["status"], d["attempts"]) for d in deliveries(store)] == [
        ("recovery_required", 1),
        ("resolved", 0),
    ]
    assert sender.deliver_due(now + 6) == 2
    # Both report the job's current state; the retried one keeps its delivery ID.
    first, second = receiver.bodies()[1:]
    assert first["delivery_id"] == receiver.bodies()[0]["delivery_id"]
    assert (first["status"], second["status"]) == ("recovery_required", "resolved")
    assert first["job"]["status"] == second["job"]["status"] == "resolved"


def test_disabled_webhooks_queue_nothing_and_drop_pending(store, sender):
    ssh = ssh_job(store)
    store.cancel(ssh["id"])
    store.set_webhooks(False)
    assert deliveries(store) == []
    store.cancel(ssh_job(store)["id"])
    assert deliveries(store) == []


def test_failures_back_off_pause_and_give_up(store, sender, receiver):
    first, second = ssh_job(store), ssh_job(store)
    store.cancel(first["id"])
    store.cancel(second["id"])
    receiver.responses = [500, httpx.ConnectError("refused"), 200, 200]
    now = time.time() + 1
    assert sender.deliver_due(now) == 0
    assert len(receiver.requests) == 1
    # Paused for the backoff: the second delivery is not tried against a failing receiver.
    assert sender.deliver_due(now + 4) == 0 and len(receiver.requests) == 1
    assert sender.deliver_due(now + 5) == 0
    row = deliveries(store)[0]
    assert (row["attempts"], row["last_error"], row["next_attempt"]) == (2, "ConnectError", now + 15)
    assert sender.deliver_due(now + 15) == 2
    assert [d["state"] for d in deliveries(store)] == ["delivered", "delivered"]

    third = ssh_job(store)
    store.cancel(third["id"])
    clock = now + 100
    with store.connect() as db:
        # Shorten the 72-hour retry window.
        db.execute("UPDATE webhook_deliveries SET expires=? WHERE job=?", (clock + 30, third["id"]))
    receiver.responses = [502] * 10
    while deliveries(store)[2]["state"] == "pending":
        sender.paused_until = 0
        sender.deliver_due(clock)
        clock = deliveries(store)[2]["next_attempt"]
    row = deliveries(store)[2]
    assert row["state"] == "failed" and row["last_error"] == "HTTP 502"
    assert row["next_attempt"] >= row["expires"]
    assert store.webhook_retry(clock) == 1
    receiver.responses = []
    sender.paused_until = 0
    assert sender.deliver_due(clock) == 1


def test_snmp_walk_includes_rows_up_to_the_limit(hooked, store, sender, receiver):
    hooked.webhook_max_rows = 2
    walk = store.submit({"device_ip": "192.0.2.9", "oids": ["1.3.6.1"]}, "snmp:9", kind="snmp_walk")
    store.claim("w")
    rows = [
        {"root_oid": "1.3.6.1", "oid": f"1.3.6.1.{n}", "type": "Integer", "value": str(n), "encoding": "text"}
        for n in range(3)
    ]
    store.append_snmp_rows(walk["id"], "w", rows, {"rows": 3})
    store.finish(walk["id"], "w", "succeeded")
    sender.deliver_due(time.time() + 1)
    [body] = receiver.bodies()
    results = body["snmp_results"]
    assert [r["oid"] for r in results["rows"]] == ["1.3.6.1.0", "1.3.6.1.1"]
    assert results["has_more"] and results["finished"] and results["status"] == "succeeded"
    assert store.snmp_results(walk["id"], results["next_cursor"])["rows"][0]["oid"] == "1.3.6.1.2"


def test_unbuildable_payload_fails_that_delivery_only(store, sender, receiver, monkeypatch):
    broken, fine = ssh_job(store), ssh_job(store)
    store.cancel(broken["id"])
    store.cancel(fine["id"])
    real = sender.payload
    monkeypatch.setattr(
        sender,
        "payload",
        lambda d: (_ for _ in ()).throw(ValueError()) if d["job"] == broken["id"] else real(d),
    )
    assert sender.deliver_due(time.time() + 1) == 1
    assert [b["job"]["id"] for b in receiver.bodies()] == [fine["id"]]
    assert deliveries(store)[0]["last_error"] == "payload: ValueError"


def test_old_records_are_purged(store, sender):
    store.cancel(ssh_job(store)["id"])
    now = time.time() + 1
    sender.deliver_due(now)
    assert len(deliveries(store)) == 1
    store.webhook_due(now + 8 * 86400)
    assert deliveries(store) == []


def test_api_status_test_and_retry(hooked, receiver):
    app = create_app(hooked)
    client = TestClient(app, headers={"Authorization": "Bearer " + hooked.token})
    app.state.webhooks.client = httpx.Client(transport=httpx.MockTransport(receiver))
    status = client.get("/api/v1/webhooks").json()
    assert status["enabled"] and status["url"] == "https://central.example/netops/webhook"
    assert (status["pending"], status["failed"], status["oldest_pending_seconds"]) == (0, 0, None)
    assert client.post("/api/v1/webhooks/test").json() == {
        "delivered": True,
        "status_code": 200,
        "error": None,
    }
    ping = receiver.requests[-1]
    assert json.loads(ping.content)["event"] == "ping" and ping.headers["X-NetOps-Event"] == "ping"
    assert ping.headers["Authorization"] == "Bearer " + TOKEN
    assert TOKEN not in client.get("/api/v1/webhooks").text
    receiver.responses = [401]
    assert client.post("/api/v1/webhooks/test").json() == {"delivered": False, "error": "HTTP 401"}
    store = app.state.store
    store.cancel(ssh_job(store)["id"])
    receiver.responses = [503]
    app.state.webhooks.deliver_due(time.time() + 1)
    status = client.get("/api/v1/webhooks").json()
    assert status["pending"] == 1 and status["recent_failures"][0]["last_error"] == "HTTP 503"
    assert client.post("/api/v1/webhooks/retry").json() == {"requeued": 0}


def test_api_without_webhook(settings):
    client = TestClient(create_app(settings), headers={"Authorization": "Bearer " + settings.token})
    assert client.get("/api/v1/webhooks").json()["enabled"] is False
    assert client.post("/api/v1/webhooks/test").status_code == 409
    assert client.post("/api/v1/webhooks/retry").status_code == 409


def test_api_lifespan_runs_the_sender(hooked, monkeypatch):
    started, stopped = threading.Event(), threading.Event()

    def run(self, stop):
        started.set()
        stop.wait(10)
        stopped.set()

    monkeypatch.setattr(api_module.WebhookSender, "run", run)
    with TestClient(create_app(hooked)):
        assert started.wait(5)
    assert stopped.wait(5)


@pytest.mark.parametrize(
    "url,valid",
    [
        ("https://central.example/hook", True),
        ("https://central.example/hook?token=abc", True),
        ("http://127.0.0.1:9000/hook", True),
        ("http://localhost/hook", True),
        ("http://central.example/hook", False),
        ("https://user:pass@central.example/hook", False),
        ("https://central.example/hook#x", False),
        ("ftp://central.example/hook", False),
    ],
)
def test_webhook_url_validation(url, valid):
    if valid:
        assert webhook_url(url) == url
    else:
        with pytest.raises(ValueError):
            webhook_url(url)


def test_settings_load_requires_a_token_and_checks_the_secret(tmp_path, monkeypatch):
    from netops_executor.config import Settings

    (tmp_path / "devices.json").write_text("[]")
    for name, value in {
        "NETOPS_ENV_FILE": str(tmp_path / "none.env"),
        "NETOPS_API_TOKEN": "t" * 40,
        "NETOPS_DEVICES_FILE": str(tmp_path / "devices.json"),
        "NETOPS_DATA_DIR": str(tmp_path / "data"),
        "NETOPS_BACKUP_ROOT": str(tmp_path / "backups"),
        "NETOPS_WEBHOOK_URL": "https://central.example/hook",
    }.items():
        monkeypatch.setenv(name, value)
    with pytest.raises(ValueError, match="TOKEN"):
        Settings.load()
    monkeypatch.setenv("NETOPS_WEBHOOK_TOKEN", "has a space in it ok")
    with pytest.raises(ValueError, match="TOKEN"):
        Settings.load()
    monkeypatch.setenv("NETOPS_WEBHOOK_TOKEN", TOKEN)
    loaded = Settings.load()
    assert (loaded.webhook_token, loaded.webhook_secret, loaded.webhook_max_rows) == (TOKEN, None, 10000)
    monkeypatch.setenv("NETOPS_WEBHOOK_SECRET", "short")
    with pytest.raises(ValueError, match="SECRET"):
        Settings.load()
    monkeypatch.setenv("NETOPS_WEBHOOK_SECRET", SECRET)
    monkeypatch.setenv("NETOPS_WEBHOOK_MAX_ROWS", "0")
    loaded = Settings.load()
    assert (loaded.webhook_url, loaded.webhook_secret, loaded.webhook_max_rows) == (
        "https://central.example/hook",
        SECRET,
        0,
    )
