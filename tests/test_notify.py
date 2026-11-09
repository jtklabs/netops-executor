import email
import smtplib
import time
from email import policy

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from netops_executor import api as api_module
from netops_executor.api import create_app
from netops_executor.execution_models import Batch
from netops_executor.models import ScheduledRequest
from netops_executor.notify import EmailSender, batch_state, job_report
from netops_executor.store import Conflict

TO = "ops@example.com"


class Relay:
    """Stands in for smtplib.SMTP: records messages, or raises the queued errors in turn."""

    def __init__(self):
        self.messages, self.errors, self.closed = [], [], 0

    def __call__(self):
        return self

    def send_message(self, msg):
        if self.errors:
            raise self.errors.pop(0)
        self.messages.append(email.message_from_bytes(msg.as_bytes(), policy=policy.default))
        return {}

    def quit(self):
        self.closed += 1


@pytest.fixture
def mailed(settings):
    settings.smtp_host, settings.smtp_from = "relay.example.com", "NetOps <netops@example.com>"
    return settings


@pytest.fixture
def relay():
    return Relay()


@pytest.fixture
def sender(mailed, store, relay):
    store.set_email(True)
    return EmailSender(mailed, store, connect=relay)


def deliveries(store):
    with store.connect() as db:
        return [dict(r) for r in db.execute("SELECT * FROM email_deliveries ORDER BY seq")]


def ssh_job(store, **request):
    return store.submit(
        {"device": "lab", "commands": [{"command": "date"}], **request}, "device:lab", kind="ssh"
    )


def run_next(store, status, worker="w"):
    job = store.claim(worker)
    store.finish(job["id"], worker, status)
    return job


def parts(msg):
    return msg.get_body(("plain",)).get_content(), msg.get_body(("html",)).get_content()


def two_wave_batch(store, name="dc1 <night>", **options):
    waves = [{"wave": 1, "ips": ["192.0.2.1"]}, {"wave": 2, "ips": ["192.0.2.2"]}]
    return store.create_batch(
        Batch(name=name, waves=waves, notify_email=TO, **options), None, lambda ip: "device:" + ip
    )


def test_notify_email_takes_one_address_or_a_list_and_rejects_header_injection():
    assert ScheduledRequest(notify_email=TO).notify_email == [TO]
    assert ScheduledRequest(notify_email=[TO, "b.c+d@mail.example.co", TO]).notify_email == [
        TO,
        "b.c+d@mail.example.co",
    ]
    for bad in ("ops", "ops@local", "Ops <ops@example.com>", "a@x.io,b@x.io", "a@x.io\nBcc: e@x.io", []):
        with pytest.raises(ValidationError):
            ScheduledRequest(notify_email=bad)


def test_finished_job_with_notify_email_is_reported_once(store, sender, relay):
    job = ssh_job(store, notify_email=[TO, "noc@example.com"])
    run_next(store, "succeeded")
    assert sender.deliver_due(time.time() + 1) == 1
    [msg] = relay.messages
    assert msg["To"] == "ops@example.com, noc@example.com"
    assert msg["From"] == "NetOps <netops@example.com>"
    assert msg["Subject"] == "[NetOps] SSH job succeeded: lab (192.0.2.10)"
    assert msg["X-NetOps-Job"] == job["id"] and msg["Auto-Submitted"] == "auto-generated"
    text, html = parts(msg)
    assert "Succeeded" in text and job["id"] in text
    assert html.startswith("<!doctype html>") and "lab (192.0.2.10)" in html
    assert relay.closed == 1
    assert sender.deliver_due(time.time() + 2) == 0
    assert [(d["state"], d["status"]) for d in deliveries(store)] == [("delivered", "succeeded")]


def test_jobs_without_notify_email_queue_nothing_and_keep_their_saved_request(store, sender):
    job = ssh_job(store)
    assert "notify_email" not in job["request"]
    run_next(store, "failed")
    assert deliveries(store) == []


def test_notify_email_needs_smtp_settings(store):
    with pytest.raises(Conflict, match="SMTP"):
        ssh_job(store, notify_email=[TO])
    waves = [{"wave": 1, "ips": ["192.0.2.1"]}]
    with pytest.raises(Conflict, match="SMTP"):
        store.create_batch(Batch(name="b", waves=waves, notify_email=TO), None, lambda ip: ip)
    # Per-device addresses in the batch defaults are checked too.
    with pytest.raises(Conflict, match="SMTP"):
        store.create_batch(Batch(name="b", waves=waves, defaults={"notify_email": TO}), None, lambda ip: ip)
    assert store.create_batch(Batch(name="b", waves=waves), None, lambda ip: ip)["notify_email"] is None


def test_unsent_report_takes_the_newer_status_and_older_ones_are_superseded(store, sender, relay):
    job = ssh_job(store, notify_email=[TO])
    run_next(store, "recovery_required")
    with store.connect() as db:
        db.execute("UPDATE jobs SET status='resolved',updated=? WHERE id=?", (time.time(), job["id"]))
        db.execute("DELETE FROM locks")
    assert [d["status"] for d in deliveries(store)] == ["resolved"]
    assert sender.deliver_due(time.time() + 1) == 1
    assert "resolved by operator" in relay.messages[0]["Subject"]

    # A report already attempted stays; a newer one replaces it if both are still waiting.
    second = ssh_job(store, notify_email=[TO])
    run_next(store, "recovery_required")
    relay.errors.append(smtplib.SMTPServerDisconnected("gone"))
    assert sender.deliver_due(time.time() + 2) == 0
    with store.connect() as db:
        db.execute("UPDATE jobs SET status='resolved',updated=? WHERE id=?", (time.time(), second["id"]))
    sender.paused_until = 0
    assert sender.deliver_due(time.time() + 3600) == 1
    assert [d["state"] for d in deliveries(store) if d["subject"] == second["id"]] == ["skipped", "delivered"]
    assert relay.messages[-1]["X-NetOps-Status"] == "resolved"


def test_relay_failures_retry_with_backoff_and_refusals_stop(store, sender, relay):
    ssh_job(store, notify_email=[TO])
    run_next(store, "succeeded")
    now = time.time() + 1
    relay.errors.append(smtplib.SMTPServerDisconnected("connection lost"))
    assert sender.deliver_due(now) == 0
    [delivery] = deliveries(store)
    assert delivery["state"] == "pending" and delivery["last_error"] == "SMTPServerDisconnected"
    assert delivery["next_attempt"] == pytest.approx(now + 30)
    assert sender.deliver_due(now + 10) == 0  # paused while the relay is failing
    assert sender.deliver_due(now + 31) == 1

    ssh_job(store, notify_email=[TO])
    run_next(store, "succeeded")
    relay.errors.append(smtplib.SMTPRecipientsRefused({TO: (550, b"no such user")}))
    assert sender.deliver_due(now + 60) == 0
    refused = deliveries(store)[-1]
    assert refused["state"] == "failed" and "all recipients refused" in refused["last_error"]
    assert sender.deliver_due(now + 3600) == 0  # not retried, and the relay is not paused
    assert sender.store.email_retry() == 1


def test_batch_is_reported_once_when_every_wave_has_passed(store, sender, relay):
    batch = two_wave_batch(store)
    assert batch["notify_email"] == [TO]
    run_next(store, "succeeded")
    assert sender.deliver_due(time.time() + 1) == 0
    assert deliveries(store)[0]["last_error"] == "batch still running"
    run_next(store, "completed_with_warnings")
    assert sender.deliver_due(time.time() + 2) == 1
    [msg] = relay.messages
    assert msg["Subject"] == '[NetOps] F5 BIG-IP upgrade batch "dc1 <night>" completed: 2 of 2 passed'
    assert msg["X-NetOps-Batch"] == batch["id"]
    text, html = parts(msg)
    assert "dc1 &lt;night&gt;" in html and "<night>" not in html
    assert "wave 2  192.0.2.2: Completed with warnings" in text
    assert sender.deliver_due(time.time() + 3) == 0


def test_stopped_batch_is_reported_and_reported_again_when_it_finishes(store, sender, relay):
    batch = two_wave_batch(store, name="night")
    first = run_next(store, "failed")
    assert sender.deliver_due(time.time() + 1) == 1
    text, html = parts(relay.messages[0])
    assert "needs attention: 0 of 2 passed" in relay.messages[0]["Subject"]
    assert "1 device was not started because an earlier wave did not pass" in text
    assert "Not started" in html

    # An operator completes the failed device by hand; wave 2 then runs.
    with store.connect() as db:
        db.execute(
            "UPDATE jobs SET status='manually_completed',updated=? WHERE id=?", (time.time(), first["id"])
        )
    assert sender.deliver_due(time.time() + 2) == 0
    run_next(store, "succeeded")
    assert sender.deliver_due(time.time() + 3) == 1
    assert relay.messages[1]["Subject"].endswith("completed: 2 of 2 passed")
    assert [d["state"] for d in deliveries(store) if d["subject"] == batch["id"]] == [
        "delivered",
        "skipped",
        "delivered",
    ]


@pytest.mark.parametrize(
    "statuses,state",
    [
        (["succeeded", "manually_completed"], "completed"),
        (["succeeded", "running"], None),
        (["needs_review", "queued"], None),
        (["failed", "queued"], "stopped"),
        (["failed", "succeeded"], "stopped"),
        # A device waiting in the same wave can still run.
        (["failed", "queued@1"], None),
        (["queued", "queued"], None),
    ],
)
def test_batch_state(statuses, state):
    jobs = []
    for index, status in enumerate(statuses):
        status, _, wave = status.partition("@")
        jobs.append({"id": str(index), "status": status, "wave": int(wave) if wave else index + 1})
    assert batch_state(jobs) == state


def f5_job(**result):
    now = time.time()
    return {
        "id": "job-1",
        "kind": "upgrade",
        "device": "192.0.2.10",
        "status": "completed_with_warnings",
        "started_at": now - 3725,
        "updated": now,
        "request": {"device": "192.0.2.10", "expected_version": "17.5.1.10"},
        "result": {
            "rollback": {"volume": "HD1.2", "version": "17.5.1.9", "build": "0.0.12"},
            "boot_verified": {"volume": "HD1.1", "version": "17.5.1.10", "build": "0.0.35"},
            "ha": {"cluster": None},
            "drain": {"initial_connections": 16, "final_connections": 5, "reason": "plateau"},
            "pre_validation": {"waf_policy_names": ["/Common/a", "/Common/b"]},
            "post_validation": {"waf_policy_names": ["/Common/a", "/Common/b"]},
            "config_sync_forced": ["lab-ha"],
            "ltm_report": {
                "pools": {
                    "before": {"up": 2, "total": 2},
                    "after": {"up": 1, "total": 2},
                    "unchanged_percent": 50.0,
                    "changes": [
                        {
                            "object": "/Common/<app>_pool",
                            "change": "went down",
                            "before": "available/enabled (2 active members)",
                            "after": "offline/enabled (0 active members)",
                        }
                    ],
                }
            },
            **result,
        },
        "validation_gates": [
            {
                "phase": "post_validation",
                "state": "applied",
                "decision": {"action": "retry", "operator": "jason", "reason": "ASM rebuilding"},
            }
        ],
    }


def test_f5_report_names_versions_traffic_changes_and_reviews():
    events = [
        {"time": 1000.0, "step": "create_ucs_started", "data": {"encrypted": True}},
        {"time": 1600.0, "step": "reboot_started", "data": {"volume": "HD1.1"}},
    ]
    subject, text, html = job_report(f5_job(), events, lambda device: "f5-a (" + device + ")")
    assert subject == "[NetOps] F5 BIG-IP upgrade completed with warnings: f5-a (192.0.2.10) (to 17.5.1.10)"
    assert "17.5.1.9 build 0.0.12 on HD1.2 → 17.5.1.10 build 0.0.35 on HD1.1" in text
    assert "Duration:         1h 02m" in text
    assert "16 → 5 connections, ended by plateau" in text
    assert "WAF policies:     2 before, 2 after" in text
    assert "Config sync needed a full-load push from the active unit for: lab-ha" in text
    assert "/Common/<app>_pool: went down" in text
    assert "Post validation: Retry by jason (ASM rebuilding)" in text
    assert "+10m 00s  Reboot started (volume HD1.1)" in text
    assert "/Common/&lt;app&gt;_pool" in html and "<app>" not in html
    assert "Pools" in html and "50%" in html


def test_failed_f5_report_says_what_to_do():
    job = f5_job(error="validation timed out; findings recorded", validation_issues=["ASM is not ready"])
    job["status"] = "recovery_required"
    del job["result"]["boot_verified"]
    subject, text, html = job_report(job, [], str)
    assert "recovery required" in subject and "(to 17.5.1.10)" in subject
    assert text.splitlines()[3] == "NEEDS ATTENTION"
    assert "validation timed out" in text and "Last validation: ASM is not ready" in text
    assert "POST /api/v1/jobs/job-1/resolve" in text
    assert "17.5.1.9 build 0.0.12 on HD1.2 → 17.5.1.10 (target, not reached)" in text


def test_settings_load_checks_smtp(tmp_path, monkeypatch):
    from netops_executor.config import Settings

    (tmp_path / "devices.json").write_text("[]")
    for name, value in {
        "NETOPS_ENV_FILE": str(tmp_path / "none.env"),
        "NETOPS_API_TOKEN": "t" * 40,
        "NETOPS_DEVICES_FILE": str(tmp_path / "devices.json"),
        "NETOPS_DATA_DIR": str(tmp_path / "data"),
        "NETOPS_BACKUP_ROOT": str(tmp_path / "backups"),
        "NETOPS_SMTP_HOST": "relay.example.com",
    }.items():
        monkeypatch.setenv(name, value)
    with pytest.raises(ValueError, match="NETOPS_SMTP_FROM"):
        Settings.load()
    monkeypatch.setenv("NETOPS_SMTP_FROM", "NetOps <netops@example.com>\r\nBcc: x@example.com")
    with pytest.raises(ValueError, match="NETOPS_SMTP_FROM"):
        Settings.load()
    monkeypatch.setenv("NETOPS_SMTP_FROM", "NetOps Executor <netops@example.com>")
    loaded = Settings.load()
    assert (loaded.smtp_port, loaded.smtp_security, loaded.smtp_username) == (587, "starttls", None)
    assert loaded.smtp_from == "NetOps Executor <netops@example.com>"
    monkeypatch.setenv("NETOPS_SMTP_SECURITY", "ssl")
    assert Settings.load().smtp_port == 465
    monkeypatch.setenv("NETOPS_SMTP_USERNAME", "netops")
    with pytest.raises(ValueError, match="both"):
        Settings.load()
    monkeypatch.setenv("NETOPS_SMTP_PASSWORD", "relay-password")
    assert "relay-password" not in repr(Settings.load())
    monkeypatch.setenv("NETOPS_SMTP_SECURITY", "none")
    with pytest.raises(ValueError, match="plain text"):
        Settings.load()
    monkeypatch.setenv("NETOPS_SMTP_HOST", "127.0.0.1")
    assert Settings.load().smtp_security == "none"
    monkeypatch.setenv("NETOPS_SMTP_SECURITY", "tls")
    with pytest.raises(ValueError, match="SECURITY"):
        Settings.load()


def test_api_reports_email_status_and_sends_a_test(mailed, relay, monkeypatch):
    monkeypatch.setattr(api_module.EmailSender, "smtp", lambda self: relay)
    client = TestClient(create_app(mailed), headers={"Authorization": "Bearer " + mailed.token})
    status = client.get("/api/v1/email").json()
    assert status["enabled"] is True and status["host"] == "relay.example.com" and status["pending"] == 0
    assert client.post("/api/v1/email/test", json={"to": [TO]}).json() == {
        "sent": True,
        "refused": [],
        "error": None,
    }
    assert relay.messages[0]["Subject"] == "[NetOps] SMTP test"
    relay.errors.append(smtplib.SMTPAuthenticationError(535, b"bad credentials"))
    assert (
        client.post("/api/v1/email/test", json={"to": [TO]}).json()["error"] == "SMTPAuthenticationError 535"
    )
    assert client.post("/api/v1/email/test", json={"to": ["Ops <ops@example.com>"]}).status_code == 422
    job = client.post(
        "/api/v1/ssh/jobs", json={"device": "lab", "commands": [{"command": "date"}], "notify_email": TO}
    )
    assert job.status_code == 202 and job.json()["request"]["notify_email"] == [TO]


def test_api_without_smtp_refuses_notify_email(settings):
    client = TestClient(create_app(settings), headers={"Authorization": "Bearer " + settings.token})
    assert client.get("/api/v1/email").json()["enabled"] is False
    assert client.post("/api/v1/email/test", json={"to": [TO]}).status_code == 409
    response = client.post(
        "/api/v1/ssh/jobs", json={"device": "lab", "commands": [{"command": "date"}], "notify_email": TO}
    )
    assert response.status_code == 409 and "SMTP" in response.json()["detail"]
