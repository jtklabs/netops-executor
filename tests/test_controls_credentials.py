import json
from concurrent.futures import ThreadPoolExecutor

import pytest
from conftest import Clock, FakeDevice
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from test_engine import execute, reboot_options

from netops_executor.api import create_app
from netops_executor.credentials import AuthenticationRejected, Credential, Selector, Vault, initialize_key
from netops_executor.engine import Runner
from netops_executor.execution_models import Batch, ManualCompletion, ValidationDecision
from netops_executor.store import Conflict


def vault_for(settings, store):
    settings.credential_key_file = settings.data_dir / "vault.key"
    initialize_key(settings.credential_key_file)
    return Vault(store, settings.credential_key_file)


def test_vault_encrypt_idempotence_revision_rotation(settings, store):
    vault = vault_for(settings, store)
    secret = "unique-sensitive-password-9325"
    request = Credential(kind="ssh", username="root", password=secret)
    assert vault.put("primary", request)["revision"] == 1
    assert vault.put("primary", request)["revision"] == 1
    with store.connect() as db:
        ciphertext = db.execute("SELECT secret FROM credentials").fetchone()[0]
        assert secret.encode() not in ciphertext
    assert secret not in json.dumps(vault.list())
    old = settings.credential_key_file.read_bytes()
    new = Fernet.generate_key() + b"\n"
    settings.credential_key_file.write_bytes(new + old)
    vault.rotate()
    settings.credential_key_file.write_bytes(new)
    assert vault.candidates("ssh")[0]["password"] == secret
    assert vault.put("primary", request.model_copy(update={"priority": 10}))["revision"] == 2
    settings.credential_key_file.chmod(0o644)
    with pytest.raises(Conflict, match="owner-only"):
        vault.candidates("ssh")


def test_fallback_audit_cooldown_scope_and_revisions(settings, store):
    vault = vault_for(settings, store)
    vault.put(
        "tacacs",
        Credential(
            kind="ssh", username="tacacs", password="primary-secret", priority=1, targets=["192.0.2.10"]
        ),
    )
    vault.put("local", Credential(kind="ssh", username="root", password="local-secret", priority=2))
    events = []
    selector = Selector(vault, "ssh", "192.0.2.10", audit=events.append)
    assert selector.run(lambda c: c["id"]) == "tacacs"
    attempts = []

    def post_reboot(c):
        attempts.append(c["id"])
        if c["id"] == "tacacs":
            raise AuthenticationRejected()
        return c["id"]

    assert selector.run(post_reboot) == "local"
    assert attempts == ["tacacs", "local"]
    assert events[-1]["previous"] == "tacacs"
    assert [e["outcome"] for e in events] == ["authenticated", "rejected", "authenticated"]
    other = Selector(vault, "ssh", "192.0.2.10", audit=events.append)
    assert other.run(lambda c: c["id"]) == "local"
    vault.put("tacacs", Credential(kind="ssh", username="tacacs", password="new-secret", priority=1))
    assert (
        other.run(lambda c: c["id"]) == "local"
    )  # Last authenticated is preferred within a connection lifecycle.
    assert Selector(vault, "ssh", "192.0.2.10").run(lambda c: c["id"]) == "tacacs"
    assert "primary-secret" not in json.dumps(events)
    assert selector.redact("local-secret and primary-secret") == "[REDACTED] and [REDACTED]"


def test_no_fallback_on_network_errors(settings, store):
    vault = vault_for(settings, store)
    for profile in ("a", "b"):
        vault.put(profile, Credential(kind="ssh", username="u", password="secret"))
    tried = []

    def failure(c):
        tried.append(c["id"])
        raise TimeoutError()

    with pytest.raises(TimeoutError):
        Selector(vault, "ssh", "host").run(failure)
    assert tried == ["a"]
    with pytest.raises(Conflict):
        Selector(vault, "ssh", "host", ["missing"]).run(failure)


def test_api_new_jobs_and_secret_errors(settings, store):
    vault_for(settings, store)
    client = TestClient(create_app(settings))
    headers = {"Authorization": "Bearer " + settings.token}
    secret = "credential-secret-not-echoed"
    response = client.put(
        "/api/v1/credentials/local", headers=headers, json={"kind": "ssh", "password": secret}
    )
    assert response.status_code == 422
    assert secret not in response.text
    response = client.put(
        "/api/v1/credentials/local",
        headers=headers,
        json={"kind": "ssh", "username": "root", "password": secret},
    )
    assert response.status_code == 200 and secret not in response.text
    assert secret not in client.get("/api/v1/credentials", headers=headers).text
    response = client.post(
        "/api/v1/ssh/jobs",
        headers=headers,
        json={"device": "192.0.2.22", "commands": [{"command": "show version"}]},
    )
    assert response.status_code == 202, response.text
    assert response.json()["request"]["credential_profiles"] is None
    batch = {
        "name": "test",
        "defaults": {},
        "waves": [
            {"wave": 1, "upgrade_at_a_time": 2, "ips": ["192.0.2.10", "192.0.2.11"]},
            {"wave": 2, "ips": ["192.0.2.12"]},
        ],
    }
    response = client.post(
        "/api/v1/upgrade-batches", headers={**headers, "Idempotency-Key": "batch-a"}, json=batch
    )
    assert response.status_code == 202, response.text
    assert response.json()["device_count"] == 3
    assert (
        client.post(
            "/api/v1/upgrade-batches", headers={**headers, "Idempotency-Key": "batch-a"}, json=batch
        ).json()["id"]
        == response.json()["id"]
    )


def test_wave_barrier_and_concurrent_claims(store):
    batch = Batch(
        name="waves",
        waves=[
            {"wave": 1, "upgrade_at_a_time": 2, "ips": ["192.0.2.1", "192.0.2.2", "192.0.2.3"]},
            {"wave": 2, "upgrade_at_a_time": 1, "ips": ["192.0.2.4"]},
        ],
    )
    result = store.create_batch(batch, "waves", lambda ip: "endpoint:" + ip)
    with ThreadPoolExecutor(max_workers=4) as pool:
        claims = list(pool.map(store.claim, ["w1", "w2", "w3", "w4"]))
    running = [c for c in claims if c]
    assert len(running) == 2
    assert [c["device"] for c in sorted(running, key=lambda c: c["created"])] == ["192.0.2.1", "192.0.2.2"]
    for c in running:
        store.finish(c["id"], c["worker"], "succeeded")
    third = store.claim("third")
    store.finish(third["id"], "third", "failed")
    assert store.claim("blocked") is None
    store.mark_done(third["id"], ManualCompletion(operator="jason", reason="inspected device"))
    fourth = store.claim("fourth")
    assert fourth["device"] == "192.0.2.4"
    store.finish(fourth["id"], "fourth", "succeeded")
    assert store.batch(result["id"])["status"] == "completed"


def test_mark_done_running_waits_for_worker_and_preserves_fence(store):
    j = store.submit({"device": "one"}, "one")
    store.claim("w")
    store.reserve(j["id"], "w", ["cluster"])
    assert (
        store.mark_done(j["id"], ManualCompletion(operator="jason", reason="manual inspection"))["status"]
        == "running"
    )
    store.finish(j["id"], "w", "recovery_required")
    assert store.get(j["id"])["status"] == "manually_completed"
    assert store.get(j["id"])["lock_held"]
    store.resolve(j["id"], {"worker_stopped": True, "device_inspected": True, "note": "inspected safely"})
    assert store.get(j["id"])["status"] == "manually_completed"
    assert not store.get(j["id"])["lock_held"]


def test_validation_accept_resumes_without_reboot_or_install(settings, store):
    fake = FakeDevice()
    original = fake.reboot

    def reboot(volume):
        original(volume)
        fake.snap["asm_ready"] = False

    fake.reboot = reboot
    job, fake = execute(settings, store, reboot_options(drain=True, validation_timeout=0), fake)
    assert job["status"] == "needs_review", job
    assert not fake.addresses["/Common/192.0.2.20"]
    gate = job["validation_gates"][-1]
    decision = ValidationDecision(
        action="accept",
        gate_id=gate["id"],
        validation_revision=gate["revision"],
        operator="jason",
        reason="verified manually",
    )
    assert store.decide(job["id"], decision)["state"] == "pending"
    assert store.decide(job["id"], decision)["state"] == "pending"
    clock = Clock()
    runner = Runner(settings, store, store.claim("continue"), "continue", fake, clock.sleep, clock.clock)
    runner.run()
    assert store.get(job["id"])["status"] == "completed_with_warnings"
    assert fake.reboots == ["HD1.2"]
    assert fake.addresses["/Common/192.0.2.20"]
    assert store.decide(job["id"], decision)["state"] == "applied"
    with pytest.raises(Conflict):
        store.decide(job["id"], decision.model_copy(update={"validation_revision": 2}))


def test_validation_retry_is_bounded_and_new_revision(settings, store):
    fake = FakeDevice()
    fake.snap["asm_ready"] = False
    job, _ = execute(settings, store, {"validation_timeout": 0}, fake)
    assert job["status"] == "needs_review"
    gate = job["validation_gates"][-1]
    store.decide(
        job["id"],
        ValidationDecision(
            action="retry",
            gate_id=gate["id"],
            validation_revision=gate["revision"],
            operator="jason",
            reason="retry health now",
        ),
    )
    clock = Clock()
    Runner(settings, store, store.claim("next"), "next", fake, clock.sleep, clock.clock).run()
    updated = store.get(job["id"])
    assert updated["status"] == "needs_review"
    assert updated["validation_gates"][-1]["revision"] == 2
    assert not fake.reboots


def test_volume_auto_select_and_always_copy(settings, store, image):
    job, fake = execute(settings, store, reboot_options(target_volume=None, install=True, images=[image]))
    assert job["status"] == "succeeded", job
    assert job["result"]["target_volume"] == "HD1.2"
    assert not fake.installs
    assert len([c for c, _ in fake.ssh.commands if c.startswith("cpcfg")]) == 1


def test_volume_create_preserves_active(settings, store, image):
    fake = FakeDevice()
    fake.v.pop("HD1.2")
    job, _ = execute(
        settings,
        store,
        {"install": True, "images": [image], "allowed_source_versions": ["16.1.5"], "ucs_unencrypted": True},
        fake,
    )
    assert job["status"] == "succeeded", job
    assert fake.installs == [("BIGIP.iso", "HD1.2", True)]
    assert fake.active()["volume"] == "HD1.1"


def test_cancel_after_install_waits_and_never_reboots(settings, store, image):
    fake = FakeDevice()
    fake.v["HD1.2"]["version"] = "old"
    original = fake.install

    def install(*args):
        original(*args)
        job = store.list()[0]
        store.cancel(job["id"])

    fake.install = install
    job, _ = execute(settings, store, reboot_options(install=True, images=[image]), fake)
    assert job["status"] == "cancelled", job
    assert fake.installs and not fake.reboots


def test_validation_deadline_covers_collection(settings, store):
    from netops_executor.models import JobRequest
    from netops_executor.store import NeedsReview

    fake = FakeDevice()
    request = JobRequest(device="lab", validation_timeout=1)
    store.submit(request.model_dump(), "lab")
    job = store.claim("w")
    clock = Clock()
    runner = Runner(settings, store, job, "w", fake, clock.sleep, clock.clock)
    runner.topology = fake.topology()
    before = fake.snapshot()

    def stalled_snapshot():
        clock.sleep(2)
        runner.guard()
        return before

    fake.snapshot = stalled_snapshot
    with pytest.raises(NeedsReview):
        runner.postvalidate(before, request)
    assert store.get(job["id"])["status"] == "needs_review"
    assert runner.io_deadline is None


def test_legacy_device_reservations_survive_api_upgrade(settings, store):
    old = store.submit({"device": "lab"}, "device:lab")
    store.claim("legacy")
    store.finish(old["id"], "legacy", "recovery_required")
    client = TestClient(create_app(settings), headers={"Authorization": "Bearer " + settings.token})
    queued = client.post("/api/v1/jobs", json={"device": "192.0.2.10"}).json()
    assert queued["lock_key"] == "device:lab"
    assert store.claim("new") is None
    peer = store.submit({"device": "peer"}, "device:peer")
    store.claim("peer")
    assert not store.reserve(peer["id"], "peer", ["ha:pair", "device:lab", "device:peer"])
