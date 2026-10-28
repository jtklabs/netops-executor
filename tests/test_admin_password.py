import json
import shlex

import pytest
from conftest import Clock, FakeDevice
from fastapi.testclient import TestClient
from passlib.hash import sha256_crypt, sha512_crypt
from test_controls_credentials import vault_for
from test_engine import execute, reboot_options

from netops_executor.admin_password import PasswordCheckUnavailable, matches_admin_password
from netops_executor.api import create_app
from netops_executor.credentials import Credential
from netops_executor.engine import Runner
from netops_executor.execution_models import ValidationDecision
from netops_executor.models import JobRequest
from netops_executor.ssh import DeviceError

EXPECTED = 'Expected-$password; [text] "quoted" \\ tail'


class AdminDevice(FakeDevice):
    def __init__(self, password=EXPECTED, after_reboot=None):
        super().__init__()
        self.password = password
        self.after_reboot = after_reboot
        self.resets = []
        self.ignore_reset = False
        self.unavailable = False
        self.reset_error = False
        self.after_reset = lambda: None
        original = self.ssh.tmsh

        def tmsh(command, **kwargs):
            original(command, **kwargs)
            if command == "list /auth user admin encrypted-password":
                if self.unavailable:
                    return 'auth user admin { encrypted-password "unsupported-sensitive-hash" }'
                value = sha512_crypt.using(rounds=1000, salt="testSalt").hash(self.password)
                return 'auth user admin { encrypted-password "' + value + '" }'
            if command.startswith("modify /auth user admin password "):
                assert kwargs["secret"] is True
                value = shlex.split(command)[-1]
                self.resets.append(value)
                if not self.ignore_reset:
                    self.password = value
                self.after_reset()
                if self.reset_error:
                    raise DeviceError("SSH command interrupted; outcome may be unknown")
            return ""

        self.ssh.tmsh = tmsh

    def reboot(self, volume):
        super().reboot(volume)
        if self.after_reboot is not None:
            self.password = self.after_reboot


def provision(settings, store, **kwargs):
    vault = vault_for(settings, store)
    vault.put("expected-admin", Credential(kind="f5_admin", password=EXPECTED, **kwargs))
    return vault


def resume(settings, store, job, fake, action):
    gate = next(g for g in job["validation_gates"] if g["state"] == "open")
    store.decide(
        job["id"],
        ValidationDecision(
            action=action,
            gate_id=gate["id"],
            validation_revision=gate["revision"],
            operator="jason",
            reason="Checked admin password through the management console",
        ),
    )
    claimed = store.claim("resumed")
    clock = Clock()
    Runner(settings, store, claimed, "resumed", fake, clock.sleep, clock.clock).run()
    return store.get(job["id"])


@pytest.mark.parametrize("hasher", [sha512_crypt, sha256_crypt])
def test_verifier_handles_tmsh_hashes_and_mismatch(hasher):
    from types import SimpleNamespace

    value = hasher.using(rounds=1000, salt="fixture").hash(EXPECTED)
    ssh = SimpleNamespace(tmsh=lambda *a, **k: 'auth user admin { encrypted-password "' + value + '" }')
    assert matches_admin_password(ssh, EXPECTED)
    assert not matches_admin_password(ssh, "different")


@pytest.mark.parametrize(
    "output",
    [
        'auth user somebody { encrypted-password "$6$salt$hash" }',
        'auth user admin { encrypted-password "!locked-sensitive" }',
        'auth user admin { encrypted-password "$6$rounds=999999999$salt$' + "a" * 86 + '" }',
        'auth user admin { encrypted-password "$6$rounds=1000001$salt$' + "a" * 86 + '" }',
        "malformed-sensitive-output",
    ],
)
def test_invalid_or_expensive_hashes_do_not_leak(output):
    from types import SimpleNamespace

    with pytest.raises(PasswordCheckUnavailable) as error:
        matches_admin_password(SimpleNamespace(tmsh=lambda *a, **k: output), EXPECTED)
    assert output not in str(error.value)
    assert "sensitive" not in str(error.value)


def test_already_matching_password_is_read_only(settings, store):
    provision(settings, store)
    job, fake = execute(settings, store, {"admin_password": {}}, AdminDevice())
    assert job["status"] == "succeeded", job["result"]
    assert not fake.resets
    assert [c for c, _ in fake.ssh.commands] == ["list /auth user admin encrypted-password"] * 2
    checks = job["result"]["admin_password"]["checks"]
    assert [c["stage"] for c in checks] == ["before", "after"]
    assert all(c["status"] == "matched" and not c["remediated"] for c in checks)


def test_resets_before_and_after_without_storing_secrets(settings, store):
    provision(settings, store)
    job, fake = execute(settings, store, reboot_options(admin_password={}), AdminDevice("old", "changed"))
    assert job["status"] == "succeeded", job["result"]
    assert fake.resets == [EXPECTED, EXPECTED]
    assert fake.reboots == ["HD1.2"]
    checks = job["result"]["admin_password"]["checks"]
    assert all(c["status"] == "matched" and c["remediated"] and not c["initial_match"] for c in checks)
    commands = [c for c, _ in fake.ssh.commands]
    assert commands.index(
        next(c for c in commands if c.startswith("modify /auth user admin"))
    ) < commands.index(next(c for c in commands if c.startswith("save /sys ucs")))
    serialized = json.dumps(job) + json.dumps(store.events(job["id"]))
    assert EXPECTED not in serialized and "testSalt" not in serialized and "$6$" not in serialized
    assert job["result"]["admin_password"]["profile"] == "expected-admin"
    assert all(c["revision"] == 1 for c in checks)


def test_no_profile_or_wrong_target_pauses_before_mutation(settings, store):
    provision(settings, store, targets=["192.0.2.99"])
    job, fake = execute(settings, store, reboot_options(admin_password={}), AdminDevice("old"))
    assert job["status"] == "needs_review"
    assert job["validation_gates"][-1]["phase"] == "admin_password_before"
    assert job["result"]["admin_password"]["checks"][-1]["status"] == "unavailable"
    assert not fake.resets and not fake.reboots and not fake.installs and not fake.ssh.commands


@pytest.mark.parametrize("action", ["accept", "retry"])
def test_precheck_review_continues_upgrade_with_audit(settings, store, action):
    provision(settings, store)
    fake = AdminDevice("old")
    policy = {"remediate": False, "after": False}
    job, fake = execute(settings, store, reboot_options(admin_password=policy), fake)
    assert job["status"] == "needs_review"
    if action == "retry":
        fake.password = EXPECTED
    job = resume(settings, store, job, fake, action)
    assert job["status"] == ("completed_with_warnings" if action == "accept" else "succeeded"), job["result"]
    assert not fake.resets and fake.reboots == ["HD1.2"]


@pytest.mark.parametrize("action", ["accept", "retry"])
def test_postcheck_review_never_repeats_upgrade(settings, store, image, action):
    provision(settings, store)
    fake = AdminDevice(after_reboot="changed")
    fake.ignore_reset = True
    fake.v["HD1.2"]["version"] = "15.1.0"
    job, fake = execute(
        settings, store, reboot_options(install=True, images=[image], admin_password={}), fake
    )
    assert job["status"] == "needs_review", job["result"]
    assert job["validation_gates"][-1]["phase"] == "admin_password_after"
    check = job["result"]["admin_password"]["checks"][-1]
    assert check["reset_attempted"] and not check["remediated"]
    fake.ignore_reset = False
    job = resume(settings, store, job, fake, action)
    assert job["status"] == ("completed_with_warnings" if action == "accept" else "succeeded"), job["result"]
    assert len(fake.installs) == 1 and fake.reboots == ["HD1.2"]
    assert len(fake.resets) == (1 if action == "accept" else 2)


def test_unverifiable_hash_is_reviewed_without_blind_reset(settings, store):
    provision(settings, store)
    fake = AdminDevice()
    fake.unavailable = True
    job, fake = execute(settings, store, {"admin_password": {}}, fake)
    assert job["status"] == "needs_review"
    assert not fake.resets
    assert "unsupported-sensitive-hash" not in json.dumps(job)


@pytest.mark.parametrize("cancel", [True, False])
def test_uncertain_password_write_is_fenced(settings, store, cancel):
    provision(settings, store)
    fake = AdminDevice("old")
    if cancel:
        fake.after_reset = lambda: store.cancel(store.list()[0]["id"])
    else:
        fake.reset_error = True
    job, fake = execute(settings, store, reboot_options(admin_password={}), fake)
    assert job["status"] == "recovery_required", job["result"]
    assert job["result"]["admin_password"]["reset_in_progress"]
    assert not fake.reboots and fake.resets == [EXPECTED]
    store.submit(JobRequest(device="lab").model_dump(), "device:lab")
    assert store.claim("other") is None


def test_profile_remains_pinned_between_checks(settings, store):
    vault = provision(settings, store, priority=100)
    fake = AdminDevice("old", "changed")
    fake.after_reset = lambda: vault.put(
        "new-priority", Credential(kind="f5_admin", password="other", priority=0)
    )
    job, fake = execute(settings, store, reboot_options(admin_password={}), fake)
    assert job["status"] == "succeeded"
    assert fake.resets == [EXPECTED, EXPECTED]
    assert {c["profile"] for c in job["result"]["admin_password"]["checks"]} == {"expected-admin"}


def test_api_profile_plan_and_job_contract(settings, store):
    vault_for(settings, store)
    client = TestClient(create_app(settings), headers={"Authorization": "Bearer " + settings.token})
    created = client.put(
        "/api/v1/credentials/expected-admin", json={"kind": "f5_admin", "password": EXPECTED}
    )
    assert created.status_code == 200 and created.json()["kind"] == "f5_admin"
    assert EXPECTED not in created.text
    for payload in ({"username": "root", "password": EXPECTED}, {"password": "bad\npassword"}):
        assert client.put("/api/v1/credentials/bad", json={"kind": "f5_admin", **payload}).status_code == 422
    request = {"device": "lab", "admin_password": {"credential_profile": "expected-admin"}}
    plan = client.post("/api/v1/plan", json=request).json()
    assert plan["steps"] == [
        "prevalidate",
        "verify_admin_password_before",
        "postvalidate_no_reboot",
        "verify_admin_password_after",
    ]
    queued = client.post("/api/v1/jobs", json=request)
    assert queued.status_code == 202
    assert queued.json()["request"]["admin_password"] == {
        "credential_profile": "expected-admin",
        "remediate": True,
        "before": True,
        "after": True,
    }
    assert (
        client.post(
            "/api/v1/jobs", json={"device": "lab", "admin_password": {"password": EXPECTED}}
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/api/v1/jobs", json={"device": "lab", "admin_password": {"before": False, "after": False}}
        ).status_code
        == 422
    )


def test_password_reset_uses_stdin_and_preserves_special_characters(settings):
    from unittest.mock import Mock

    from netops_executor.admin_password import reset_admin_password
    from netops_executor.ssh import SSH

    ssh = SSH(settings, settings.devices["lab"])
    ssh.shell = Mock(return_value="")
    reset_admin_password(ssh, EXPECTED)
    command, timeout, stdin = ssh.shell.call_args.args
    assert command == "tmsh -q" and EXPECTED not in command
    assert shlex.split(stdin.splitlines()[0])[-1] == EXPECTED
    assert stdin.endswith("\nquit\n")


def test_precheck_retry_uses_updated_expected_profile_revision(settings, store):
    vault = provision(settings, store)
    fake = AdminDevice("actual-local-password")
    job, fake = execute(settings, store, {"admin_password": {"remediate": False, "after": False}}, fake)
    assert job["status"] == "needs_review"
    vault.put("expected-admin", Credential(kind="f5_admin", password="actual-local-password"))
    job = resume(settings, store, job, fake, "retry")
    assert job["status"] == "succeeded"
    assert [c["revision"] for c in job["result"]["admin_password"]["checks"]] == [1, 2]
    assert not fake.resets


def test_read_only_precheck_review_does_not_invent_mutation(settings, store):
    provision(settings, store)
    fake = AdminDevice("old")
    job, fake = execute(settings, store, reboot_options(admin_password={"remediate": False}), fake)
    assert job["status"] == "needs_review"
    fake.password = EXPECTED
    fake.snap["active"]["version"] = "15.1.0"
    job = resume(settings, store, job, fake, "retry")
    assert job["status"] == "failed"
    assert not job["lock_held"] and not fake.resets and not fake.reboots
