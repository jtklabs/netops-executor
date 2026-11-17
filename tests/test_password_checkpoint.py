import copy
import json
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from passlib.hash import sha512_crypt
from test_controls_credentials import vault_for
from test_password_rotation import PASSWORD, work

from netops_executor.api import create_app
from netops_executor.password_checkpoint import CheckpointAccounts
from netops_executor.password_devices import ChangeNotAccepted, PasswordRejected, crypt_matches
from netops_executor.password_models import PasswordRotationOptions
from netops_executor.ssh import DeviceError

OLD = sha512_crypt.using(rounds=5000).hash("old-password")
LOCK_PRESENT = "CLINFR0519  Configuration lock present. Can not execute this command."
WRITES = ("add user", "set user", "add rba user", "save config")


class Gaia:
    """Fake Gaia clish: running and saved configuration, config-state and the database lock."""

    def __init__(self, failure=None, existing=True):
        self.selector = SimpleNamespace(secrets=set())
        self.users = {
            "admin": [
                "add user admin uid 0 homedir /home/admin",
                "set user admin gid 0 shell /bin/bash",
                'set user admin realname "Admin error handler"',
                "set user admin password-hash " + OLD,
            ],
            "monitor": [
                "add user monitor uid 103 homedir /home/monitor",
                "set user monitor gid 100 shell /etc/cli.sh",
                "set user monitor password-hash *",
            ],
        }
        self.rba = [
            "add rba role auditRole domain-type System readonly-features route",
            "add rba user admin roles adminRole",
            "add rba user monitor roles monitorRole",
        ]
        if existing:
            self.users["automation"] = [
                "add user automation uid 105 homedir /home/automation",
                "set user automation gid 100 shell /etc/cli.sh",
                "set user automation password-hash " + OLD,
            ]
            self.rba.append("add rba user automation roles adminRole")
        self.saved = copy.deepcopy((self.users, self.rba))
        self.state, self.lock, self.failure = "saved", "webui-admin", failure
        self.commands, self.closed, self.expert = [], 0, False

    def connect(self):
        return self

    def dialogue(self, *args, **kwargs):
        raise AssertionError("dialogue() enables first, which is expert mode on Gaia")

    def close(self):
        # Ending the session releases a lock it holds.
        self.closed += 1
        if self.lock == "us":
            self.lock = None

    def redact(self, text):
        for value in sorted(self.selector.secrets, key=len, reverse=True):
            text = text.replace(value, "[REDACTED]")
        return text

    def execute(self, command, timeout, mode="exec", enable=False):
        assert mode == "exec" and not enable
        self.commands.append(command)
        return {"stdout": self.redact(self.handle(command)), "cli_error": False}

    def handle(self, command):
        if self.expert:
            return "bash: " + command.split()[0] + ": command not found"
        if command == "show config-state":
            return self.state
        if command == "show configuration user":
            return "\n".join(line for lines in self.users.values() for line in lines)
        if command == "show configuration rba":
            return "\n".join(self.rba)
        if command == "lock database override":
            if self.failure == "lock_denied":
                return "CLINFR0409  Permission denied"
            self.lock = "us"
            return ""
        if command == "unlock database":
            self.lock = None if self.lock == "us" else self.lock
            return ""
        assert command.startswith(WRITES), command
        if self.failure == "stolen":
            self.lock = "webui-admin"
        if self.lock != "us":
            return LOCK_PRESENT
        if command == "save config":
            if self.failure != "save_lost":
                self.saved, self.state = copy.deepcopy((self.users, self.rba)), "saved"
            return ""
        if self.failure == "deny" or (self.failure == "partial" and "password-hash" in command):
            return "CLINFR0409  Permission denied"
        if self.failure == "ignore":
            return ""
        words = command.split()
        user = words[3] if words[1] == "rba" else words[2]
        if words[:2] == ["add", "user"]:
            self.users[user] = [command]
        elif words[:2] == ["add", "rba"]:
            self.rba.append(command)
        else:
            key, value = words[3], words[4]
            if self.failure == "wrong_hash" and key == "password-hash":
                value = sha512_crypt.hash("other")
            lines = [line for line in self.users[user] if key not in line.split()]
            if key == "shell":
                lines.append("set user " + user + " gid 100 shell " + value)
            else:
                lines.append("set user " + user + " " + key + " " + value)
            if self.failure == "reshell":
                lines = [line.replace("/etc/cli.sh", "/bin/bash") for line in lines]
            self.users[user] = lines
        self.state = "unsaved"
        return ""


def request(**options):
    r = PasswordRotationOptions.model_validate(
        {
            "device": "lab",
            "device_type": "checkpoint_gaia",
            "username": "automation",
            "allow_preview": True,
            "verification": "local_hash",
            **options,
        }
    )
    r.for_platform(r.device_type)
    return r


def client(gaia, **options):
    return CheckpointAccounts(None, None, None, request(**options), PASSWORD, lambda: None, None, ssh=gaia)


def stored(gaia, user="automation", saved=False):
    users = gaia.saved[0] if saved else gaia.users
    return [line.split()[-1] for line in users[user] if "password-hash" in line][0]


def failure(exc, action):
    """The fixed message of the expected exception (exactly that class); never a secret."""
    with pytest.raises(exc) as raised:
        action()
    assert type(raised.value) is exc
    assert PASSWORD not in str(raised.value) and "$6$" not in str(raised.value)
    return str(raised.value)


def test_update_locks_sets_hash_saves_and_confirms():
    gaia = Gaia()
    device = client(gaia)
    assert device.preflight() is True
    assert "lock database override" not in gaia.commands
    device.apply()
    assert stored(gaia, saved=True) == OLD
    device.save()
    device.verify()
    assert crypt_matches(PASSWORD, stored(gaia, saved=True)) and stored(gaia).startswith("$6$")
    assert gaia.users["automation"][:2] == Gaia().users["automation"][:2]
    assert gaia.state == "saved" and gaia.lock is None
    writes = [c for c in gaia.commands if c.startswith(("lock", "unlock", *WRITES))]
    assert writes == [
        "lock database override",
        "set user automation password-hash " + device.hashed,
        "save config",
        "unlock database",
    ]
    assert device.report == {"confirmed": ["running_matches", "saved"]}
    assert all(PASSWORD not in command for command in gaia.commands)
    assert {PASSWORD, device.hashed} <= device.ssh.selector.secrets


def test_creation_uses_free_uid_clish_shell_and_requested_role():
    gaia = Gaia(existing=False)
    device = client(gaia)
    assert device.preflight() is False
    device.apply()
    device.save()
    device.verify()
    assert [c for c in gaia.commands if c.startswith(("add ", "set "))] == [
        "add user automation uid 104 homedir /home/automation",
        "set user automation password-hash " + device.hashed,
        "set user automation shell /etc/cli.sh",
        "add rba user automation roles adminRole",
    ]
    assert crypt_matches(PASSWORD, stored(gaia, saved=True))
    assert "add rba user automation roles adminRole" in gaia.saved[1]


def test_preflight_refuses_missing_disabled_unsaved_expert_and_unknown_role():
    assert "create_if_missing" in failure(
        DeviceError, client(Gaia(existing=False), create_if_missing=False).preflight
    )
    assert "no usable local password" in failure(DeviceError, client(Gaia(), username="monitor").preflight)
    unsaved = Gaia()
    unsaved.state = "unsaved"
    assert "unsaved configuration" in failure(DeviceError, client(unsaved).preflight)
    expert = Gaia()
    expert.expert = True
    assert "expert" in failure(DeviceError, client(expert).preflight)
    missing_role = client(Gaia(existing=False), new_account={"role": "invented"})
    assert "role" in failure(DeviceError, missing_role.preflight)
    assert client(Gaia(existing=False), new_account={"role": "auditRole"}).preflight() is False


@pytest.mark.parametrize(
    "mode,existing,wording",
    [
        ("deny", True, "permission denied"),
        ("deny", False, "permission denied"),
        ("lock_denied", True, "permission denied"),
        ("stolen", True, "configuration lock"),
        ("ignore", True, "did not apply the change"),
        ("ignore", False, "did not apply the change"),
    ],
)
def test_refused_or_ignored_change_is_not_accepted_and_releases_the_lock(mode, existing, wording):
    gaia = Gaia(mode, existing)
    before = copy.deepcopy((gaia.users, gaia.rba))
    device = client(gaia)
    device.preflight()
    message = failure(ChangeNotAccepted, device.apply)
    assert wording in message and "unchanged" in message
    assert (gaia.users, gaia.rba) == before and gaia.saved == before
    assert "save config" not in gaia.commands and gaia.lock != "us"
    if mode != "lock_denied":
        assert gaia.commands[-1] == "unlock database"
    assert "confirmed" not in device.report


def test_pending_changes_after_precheck_are_not_written_and_unlock():
    gaia = Gaia()
    device = client(gaia)
    device.preflight()
    gaia.state = "unsaved"
    assert "unsaved configuration changes" in failure(ChangeNotAccepted, device.apply)
    assert not any(c.startswith(WRITES) for c in gaia.commands) and gaia.lock is None


def test_account_changed_since_precheck_is_not_written():
    gaia = Gaia()
    device = client(gaia)
    device.preflight()
    gaia.rba[-1] = "add rba user automation roles monitorRole"
    assert "changed since precheck" in failure(DeviceError, device.apply)
    assert not any(c.startswith(WRITES) for c in gaia.commands) and gaia.lock is None


@pytest.mark.parametrize("mode,existing", [("partial", False), ("wrong_hash", True), ("reshell", True)])
def test_partial_or_unexpected_change_needs_recovery(mode, existing):
    gaia = Gaia(mode, existing)
    device = client(gaia)
    device.preflight()
    assert "partly changed" in failure(DeviceError, device.apply)
    assert "save config" not in gaia.commands


def test_save_confirms_saved_state_and_refuses_without_the_change_step():
    gaia = Gaia("save_lost")
    device = client(gaia)
    device.preflight()
    device.apply()
    assert "does not hold the new password hash" in failure(DeviceError, device.save)
    assert "confirmed" in device.report and "saved" not in device.report["confirmed"]
    # A new adapter after a worker restart holds neither the lock nor the staged account.
    fresh = client(Gaia())
    assert "did not complete in this session" in failure(DeviceError, fresh.save)
    assert "save config" not in fresh.ssh.commands
    # Losing the lock before the save is a refusal after the running change: recovery.
    gaia = Gaia()
    device = client(gaia)
    device.preflight()
    device.apply()
    gaia.lock = "webui-admin"
    assert "save config was refused" in failure(DeviceError, device.save)


def test_verification_by_hash_and_ssh_login(monkeypatch):
    gaia = Gaia()
    device = client(gaia)
    device.preflight()
    device.apply()
    device.save()
    # A review continuation has a new session whose output shows the stored hash itself.
    rerun = Gaia()
    rerun.users["automation"] = copy.deepcopy(gaia.users["automation"])
    client(rerun).verify()
    rerun.users["automation"][-1] = "set user automation password-hash " + OLD
    assert "does not match" in failure(PasswordRejected, client(rerun).verify)
    del rerun.users["automation"]
    assert "no readable password hash" in failure(DeviceError, client(rerun).verify)
    calls = []
    monkeypatch.setattr(
        "netops_executor.password_checkpoint.verify_login",
        lambda settings, device, username, password, guard: calls.append((username, password)),
    )
    client(Gaia(), verification="ssh_login").verify()
    assert calls == [("automation", PASSWORD)]


@pytest.fixture
def api(settings, store):
    vault_for(settings, store)
    return TestClient(create_app(settings), headers={"Authorization": "Bearer " + settings.token})


@pytest.mark.parametrize("mode", [None, "deny"])
def test_runner_finishes_or_fails_cleanly_without_recovery(settings, store, api, mode):
    response = api.post(
        "/api/v1/password-rotation/jobs",
        json={
            "device": "lab",
            "device_type": "checkpoint_gaia",
            "username": "automation",
            "password": PASSWORD,
            "allow_preview": True,
            "verification": "local_hash",
            "validation_timeout": 0,
        },
    )
    assert response.status_code == 202, response.text
    job = work(settings, store, client(Gaia(mode)))
    if mode is None:
        assert job["status"] == "succeeded", job["result"]
        assert job["result"]["confirmed"] == ["running_matches", "saved"] and job["result"]["verified"]
    else:
        assert job["status"] == "failed" and job["result"]["change_accepted"] is False
        assert "permission denied" in job["result"]["error"]
    assert PASSWORD not in json.dumps(job) and "$6$" not in json.dumps(job)
