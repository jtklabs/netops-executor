import copy
import json
import re
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from passlib.hash import sha512_crypt
from test_controls_credentials import vault_for
from test_password_rotation import PASSWORD, work

from netops_executor.api import create_app
from netops_executor.password_devices import ChangeNotAccepted, PasswordRejected, crypt_matches
from netops_executor.password_junos import COMMIT_COMMENT, JunosAccounts, only_account
from netops_executor.password_models import PasswordRotationOptions
from netops_executor.ssh import DeviceError
from netops_executor.store import CancelRequested

OLD = sha512_crypt.using(rounds=5000).hash("old-password")
COMMIT = 'commit comment "' + COMMIT_COMMENT + '"'


def statements(name, cls, hashed=OLD, uid=2001):
    prefix = "set system login user " + name
    lines = [prefix + " uid " + str(uid), prefix + " class " + cls]
    if hashed:
        lines.append(prefix + ' authentication encrypted-password "' + hashed + '"')
    return lines


class Driver:
    """The Netmiko driver: only used to open the private configuration session."""

    def __init__(self, junos):
        self.junos = junos

    def config_mode(self, config_command, pattern):
        self.junos.commands.append(config_command)
        assert config_command == "configure private" and self.junos.candidate is None
        if self.junos.cancel:
            raise CancelRequested()
        if self.junos.shared_dirty:
            # error: shared configuration database modified
            raise ValueError("Failed to enter configuration mode.")
        self.junos.candidate = copy.deepcopy(self.junos.committed)
        return ""


class Junos:
    """Fake Junos CLI: a committed configuration and this session's private candidate."""

    def __init__(self, failure=None, **users):
        self.selector = SimpleNamespace(secrets=set())
        self.committed = {"admin": statements("admin", "super-user", uid=2000), **users}
        self.candidate = self.driver = None
        self.commands, self.failure = [], failure
        self.shared_dirty = self.unrelated = self.cancel = False

    def connect(self):
        if self.driver is None:
            self.driver = Driver(self)
        return self.driver

    def close(self):
        # Junos discards an uncommitted private candidate when its session ends.
        self.driver = self.candidate = None

    def redact(self, text):
        for value in sorted(self.selector.secrets, key=len, reverse=True):
            text = text.replace(value, "[REDACTED]")
        return text

    def execute(self, command, timeout, mode="exec"):
        assert mode == "exec"
        self.connect()
        # Netmiko leaves configuration mode first, which discards an uncommitted private candidate.
        self.candidate = None
        self.commands.append(command)
        user = re.fullmatch(r"show configuration system login user (\S+) \| display set", command)
        role = re.fullmatch(r"show configuration system login class (\S+) \| display set", command)
        if user:
            output = "\n".join(self.committed.get(user[1], []))
        elif role:
            output = "set system login class netops permissions all" if role[1] == "netops" else ""
        else:
            raise AssertionError(command)
        return {"stdout": self.redact(output + "\n\n{master:0}"), "cli_error": False}

    def dialogue(self, command, replies, timeout, mode="exec", max_replies=None):
        assert mode == "config" and replies == [] and max_replies == 0
        assert self.candidate is not None, "configuration command outside the private session"
        self.commands.append(command)
        output = self.configure(command)
        return self.redact(command + "\n" + output + "\n\n{master:0}[edit]\nautomation@mx1# "), False

    def configure(self, command):
        if command == "show | compare":
            return self.diff()
        shown = re.fullmatch(r"show system login user (\S+) \| display set", command)
        if shown:
            return "\n".join(self.candidate.get(shown[1], []))
        if command == "rollback 0":
            self.candidate, self.unrelated = copy.deepcopy(self.committed), False
            return "load complete"
        if command == "commit check":
            if self.failure == "check":
                return "error: class 'netops' is not defined\nerror: configuration check-out failed"
            return "configuration check succeeds"
        if command == COMMIT:
            if self.failure == "commit":
                return "error: configuration database locked by:\n  bob terminal p1 (pid 7) exclusive"
            for name, lines in self.candidate.items():
                if name not in self.committed:
                    lines.insert(0, "set system login user " + name + " uid 2002")
            self.committed = copy.deepcopy(self.candidate)
            return "commit complete"
        match = re.fullmatch(
            r"set system login user (\S+) (class \S+|authentication encrypted-password \"\S+\")", command
        )
        assert match, command
        name, statement = match[1], match[2]
        if self.failure == "deny" or (self.failure == "partial" and statement.startswith("authentication")):
            return "error: permission denied"
        if self.failure == "syntax":
            return " " * 20 + "^\nsyntax error."
        if self.failure == "ignore":
            return ""
        if self.failure == "wrong_hash" and statement.startswith("authentication"):
            statement = 'authentication encrypted-password "' + sha512_crypt.hash("other") + '"'
        prefix = "set system login user " + name + " "
        key = statement.rsplit(" ", 1)[0] + " "
        lines = self.candidate.setdefault(name, [])
        lines[:] = [line for line in lines if not line.startswith(prefix + key)] + [prefix + statement]
        if self.failure == "reclass" and len(lines) > 1:
            lines[1] = prefix + "class super-user"
        self.unrelated = self.failure == "unrelated"
        return ""

    def diff(self):
        lines = []
        for name in sorted(set(self.committed) | set(self.candidate)):
            prefix = "set system login user " + name + " "
            old = [line[len(prefix) :] for line in self.committed.get(name, [])]
            new = [line[len(prefix) :] for line in self.candidate.get(name, [])]
            if old == new:
                continue
            if not old:
                lines += ["[edit system login]", "+    user " + name + " {"]
                for statement in new:
                    if statement.startswith("authentication "):
                        lines += [
                            "+        authentication {",
                            "+            " + statement.split(" ", 1)[1] + "; ## SECRET-DATA",
                            "+        }",
                        ]
                    else:
                        lines.append("+        " + statement + ";")
                lines.append("+    }")
                continue
            for section in ("authentication ", ""):
                header = "[edit system login user " + name + (" authentication]" if section else "]")
                pick = [s for s in old if s.startswith("authentication ") == bool(section)]
                put = [s for s in new if s.startswith("authentication ") == bool(section)]
                gone, added = [s for s in pick if s not in put], [s for s in put if s not in pick]
                if gone or added:
                    lines.append(header)
                    lines += ["-    " + s[len(section) :] + ";" for s in gone]
                    lines += ["+    " + s[len(section) :] + ";" for s in added]
        if self.unrelated:
            lines += ["[edit snmp]", "+    community public;"]
        return "\n".join(lines)


def request(**options):
    r = PasswordRotationOptions.model_validate(
        {
            "device": "lab",
            "device_type": "juniper_junos",
            "username": "automation",
            "allow_preview": True,
            "verification": "local_hash",
            **options,
        }
    )
    r.for_platform(r.device_type)
    return r


def client(junos, **options):
    return JunosAccounts(None, None, None, request(**options), PASSWORD, lambda: None, None, ssh=junos)


def existing(failure=None):
    return Junos(failure, automation=statements("automation", "operator"))


def committed_hash(junos):
    return junos.committed["automation"][-1].split('"')[1]


def failure(exc, action):
    """The fixed message of the expected exception (exactly that class); never a secret."""
    with pytest.raises(exc) as raised:
        action()
    assert type(raised.value) is exc
    assert PASSWORD not in str(raised.value) and "$6$" not in str(raised.value)
    return str(raised.value)


def test_update_stages_privately_checks_commits_and_confirms_only_the_hash():
    junos = existing()
    device = client(junos)
    assert device.preflight() is True
    device.apply()
    assert junos.committed["automation"] == statements("automation", "operator")
    device.save()
    device.verify()
    record = junos.committed["automation"]
    assert record[:2] == statements("automation", "operator")[:2]
    assert committed_hash(junos).startswith("$6$") and crypt_matches(PASSWORD, committed_hash(junos))
    assert device.report == {"confirmed": ["change_staged", "committed", "running_matches"]}
    assert "configure" not in junos.commands and junos.commands.count("configure private") == 2
    assert junos.commands.index("commit check") < junos.commands.index(COMMIT)
    assert junos.commands.count(COMMIT) == 1
    assert all(PASSWORD not in command for command in junos.commands)
    assert device.hashed in device.ssh.selector.secrets and PASSWORD in device.ssh.selector.secrets


@pytest.mark.parametrize("role", [None, "netops"])
def test_creation_sets_class_and_hash_and_accepts_the_assigned_uid(role):
    junos = Junos()
    device = client(junos, **({"new_account": {"role": role}} if role else {}))
    assert device.preflight() is False
    device.apply()
    device.save()
    device.verify()
    record = junos.committed["automation"]
    assert record[:2] == [
        "set system login user automation uid 2002",
        "set system login user automation class " + (role or "super-user"),
    ]
    assert crypt_matches(PASSWORD, committed_hash(junos))


def test_preflight_refuses_missing_remote_masked_root_and_unknown_class_without_writing():
    assert "create_if_missing" in failure(DeviceError, client(Junos(), create_if_missing=False).preflight)
    remote = Junos(automation=statements("automation", "super-user", hashed=None))
    assert "no local password" in failure(DeviceError, client(remote).preflight)
    masked = Junos(automation=statements("automation", "super-user", hashed="/* SECRET-DATA */"))
    assert "secret permission" in failure(DeviceError, client(masked).preflight)
    assert "root-authentication" in failure(DeviceError, client(Junos(), username="root").preflight)
    unknown = client(Junos(), new_account={"role": "invented"})
    assert "class" in failure(DeviceError, unknown.preflight)
    for junos in (remote, masked):
        assert not any(c.startswith(("set ", "commit")) for c in junos.commands)


def test_uncommitted_shared_changes_block_preflight_and_a_later_private_session():
    junos = existing()
    junos.shared_dirty = True
    assert "private configuration" in failure(DeviceError, client(junos).preflight)
    junos = existing()
    device = client(junos)
    device.preflight()
    junos.shared_dirty = True
    message = failure(ChangeNotAccepted, device.apply)
    assert "nothing was written" in message
    assert not any(c.startswith(("set ", "commit")) for c in junos.commands)


@pytest.mark.parametrize(
    "mode,existing_account,wording",
    [
        ("deny", True, "permission denied"),
        ("syntax", True, "refused the account change"),
        ("partial", False, "permission denied"),
        ("ignore", True, "absent from show | compare"),
        ("ignore", False, "absent from show | compare"),
        ("check", True, "commit check"),
    ],
)
def test_refused_or_ignored_change_is_discarded_and_not_accepted(mode, existing_account, wording):
    junos = existing(mode) if existing_account else Junos(mode)
    before = copy.deepcopy(junos.committed)
    device = client(junos)
    device.preflight()
    message = failure(ChangeNotAccepted, device.apply)
    assert wording in message and "unchanged" in message
    assert junos.committed == before and junos.candidate is None
    assert "rollback 0" in junos.commands and COMMIT not in junos.commands
    assert "confirmed" not in device.report
    # The private candidate is gone: nothing is left to commit.
    assert "not open" in failure(DeviceError, device.save)


@pytest.mark.parametrize("mode", ["unrelated", "wrong_hash", "reclass"])
def test_unexpected_staged_state_is_discarded_and_needs_recovery(mode):
    junos = existing(mode)
    before = copy.deepcopy(junos.committed)
    device = client(junos)
    device.preflight()
    assert "not exactly the requested" in failure(DeviceError, device.apply)
    assert junos.committed == before and "rollback 0" in junos.commands
    assert "commit check" not in junos.commands and COMMIT not in junos.commands


def test_cancellation_while_opening_the_private_session_is_not_a_refusal():
    junos = existing()
    device = client(junos)
    device.preflight()
    junos.cancel = True
    with pytest.raises(CancelRequested):
        device.apply()
    assert junos.driver is None and not any(c.startswith(("set ", "commit")) for c in junos.commands)


def test_account_changed_since_precheck_is_not_written():
    junos = existing()
    device = client(junos)
    device.preflight()
    junos.committed["automation"][1] = "set system login user automation class super-user"
    assert "changed since precheck" in failure(DeviceError, device.apply)
    assert not any(c.startswith(("set ", "commit")) for c in junos.commands)


def test_save_requires_the_same_private_session_and_confirms_the_commit():
    # A lost session (or a new adapter after a worker restart) has nothing left to commit.
    junos = existing()
    device = client(junos)
    device.preflight()
    device.apply()
    junos.close()
    assert "session was lost" in failure(DeviceError, device.save)
    assert COMMIT not in junos.commands
    fresh = client(existing())
    assert "not open" in failure(DeviceError, fresh.save)
    # A refused commit leaves the candidate uncommitted: it is discarded and proven unchanged.
    junos = existing("commit")
    device = client(junos)
    device.preflight()
    device.apply()
    assert "refused the commit" in failure(ChangeNotAccepted, device.save)
    assert junos.committed["automation"] == statements("automation", "operator")
    # A commit that reports success but leaves another hash is never accepted.
    junos = existing()
    device = client(junos)
    device.preflight()
    device.apply()
    original = junos.configure

    def lossy(command):
        output = original(command)
        if command == COMMIT:
            junos.committed["automation"][-1] = statements("automation", "operator")[-1]
        return output

    junos.configure = lossy
    assert "does not match the staged change" in failure(DeviceError, device.save)
    assert device.report["confirmed"] == ["change_staged", "committed"]


def test_save_refuses_a_candidate_that_changed_after_staging():
    junos = existing()
    device = client(junos)
    device.preflight()
    device.apply()
    junos.unrelated = True
    assert "changed before commit" in failure(DeviceError, device.save)
    assert COMMIT not in junos.commands


def test_verification_by_hash_and_ssh_login(monkeypatch):
    junos = existing()
    device = client(junos)
    device.preflight()
    device.apply()
    device.save()
    # A review continuation builds a new adapter and session, which see the real committed hash.
    rerun = Junos(automation=copy.deepcopy(junos.committed["automation"]))
    client(rerun).verify()
    rerun.committed["automation"][-1] = statements("automation", "operator")[-1]
    assert "does not match" in failure(PasswordRejected, client(rerun).verify)
    del rerun.committed["automation"]
    assert "no readable password hash" in failure(DeviceError, client(rerun).verify)
    calls = []
    monkeypatch.setattr(
        "netops_executor.password_junos.verify_login",
        lambda settings, device, username, password, guard: calls.append((username, password)),
    )
    client(existing(), verification="ssh_login").verify()
    assert calls == [("automation", PASSWORD)]


def test_only_account_accepts_just_this_users_stanza():
    own = [
        "[edit system login user automation authentication]",
        '-    encrypted-password "x";',
        '+    encrypted-password "y";',
    ]
    new = [
        "[edit system login]",
        "+    user automation {",
        "+        class super-user;",
        "+        authentication {",
        "+        }",
        "+    }",
    ]
    assert only_account(own, "automation") and only_account(new, "automation")
    assert not only_account(new + ["[edit snmp]", "+    community public;"], "automation")
    assert not only_account(["[edit system login]", "+    user other {", "+    }"], "automation")
    assert not only_account(new[:-1], "automation")
    assert not only_account(["[edit system login]", "-    user automation {", "-    }"], "automation")
    assert not only_account(new + ["+    user other {", "+    }"], "automation")
    assert not only_account(['+    encrypted-password "y";'], "automation")
    assert not only_account(["[edit system login user automation2]", "+    class operator;"], "automation")


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
            "device_type": "juniper_junos",
            "username": "automation",
            "password": PASSWORD,
            "allow_preview": True,
            "verification": "local_hash",
            "validation_timeout": 0,
        },
    )
    assert response.status_code == 202, response.text
    junos = existing(mode)
    job = work(settings, store, client(junos))
    if mode is None:
        assert job["status"] == "succeeded", job["result"]
        assert job["result"]["confirmed"] == ["change_staged", "committed", "running_matches"]
        assert job["result"]["verified"]
    else:
        assert job["status"] == "failed" and job["result"]["change_accepted"] is False
        assert "permission denied" in job["result"]["error"]
    assert PASSWORD not in json.dumps(job) and "$6$" not in json.dumps(job)
