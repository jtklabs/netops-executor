"""A rotation is reported only once the device is proven to have accepted it.

Logins with a restricted role (often a TACACS+ or RADIUS role) can be refused, or get an
acknowledgement for a change that was never applied. When a fresh read proves the account
unchanged, the job fails cleanly (nothing to recover); otherwise it needs recovery.
"""

import copy
import xml.etree.ElementTree as ET
from types import SimpleNamespace

import pytest
from passlib.hash import sha256_crypt
from test_password_panos import SERIAL, Backend, client
from test_password_rotation import PASSWORD, Account, submit, work
from test_password_rotation import api as rotation_api

from netops_executor.password_devices import ChangeNotAccepted, PermissionRefused
from netops_executor.password_panos import CommitRefused, SshAccounts, account, canonical
from netops_executor.ssh import DeviceError


class Refusing(Backend):
    def __init__(self, mode, **kwargs):
        super().__init__(**kwargs)
        self.mode = mode

    def set_password(self, username, password, creation):
        if self.mode == "ignored":
            self.calls.append("set_password")
            return
        if self.mode == "partial":
            super().set_password(username, password, creation)
            raise DeviceError("PAN-OS password dialogue failed")
        if self.mode == "permission":
            raise PermissionRefused(
                "PAN-OS refused the operation for this login's admin role (permission denied)"
            )
        super().set_password(username, password, creation)

    def commit(self):
        if self.mode in ("commit_refused", "revert_fails"):
            self.calls.append("commit")
            raise CommitRefused("PAN-OS refused the commit for this login's admin role (permission denied)")
        super().commit()

    def revert(self):
        if self.mode == "revert_fails":
            raise DeviceError("PAN-OS account command rejected; output omitted")
        super().revert()


@pytest.mark.parametrize(
    "mode,match",
    [
        ("permission", "admin role \\(permission denied\\); the candidate configuration is unchanged"),
        ("ignored", "acknowledged the password change but did not stage it"),
    ],
)
def test_panos_write_refused_or_ignored_is_not_accepted_and_releases_locks(mode, match):
    backend = Refusing(mode)
    device = client(backend)
    device.preflight()
    with pytest.raises(ChangeNotAccepted, match=match) as exc:
        device.apply()
    assert backend.calls[-1] == "unlock" and "commit" not in backend.calls
    assert PASSWORD not in str(exc.value)


def test_panos_partially_staged_write_needs_recovery_and_keeps_its_locks():
    backend = Refusing("partial")
    device = client(backend)
    device.preflight()
    with pytest.raises(DeviceError) as exc:
        device.apply()
    assert not isinstance(exc.value, ChangeNotAccepted) and "unlock" not in backend.calls


def test_panos_refused_commit_is_reverted_and_not_accepted():
    backend = Refusing("commit_refused")
    before = copy.deepcopy(backend.running)
    device = client(backend)
    device.preflight()
    device.apply()
    assert device.report["confirmed"] == ["candidate_hash"]
    with pytest.raises(ChangeNotAccepted, match="permission denied.*reverted.*unchanged"):
        device.save()
    assert backend.calls[-2:] == ["revert", "unlock"]
    assert canonical(backend.candidate) == canonical(backend.running) == canonical(before)


def test_panos_refused_commit_that_cannot_be_reverted_needs_recovery():
    backend = Refusing("revert_fails")
    device = client(backend)
    device.preflight()
    device.apply()
    with pytest.raises(DeviceError, match="still holds it") as exc:
        device.save()
    assert not isinstance(exc.value, ChangeNotAccepted)


def test_panos_success_reports_each_confirmation():
    backend = Backend()
    device = client(backend)
    device.preflight()
    device.apply()
    device.save()
    device.verify()
    assert device.report["confirmed"] == ["candidate_hash", "commit", "running_hash"]


def test_panos_refuses_a_local_override_of_a_template_account():
    backend = Backend(existing=False)
    backend.template_users = lambda: {"automation"}
    with pytest.raises(DeviceError, match="Panorama template"):
        client(backend).preflight()
    assert "lock" not in backend.calls


class Cli:
    def __init__(self, output, disconnected=False):
        self.output, self.disconnected = output, disconnected

    def dialogue(self, command, replies, timeout, **kwargs):
        return self.output, self.disconnected


def ssh_commit(output, disconnected=False):
    accounts = object.__new__(SshAccounts)
    accounts.request = SimpleNamespace(commit_timeout=60, command_timeout=30)
    accounts.ssh, accounts.ready = Cli(output, disconnected), lambda: None
    accounts.commit()


def test_ssh_commit_outcomes_are_classified():
    ssh_commit("Configuration committed successfully\n")
    with pytest.raises(CommitRefused, match="permission denied"):
        ssh_commit("Commit failed\n Error: admin user is not authorized to commit\n")
    with pytest.raises(CommitRefused, match="^PAN-OS commit failed$"):
        ssh_commit("Commit failed\n Validation Error: something\n")
    for output, disconnected in (("", True), ("unexpected\n", False)):
        with pytest.raises(DeviceError) as exc:
            ssh_commit(output, disconnected)
        assert not isinstance(exc.value, CommitRefused)


api = rotation_api


def test_engine_reports_a_refused_commit_as_failed_without_recovery(settings, store, api):
    submit(api)
    rotation = Account()

    def refuse():
        rotation.calls.append("save")
        raise ChangeNotAccepted("PAN-OS refused the commit; the staged change was reverted")

    rotation.save = refuse
    job = work(settings, store, rotation)
    assert job["status"] == "failed" and not job["lock_held"]
    assert job["result"]["change_accepted"] is False and job["result"]["mutations"] == []
    assert "reverted" in job["result"]["error"]


# Existing CLI platforms: IOS over TACACS+ command authorization.


class Ios:
    def __init__(self, behaviour):
        self.behaviour, self.closed = behaviour, 0
        self.selector = SimpleNamespace(secrets=set())
        self.line = "username automation privilege 15 secret 9 $9$old$hash"

    def execute(self, command, timeout=60, mode="exec", enable=False):
        if command.startswith("show running-config"):
            return {"stdout": self.line + "\n", "cli_error": False}
        if command.startswith("username automation"):
            if self.behaviour == "authorization":
                return {"stdout": "% Command authorization failed.\n", "cli_error": False}
            if self.behaviour == "applied_then_error":
                self.line = "username automation privilege 15 secret 9 $9$new$hash"
                return {"stdout": "% Invalid input detected\n", "cli_error": True}
            if self.behaviour == "applied":
                self.line = "username automation privilege 15 secret 9 $9$new$hash"
            return {"stdout": "", "cli_error": False}
        raise AssertionError(command)

    def close(self):
        self.closed += 1


def ios(behaviour):
    from test_password_rotation import device

    shell = Ios(behaviour)
    return device("cisco_ios", shell), shell


@pytest.mark.parametrize(
    "behaviour,error,match",
    [
        ("authorization", ChangeNotAccepted, "privileges.*account is unchanged"),
        ("ignored", ChangeNotAccepted, "stored password did not change"),
        ("applied_then_error", DeviceError, "rejected"),
    ],
)
def test_ios_refusals_are_proven_before_they_count_as_not_accepted(behaviour, error, match):
    device, shell = ios(behaviour)
    device.preflight()
    with pytest.raises(error, match=match) as exc:
        device.apply()
    if error is DeviceError:
        assert not isinstance(exc.value, ChangeNotAccepted)
    assert PASSWORD not in str(exc.value)


def test_ios_accepted_change_is_confirmed():
    device, _ = ios("applied")
    device.preflight()
    device.apply()
    assert device.report["confirmed"] == ["account_changed"]


def test_template_user_parser_reads_pushed_template_output():
    from netops_executor.password_panos import template_users

    text = (
        "<response><result><config><mgt-config><users><entry name='automation'><phash>x</phash>"
        "</entry></users></mgt-config></config></result></response>"
    )
    assert template_users(text) == {"automation"}
    assert template_users("Server error: no template") is None
    assert template_users(ET.fromstring(text)) == {"automation"}


def test_hash_helper_is_unused_by_reports():
    # Hashes from the device never reach the public report.
    backend = Backend()
    device = client(backend)
    device.preflight()
    device.apply()
    device.save()
    assert "$5$" not in repr(device.report)
    assert sha256_crypt.identify(account(backend.running, "automation").findtext("phash"))
    assert SERIAL == device.serial


# Arista EOS and NX-OS: local_hash reads the hash from the running configuration, so a switch
# that checks TACACS before local accounts can still be verified.


class Running:
    def __init__(self, line):
        self.line, self.selector = line, SimpleNamespace(secrets=set())

    def execute(self, command, timeout=60, mode="exec", enable=False):
        return {"stdout": self.line + "\n", "cli_error": False}

    def close(self):
        pass


@pytest.mark.parametrize(
    "platform,template,algorithm",
    [
        ("arista_eos", "username automation privilege 15 role network-admin secret sha512 {}", "sha512"),
        ("cisco_nxos", "username automation password 5 {} role network-admin", "sha256"),
    ],
)
def test_switch_local_hash_reads_the_running_configuration(platform, template, algorithm):
    from passlib.hash import sha256_crypt, sha512_crypt
    from test_password_rotation import device

    from netops_executor.password_devices import PasswordRejected

    crypt = sha512_crypt if algorithm == "sha512" else sha256_crypt
    shell = Running(template.format(crypt.hash(PASSWORD)))
    client = device(platform, shell, verification="local_hash")
    client.verify()
    shell.line = template.format(crypt.hash("some-other-password"))
    with pytest.raises(PasswordRejected):
        client.verify()
    # Output redaction hides the hash this job wrote; that is the hash to check.
    client.hashed = crypt.hash(PASSWORD)
    shell.line = template.format("[REDACTED]")
    client.verify()
    shell.line = "username automation privilege 15 nopassword"
    with pytest.raises(DeviceError):
        client.verify()
