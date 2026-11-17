"""ArubaOS 8 mgmt-user rotation against a simulated controller at /mm/mynode."""

import hashlib
import json
import os
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from test_controls_credentials import vault_for
from test_password_rotation import PASSWORD, submit, work

from netops_executor.api import create_app
from netops_executor.network_ssh import NetworkSSH
from netops_executor.password_aruba import NODE, ArubaAccounts, user_table
from netops_executor.password_devices import ChangeNotAccepted, PasswordRejected
from netops_executor.password_engine import adapter
from netops_executor.password_models import PasswordRotationOptions
from netops_executor.ssh import DeviceError


def encrypted(password):
    # Stand-in for the controller's salted, encrypted value: different on every write.
    return hashlib.sha1(os.urandom(8) + password.encode()).hexdigest()


def table(rows):
    # Columns as wide as their longest cell, two spaces apart; the PATH cell is empty.
    names = ["USER", "PASSWD", "ROLE", "STATUS", "PATH", "Max-concurrent-sessions"]
    cells = [[user, "*****", role, "ACTIVE", "", "N/A"] for user, role in rows.items()]
    widths = [max(len(row[i]) for row in [names] + cells) + 2 for i in range(len(names))]

    def line(row):
        return "".join(f"{cell:<{width}}" for cell, width in zip(row, widths)).rstrip()

    return "\n".join(
        ["Default password recovery user: enabled", "", "Management User Table", "-" * 21]
        + [line(names), line(["-" * (width - 2) for width in widths])]
        + [line(row) for row in cells]
        + [""]
    )


class Controller:
    """A Mobility Conductor's own node: committed lines, pending lines and unsaved nodes."""

    def __init__(self, existing=True):
        self.committed = ['hostname "mm1"', "mgmt-user admin root " + encrypted("admin-password")]
        if existing:
            self.committed.append("mgmt-user automation read-only " + encrypted("old-password"))
        # Configuration text that contains permission-like words is not an error.
        self.committed.append("ip access-list session deny-unauthorized")
        self.inherited, self.pending, self.unsaved = {}, [], []
        self.behaviour, self.calls, self.answers, self.closed = "accept", [], [], 0
        self.selector = SimpleNamespace(secrets=set())

    def users(self):
        rows = dict(self.inherited)
        for words in (line.split() for line in self.committed):
            if words[0] == "mgmt-user" and words[1] not in ("ssh-pubkey", "localauth-disable"):
                rows[words[1]] = words[2]
        return rows

    def connect(self):
        return self

    def close(self):
        self.closed += 1

    def commit(self):
        for line in self.pending:
            user = line.split()[1]
            self.committed = [line if c.split()[:2] == ["mgmt-user", user] else c for c in self.committed]
            if line not in self.committed:
                self.committed.insert(2, line)
        self.pending, self.unsaved = [], []

    def execute(self, command, timeout=None, mode="exec", enable=False):
        self.calls.append(command)
        if command == "write memory":
            if self.behaviour == "save_refused":
                return {"stdout": "% Error: configuration could not be saved", "cli_error": True}
            if self.behaviour != "save_lost":
                self.commit()
            return {"stdout": "Saving Configuration...\n\nConfiguration Saved.", "cli_error": False}
        output = {
            "show mgmt-user": table(self.users()),
            "show configuration unsaved-nodes": "\n".join(self.unsaved),
            "show configuration committed " + NODE: "\n".join(self.committed + ["!"]),
            "show configuration pending " + NODE: "\n".join(self.pending),
        }[command]
        return {"stdout": output, "cli_error": False}

    def dialogue(self, command, replies, timeout, *, mode="exec", max_replies=None):
        assert mode == "config" and max_replies == 2
        self.calls.append(command)
        answers = [
            answer
            for prompt in ("Password:", "Re-Type password:")
            for pattern, answer in replies
            if pattern.search(prompt)
        ]
        self.answers.append(answers)
        _, user, role = command.split()
        b = self.behaviour
        if b == "refuse":
            return command + "\n% Command not authorized\n", False
        if b == "policy":
            return "Password:\nRe-Type password:\nNon-Compliant to Mgmt Password Policy\n", False
        if b in ("noop", "timeout_unchanged"):
            if b == "timeout_unchanged":
                raise DeviceError("network CLI deadline exceeded; outcome may be unknown")
            return "Password:\nRe-Type password:\n", False
        line = f"mgmt-user {user} {'root' if b == 'role' else role} {encrypted(answers[0])}"
        if b == "immediate":
            self.pending = [line]
            self.commit()
            return "Password:\nRe-Type password:\n", False
        self.pending = [line]
        self.unsaved = [NODE]
        if b == "extra":
            self.pending.append("vlan 99")
        if b == "timeout":
            raise DeviceError("network CLI deadline exceeded; outcome may be unknown")
        return "Password:\nRe-Type password:\n", False


def request(**options):
    r = PasswordRotationOptions.model_validate(
        {
            "device": "lab",
            "device_type": "aruba_os",
            "username": "automation",
            "allow_preview": True,
            **options,
        }
    )
    r.for_platform("aruba_os")
    return r


def client(controller, **options):
    return ArubaAccounts(None, None, None, request(**options), PASSWORD, lambda: None, None, ssh=controller)


def entry(controller, user="automation"):
    return next(line.split() for line in controller.committed if line.split()[:2] == ["mgmt-user", user])


def test_existing_admin_keeps_its_role_and_is_committed_with_write_memory():
    controller = Controller()
    old = entry(controller)
    device = client(controller)
    assert device.preflight() is True
    device.apply()
    assert controller.pending and entry(controller) == old  # staged, not yet committed
    device.save()
    new = entry(controller)
    assert new[:3] == ["mgmt-user", "automation", "read-only"] and new[3] != old[3]
    assert "mgmt-user automation read-only" in controller.calls
    assert controller.answers == [[PASSWORD, PASSWORD]]
    assert controller.calls.count("write memory") == 1
    assert all(PASSWORD not in command for command in controller.calls)
    assert PASSWORD in controller.selector.secrets
    assert device.report == {"config_node": NODE, "confirmed": ["change_staged", "saved"]}


def test_change_applied_without_a_pending_stage_is_accepted_and_saved():
    controller = Controller()
    old = entry(controller)
    device = client(controller)
    device.preflight()
    controller.behaviour = "immediate"
    device.apply()
    device.save()
    assert entry(controller)[3] != old[3] and device.report["confirmed"] == ["change_staged", "saved"]


@pytest.mark.parametrize(
    "creation,role", [(None, "root"), ({"role": "network-operations"}, "network-operations")]
)
def test_missing_admin_is_created_with_requested_or_default_role(creation, role):
    controller = Controller(existing=False)
    device = client(controller, new_account=creation)
    assert device.preflight() is False
    device.apply()
    device.save()
    assert entry(controller)[2] == role and "mgmt-user automation " + role in controller.calls


def test_missing_or_externally_authenticated_admin_without_create_if_missing_is_refused():
    # A TACACS/RADIUS login has no mgmt-user entry: it is missing, never converted silently.
    controller = Controller(existing=False)
    with pytest.raises(DeviceError, match="create_if_missing"):
        client(controller, create_if_missing=False).preflight()
    assert not controller.answers


@pytest.mark.parametrize("case", ["inherited", "certificate", "options", "keyword"])
def test_admins_this_node_cannot_rotate_are_refused_before_any_write(case):
    controller = Controller(existing=case not in ("inherited", "certificate"))
    username = "automation"
    if case == "inherited":
        controller.inherited["automation"] = "root"  # defined at /mm, shared with the standby
    elif case == "certificate":
        controller.committed.append("mgmt-user ssh-pubkey client-cert automation-cert automation root")
    elif case == "options":
        controller.committed[2] += " sha2"
    else:
        username = "localauth-disable"
    with pytest.raises(DeviceError, match="parent configuration node|certificate|options|keyword"):
        client(controller, username=username).preflight()
    assert not controller.answers


@pytest.mark.parametrize("pending,unsaved", [(["vlan 40"], [NODE]), ([], ["/md/branch"])])
def test_uncommitted_changes_anywhere_are_refused_in_preflight(pending, unsaved):
    controller = Controller()
    controller.pending, controller.unsaved = pending, unsaved
    with pytest.raises(DeviceError, match="uncommitted"):
        client(controller).preflight()
    assert not controller.answers and "write memory" not in controller.calls


def test_change_after_precheck_is_never_written():
    controller = Controller()
    device = client(controller)
    device.preflight()
    controller.pending, controller.unsaved = ["vlan 40"], [NODE]
    with pytest.raises(DeviceError, match="changed since precheck"):
        device.apply()
    assert not controller.answers


@pytest.mark.parametrize(
    "behaviour,match",
    [
        ("refuse", "privileges.*unchanged"),
        ("policy", "rejected the change.*unchanged"),
        ("timeout_unchanged", "rejected the change.*unchanged"),
        ("noop", "did not change.*permission.*unchanged"),
    ],
)
def test_refused_or_ignored_change_is_not_accepted_and_nothing_is_saved(behaviour, match):
    controller = Controller()
    before = list(controller.committed)
    device = client(controller)
    device.preflight()
    controller.behaviour = behaviour
    with pytest.raises(ChangeNotAccepted, match=match) as exc:
        device.apply()
    assert PASSWORD not in str(exc.value) and PASSWORD not in json.dumps(device.report)
    assert controller.committed == before and not controller.pending
    assert "write memory" not in controller.calls
    if behaviour in ("refuse", "policy", "timeout_unchanged"):
        assert controller.closed  # the proof comes from a fresh session


def test_creation_the_device_ignores_is_not_accepted():
    controller = Controller(existing=False)
    device = client(controller)
    device.preflight()
    controller.behaviour = "noop"
    with pytest.raises(ChangeNotAccepted, match="was not created"):
        device.apply()


@pytest.mark.parametrize("behaviour", ["extra", "role", "timeout"])
def test_partial_or_unknown_state_requires_recovery(behaviour):
    controller = Controller()
    device = client(controller)
    device.preflight()
    controller.behaviour = behaviour
    with pytest.raises(DeviceError) as exc:
        device.apply()
    assert not isinstance(exc.value, ChangeNotAccepted) and PASSWORD not in str(exc.value)
    assert "write memory" not in controller.calls


def test_save_commits_only_this_change_and_confirms_the_committed_entry():
    controller = Controller()
    device = client(controller)
    device.preflight()
    device.apply()
    controller.pending.append("vlan 40")  # someone else's change after staging
    with pytest.raises(DeviceError, match="before write memory"):
        device.save()
    assert "write memory" not in controller.calls


@pytest.mark.parametrize("behaviour,match", [("save_lost", "does not match"), ("save_refused", "refused")])
def test_save_that_does_not_commit_requires_recovery(behaviour, match):
    controller = Controller()
    device = client(controller)
    device.preflight()
    device.apply()
    controller.behaviour = behaviour
    with pytest.raises(DeviceError, match=match) as exc:
        device.save()
    assert not isinstance(exc.value, ChangeNotAccepted) and "saved" not in device.report["confirmed"]


def test_verification_is_one_ssh_login(monkeypatch):
    attempts = []
    monkeypatch.setattr(
        "netops_executor.password_aruba.verify_login",
        lambda settings, device, user, password, guard: attempts.append((user, password)),
    )
    device = client(Controller())
    device.verify()
    assert attempts == [("automation", PASSWORD)] and device.report["confirmed"] == ["login"]

    def rejected(*args):
        raise PasswordRejected(
            "new-account SSH authentication was rejected; no automatic authentication retry"
        )

    monkeypatch.setattr("netops_executor.password_aruba.verify_login", rejected)
    with pytest.raises(PasswordRejected):
        client(Controller()).verify()
    with pytest.raises(ValueError, match="local_hash"):
        request(verification="local_hash")


def test_management_user_table_parser_slices_columns_and_fails_closed():
    # The PATH cell is empty: columns are sliced at the dashed rule, not split on whitespace.
    rows = user_table(table({"admin": "root", "a.very-long_name": "read-only"}))
    assert rows == {"admin": "root", "a.very-long_name": "read-only"}
    for bad in ("% Invalid input detected", table({"admin": "root"}).replace("root", "    ")):
        with pytest.raises(DeviceError, match="unreadable"):
            user_table(bad)


def test_engine_loads_the_adapter_and_constructor_uses_aruba_driver(settings):
    assert adapter("aruba_os") is ArubaAccounts
    device = ArubaAccounts(settings, None, settings.device("lab"), request(), PASSWORD, lambda: None, None)
    assert isinstance(device.ssh, NetworkSSH) and device.ssh.device_type == "aruba_os"
    assert PASSWORD in device.ssh.selector.secrets


@pytest.fixture
def jobs(settings, store):
    vault_for(settings, store)
    return TestClient(create_app(settings), headers={"Authorization": "Bearer " + settings.token})


@pytest.mark.parametrize("behaviour,status", [("accept", "succeeded"), ("refuse", "failed")])
def test_runner_finishes_cleanly_or_releases_a_refused_change(
    settings, store, jobs, monkeypatch, behaviour, status
):
    monkeypatch.setattr("netops_executor.password_aruba.verify_login", lambda *args: None)
    submit(jobs, platform="aruba_os", allow_preview=True)
    controller = Controller()
    controller.behaviour = behaviour
    job = work(settings, store, client(controller))
    assert job["status"] == status, job
    assert job["result"]["change_accepted"] is (behaviour == "accept")
    assert PASSWORD not in json.dumps(job)
