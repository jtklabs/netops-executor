import json
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest
from conftest import Clock
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from passlib.hash import sha512_crypt
from test_controls_credentials import vault_for
from test_ssh_wire import ssh_server

from netops_executor.api import create_app
from netops_executor.config import Device
from netops_executor.credentials import Vault, digest_matches, secret_digest
from netops_executor.execution_models import ValidationDecision
from netops_executor.password_devices import (
    AccountDevice,
    PasswordRejected,
    check_password_syntax,
    crypt_matches,
    forti_accounts,
    network_account,
    verify_login,
)
from netops_executor.password_engine import PasswordRotationRunner
from netops_executor.password_models import PasswordRotationOptions, PasswordRotationRequest
from netops_executor.ssh import DeviceError
from netops_executor.store import LostOwnership

PASSWORD = "Desired-Password-123!"


@pytest.fixture
def api(settings, store):
    vault_for(settings, store)
    return TestClient(create_app(settings), headers={"Authorization": "Bearer " + settings.token})


def body(platform="linux", **options):
    return {
        "device": "lab",
        "device_type": platform,
        "username": "automation",
        "password": PASSWORD,
        **options,
    }


def submit(api, **options):
    response = api.post("/api/v1/password-rotation/jobs", json=body(**options))
    assert response.status_code == 202, response.text
    return response.json()


class Account:
    def __init__(self, exists=True):
        self.exists, self.calls = exists, []
        self.verify_error = None
        self.apply_error = None
        self.on_apply = lambda: None
        self.on_save = lambda: None

    def preflight(self):
        self.calls.append("preflight")
        return self.exists

    def apply(self):
        self.calls.append("apply")
        self.on_apply()
        if self.apply_error:
            raise self.apply_error

    def save(self):
        self.calls.append("save")
        self.on_save()

    def verify(self):
        self.calls.append("verify")
        if self.verify_error:
            raise self.verify_error

    def close(self):
        pass


def work(settings, store, account):
    job = store.claim("worker")
    clock = Clock()
    PasswordRotationRunner(
        settings, store, job, "worker", client=account, sleep=clock.sleep, clock=clock.clock
    ).run()
    return store.get(job["id"])


@pytest.mark.parametrize("exists", [True, False])
def test_runner_reports_creation_or_update_and_verification(settings, store, api, exists):
    created = submit(api, new_account={"groups": []})
    account = Account(exists)
    job = work(settings, store, account)
    assert job["id"] == created["id"] and job["status"] == "succeeded", job
    assert account.calls == ["preflight", "apply", "save", "verify"]
    assert job["result"]["action"] == ("updated" if exists else "created")
    assert job["result"]["saved"] and job["result"]["verified"] and not job["lock_held"]
    assert job["result"]["progress"]["percent"] == 100


def test_secret_is_separate_encrypted_and_absent_from_api_events_webhook(settings, store, api):
    created = submit(api)
    assert created["queue"] == "priority" and "password" not in created["request"]
    with store.connect() as db:
        encrypted = db.execute("SELECT secret FROM job_secrets WHERE job=?", (created["id"],)).fetchone()[0]
        rows = [tuple(r) for r in db.execute("SELECT * FROM jobs")]
    assert PASSWORD.encode() not in encrypted and PASSWORD not in repr(rows)
    assert Vault(store, settings.credential_key_file).job_password(created["id"]) == PASSWORD
    work(settings, store, Account())
    for endpoint in (
        "/api/v1/jobs",
        "/api/v1/jobs/" + created["id"],
        "/api/v1/jobs/" + created["id"] + "/events",
    ):
        response = api.get(endpoint)
        assert response.status_code == 200 and PASSWORD not in response.text
        assert encrypted.decode() not in response.text
    from netops_executor.webhooks import WebhookSender

    settings.webhook_url = "https://controller.example/finished"
    sender = WebhookSender(settings, store)
    # Webhooks serialize public job state; private secret rows have no public serializer.
    delivery = {"job": created["id"], "id": "delivery", "status": "succeeded"}
    serialized = json.dumps(sender.payload(delivery))
    assert PASSWORD not in serialized and encrypted.decode() not in serialized
    sender.client.close()
    assert PASSWORD not in json.dumps(store.events(created["id"], 0, 1000))


def test_idempotency_compares_secret_and_key_rotation_keeps_queued_password(settings, store, api):
    headers = {"Idempotency-Key": "rotate-once"}
    first = api.post("/api/v1/password-rotation/jobs", json=body(), headers=headers)
    again = api.post("/api/v1/password-rotation/jobs", json=body(), headers=headers)
    assert first.json()["id"] == again.json()["id"]
    changed = api.post(
        "/api/v1/password-rotation/jobs", json=body(password="AnotherSecret-234!"), headers=headers
    )
    assert changed.status_code == 409 and "AnotherSecret" not in changed.text
    old = settings.credential_key_file.read_bytes()
    new = Fernet.generate_key() + b"\n"
    settings.credential_key_file.write_bytes(new + old)
    Vault(store, settings.credential_key_file).rotate()
    settings.credential_key_file.write_bytes(new)
    assert Vault(store, settings.credential_key_file).job_password(first.json()["id"]) == PASSWORD
    assert (
        api.post("/api/v1/password-rotation/jobs", json=body(), headers=headers).json()["id"]
        == first.json()["id"]
    )


def test_atomic_secret_submission_under_concurrent_retries(settings, store, api):
    vault = Vault(store, settings.credential_key_file)
    cipher = vault.cipher()
    public = PasswordRotationRequest.model_validate(body()).model_dump(mode="json")

    def create(_):
        return store.submit(
            public,
            "device:lab",
            "same-key",
            kind="password_rotation",
            secret=cipher.encrypt(PASSWORD.encode()),
            secret_digest=secret_digest(PASSWORD.encode()),
            secret_matches=lambda saved: digest_matches(saved["digest"], PASSWORD.encode()),
        )["id"]

    with ThreadPoolExecutor(max_workers=5) as pool:
        ids = list(pool.map(create, range(10)))
    assert len(set(ids)) == 1 and vault.job_password(ids[0]) == PASSWORD
    with store.connect() as db:
        assert db.execute("SELECT count(*) FROM job_secrets").fetchone()[0] == 1


def test_auth_validation_and_required_key_never_echo_password(settings, api):
    api.headers.pop("Authorization")
    assert api.post("/api/v1/password-rotation/jobs", json=body()).status_code == 401
    api.headers["Authorization"] = "Bearer " + settings.token
    invalid = api.post("/api/v1/password-rotation/jobs", json=body(password=PASSWORD + "\n"))
    assert invalid.status_code == 422 and PASSWORD not in invalid.text
    settings.credential_key_file = None
    api = TestClient(create_app(settings), headers={"Authorization": "Bearer " + settings.token})
    unavailable = api.post("/api/v1/password-rotation/jobs", json=body())
    assert unavailable.status_code == 409 and PASSWORD not in unavailable.text
    plan = api.post("/api/v1/password-rotation/plan", json=body())
    assert plan.status_code == 200 and "password" not in plan.json()["request"]
    spec = api.get("/openapi.json").json()
    field = spec["components"]["schemas"]["PasswordRotationRequest"]["properties"]["password"]
    assert field["writeOnly"] and field["format"] == "password"


@pytest.mark.parametrize("action", ["retry", "accept"])
def test_auth_rejection_opens_gate_once_and_never_replays_change(settings, store, api, action):
    submit(api)
    account = Account()
    account.verify_error = PasswordRejected("authentication rejected")
    job = work(settings, store, account)
    assert job["status"] == "needs_review" and job["lock_held"]
    assert account.calls.count("verify") == 1 and not job["result"]["verified"]
    gate = job["validation_gates"][-1]
    store.decide(
        job["id"],
        ValidationDecision(
            gate_id=gate["id"],
            validation_revision=gate["revision"],
            action=action,
            operator="jason",
            reason="checked account",
        ),
    )
    account.verify_error = None
    job = work(settings, store, account)
    assert job["status"] in ("succeeded", "completed_with_warnings") and not job["lock_held"]
    assert account.calls.count("apply") == account.calls.count("save") == 1
    assert job["result"]["verified"] is (action == "retry")


def test_auth_rejection_with_fail_policy_is_not_retried(settings, store, api):
    submit(api, validation_timeout=60, validation_policy={"on_timeout": "fail"})
    account = Account()
    account.verify_error = PasswordRejected("authentication rejected")
    job = work(settings, store, account)
    assert job["status"] == "recovery_required" and job["lock_held"]
    assert account.calls.count("verify") == 1
    assert job["result"]["error"] == "authentication rejected"


def test_network_verification_is_bounded_and_failure_keeps_reservation(settings, store, api):
    submit(api, validation_timeout=15, validation_policy={"on_timeout": "fail"})
    account = Account()
    account.verify_error = DeviceError("offline")
    job = work(settings, store, account)
    assert job["status"] == "recovery_required" and job["lock_held"]
    assert account.calls.count("verify") == 2


def test_cancel_after_change_still_saves_but_requires_recovery(settings, store, api):
    created = submit(api)
    account = Account()
    account.on_apply = lambda: store.cancel(created["id"])
    job = work(settings, store, account)
    assert account.calls == ["preflight", "apply", "save"]
    assert job["status"] == "recovery_required" and job["result"]["saved"]


def test_ambiguous_write_is_never_retried_and_does_not_expose_exception(settings, store, api):
    submit(api)
    account = Account()
    account.apply_error = RuntimeError(PASSWORD)
    job = work(settings, store, account)
    assert job["status"] == "recovery_required" and account.calls.count("apply") == 1
    assert PASSWORD not in json.dumps(job)
    assert store.claim("other") is None


def test_lost_ownership_does_not_save_or_verify(settings, store, api):
    submit(api)
    account = Account()
    account.apply_error = LostOwnership()
    job = work(settings, store, account)
    assert account.calls == ["preflight", "apply"] and job["result"]["mutations"] == ["account_change"]


def test_scheduling_and_dispatch(settings, store, api, monkeypatch):
    future = submit(api, start_at="2099-01-01T00:00:00Z", queue="scheduled")
    assert store.claim("worker") is None
    due = submit(api, start_at="2020-01-01T00:00:00Z", queue="upgrade")
    job = store.claim("worker")
    assert job["id"] == due["id"] and future["queue"] == "scheduled"
    from netops_executor import worker

    called = []

    class Runner:
        def __init__(self, *args):
            called.append(args[2]["id"])

        def run(self):
            pass

    monkeypatch.setattr(worker, "PasswordRotationRunner", Runner)
    worker.process(settings, store, job, "worker")
    assert called == [due["id"]]


class Shell:
    def __init__(self, outputs=None):
        self.outputs = outputs or {}
        self.calls = []
        self.selector = SimpleNamespace(secrets=set())
        self.guard = lambda: None

    def execute(self, command, **kwargs):
        self.calls.append((command, kwargs))
        output = self.outputs.get(command, "")
        return output if isinstance(output, dict) else {"stdout": output, "exit_code": 0, "cli_error": False}

    def tmsh(self, command, **kwargs):
        self.calls.append((command, kwargs))
        return self.outputs.get(command, "")

    def close(self):
        pass


F5_STANDALONE = {
    "list /cm device all-properties": "cm device a { self-device true management-ip 192.0.2.10 }",
    "list /cm device-group all-properties": "",
    "show /cm failover-status field-fmt": "cm failover-status {\n status ACTIVE\n}",
}
UNLOCKED = {"LC_ALL=C passwd -S automation": "automation P 2026-01-01 0 99999 7 -1"}

CREATION = {
    "linux": {"groups": ["sudo"]},
    "opengear": {"groups": ["admin"]},
    "f5": {"role": "admin"},
    "cisco_ios": {"privilege": 15},
    "cisco_nxos": {"role": "network-admin"},
    "arista_eos": {"role": "network-admin", "privilege": 15},
    "fortinet": {"role": "super_admin"},
}


def device(platform, shell, **options):
    request = PasswordRotationOptions.model_validate(
        {k: v for k, v in body(platform, **options).items() if k != "password"}
    )
    request.for_platform(platform)
    return AccountDevice(None, None, request, PASSWORD, lambda: None, None, ssh=shell)


@pytest.mark.parametrize("platform", list(CREATION))
@pytest.mark.parametrize("existing", [True, False])
def test_native_account_commands_create_or_preserve_access(platform, existing, monkeypatch):
    shell = Shell()
    client = device(platform, shell, new_account=CREATION[platform])
    before = ["original"] if existing else None
    client.before = before
    client.read = lambda: before if len(shell.calls) == 0 else ["after"]
    client.access = lambda record: "unchanged"
    client.index, client.total = 2, 1
    monkeypatch.setattr(
        "netops_executor.password_devices.password_prompt",
        lambda ssh, command, password, timeout: ssh.calls.append((command, {"password_input": password})),
    )
    client.apply()
    commands = [c for c, _ in shell.calls]
    if platform == "linux":
        assert any(c.startswith("useradd ") for c in commands) is not existing
        assert (
            commands[-1] == "chpasswd" and shell.calls[-1][1]["stdin_text"] == "automation:" + PASSWORD + "\n"
        )
        assert all(PASSWORD not in c for c in commands)
    elif platform == "opengear":
        assert "config -P config.users.user2.password" in commands and commands[-1] == "config -a"
        assert any("groups.group" in c for c in commands) is not existing
        assert all(PASSWORD not in c for c in commands)
    elif platform == "f5":
        assert commands[0].startswith(
            ("modify" if existing else "create") + " /auth user automation password "
        )
        assert ("partition-access" in commands[0]) is not existing
        assert shell.calls[0][1]["secret"]
    elif platform == "fortinet":
        assert 'set password "' + PASSWORD + '"' in commands
        assert any(c.startswith("set accprofile") for c in commands) is not existing
        assert commands[-2:] == ["next", "end"]
    else:
        command = commands[0]
        assert command.startswith("username automation ")
        assert ("role network-admin" in command or "privilege 15" in command) is not existing
        if platform == "cisco_ios":
            assert "algorithm-type scrypt secret " + PASSWORD in command
        else:
            assert PASSWORD not in command
            assert ("secret sha512 $6$" if platform == "arista_eos" else "password 5 $5$") in command


@pytest.mark.parametrize("platform", list(CREATION))
def test_missing_account_defaults_to_administrator(platform):
    shell = Shell(
        {
            "id -u": "0",
            "cat /etc/version": "OpenGear/IM7248 version 5.3.3",
            "get system status": "Virtual domain configuration: disable",
            "cat /etc/os-release": "ID=ubuntu\nID_LIKE=debian",
            "cat /etc/group": "sudo:x:27:\nadmin:x:100:",
            "getent passwd automation": {"stdout": "", "exit_code": 2},
            **F5_STANDALONE,
        }
    )
    client = device(platform, shell)
    client.read = lambda: None
    assert client.preflight() is False
    for key, value in CREATION[platform].items():
        assert getattr(client.creation, key) == value
    client.creation.for_platform(platform)
    if platform == "f5":
        assert client.creation.partition == "all-partitions" and client.creation.shell == "bash"
    assert not any("password " in c or c == "chpasswd" for c, _ in shell.calls)


@pytest.mark.parametrize(
    "release,group",
    [("ID=ubuntu", "sudo"), ("ID=rhel", "wheel"), ('ID=rocky\nID_LIKE="rhel centos fedora"', "wheel")],
)
@pytest.mark.parametrize("sudo_access", ["(ALL : ALL) ALL", "(ALL) NOPASSWD: ALL", "(root) /usr/bin/id"])
def test_default_linux_creation_checks_administrator_access(release, group, sudo_access):
    shell = Shell(
        {
            "id -u": "0",
            "cat /etc/os-release": release,
            "cat /etc/group": group + ":x:27:",
            "getent passwd automation": {"stdout": "", "exit_code": 2},
            "LC_ALL=C sudo -l -U automation": "User automation may run the following commands:\n    "
            + sudo_access,
        }
    )
    client = device("linux", shell)
    records = iter([None, None, "automation:x:1000:1000::/home/automation:/bin/bash"])
    client.read = lambda: next(records)
    assert client.preflight() is False
    if sudo_access.endswith("/usr/bin/id"):
        with pytest.raises(DeviceError, match="full sudo access"):
            client.apply()
    else:
        client.apply()
    assert any(command == "useradd -m -s /bin/bash -G " + group + " automation" for command, _ in shell.calls)


def test_creation_override_and_existing_account_do_not_use_admin_defaults():
    shell = Shell(
        {
            "id -u": "0",
            "cat /etc/group": "",
            "getent passwd automation": {"stdout": "", "exit_code": 2},
            **UNLOCKED,
        }
    )
    client = device("linux", shell, new_account={"groups": []})
    client.read = lambda: None
    assert client.preflight() is False and client.creation.groups == []
    existing = device("linux", shell)
    existing.read = lambda: "automation:x:1000:1000::/home/automation:/bin/sh"
    assert existing.preflight() is True and existing.creation is None
    assert all(command != "cat /etc/os-release" for command, _ in shell.calls)


def test_unknown_linux_and_missing_admin_group_fail_before_creation():
    shell = Shell({"id -u": "0", "cat /etc/os-release": "ID=unknown"})
    client = device("linux", shell)
    client.read = lambda: None
    with pytest.raises(DeviceError, match="defaults are unknown"):
        client.preflight()
    shell.outputs["cat /etc/os-release"] = "ID=rhel"
    with pytest.raises(DeviceError, match="group does not exist"):
        client.preflight()
    assert all(not command.startswith("useradd ") for command, _ in shell.calls)


def test_create_if_missing_false_still_rejects_missing_account():
    client = device("linux", Shell({"id -u": "0"}), create_if_missing=False)
    client.read = lambda: None
    with pytest.raises(DeviceError, match="create_if_missing is false"):
        client.preflight()


def test_parsers_require_complete_local_account_output():
    assert network_account(
        "username automation privilege 15 secret 9 HASH\nusername other secret 9 OTHER", "automation"
    ) == ["username automation privilege 15 secret 9 HASH"]
    assert network_account("username automation2 secret 9 OTHER", "automation") is None
    with pytest.raises(DeviceError):
        network_account("% permission denied", "automation")
    output = 'config system admin\n edit "automation"\n set accprofile "super_admin"\n set password ENC opaque\n next\nend'
    assert forti_accounts(output)["automation"]["accprofile"] == ["super_admin"]
    for bad in ("", "permission denied", output.removesuffix("end")):
        with pytest.raises(DeviceError):
            forti_accounts(bad)


def test_opengear_reads_username_slot_not_fixed_root_slot_and_checks_groups():
    shell = Shell(
        {
            "id -u": "0",
            "cat /etc/version": "OpenGear/IM7248 version 5.3.3",
            "config -g config.users": "config.users.total 2\nconfig.users.user1.username root\nconfig.users.user2.username automation\nconfig.users.user2.groups.group1 admin\nconfig.users.user2.password HASH",
        }
    )
    client = device("opengear", shell)
    assert client.preflight() and client.index == 2
    assert client.before["groups.group1"] == "admin"
    shell.outputs["config -g config.users"] += "\nconfig.users.user3.username automation"
    with pytest.raises(DeviceError, match="duplicate"):
        client.read()


def test_f5_reads_local_account_and_preserves_partition_role_and_shell():
    shell = Shell(
        {
            "list /auth user": "auth user automation {\n encrypted-password HASH\n shell tmsh\n partition-access { all-partitions { role operator } }\n}\n",
            **F5_STANDALONE,
        }
    )
    client = device("f5", shell)
    assert client.preflight()
    assert client.access(client.before)[0] == "tmsh"
    assert "operator" in client.access(client.before)[1]


def test_linux_rejects_directory_account_collision():
    shell = Shell(
        {
            "id -u": "0",
            "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash",
            "cat /etc/group": "sudo:x:27:",
            "getent passwd automation": "automation:x:2001:2001:remote:/home/automation:/bin/bash",
        }
    )
    client = device("linux", shell, new_account={"groups": ["sudo"]})
    with pytest.raises(DeviceError, match="outside the local"):
        client.preflight()


def test_ios_legacy_password_and_fortigate_remote_accounts_are_not_recreated():
    shell = Shell(
        {"show running-config | include ^username": "username automation privilege 15 password 7 HASH"}
    )
    with pytest.raises(DeviceError, match="migrate"):
        device("cisco_ios", shell).preflight()
    shell = Shell(
        {
            "get system status": "Virtual domain configuration: disable",
            "show system admin": 'config system admin\n edit "automation"\n set remote-auth enable\n next\nend',
        }
    )
    with pytest.raises(DeviceError, match="remote or wildcard"):
        device("fortinet", shell).preflight()


def test_save_checks_running_and_startup_account_and_never_logs_hashes():
    shell = Shell(
        {
            "show running-config | include ^username": "username automation secret 9 NEW",
            "show startup-config | include ^username": "username automation secret 9 OLD",
        }
    )
    client = device("cisco_ios", shell)
    with pytest.raises(DeviceError, match="do not match") as exc:
        client.save()
    assert "NEW" not in str(exc.value) and shell.calls[0][0] == "write memory"


@pytest.mark.parametrize(
    "platform,options",
    [
        ("linux", {"role": "admin"}),
        ("cisco_ios", {"role": "admin"}),
        ("opengear", {"groups": []}),
        ("f5", {"role": "admin", "shell": "/bin/bash"}),
        ("fortinet", {"role": "super_admin", "groups": ["admin"]}),
    ],
)
def test_creation_options_are_platform_specific(platform, options):
    request = PasswordRotationRequest.model_validate(body(platform, new_account=options))
    with pytest.raises(ValueError):
        request.for_platform(platform)


@pytest.mark.parametrize(
    "password", ["secret\nreload", "secret\x1b", "secret\u009b", "secret\u2028", "", "x" * 257]
)
def test_control_characters_and_oversized_password_rejected(password):
    with pytest.raises(ValueError):
        PasswordRotationRequest.model_validate(body(password=password))


def test_special_character_handling_and_hash_work_bound():
    for password in ["value?help", "a b", "x;reload", "x\\y"]:
        with pytest.raises(ValueError):
            check_password_syntax("cisco_ios", password)
    hash_value = sha512_crypt.using(rounds=5000).hash('value?with "quotes" and $')
    assert crypt_matches('value?with "quotes" and $', hash_value)
    assert not crypt_matches("wrong", hash_value)
    with pytest.raises(DeviceError, match="work limit"):
        crypt_matches("test", "$6$rounds=999999999$salt$hash")


def test_password_probe_real_ssh_uses_only_requested_account_and_trust(settings):
    with ssh_server() as (port, key, state):
        settings.known_hosts.write_text(f"[127.0.0.1]:{port} {key.get_name()} {key.get_base64()}\n")
        target = Device(id="test", host="127.0.0.1", port=port)
        verify_login(settings, target, "tacacs", "tacacs-secret", lambda: None)
        with pytest.raises(PasswordRejected):
            verify_login(settings, target, "tacacs", "wrong-secret", lambda: None)
        assert state["attempts"] == ["tacacs", "tacacs"] and state["commands"] == []


def test_password_probe_does_not_ignore_host_keys(settings):
    settings.known_hosts.write_text("")
    with ssh_server() as (port, key, state):
        with pytest.raises(DeviceError):
            verify_login(
                settings,
                Device(id="test", host="127.0.0.1", port=port),
                "tacacs",
                "tacacs-secret",
                lambda: None,
            )
        assert not state["attempts"]


@pytest.mark.parametrize("repeat", [False, True])
def test_password_prompt_answers_only_bounded_native_prompts(repeat):
    from netops_executor.password_devices import password_prompt

    class Channel:
        def __init__(self):
            self.chunks = [
                b"New password:",
                b"Retype password:",
                b"New password:" if repeat else b"Password changed\n",
            ]
            self.sent = []
            self.command = None
            self.closed = False

        def get_pty(self):
            pass

        def exec_command(self, command):
            self.command = command

        def recv_ready(self):
            return bool(self.chunks)

        def recv(self, count):
            return self.chunks.pop(0)

        def sendall(self, value):
            self.sent.append(value)

        def exit_status_ready(self):
            return not self.chunks

        def recv_exit_status(self):
            return 0

        def close(self):
            self.closed = True

    channel = Channel()
    ssh = SimpleNamespace(
        guard=lambda: None,
        connect=lambda: SimpleNamespace(
            get_transport=lambda: SimpleNamespace(open_session=lambda **kwargs: channel)
        ),
    )
    if repeat:
        with pytest.raises(DeviceError, match="repeated"):
            password_prompt(ssh, "config -P config.users.user2.password", PASSWORD, 10)
    else:
        password_prompt(ssh, "config -P config.users.user2.password", PASSWORD, 10)
    assert channel.sent == [(PASSWORD + "\n").encode()] * 2
    assert PASSWORD not in channel.command and channel.closed


def test_creation_options_survive_public_metadata_round_trip(api):
    for platform, creation in CREATION.items():
        response = api.post("/api/v1/password-rotation/plan", json=body(platform, new_account=creation))
        assert response.status_code == 200, response.text
        parsed = PasswordRotationOptions.model_validate(response.json()["request"])
        parsed.for_platform(platform)
        assert parsed.new_account.model_dump(exclude_unset=True) == creation


def test_existing_privilege_change_fails_before_success():
    shell = Shell()
    client = device("cisco_ios", shell)
    client.before = ["username automation privilege 15 secret 9 OLD"]
    client.read = lambda: (
        client.before if not shell.calls else ["username automation privilege 1 secret 9 NEW"]
    )
    with pytest.raises(DeviceError, match="privileges changed"):
        client.apply()


def test_empty_or_bad_opengear_user_tree_is_not_missing_account():
    for output in ["", "config.users.user1.username root", "config.users.total invalid"]:
        client = device("opengear", Shell({"config -g config.users": output}))
        with pytest.raises(DeviceError):
            client.read()


def test_fortigate_admin_tables_are_parsed_without_reading_access_from_them():
    output = """config system admin
    edit "automation"
        set accprofile "super_admin"
        set vdom "root"
        config gui-dashboard
            edit 1
                set name "Status"
                config widget
                    edit 1
                        set type sysinfo
                    next
                end
            next
        end
        set password ENC opaque
    next
end"""
    record = forti_accounts(output)["automation"]
    assert record["accprofile"] == ["super_admin"] and record["password"] == ["ENC", "opaque"]
    assert record["config gui-dashboard"][0] == ["edit", "1"]
    client = device("fortinet", Shell())
    assert client.access(record) == {"accprofile": ["super_admin"], "vdom": ["root"]}
    # A different dashboard is still a change since precheck; an unterminated table is not trusted.
    assert forti_accounts(output.replace("Status", "Other")) != forti_accounts(output)
    with pytest.raises(DeviceError, match="incomplete"):
        forti_accounts(output.replace("        end\n        set password", "        set password"))


def test_fortigate_question_mark_password_is_rejected_before_submission(api):
    with pytest.raises(ValueError, match="question mark"):
        check_password_syntax("fortinet", "value?help")
    check_password_syntax("linux", "value?help")
    response = api.post("/api/v1/password-rotation/jobs", json=body("fortinet", password="Value?Help-123"))
    assert response.status_code == 422 and "Value?Help" not in response.text


@pytest.mark.parametrize("state", ["L", "LK", "P", "PS", "NP"])
def test_locked_linux_account_is_not_unlocked_by_rotation(state):
    shell = Shell(
        {
            "id -u": "0",
            "cat /etc/passwd": "automation:x:1000:1000::/home/automation:/bin/bash",
            "LC_ALL=C passwd -S automation": "automation " + state + " 2026-01-01 0 99999 7 -1",
        }
    )
    client = device("linux", shell)
    if state in ("L", "LK"):
        with pytest.raises(DeviceError, match="locked"):
            client.preflight()
    else:
        assert client.preflight() is True
    assert all(command != "chpasswd" for command, _ in shell.calls)
    shell.outputs["LC_ALL=C passwd -S automation"] = "other P"
    with pytest.raises(DeviceError, match="status is unavailable"):
        client.preflight()


F5_PAIR = {
    "list /cm device all-properties": "cm device a { self-device true management-ip 192.0.2.10 version 17.1.1 build 0.0.2 }"
    " cm device b { self-device false management-ip 192.0.2.11 version 17.1.1 build 0.0.2 }",
    "list /cm device-group all-properties": "cm device-group pair { type sync-failover auto-sync disabled devices { a { } b { } } }",
    "show /cm failover-status field-fmt": "cm failover-status {\n status ACTIVE\n}",
    "show /cm sync-status field-fmt": 'cm sync-status {\n status "In Sync"\n}',
    "list /auth user": "auth user automation {\n encrypted-password HASH\n shell tmsh\n"
    " partition-access { all-partitions { role admin } }\n}\n",
}


def f5_pair(after_save=('"Changes Pending"', '"In Sync"'), **outputs):
    shell = Shell({**F5_PAIR, **outputs})
    request = PasswordRotationOptions.model_validate({k: v for k, v in body("f5").items() if k != "password"})
    request.for_platform("f5")
    hosts = {"192.0.2.10": "a", "192.0.2.11": "b"}
    settings = SimpleNamespace(device=lambda host: SimpleNamespace(id=hosts[host]))
    client = AccountDevice(settings, None, request, PASSWORD, lambda: None, None, ssh=shell)
    clock = Clock()
    client.sleep, client.clock = clock.sleep, clock.clock
    statuses, read = iter(after_save), shell.tmsh

    def tmsh(command, **kwargs):
        # Sync status as observed after the account change was saved.
        if command == "show /cm sync-status field-fmt" and any(
            c == "save /sys config" for c, _ in shell.calls
        ):
            return "cm sync-status {\n status " + next(statuses, '"Changes Pending"') + "\n}"
        return read(command, **kwargs)

    shell.tmsh = tmsh
    return client, shell


@pytest.mark.parametrize("auto_sync", [False, True])
def test_f5_pair_account_change_is_synchronized_and_peer_reserved(auto_sync):
    group = "cm device-group pair { type sync-failover auto-sync enabled devices { a { } b { } } }"
    client, shell = f5_pair(**({"list /cm device-group all-properties": group} if auto_sync else {}))
    assert client.preflight() is True
    keys = set(client.reservations)
    assert {"endpoint:192.0.2.10", "endpoint:192.0.2.11", "device:a", "device:b"} <= keys
    assert any(key.startswith("ha:") for key in keys)
    client.save()
    commands = [c for c, _ in shell.calls]
    assert ("run /cm config-sync to-group pair" in commands) is not auto_sync
    assert commands.index("save /sys config") < len(commands) - 1
    assert client.report == {"config_sync": "in sync"}


@pytest.mark.parametrize(
    "outputs,message",
    [
        ({"show /cm sync-status field-fmt": 'cm sync-status {\n status "Changes Pending"\n}'}, "not in sync"),
        (
            {
                "list /cm device all-properties": F5_PAIR["list /cm device all-properties"].replace(
                    "self-device false management-ip 192.0.2.11 version 17.1.1",
                    "self-device false management-ip 192.0.2.11 version 17.5.1",
                )
            },
            "same version",
        ),
    ],
)
def test_f5_pair_out_of_sync_or_mixed_release_is_refused_before_write(outputs, message):
    client, shell = f5_pair(**outputs)
    with pytest.raises(DeviceError, match=message):
        client.preflight()
    assert not any(c.startswith(("modify", "create", "save", "run")) for c, _ in shell.calls)


def test_f5_pair_sync_that_never_completes_requires_recovery():
    client, shell = f5_pair(after_save=())
    client.preflight()
    with pytest.raises(DeviceError, match="did not complete"):
        client.save()
    assert client.clock() >= 120 and "config_sync" not in client.report


def test_standalone_f5_reports_and_reserves_nothing_extra():
    client = device("f5", Shell({**F5_STANDALONE, "list /auth user": F5_PAIR["list /auth user"]}))
    assert client.preflight() is True
    assert client.reservations == [] and client.report == {"config_sync": "standalone"}


@pytest.mark.parametrize("platform,user", [("linux", "automation"), ("f5", "root")])
def test_local_hash_mismatch_is_definitive_but_missing_verifier_is_not(platform, user):
    shell = Shell()
    client = device(platform, shell, verification="local_hash", username=user)
    for code, outcome in ((0, None), (3, PasswordRejected), (1, DeviceError), (127, DeviceError)):
        shell.execute = lambda command, code=code, **kwargs: {"stdout": "", "stderr": "", "exit_code": code}
        if outcome is None:
            client.verify()
            continue
        with pytest.raises(outcome) as exc:
            client.verify()
        assert isinstance(exc.value, PasswordRejected) is (code == 3)


def test_hash_mismatch_opens_review_with_its_own_message(settings, store, api):
    submit(api, verification="local_hash")
    account = Account()
    account.verify_error = PasswordRejected("local password hash does not match the requested password")
    job = work(settings, store, account)
    assert job["status"] == "needs_review" and account.calls.count("verify") == 1
    assert job["validation_gates"][-1]["findings"]["critical"] == [
        "local password hash does not match the requested password"
    ]


def test_discovered_reservations_defer_and_are_kept_for_continuation(settings, store, api):
    other = store.submit({"device": "peer"}, "device:peer", kind="ssh")
    assert store.claim("other")["id"] == other["id"]
    assert store.reserve(other["id"], "other", ["ha:pair"])
    created = submit(api)
    account = Account()
    account.reservations, account.report = ["ha:pair", "endpoint:192.0.2.11"], {"config_sync": "in sync"}
    job = work(settings, store, account)
    assert job["id"] == created["id"] and job["status"] == "queued"
    assert account.calls == ["preflight"] and "mutations" not in job["result"]
    store.finish(other["id"], "other", "succeeded")
    with store.connect() as db:
        db.execute("UPDATE controls SET next_attempt=0 WHERE job=?", (created["id"],))
    account.verify_error = PasswordRejected("authentication rejected")
    job = work(settings, store, account)
    assert job["status"] == "needs_review"
    assert job["result"]["reservations"] == ["endpoint:192.0.2.11", "ha:pair"]
    assert job["result"]["config_sync"] == "in sync"
    with store.connect() as db:
        held = {r[0] for r in db.execute("SELECT key FROM resources WHERE job=?", (created["id"],))}
    assert {"ha:pair", "endpoint:192.0.2.11"} <= held


def test_job_password_is_purged_when_the_job_can_no_longer_resume(settings, store, api):
    headers = {"Idempotency-Key": "purge-once"}
    first = api.post("/api/v1/password-rotation/jobs", json=body(), headers=headers).json()
    vault = Vault(store, settings.credential_key_file)
    assert vault.job_password(first["id"]) == PASSWORD
    account = Account()
    account.verify_error = PasswordRejected("authentication rejected")
    assert work(settings, store, account)["status"] == "needs_review"
    # A review gate still needs the password for its verification continuation.
    assert vault.job_password(first["id"]) == PASSWORD
    store.cancel(first["id"])
    with store.connect() as db:
        secret, digest = db.execute(
            "SELECT secret,digest FROM job_secrets WHERE job=?", (first["id"],)
        ).fetchone()
    assert secret == b"" and digest.startswith("scrypt$") and PASSWORD not in digest
    with pytest.raises(Exception, match="unavailable"):
        vault.job_password(first["id"])
    # Idempotent replay still recognizes the same password and rejects a different one.
    again = api.post("/api/v1/password-rotation/jobs", json=body(), headers=headers)
    assert again.status_code == 202 and again.json()["id"] == first["id"]
    changed = api.post(
        "/api/v1/password-rotation/jobs", json=body(password="Other-Secret-345!"), headers=headers
    )
    assert changed.status_code == 409
    # Keyring rotation skips purged rows.
    old = settings.credential_key_file.read_bytes()
    settings.credential_key_file.write_bytes(Fernet.generate_key() + b"\n" + old)
    assert vault.rotate() == {"rotated": True}


def test_existing_finished_job_secrets_are_purged_on_upgrade(settings, store, api):
    from netops_executor.store import Store

    legacy = submit(api)
    vault = Vault(store, settings.credential_key_file)
    with store.connect() as db:
        db.execute("DROP TRIGGER job_secrets_purge")
        db.execute("UPDATE job_secrets SET digest=NULL WHERE job=?", (legacy["id"],))
        db.execute("UPDATE jobs SET status='succeeded' WHERE id=?", (legacy["id"],))
        assert db.execute("SELECT length(secret) FROM job_secrets").fetchone()[0] > 0
    Store(store.path)
    with store.connect() as db:
        assert db.execute("SELECT secret FROM job_secrets WHERE job=?", (legacy["id"],)).fetchone()[0] == b""
    with pytest.raises(Exception, match="unavailable"):
        vault.job_password(legacy["id"])
