import json

import pytest
from fastapi.testclient import TestClient
from test_controls_credentials import vault_for
from test_ssh_wire import ssh_server

from netops_executor.api import create_app
from netops_executor.config import Device, Settings
from netops_executor.credentials import Credential, Selector
from netops_executor.execution import ExecutionRunner
from netops_executor.network_ssh import NetworkSSH


@pytest.mark.parametrize("platform", ["cisco_ios", "cisco_nxos", "arista_eos"])
def test_real_interactive_session_platforms_fallback_config_and_redaction(settings, store, platform):
    vault = vault_for(settings, store)
    vault.put("wrong", Credential(kind="ssh", username="wrong", password="wrong-secret", priority=1))
    vault.put("right", Credential(kind="ssh", username="tacacs", password="tacacs-secret", priority=2))
    with ssh_server(cli=True) as (port, key, state):
        settings.known_hosts.write_text(f"[127.0.0.1]:{port} {key.get_name()} {key.get_base64()}\n")
        device = Device(id="test", host="127.0.0.1", port=port, device_type=platform)
        events = []
        ssh = NetworkSSH(settings, device, audit=events.append, device_type=platform)
        try:
            result = ssh.execute("show version", timeout=5)
            assert "version test [REDACTED]" in result["stdout"]
            assert result["exit_code"] is None and not result["cli_error"]
            ssh.execute("interface Ethernet1", mode="config", timeout=5)
            ssh.execute("description managed", mode="config", timeout=5)
            assert ssh.execute("bad-command", timeout=5)["cli_error"]
            assert state["commands"].count("configure terminal") == 1
            assert state["attempts"] == ["wrong", "tacacs"]
            assert [e["outcome"] for e in events] == ["rejected", "authenticated"]
        finally:
            ssh.close()


def test_platform_inheritance_overrides_and_validation(settings):
    settings.devices["lab"].device_type = "arista_eos"
    client = TestClient(create_app(settings))
    client.headers["Authorization"] = "Bearer " + settings.token
    payload = {"device": "lab", "commands": [{"command": "show version"}]}
    response = client.post("/api/v1/ssh/jobs", json=payload)
    assert response.status_code == 202
    assert response.json()["request"]["device_type"] == "arista_eos"
    payload["device_type"] = "cisco_ios"
    assert client.post("/api/v1/ssh/jobs", json=payload).json()["request"]["device_type"] == "cisco_ios"
    payload["device_type"] = "guess"
    assert client.post("/api/v1/ssh/jobs", json=payload).status_code == 422
    payload["device_type"] = "linux"
    payload["commands"][0]["mode"] = "config"
    assert client.post("/api/v1/ssh/jobs", json=payload).status_code == 422
    payload["device_type"] = "cisco_ios"
    payload["commands"][0]["command"] = "show version\nreload"
    assert client.post("/api/v1/ssh/jobs", json=payload).status_code == 422


@pytest.mark.parametrize("cancel", [False, True])
def test_network_timeout_is_fenced_and_never_replayed(settings, store, cancel):
    vault = vault_for(settings, store)
    vault.put("right", Credential(kind="ssh", username="tacacs", password="tacacs-secret"))
    with ssh_server(cli=True) as (port, key, state):
        settings.known_hosts.write_text(f"[127.0.0.1]:{port} {key.get_name()} {key.get_base64()}\n")
        settings.devices["lab"] = Device(id="lab", host="127.0.0.1", port=port, device_type="cisco_ios")
        job = store.submit(
            {"device": "lab", "commands": [{"command": "hang", "timeout_seconds": 1}, {"command": "later"}]},
            "device:lab",
            kind="ssh",
        )
        claimed = store.claim("worker")
        runner = ExecutionRunner(settings, store, claimed, "worker")
        guard = runner.guard

        def checkpoint():
            if cancel and "hang" in state["commands"]:
                store.cancel(job["id"])
            guard()

        runner.guard = checkpoint
        runner.run()
        result = store.get(job["id"])
        assert result["status"] == "recovery_required"
        assert result["result"]["in_flight"] == 0
        assert state["commands"].count("hang") == 1
        assert "later" not in state["commands"]


def test_enable_password_is_encrypted_and_redacted(settings, store):
    vault = vault_for(settings, store)
    vault.put(
        "right",
        Credential(kind="ssh", username="u", password="login-secret", enable_password="enable-secret"),
    )
    selector = Selector(vault, "ssh", "host")
    assert selector.run(lambda c: c["enable_password"]) == "enable-secret"
    assert selector.redact("enable-secret") == "[REDACTED]"
    assert "enable-secret" not in json.dumps(vault.list())
    with store.connect() as db:
        assert b"enable-secret" not in db.execute("SELECT secret FROM credentials").fetchone()[0]


def test_legacy_env_and_generic_precedence(settings, monkeypatch, tmp_path):
    inventory = tmp_path / "devices.json"
    inventory.write_text("[]")
    monkeypatch.setenv("F5_ENV_FILE", str(tmp_path / "missing"))
    for suffix, value in {
        "API_TOKEN": "a" * 40,
        "DEVICES_FILE": str(inventory),
        "DATA_DIR": str(settings.data_dir),
        "BACKUP_ROOT": str(settings.backup_root),
    }.items():
        monkeypatch.delenv("NETOPS_" + suffix, raising=False)
        monkeypatch.setenv("F5_" + suffix, value)
    assert Settings.load().token == "a" * 40
    monkeypatch.setenv("NETOPS_API_TOKEN", "b" * 40)
    assert Settings.load().token == "b" * 40


def test_continuous_output_remains_cancellable():
    from types import SimpleNamespace

    from netops_executor.network_ssh import GuardedChannel
    from netops_executor.store import CancelRequested

    count = 0

    def check():
        nonlocal count
        count += 1
        if count == 3:
            raise CancelRequested()

    owner = SimpleNamespace(check=check, output_bytes=0)
    remote = SimpleNamespace(recv_ready=lambda: True, recv=lambda n: b"stream")
    channel = GuardedChannel(owner, conn=remote, encoding="utf-8")
    with pytest.raises(CancelRequested):
        channel.read_channel()
    assert owner.output_bytes == 12


@pytest.mark.parametrize("stop_on_error", [True, False])
def test_cli_rejection_controls_sequence_and_records_platform(settings, store, stop_on_error):
    vault = vault_for(settings, store)
    vault.put("right", Credential(kind="ssh", username="tacacs", password="tacacs-secret"))
    with ssh_server(cli=True) as (port, key, state):
        settings.known_hosts.write_text(f"[127.0.0.1]:{port} {key.get_name()} {key.get_base64()}\n")
        settings.devices["lab"] = Device(id="lab", host="127.0.0.1", port=port, device_type="cisco_ios")
        job = store.submit(
            {
                "device": "lab",
                "commands": [{"command": "bad-command"}, {"command": "show version"}],
                "stop_on_error": stop_on_error,
            },
            "device:lab",
            kind="ssh",
        )
        ExecutionRunner(settings, store, store.claim("worker"), "worker").run()
        result = store.get(job["id"])
        assert result["status"] == "failed"
        assert result["result"]["device_type"] == "cisco_ios"
        operations = result["result"]["operations"]
        assert len(operations) == (1 if stop_on_error else 2)
        assert operations[0]["cli_error"] and operations[0]["exit_code"] is None
        assert operations[0]["credential_profile"] == "right"
        assert ("show version" in state["commands"]) is not stop_on_error
