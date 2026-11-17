"""A changed SSH host key stops before login, records one alert and emails once."""

import paramiko
import pytest
from test_controls_credentials import vault_for
from test_ssh_wire import ssh_server

from netops_executor.config import Device
from netops_executor.credentials import Credential
from netops_executor.notify import EmailSender
from netops_executor.pins import ssh_fingerprint
from netops_executor.ssh import SSH, HostKeyChangedError
from netops_executor.store import Conflict

OLD = "ssh-rsa:" + "0" * 64


def deliveries(store):
    with store.connect() as db:
        return [dict(r) for r in db.execute("SELECT * FROM email_deliveries WHERE kind='host_key'")]


def test_changed_pinned_key_alerts_once_and_trusting_it_resumes(settings, store):
    settings.ssh_host_keys, settings.alert_email = "pin", ["netops@example.com"]
    settings.poller_instance = "checkmk-au"
    vault_for(settings, store).put(
        "tacacs", Credential(kind="ssh", username="tacacs", password="tacacs-secret")
    )
    with ssh_server() as (port, key, state):
        endpoint = f"ssh:127.0.0.1:{port}"
        device = Device(id="core-sw", host="127.0.0.1", port=port)
        ssh = SSH(settings, device)
        try:
            ssh.connect()
            assert ssh.host_key_status == "pinned_now"
            ssh.close()
            ssh.connect()
            assert ssh.host_key_status == "pinned"
            ssh.close()
            # The device's key changes (simulated by trusting another key for it).
            with store.connect() as db:
                db.execute("UPDATE pins SET fingerprint=? WHERE key=?", (OLD, endpoint))
            attempts = len(state["attempts"])
            for _ in range(3):
                with pytest.raises(HostKeyChangedError, match="no credentials were sent"):
                    ssh.connect()
            assert len(state["attempts"]) == attempts  # never authenticated to the changed key
            (alert,) = store.host_key_alerts("open")
            assert alert["presented"] == ssh_fingerprint(key) and alert["expected"] == OLD
            assert alert["attempts"] == 3 and alert["poller"] == "checkmk-au" and alert["device"] == "core-sw"
            assert len(deliveries(store)) == 1  # one email, not one per attempt
            trusted = store.trust_host_key(alert["id"])
            assert trusted["state"] == "trusted"
            ssh.connect()
            assert ssh.host_key_status == "pinned" and store.host_key_alerts("open") == []
        finally:
            ssh.close()


def test_device_presenting_its_trusted_key_again_closes_the_alert(settings, store):
    settings.ssh_host_keys = "pin"
    vault_for(settings, store).put(
        "tacacs", Credential(kind="ssh", username="tacacs", password="tacacs-secret")
    )
    with ssh_server() as (port, key, state):
        endpoint = f"ssh:127.0.0.1:{port}"
        store.pin(endpoint, "ssh", ssh_fingerprint(key))
        # Earlier the device presented another key (for example during a failed replacement).
        store.host_key_alert(endpoint, "sw", "ssh-rsa:" + "f" * 64, ssh_fingerprint(key), "pin", None, False)
        assert deliveries(store) == []  # no NETOPS_ALERT_EMAIL: recorded, not emailed
        ssh = SSH(settings, Device(id="sw", host="127.0.0.1", port=port))
        ssh.connect()  # now it presents its trusted key again
        ssh.close()
        (alert,) = store.host_key_alerts()
        assert alert["state"] == "resolved" and alert["resolution"] == "trusted key presented again"


def test_known_hosts_mismatch_alerts_but_is_trusted_by_editing_known_hosts(settings, store):
    vault_for(settings, store).put(
        "tacacs", Credential(kind="ssh", username="tacacs", password="tacacs-secret")
    )
    other = paramiko.RSAKey.generate(2048)
    with ssh_server() as (port, key, state):
        settings.known_hosts.write_text(f"[127.0.0.1]:{port} {other.get_name()} {other.get_base64()}\n")
        ssh = SSH(settings, Device(id="sw", host="127.0.0.1", port=port))
        with pytest.raises(HostKeyChangedError):
            ssh.connect()
        assert not state["attempts"]
        (alert,) = store.host_key_alerts("open")
        assert alert["mode"] == "known_hosts" and alert["expected"] == ssh_fingerprint(other)
        with pytest.raises(Conflict, match="NETOPS_KNOWN_HOSTS"):
            store.trust_host_key(alert["id"])


def test_alert_email_names_the_device_keys_and_trust_action(settings, store):
    settings.ssh_host_keys, settings.alert_email = "pin", ["netops@example.com"]
    settings.smtp_from = "NetOps <netops@example.com>"
    alert_id, new = store.host_key_alert(
        "ssh:192.0.2.10:22", "lab", "ssh-ed25519:" + "a" * 64, OLD, "pin", "au", True
    )
    assert (
        new
        and store.host_key_alert(
            "ssh:192.0.2.10:22", "lab", "ssh-ed25519:" + "a" * 64, OLD, "pin", "au", True
        )[1]
        is False
    )
    sender = EmailSender(settings, store)
    (delivery,) = deliveries(store)
    message, status = sender.build(delivery)
    text = message.get_body(("plain",)).get_content()
    assert "lab (192.0.2.10)" in message["Subject"] and status == "open"
    assert OLD in text and "ssh-ed25519:" + "a" * 64 in text
    assert f"/api/v1/host-keys/alerts/{alert_id}/trust" in text
    store.trust_host_key(alert_id)
    assert sender.build(delivery) == "alert closed before delivery"


def test_host_key_api_lists_and_trusts_alerts(settings, store):
    from fastapi.testclient import TestClient

    from netops_executor.api import create_app

    alert_id, _ = store.host_key_alert(
        "ssh:192.0.2.10:22", "lab", "ssh-ed25519:" + "b" * 64, None, "pin", None, False
    )
    client = TestClient(create_app(settings), headers={"Authorization": "Bearer " + settings.token})
    assert [a["id"] for a in client.get("/api/v1/host-keys/alerts?state=open").json()] == [alert_id]
    assert client.post(f"/api/v1/host-keys/alerts/{alert_id}/trust").json()["state"] == "trusted"
    assert store.pinned("ssh:192.0.2.10:22") == "ssh-ed25519:" + "b" * 64
    assert client.post(f"/api/v1/host-keys/alerts/{alert_id}/trust").status_code == 409
