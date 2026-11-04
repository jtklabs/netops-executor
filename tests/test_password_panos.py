import copy
import json
import xml.etree.ElementTree as ET

import httpx
import pytest
from fastapi.testclient import TestClient
from passlib.hash import sha256_crypt
from test_controls_credentials import vault_for
from test_password_rotation import PASSWORD, work
from test_ssh_wire import ssh_server

from netops_executor.api import create_app
from netops_executor.config import Device, HTTPTarget
from netops_executor.credentials import Credential
from netops_executor.network_ssh import NetworkSSH
from netops_executor.password_models import AccountCreation, PasswordRotationOptions
from netops_executor.password_panos import PanosAccountDevice, SshAccounts, account, canonical, config_xml
from netops_executor.ssh import DeviceError

SERIAL = "012345678901"
HOST = "192.0.2.10"


def configuration(existing=True):
    root = ET.fromstring(
        '<config><mgt-config><users><entry name="admin"><permissions><role-based><superuser>yes</superuser></role-based></permissions></entry></users></mgt-config><shared><address/></shared></config>'
    )
    if existing:
        user = ET.SubElement(root.find("mgt-config/users"), "entry", name="automation")
        ET.SubElement(user, "phash").text = sha256_crypt.hash("old-password")
        ET.SubElement(
            ET.SubElement(ET.SubElement(user, "permissions"), "role-based"), "superreader"
        ).text = "yes"
    return root


class Backend:
    def __init__(self, existing=True):
        self.running = configuration(existing)
        self.candidate = copy.deepcopy(self.running)
        self.calls = []

    def prepare(self):
        self.calls.append("prepare")
        return SERIAL

    def config(self, running=False):
        return copy.deepcopy(self.running if running else self.candidate)

    def lock(self, marker):
        self.calls.append("lock")

    def set_password(self, username, password, creation):
        self.calls.append("set_password")
        node = account(self.candidate, username)
        if node is None:
            node = ET.SubElement(self.candidate.find("mgt-config/users"), "entry", name=username)
            ET.SubElement(node, "phash")
        node.find("phash").text = sha256_crypt.hash(password)
        if creation:
            ET.SubElement(
                ET.SubElement(ET.SubElement(node, "permissions"), "role-based"), creation.role
            ).text = "yes"

    def commit(self):
        self.calls.append("commit")
        self.running = copy.deepcopy(self.candidate)

    def close(self):
        pass


def request(**kwargs):
    r = PasswordRotationOptions(
        device=HOST, device_type="paloalto_panos", username="automation", verification="local_hash", **kwargs
    )
    r.for_platform(r.device_type)
    return r


def client(backend, **kwargs):
    return PanosAccountDevice(None, None, None, request(**kwargs), PASSWORD, lambda: None, None, backend)


@pytest.mark.parametrize("existing", [True, False])
def test_panos_create_and_update_preserve_role_and_commit_then_verify(existing):
    backend = Backend(existing)
    device = client(backend)
    assert device.preflight() is existing
    device.apply()
    device.save()
    device.verify()
    role = account(backend.running, "automation").find("permissions/role-based")
    assert [child.tag for child in role] == ["superreader" if existing else "superuser"]
    assert backend.calls == ["prepare", "lock", "set_password", "commit"]


@pytest.mark.parametrize("phase", ["preflight", "apply", "save"])
def test_panos_never_commits_unrelated_pending_changes(phase):
    backend = Backend()
    device = client(backend)
    if phase != "preflight":
        device.preflight()
    if phase == "save":
        device.apply()
    ET.SubElement(backend.candidate.find("shared/address"), "entry", name="someone-elses-change")
    with pytest.raises(DeviceError, match="pending|changed"):
        getattr(device, phase)()
    assert "commit" not in backend.calls


@pytest.mark.parametrize(
    "field,value", [("authentication-profile", "tacacs"), ("client-certificate-only", "yes")]
)
def test_panos_remote_authentication_is_not_converted_to_local(field, value):
    backend = Backend()
    ET.SubElement(account(backend.running, "automation"), field).text = value
    backend.candidate = copy.deepcopy(backend.running)
    with pytest.raises(DeviceError, match="external or certificate"):
        client(backend).preflight()
    assert "set_password" not in backend.calls


def test_panos_wrong_serial_and_missing_user_are_rejected_before_write():
    with pytest.raises(DeviceError, match="serial"):
        client(Backend(), serial="999999999999").preflight()
    with pytest.raises(DeviceError, match="create_if_missing"):
        client(Backend(False), create_if_missing=False).preflight()


def test_panos_commit_and_hash_verification_fail_closed():
    backend = Backend()
    device = client(backend)
    device.preflight()
    device.apply()
    backend.commit = lambda: None
    with pytest.raises(DeviceError, match="committed account"):
        device.save()
    with pytest.raises(DeviceError, match="password hash"):
        device.verify()


def test_panos_configuration_parser_requires_admin_tree_and_ignores_only_edit_annotations():
    root = configuration()
    changed = copy.deepcopy(root)
    account(changed, "automation").set("dirtyId", "3")
    assert canonical(changed) == canonical(root)
    account(changed, "automation").set("source", "template")
    assert canonical(changed) != canonical(root)
    assert config_xml("[edit]\n" + ET.tostring(root, encoding="unicode") + "\n[edit]").tag == "config"
    for bad in ("permission denied", "<config></config>", "<config><broken></config>"):
        with pytest.raises(DeviceError):
            config_xml(bad)


def api_setup(settings, store):
    vault = vault_for(settings, store)
    settings.http_targets["panorama"] = HTTPTarget(
        id="panorama",
        base_url="https://panorama.test",
        auth_probe_path="/api/",
        auth_probe_params={"type": "op", "cmd": "<show><system><info/></system></show>"},
    )
    return vault, TestClient(create_app(settings), headers={"Authorization": "Bearer " + settings.token})


def payload(**kwargs):
    return {
        "device": HOST,
        "device_type": "paloalto_panos",
        "username": "automation",
        "password": PASSWORD,
        **kwargs,
    }


def test_panos_api_discovery_defaults_and_invalid_transport_options(settings, store):
    _, api = api_setup(settings, store)
    assert {"device_type": "paloalto_panos", "modes": ["exec", "config"]} in api.get(
        "/api/v1/ssh/device-types"
    ).json()
    response = api.post(
        "/api/v1/ssh/jobs",
        json={"device": HOST, "device_type": "paloalto_panos", "commands": [{"command": "show system info"}]},
    )
    assert response.status_code == 202
    plan = api.post("/api/v1/password-rotation/plan", json=payload(panorama="panorama", serial=SERIAL))
    assert plan.status_code == 200 and plan.json()["request"]["verification"] == "local_hash"
    assert "password" not in plan.json()["request"]
    parsed = PasswordRotationOptions.model_validate(plan.json()["request"])
    parsed.for_platform(parsed.device_type)
    assert parsed.verification == "local_hash"
    for options in (
        {"panorama": "panorama"},
        {"panorama": "missing", "serial": SERIAL},
        {"http_credential_profiles": ["one"]},
        {"panorama": "panorama", "serial": SERIAL, "credential_profiles": ["one"]},
        {"new_account": {"role": "invented"}},
    ):
        assert api.post("/api/v1/password-rotation/jobs", json=payload(**options)).status_code == 422


def test_panos_runner_reserves_serial_and_does_not_replay_after_review(settings, store):
    _, api = api_setup(settings, store)
    response = api.post(
        "/api/v1/password-rotation/jobs", json=payload(verification="local_hash", validation_timeout=0)
    )
    assert response.status_code == 202
    backend = Backend()
    device = client(backend)
    device.verify = lambda: (_ for _ in ()).throw(DeviceError("temporarily unavailable"))
    job = work(settings, store, device)
    assert job["status"] == "needs_review" and job["result"]["serial"] == SERIAL
    with store.connect() as db:
        assert (
            db.execute("SELECT job FROM resources WHERE key=?", ("panos:" + SERIAL,)).fetchone()[0]
            == job["id"]
        )
    gate = job["validation_gates"][-1]
    from netops_executor.execution_models import ValidationDecision

    store.decide(
        job["id"],
        ValidationDecision(
            gate_id=gate["id"],
            validation_revision=gate["revision"],
            action="retry",
            operator="jason",
            reason="ready",
        ),
    )
    device.verify = lambda: None
    job = work(settings, store, device)
    assert job["status"] == "succeeded"
    assert backend.calls.count("set_password") == backend.calls.count("commit") == 1
    assert PASSWORD not in json.dumps(job)


@pytest.mark.parametrize("repeat_password", [False, True])
def test_panos_real_ssh_driver_supports_operational_and_configuration_modes(settings, store, repeat_password):
    vault = vault_for(settings, store)
    vault.put("ssh", Credential(kind="ssh", username="tacacs", password="tacacs-secret"))
    with ssh_server(cli="paloalto") as (port, key, state):
        settings.known_hosts.write_text(f"[127.0.0.1]:{port} {key.get_name()} {key.get_base64()}\n")
        device = Device(id="fw", host="127.0.0.1", port=port, device_type="paloalto_panos")
        ssh = NetworkSSH(settings, device, device_type="paloalto_panos")
        try:
            assert SERIAL in ssh.execute("show system info", timeout=5)["stdout"]
            ssh.execute("set deviceconfig system hostname test", mode="config", timeout=5)
            ssh.execute("set deviceconfig system domain example.test", mode="config", timeout=5)
            assert ssh.execute("bad-command", timeout=5)["cli_error"]
            assert state["commands"].count("configure") == 1
            assert "exit" in state["commands"]
            backend = SshAccounts(settings, device, request(), PASSWORD, lambda: None, None)
            backend.ssh = ssh
            assert backend.prepare() == SERIAL
            state["repeat_password"] = repeat_password
            if repeat_password:
                with pytest.raises(DeviceError, match="repeated"):
                    backend.set_password(
                        "automation", PASSWORD, AccountCreation.administrator("paloalto_panos")
                    )
                assert "commit" not in state["commands"]
            else:
                backend.set_password("automation", PASSWORD, AccountCreation.administrator("paloalto_panos"))
                backend.commit()
            assert state["password_inputs"] == [PASSWORD, PASSWORD]
            assert PASSWORD not in " ".join(state["commands"])
        finally:
            ssh.close()


@pytest.mark.parametrize("existing", [True, False])
@pytest.mark.parametrize(
    "failure",
    [
        None,
        "wrong_ip",
        "wrong_serial",
        "commit_failure",
        "lost_commit",
        "wrong_hash",
        "lock_denied",
        "extra_change",
    ],
)
def test_panorama_rotation_uses_serial_proxy_and_http_fallback_without_ssh(
    settings, store, monkeypatch, existing, failure
):
    vault, api = api_setup(settings, store)
    vault.put(
        "wrong", Credential(kind="http", scheme="header", header="X-PAN-KEY", token="wrong", priority=1)
    )
    vault.put(
        "right", Credential(kind="http", scheme="header", header="X-PAN-KEY", token="right", priority=2)
    )
    backend, calls, markers = Backend(existing), [], {}
    desired = PASSWORD + '<&>"'

    def handle(req):
        from urllib.parse import parse_qs

        if req.headers.get("X-PAN-KEY") == "wrong":
            return httpx.Response(
                200, text='<response status="error" code="403"><msg>Invalid credentials</msg></response>'
            )
        if req.method == "GET":
            return httpx.Response(200, text='<response status="success"><result/></response>')
        form = {k: v[0] for k, v in parse_qs(req.content.decode()).items()}
        calls.append(form)
        body = ET.Element("result")
        if form["type"] == "config":
            assert form["target"] == SERIAL
            if form["action"] in ("get", "show"):
                body.append(backend.config(form["action"] == "show"))
            else:
                entry = ET.fromstring(form["element"])
                node = account(backend.candidate, "automation")
                if node is None:
                    backend.candidate.find("mgt-config/users").append(entry)
                else:
                    for child in entry:
                        old = node.find(child.tag)
                        if old is not None:
                            node.remove(old)
                        node.append(child)
                if failure == "extra_change":
                    ET.SubElement(backend.candidate.find("shared/address"), "entry", name="unrelated")
        elif form["type"] == "commit":
            assert form["target"] == SERIAL
            if failure != "commit_failure":
                backend.commit()
            if failure == "lost_commit":
                raise httpx.ReadTimeout("lost commit response", request=req)
            ET.SubElement(body, "job").text = "77"
        else:
            cmd = ET.fromstring(form["cmd"])
            if cmd.find("devices") is not None:
                assert "target" not in form
                entry = ET.SubElement(ET.SubElement(body, "devices"), "entry", name=SERIAL)
                ET.SubElement(entry, "connected").text = "yes"
                ET.SubElement(entry, "ip-address").text = "192.0.2.99" if failure == "wrong_ip" else HOST
            else:
                assert form["target"] == SERIAL
                if cmd.find("system") is not None:
                    ET.SubElement(ET.SubElement(body, "system"), "serial").text = (
                        "999999999999" if failure == "wrong_serial" else SERIAL
                    )
                elif cmd.find("password-hash") is not None:
                    assert cmd.findtext("password-hash/password") == desired
                    ET.SubElement(body, "phash").text = sha256_crypt.hash(
                        "incorrect" if failure == "wrong_hash" else desired
                    )
                elif cmd.find("jobs") is not None:
                    job = ET.SubElement(body, "job")
                    for k, v in (
                        ("id", "77"),
                        ("status", "FIN"),
                        ("result", "FAIL" if failure == "commit_failure" else "OK"),
                    ):
                        ET.SubElement(job, k).text = v
                else:
                    for kind in ("config", "commit"):
                        if cmd.find(kind + "-lock") is not None:
                            if failure == "lock_denied":
                                return httpx.Response(
                                    200,
                                    text='<response status="error"><msg>' + PASSWORD + "</msg></response>",
                                )
                            markers[kind] = cmd.findtext(kind + "-lock/add/comment")
                        if cmd.find(kind + "-locks") is not None:
                            ET.SubElement(ET.SubElement(body, kind + "-locks"), "comment").text = markers[
                                kind
                            ]
        root = ET.Element("response", status="success")
        root.append(body)
        return httpx.Response(200, text=ET.tostring(root, encoding="unicode"))

    original = httpx.Client
    monkeypatch.setattr(
        "netops_executor.panos.httpx.Client",
        lambda **kwargs: original(transport=httpx.MockTransport(handle), **kwargs),
    )
    monkeypatch.setattr(
        "netops_executor.password_panos.NetworkSSH",
        lambda *a, **k: pytest.fail("Panorama must not connect over SSH"),
    )
    response = api.post(
        "/api/v1/password-rotation/jobs", json=payload(panorama="panorama", serial=SERIAL, password=desired)
    )
    assert response.status_code == 202
    from netops_executor.password_engine import PasswordRotationRunner

    PasswordRotationRunner(settings, store, store.claim("worker"), "worker").run()
    job = store.get(response.json()["id"])
    if failure is None:
        assert job["result"].get("error") is None
        assert job["status"] == "succeeded", job["result"]
        assert job["result"]["verified"] and job["result"]["saved"]
    else:
        assert job["status"] == ("failed" if failure in ("wrong_ip", "wrong_serial") else "recovery_required")
        assert not job["result"]["verified"]
    assert [entry["outcome"] for entry in job["credential_usage"]] == ["rejected", "authenticated"]
    assert sum(form["type"] == "commit" for form in calls) == (
        1 if failure in (None, "commit_failure", "lost_commit") else 0
    )
    assert PASSWORD not in json.dumps(job) and "$5$" not in json.dumps(job)
