import subprocess
import sys
import time

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from netops_executor import cipher_scan
from netops_executor.api import create_app
from netops_executor.cipher_models import CipherScanRequest
from netops_executor.store import CancelRequested, LostOwnership
from netops_executor.worker import process

SSH_DATA = '<table key="encryption_algorithms"><elem>aes256-ctr</elem><elem>aes128-ctr</elem></table><table key="mac_algorithms"><elem>hmac-sha2-256</elem></table>'
TLS_DATA = '<table key="TLSv1.2"><table key="ciphers"><table><elem key="name">TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384</elem><elem key="strength">A</elem></table></table><table key="warnings"><elem>example warning</elem></table><elem key="cipher preference">server</elem></table><elem key="least strength">A</elem>'


def xml(protocol="ssh", port=22, state="open", data=None, output="cipher output", exit="success"):
    data = (SSH_DATA if protocol == "ssh" else TLS_DATA) if data is None else data
    return f'''<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun version="7.95"><host><ports>
    <port protocol="tcp" portid="{port}"><state state="{state}" reason="syn-ack"/>
    <script id="{cipher_scan.SCRIPTS[protocol]}" output="{output}">{data}</script></port>
    </ports></host><runstats><finished exit="{exit}"/></runstats></nmaprun>'''.encode()


@pytest.fixture
def client(settings):
    return TestClient(create_app(settings), headers={"Authorization": "Bearer " + settings.token})


def submit(client, **extra):
    response = client.post(
        "/api/v1/cipher-scans", json={"device_ip": "192.0.2.9", "protocol": "ssh", **extra}
    )
    assert response.status_code == 202, response.text
    return response.json()


def test_api_contract(client):
    path = "/api/v1/cipher-scans"
    body = {"device_ip": "2001:0db8::1", "protocol": "https", "port": 8443, "server_name": "app.example.com"}
    assert client.post(path, json=body, headers={"Authorization": ""}).status_code == 401
    response = client.post(path, json=body, headers={"Idempotency-Key": "cipher-1"})
    assert response.status_code == 202
    job = response.json()
    assert job["kind"] == "cipher_scan" and job["status"] == "queued"
    assert job["request"]["device_ip"] == "2001:db8::1"
    assert job["request"]["port"] == 8443
    assert job["result"]["data"] == {}
    assert client.post(path, json=body, headers={"Idempotency-Key": "cipher-1"}).json()["id"] == job["id"]
    assert (
        client.post(path, json={**body, "port": 9443}, headers={"Idempotency-Key": "cipher-1"}).status_code
        == 409
    )
    assert client.get(path + "/" + job["id"]).json() == job
    assert client.get(path + "/" + job["id"], headers={"Authorization": ""}).status_code == 401
    assert client.get("/api/v1/jobs/" + job["id"]).json()["kind"] == "cipher_scan"
    assert client.get("/api/v1/jobs").json()[0]["id"] == job["id"]
    assert client.get(path + "/missing").status_code == 404
    assert client.get("/api/v1/snmp/walks/" + job["id"]).status_code == 404
    assert client.post("/api/v1/jobs/" + job["id"] + "/rollback", json={}).status_code == 409
    schema = client.get("/openapi.json").json()
    assert schema["paths"][path]["post"]["security"] == [{"HTTPBearer": []}]
    assert "CipherScanRequest" in schema["components"]["schemas"]
    assert "CipherScanResult" in schema["components"]["schemas"]


@pytest.mark.parametrize(
    "bad",
    [
        {"device_ip": "example.com"},
        {"device_ip": "192.0.2.0/24"},
        {"device_ip": "192.0.2.1 --script=all"},
        {"device_ip": "fe80::1%en0"},
        {"protocol": "ftp"},
        {"port": 0},
        {"port": 65536},
        {"port": "443,22"},
        {"job_timeout": 0},
        {"job_timeout": 3601},
        {"script": "vuln"},
        {"server_name": "example.com"},
        {"protocol": "https", "server_name": "foo,tls.servername=other"},
        {"protocol": "https", "server_name": "$(touch /tmp/example)"},
    ],
)
def test_reject_invalid_or_extra_scan_input(client, bad):
    assert (
        client.post(
            "/api/v1/cipher-scans", json={"device_ip": "192.0.2.1", "protocol": "ssh", **bad}
        ).status_code
        == 422
    )


def test_defaults_and_fixed_command():
    ssh = CipherScanRequest(device_ip="192.0.2.1", protocol="ssh")
    https = CipherScanRequest(
        device_ip="2001:db8::1", protocol="https", port=9443, server_name="APP.Example.COM."
    )
    assert ssh.port == 22
    assert CipherScanRequest(device_ip="192.0.2.1", protocol="https").port == 443
    args = cipher_scan.command(https)
    assert args[args.index("-p") + 1] == "9443"
    assert args[args.index("--script") + 1] == "+ssl-enum-ciphers"
    assert args[args.index("--script-args") + 1] == "tls.servername=app.example.com"
    assert "-6" in args and args[-1] == "2001:db8::1"
    assert "--unprivileged" in args and "-sT" in args and "-Pn" in args and "-n" in args
    assert cipher_scan.command(ssh)[-1] == "192.0.2.1"
    with pytest.raises(ValidationError):
        CipherScanRequest(device_ip="192.0.2.1", protocol="https", server_name="a" * 64 + ".example")


@pytest.mark.parametrize("protocol,port", [("ssh", 22), ("https", 8443)])
def test_worker_success_and_structured_results(settings, store, client, monkeypatch, protocol, port):
    job = submit(client, protocol=protocol, port=port)
    monkeypatch.setattr(cipher_scan, "execute", lambda request, checkpoint: (xml(protocol, port), "", 0))
    process(settings, store, store.claim("worker"), "worker")
    result = client.get("/api/v1/cipher-scans/" + job["id"]).json()
    assert result["status"] == "succeeded" and not result["lock_held"]
    assert result["credential_usage"] == []
    assert result["result"]["port_state"] == "open"
    assert result["result"]["nmap_version"] == "7.95"
    data = result["result"]["data"]
    if protocol == "ssh":
        assert data["encryption_algorithms"] == ["aes256-ctr", "aes128-ctr"]
    else:
        assert data["TLSv1.2"]["ciphers"][0]["strength"] == "A"
        assert data["TLSv1.2"]["warnings"] == ["example warning"]
        assert data["least strength"] == "A"
    assert store.events(job["id"])[-1]["step"] == "cipher_scan_succeeded"


@pytest.mark.parametrize(
    "output,code,error",
    [
        (xml(state="closed"), 0, "port_not_open"),
        (xml(state="filtered"), 0, "port_not_open"),
        (xml(data="", output="ERROR: Script execution failed"), 0, "no_cipher_data"),
        (b'<nmaprun><runstats><finished exit="success"/></runstats></nmaprun>', 0, "no_port_result"),
        (b"<nmaprun>", 0, "invalid_output"),
        (xml(exit="error"), 0, "nmap_failed"),
        (xml(), 1, "nmap_failed"),
        (b'<!ENTITY bomb "bad"><nmaprun/>', 0, "invalid_output"),
    ],
)
def test_failed_scans_not_clean(settings, store, client, monkeypatch, output, code, error):
    job = submit(client)
    monkeypatch.setattr(cipher_scan, "execute", lambda request, checkpoint: (output, "diagnostic", code))
    process(settings, store, store.claim("worker"), "worker")
    result = client.get("/api/v1/cipher-scans/" + job["id"]).json()
    assert result["status"] == "failed" and not result["lock_held"]
    assert result["result"]["error_code"] == error
    assert result["result"]["stderr"] == "diagnostic"


def test_scan_locks_and_stale_worker(settings, store, client):
    first, second = submit(client), submit(client)
    claimed = store.claim("worker")
    assert claimed["id"] == first["id"]
    assert store.claim("other") is None
    with store.connect() as db:
        db.execute("UPDATE jobs SET heartbeat=0 WHERE id=?", (first["id"],))
    store.reap(1)
    job = store.get(first["id"])
    assert job["status"] == "failed" and not job["lock_held"]
    assert job["result"]["error_code"] == "worker_lost"
    with pytest.raises(LostOwnership):
        store.record(first["id"], "worker", "late")
    assert store.claim("other")["id"] == second["id"]


def test_cancellation_before_dispatch(settings, store, client, monkeypatch):
    job = submit(client)
    claimed = store.claim("worker")
    client.post("/api/v1/jobs/" + job["id"] + "/cancel")
    monkeypatch.setattr(cipher_scan, "execute", lambda *args: pytest.fail("must not dispatch"))
    process(settings, store, claimed, "worker")
    assert store.get(job["id"])["status"] == "cancelled"
    assert not store.get(job["id"])["lock_held"]
    queued = submit(client)
    assert client.post("/api/v1/jobs/" + queued["id"] + "/cancel").json()["status"] == "cancelled"


@pytest.mark.parametrize("failure", ["timeout", "output_limit", "cancel", "ownership"])
def test_child_is_terminated_on_limits_and_control(monkeypatch, failure):
    # Real OS pipes/processes exercise bounded streaming and subprocess cleanup.
    code = "import time; time.sleep(30)"
    if failure == "output_limit":
        code = f'import sys; sys.stdout.buffer.write(b"x" * {cipher_scan.MAX_OUTPUT_BYTES + 1}); sys.stdout.flush()'
    monkeypatch.setattr(cipher_scan, "command", lambda _: [sys.executable, "-c", code])
    original = subprocess.Popen
    children = []

    def spawn(*args, **kwargs):
        child = original(*args, **kwargs)
        children.append(child)
        return child

    monkeypatch.setattr(cipher_scan.subprocess, "Popen", spawn)
    calls = 0

    def checkpoint():
        nonlocal calls
        calls += 1
        if calls > 2:
            if failure == "cancel":
                raise CancelRequested()
            if failure == "ownership":
                raise LostOwnership()

    exception = {"cancel": CancelRequested, "ownership": LostOwnership}.get(failure, cipher_scan.ScanError)
    start = time.monotonic()
    with pytest.raises(exception) as error:
        cipher_scan.execute(
            CipherScanRequest(device_ip="127.0.0.1", protocol="ssh", job_timeout=1), checkpoint
        )
    if failure in ("timeout", "output_limit"):
        assert error.value.code == failure
    assert time.monotonic() - start < 5
    assert len(children) == 1 and children[0].poll() is not None


def test_missing_nmap(settings, store, client, monkeypatch):
    monkeypatch.setattr(cipher_scan, "command", lambda _: ["/does-not-exist/nmap"])
    job = submit(client)
    process(settings, store, store.claim("worker"), "worker")
    assert store.get(job["id"])["result"]["error_code"] == "nmap_unavailable"
    assert not store.get(job["id"])["lock_held"]
