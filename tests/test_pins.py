import datetime
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import paramiko
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from netops_executor.api import create_app
from netops_executor.pins import PinnedContext, PinnedHostKeys


def self_signed(tmp_path, name):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    cert_file, key_file = tmp_path / (name + ".pem"), tmp_path / (name + ".key")
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    return cert_file, key_file


def server(cert_file, key_file, hits):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.headers.get("x-pan-key"))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"<response status='success'/>")

        def log_message(self, *args):
            pass

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_file, key_file)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def test_tls_pin_trusts_first_self_signed_certificate_and_rejects_a_change(tmp_path, store):
    hits = []
    first = server(*self_signed(tmp_path, "first"), hits)
    url = f"https://127.0.0.1:{first.server_port}"
    key = f"tls:127.0.0.1:{first.server_port}"
    for _ in range(2):
        with httpx.Client(base_url=url, verify=PinnedContext(store, key), trust_env=False) as client:
            assert client.get("/api/", headers={"X-PAN-KEY": "secret"}).status_code == 200
    assert [p["key"] for p in store.pins()] == [key] and len(hits) == 2
    first.shutdown()
    second = server(*self_signed(tmp_path, "second"), hits)
    with pytest.raises(httpx.ConnectError, match="does not match its pinned fingerprint"):
        with httpx.Client(
            base_url=f"https://127.0.0.1:{second.server_port}",
            verify=PinnedContext(store, key),
            trust_env=False,
        ) as client:
            client.get("/api/", headers={"X-PAN-KEY": "secret"})
    # The handshake failed before any request, so the API key never reached the new endpoint.
    assert len(hits) == 2
    second.shutdown()


def test_ssh_host_key_pin(store):
    policy = PinnedHostKeys(store, "ssh:192.0.2.10:22")
    first, second = paramiko.RSAKey.generate(1024), paramiko.RSAKey.generate(1024)
    policy.missing_host_key(None, "192.0.2.10", first)
    policy.missing_host_key(None, "192.0.2.10", first)
    with pytest.raises(paramiko.SSHException, match="does not match its pinned key"):
        policy.missing_host_key(None, "192.0.2.10", second)


def test_pins_api_lists_and_resets(settings, store):
    store.pin("tls:192.0.2.10:443", "tls", "a" * 64)
    client = TestClient(create_app(settings), headers={"Authorization": "Bearer " + settings.token})
    assert [p["key"] for p in client.get("/api/v1/pins").json()] == ["tls:192.0.2.10:443"]
    assert client.delete("/api/v1/pins/tls:192.0.2.10:443").status_code == 204
    assert client.get("/api/v1/pins").json() == []
    assert client.delete("/api/v1/pins/tls:192.0.2.10:443").status_code == 404
