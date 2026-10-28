"""Real Nmap against loopback services; CI installs Nmap to require these checks."""

import datetime
import shutil
import socket
import ssl
import threading
from contextlib import contextmanager

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from test_ssh_wire import ssh_server

from netops_executor.cipher_models import CipherScanRequest
from netops_executor.cipher_scan import CipherScanRunner

pytestmark = pytest.mark.skipif(shutil.which("nmap") is None, reason="Nmap is not installed")


@contextmanager
def tls_server(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "scan.example.test")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    (tmp_path / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "key.pem").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers("ECDHE-RSA-AES256-GCM-SHA384")
    context.load_cert_chain(tmp_path / "cert.pem", tmp_path / "key.pem")
    server_names = []
    context.set_servername_callback(lambda sock, name, ctx: server_names.append(name))
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(128)
    listener.settimeout(0.1)
    stop = threading.Event()
    threads = []

    def connection(client):
        try:
            client.settimeout(2)
            with context.wrap_socket(client, server_side=True):
                pass
        except (OSError, ssl.SSLError):
            client.close()

    def listen():
        while not stop.is_set():
            try:
                client, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            thread = threading.Thread(target=connection, args=(client,), daemon=True)
            threads.append(thread)
            thread.start()

    thread = threading.Thread(target=listen, daemon=True)
    thread.start()
    try:
        yield listener.getsockname()[1], server_names
    finally:
        stop.set()
        listener.close()
        thread.join(timeout=3)
        for child in threads:
            child.join(timeout=3)


def scan(settings, store, protocol, port, **kwargs):
    request = CipherScanRequest(device_ip="127.0.0.1", protocol=protocol, port=port, job_timeout=45, **kwargs)
    job = store.submit(request.model_dump(mode="json"), f"cipher:127.0.0.1:{port}", kind="cipher_scan")
    CipherScanRunner(settings, store, store.claim("wire"), "wire").run()
    return store.get(job["id"])


def test_nmap_ssh_on_nonstandard_port(settings, store):
    with ssh_server() as (port, key, state):
        job = scan(settings, store, "ssh", port)
    assert job["status"] == "succeeded", job["result"]
    assert job["result"]["port_state"] == "open"
    assert "aes128-ctr" in job["result"]["data"]["encryption_algorithms"]
    assert state["attempts"] == []  # Cipher enumeration never authenticates.
    assert not job["lock_held"]


def test_nmap_https_on_nonstandard_port_and_sni(settings, store, tmp_path):
    with tls_server(tmp_path) as (port, server_names):
        job = scan(settings, store, "https", port, server_name="scan.example.test")
    assert job["status"] == "succeeded", job["result"]
    assert job["result"]["data"]["TLSv1.2"]["ciphers"][0]["name"] == "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
    assert "scan.example.test" in server_names
    assert not job["lock_held"]
