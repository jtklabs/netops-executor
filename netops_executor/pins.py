"""Trust on first use for device TLS certificates and SSH host keys, shared by every worker.

Devices commonly present self-signed certificates. The first certificate or host key seen
for an endpoint is pinned in the job store; afterwards only that one is accepted. TLS pins
are checked during the handshake, before any request bytes or credentials are sent.
"""

import hashlib
import ssl
from urllib.parse import urlsplit

import paramiko


class PinnedContext(ssl.SSLContext):
    """Client TLS context that accepts an endpoint's first certificate, then only that one."""

    def __new__(cls, store, key):
        return super().__new__(cls, ssl.PROTOCOL_TLS_CLIENT)

    def __init__(self, store, key):
        self.check_hostname = False
        self.verify_mode = ssl.CERT_NONE
        self.minimum_version = ssl.TLSVersion.TLSv1_2
        self.pin_store, self.pin_key = store, key

    def wrap_socket(self, *args, **kwargs):
        sock = super().wrap_socket(*args, **kwargs)
        der = sock.getpeercert(binary_form=True)
        if not der or not self.pin_store.pin(self.pin_key, "tls", hashlib.sha256(der).hexdigest()):
            sock.close()
            raise ssl.SSLError(
                "certificate for "
                + self.pin_key
                + " does not match its pinned fingerprint; inspect, then reset the pin"
            )
        return sock


def tls_key(base_url):
    parsed = urlsplit(base_url)
    return "tls:" + (parsed.hostname or "") + ":" + str(parsed.port or 443)


class PinnedHostKeys(paramiko.MissingHostKeyPolicy):
    """SSH host keys missing from known_hosts are pinned on first use; a changed key is rejected."""

    def __init__(self, store, key):
        self.store, self.key = store, key

    def missing_host_key(self, client, hostname, key):
        fingerprint = key.get_name() + ":" + hashlib.sha256(key.asbytes()).hexdigest()
        if not self.store.pin(self.key, "ssh", fingerprint):
            raise paramiko.SSHException("SSH host key for " + self.key + " does not match its pinned key")
