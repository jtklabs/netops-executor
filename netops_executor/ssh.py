import hashlib
import io
import os
import re
import shlex
import time
from pathlib import Path

import paramiko

from .credentials import AuthenticationRejected, Selector, Vault
from .store import Store


class DeviceError(Exception):
    """Deliberately excludes remote output and credentials from public errors."""


class SSH:
    def __init__(self, settings, device, guard=lambda: None, credential_profiles=None, audit=None):
        self.settings, self.device, self.guard = settings, device, guard
        self.client = None
        self.enable_password = None
        self.transfer_guard = guard
        self.progress = lambda done, total: None
        self.selector = Selector(
            Vault(Store(settings.data_dir / "jobs.sqlite3"), settings.credential_key_file),
            "ssh",
            device.host,
            credential_profiles if credential_profiles is not None else device.credential_profiles,
            audit,
        )

    def connect(self):
        self.guard()
        if self.client and self.client.get_transport() and self.client.get_transport().is_active():
            return self.client
        self.close()
        client = paramiko.SSHClient()
        client.load_host_keys(str(self.settings.known_hosts))
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        d = self.device
        base = dict(
            hostname=d.host,
            port=d.port,
            look_for_keys=False,
            allow_agent=False,
            timeout=15,
            auth_timeout=15,
            banner_timeout=15,
        )

        def authenticate(c):
            self.enable_password = c.get("enable_password")
            pkey = None
            if c.get("private_key"):
                for keytype in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
                    try:
                        pkey = keytype.from_private_key(
                            io.StringIO(c["private_key"]), password=c.get("passphrase")
                        )
                        break
                    except (paramiko.SSHException, ValueError):
                        pass
                if pkey is None:
                    raise DeviceError("SSH private key could not be loaded")
            try:
                client.connect(**base, username=c["username"], password=c.get("password"), pkey=pkey)
            except (paramiko.BadAuthenticationType, paramiko.ssh_exception.PartialAuthentication):
                client.close()
                raise DeviceError(
                    "SSH authentication method is not supported or requires another factor"
                ) from None
            except paramiko.AuthenticationException:
                client.close()
                raise AuthenticationRejected() from None
            return client

        try:
            has_profiles = self.selector.names is not None or any(
                c["kind"] == "ssh" for c in self.selector.vault.list()
            )
            if has_profiles:
                self.selector.run(authenticate, aliases=(d.id,))
            else:
                self.selector.secrets.update(
                    value
                    for value in (
                        os.environ.get(d.password_env or ""),
                        os.environ.get(d.key_passphrase_env or ""),
                    )
                    if value
                )
                client.connect(
                    **base,
                    username=d.username,
                    key_filename=d.key_file,
                    password=os.environ.get(d.password_env) if d.password_env else None,
                    passphrase=os.environ.get(d.key_passphrase_env) if d.key_passphrase_env else None,
                )
                self.selector.last = "legacy:" + d.id
                self.selector.audit(
                    {
                        "profile": self.selector.last,
                        "revision": 0,
                        "transport": "ssh",
                        "target": d.host,
                        "outcome": "authenticated",
                        "source": "environment",
                    }
                )
        except Exception as exc:
            client.close()
            if isinstance(exc, DeviceError):
                raise
            raise DeviceError("SSH authentication or connection failed; see credential attempts") from None
        self.client = client
        return client

    def close(self):
        if self.client:
            self.client.close()
        self.client = None

    def execute(self, command, timeout=120, stdin_text=None):
        self.guard()
        channel = self.connect().get_transport().open_session(timeout=15)
        channel.settimeout(15)
        output, errors = bytearray(), bytearray()
        deadline = time.monotonic() + timeout
        try:
            channel.exec_command(command)
            if stdin_text is not None:
                channel.sendall(stdin_text.encode())
            channel.shutdown_write()
            while True:
                self.guard()
                if channel.recv_ready():
                    output.extend(channel.recv(65536))
                if channel.recv_stderr_ready():
                    errors.extend(channel.recv_stderr(65536))
                if len(output) + len(errors) > 32 * 1024 * 1024:
                    raise DeviceError("SSH command output exceeds limit")
                if (
                    channel.exit_status_ready()
                    and not channel.recv_ready()
                    and not channel.recv_stderr_ready()
                ):
                    break
                if time.monotonic() >= deadline:
                    raise DeviceError("SSH command timed out; outcome may be unknown")
                time.sleep(0.05)
            code = channel.recv_exit_status()
            value = output.decode("utf-8", errors="replace")
            return {
                "exit_code": code,
                "stdout": self.selector.redact(value),
                "stderr": self.selector.redact(errors.decode("utf-8", errors="replace")),
            }
        except (EOFError, OSError, paramiko.SSHException):
            self.close()
            raise DeviceError("SSH command interrupted; outcome may be unknown") from None
        finally:
            channel.close()

    def shell(self, command, timeout=120, stdin_text=None):
        result = self.execute(command, timeout, stdin_text)
        if (
            result["exit_code"] != 0
            or result["stderr"]
            or re.search(r"(?im)^.*(?:syntax error|\berror:|\bfailed\b)", result["stdout"])
        ):
            raise DeviceError("SSH command failed; remote output withheld")
        return result["stdout"]

    def tmsh(self, command, timeout=120, secret=False):
        if secret:
            # Keep the UCS passphrase off process argument lists and never persist the command/output.
            return self.shell("tmsh -q", timeout, command + "\nquit\n")
        return self.shell("tmsh -q -c " + shlex.quote(command), timeout)

    def put(self, local, remote):
        self.guard()
        with self.connect().open_sftp() as sftp:
            sftp.get_channel().settimeout(60)
            deadline = time.monotonic() + 7200

            def progress(done, total):
                self.transfer_guard()
                self.progress(done, total)
                if time.monotonic() > deadline:
                    raise DeviceError("image transfer timed out")

            sftp.put(str(local), remote, callback=progress, confirm=True)

    def get(self, remote, local):
        self.guard()
        temporary = Path(str(local) + ".partial")
        try:
            with self.connect().open_sftp() as sftp:
                sftp.get_channel().settimeout(60)
                size = sftp.stat(remote).st_size
                if size <= 0:
                    raise DeviceError("empty UCS archive")
                deadline = time.monotonic() + 3600
                with temporary.open("xb") as stream:
                    os.chmod(temporary, 0o600)

                    def progress(done, total):
                        self.transfer_guard()
                        self.progress(done, total)
                        if time.monotonic() > deadline:
                            raise DeviceError("UCS download timed out")

                    sftp.getfo(remote, stream, callback=progress)
                    stream.flush()
                    os.fsync(stream.fileno())
                if temporary.stat().st_size != size:
                    raise DeviceError("UCS size mismatch")
                if digest(temporary) != self.remote_digest(remote):
                    raise DeviceError("UCS SHA-256 mismatch")
                temporary.replace(local)
        finally:
            temporary.unlink(missing_ok=True)

    def remote_digest(self, remote):
        output = self.shell("sha256sum -- " + shlex.quote(remote), timeout=1800)
        if not re.fullmatch(r"[0-9a-f]{64}", output.split()[0] if output.split() else ""):
            raise DeviceError("unrecognized remote checksum")
        return output.split()[0]


def digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()
