"""IM7200 Linux shell, config export and netflash over the audited SSH transport.

No version/product/signature bypass flags are passed to netflash. SCP is used because
legacy console-server releases need not provide an SFTP subsystem. An account without
UID 0 (a TACACS login) runs each command through sudo on a terminal; see opengear_sudo.
"""

import os
import re
import shlex
import time
from pathlib import Path

import paramiko
from scp import SCPClient, SCPException

from .opengear_sudo import run_as_root
from .ssh import SSH, DeviceError, digest

MODEL = re.compile(r"\b(IM72(?:08|16|32|48)(?:-[A-Za-z0-9]+)*)(?=\s|$)", re.I)
VERSION = re.compile(r"\bversion\s+(\S+)", re.I)
SCRATCH = re.compile(r"/tmp/netops-transfer\.[A-Za-z0-9]{6,}")


def parse_version(version, issue=""):
    model = MODEL.search(version + "\n" + issue)
    match = VERSION.search(version)
    value = match[1] if match else version.strip()
    if not model or not re.fullmatch(r"\d{1,2}\.\d{1,3}\.\d{1,3}(?:u\d{1,3})?", value):
        raise DeviceError(
            "cannot identify an IM7200 model and firmware version from version and model information"
        )
    return {"model": model[1].upper(), "version": value.lower()}


def version_key(version):
    parts = [int(n) for n in re.findall(r"\d+", version)]
    return tuple(parts + [0] * (4 - len(parts)))


class Opengear:
    def __init__(self, settings, device, guard, profiles, audit, ssh=None):
        self.ssh = ssh or SSH(settings, device, guard, profiles, audit)
        self._uid = None

    def sudo_password(self):
        """Use only the credential that authenticated this connection."""
        self.ssh.connect()
        selector = self.ssh.selector
        if selector.last and not selector.last.startswith("legacy:"):
            candidates = selector.vault.candidates(
                "ssh", [selector.last], (self.ssh.device.host, self.ssh.device.id)
            )
            return candidates[0].get("password") if candidates else None
        return os.environ.get(self.ssh.device.password_env or "")

    def uid(self):
        """The login account's UID: the connection's own identity, before any sudo."""
        if self._uid is None:
            identity = self.ssh.execute("id -u")
            if identity["exit_code"] != 0 or not re.fullmatch(r"\d+", identity["stdout"].strip()):
                raise DeviceError("Opengear shell identity is unavailable")
            self._uid = identity["stdout"].strip()
        return self._uid

    def elevated(self):
        return self.uid() != "0"

    def execute(self, command, timeout=120):
        if not self.elevated():
            return self.ssh.execute(command, timeout=timeout)
        # The terminal belongs to sudo's prompt; the root command never reads from it.
        response = run_as_root(
            self.ssh.connect().get_transport(),
            "exec sh -c " + shlex.quote(command) + " < /dev/null",
            self.sudo_password(),
            self.ssh.guard,
            timeout,
        )
        selector = getattr(self.ssh, "selector", None)
        if selector is not None:
            response["stdout"] = selector.redact(response["stdout"])
        return response

    def text(self, command, timeout=120):
        try:
            response = self.execute(command, timeout=timeout)
        except (EOFError, OSError, paramiko.SSHException):
            self.close()
            raise DeviceError("Opengear SSH command interrupted; device output omitted") from None
        if response["exit_code"] != 0 or response.get("stderr", "").strip():
            # Do not return config contents or raw errors containing device secrets.
            raise DeviceError("Opengear command failed; device output omitted")
        return response["stdout"].strip()

    def preflight(self):
        if self.text("id -u") != "0":
            raise DeviceError("Opengear upgrades require a root shell (UID 0)")
        self.text(
            "command -v netflash >/dev/null && command -v config >/dev/null && command -v scp >/dev/null"
        )
        self.sha256("/etc/version")

    def version(self):
        version = self.text("cat /etc/version")
        info = parse_version(
            version, self.text("config -g config.system.model") if not MODEL.search(version) else ""
        )
        mac = self.text("cat /sys/class/net/eth0/address").lower()
        boot = self.text("cat /proc/sys/kernel/random/boot_id").lower()
        if not re.fullmatch(r"(?:[a-f0-9]{2}:){5}[a-f0-9]{2}", mac) or mac == "00:00:00:00:00:00":
            raise DeviceError("cannot establish device identity from eth0 MAC address")
        if not re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", boot):
            raise DeviceError("cannot establish boot identity")
        return {**info, "mac": mac, "boot_id": boot}

    def snapshot(self):
        config = self.sha256("/etc/config/config.xml")
        output = self.text(
            'for n in /sys/class/net/eth*; do [ -e "$n/address" ] || continue; '
            'printf "%s " "${n##*/}"; cat "$n/operstate" || exit 1; done'
        )
        interfaces = {}
        for line in output.splitlines():
            parts = line.split()
            if len(parts) != 2 or not re.fullmatch(r"eth[0-9]+", parts[0]):
                raise DeviceError("cannot parse Ethernet interface state")
            interfaces[parts[0]] = parts[1]
        if "eth0" not in interfaces:
            raise DeviceError("Ethernet interface state is unavailable")
        return {"config_sha256": config, "interfaces": interfaces}

    def prepare(self, base):
        directory = base + "/netops-executor"
        q = shlex.quote(directory)
        self.text(
            "test -d "
            + shlex.quote(base)
            + " && test ! -L "
            + q
            + " && (umask 077; mkdir -p "
            + q
            + ") && test -d "
            + q
            + " && test -O "
            + q
            + " && chmod 700 "
            + q
        )
        return directory

    def free_bytes(self, directory):
        output = self.text("df -k " + shlex.quote(directory))
        lines = output.splitlines()
        try:
            value = int(lines[-1].split()[3]) * 1024
            if len(lines) < 2 or value < 0:
                raise ValueError()
            return value
        except (ValueError, IndexError):
            raise DeviceError("cannot determine free firmware staging space") from None

    def sha256(self, path):
        quoted = shlex.quote(path)
        output = self.text(
            "if command -v sha256sum >/dev/null; then sha256sum "
            + quoted
            + "; else openssl dgst -sha256 "
            + quoted
            + "; fi",
            timeout=300,
        )
        match = re.fullmatch(r"([a-fA-F0-9]{64})\s+\*?" + re.escape(path), output)
        if not match:
            match = re.fullmatch(r"SHA(?:2-)?256\(" + re.escape(path) + r"\)= ([a-fA-F0-9]{64})", output)
        if not match:
            raise DeviceError("device SHA-256 checksum was unavailable")
        return match[1].lower()

    def staged(self, path):
        q = shlex.quote(path)
        return (
            self.text("if [ -f " + q + " ] && [ ! -L " + q + " ]; then echo yes; else echo no; fi") == "yes"
        )

    def scp(self, local, remote, timeout, progress, download=False):
        """Copy one file as the login account."""
        deadline = time.monotonic() + timeout

        def updated(filename, size, done):
            self.ssh.guard()
            if time.monotonic() >= deadline:
                raise DeviceError("Opengear file transfer timed out")
            progress(done, size)

        try:
            with SCPClient(self.ssh.connect().get_transport(), socket_timeout=30, progress=updated) as scp:
                if download:
                    scp.get(remote, str(local))
                else:
                    scp.put(str(local), remote_path=remote)
        except (SCPException, OSError, paramiko.SSHException):
            raise DeviceError("Opengear SCP transfer failed; device output omitted") from None

    def scratch(self):
        """A private directory the login account owns, for files root moves in or out."""
        response = self.ssh.execute("umask 077; mktemp -d /tmp/netops-transfer.XXXXXX")
        path = response["stdout"].strip()
        if response["exit_code"] != 0 or not SCRATCH.fullmatch(path):
            raise DeviceError("cannot create a private /tmp transfer directory for the login account")
        return path

    def discard(self, scratch):
        if SCRATCH.fullmatch(scratch):
            try:
                self.ssh.execute("rm -rf " + shlex.quote(scratch))
            except DeviceError:
                pass

    def transfer(self, local, remote, timeout, progress, download=False):
        if not self.elevated():
            self.scp(local, remote, timeout, progress, download)
            return
        # SCP cannot pass through sudo's terminal. The login account copies files through its own
        # private /tmp directory, and root moves them to and from the root-only staging directory.
        scratch = self.scratch()
        staged = scratch + ("/download" if download else "/upload")
        q, s = shlex.quote(remote), shlex.quote(staged)
        try:
            if download:
                self.text(
                    f"test -f {q} && test ! -L {q} && test ! -e {s} && test ! -L {s}"
                    f" && cp {q} {s} && chown {self.uid()} {s} && chmod 600 {s}",
                    timeout=300,
                )
                self.scp(local, staged, timeout, progress, download=True)
            else:
                if self.free_bytes("/tmp") < Path(local).stat().st_size:
                    raise DeviceError("insufficient /tmp space to transfer the image through sudo")
                self.scp(local, staged, timeout, progress)
                self.text(
                    f"test -f {s} && test ! -L {s} && test ! -e {q} && mv -f {s} {q}"
                    f" && test -f {q} && test ! -L {q} && chown 0:0 {q} && chmod 600 {q}",
                    timeout=300,
                )
        finally:
            self.discard(scratch)

    def upload(self, local, remote, timeout, progress, job_id):
        partial = remote + "." + job_id + ".partial"
        # Directory is root-owned and private; refuse pre-existing staging symlinks.
        self.text("test ! -e " + shlex.quote(partial) + " && test ! -L " + shlex.quote(partial))
        self.transfer(local, partial, timeout, progress)
        if self.sha256(partial) != digest(local):
            raise DeviceError("uploaded image SHA-256 mismatch")
        self.text(
            "chmod 600 "
            + shlex.quote(partial)
            + " && mv -f "
            + shlex.quote(partial)
            + " "
            + shlex.quote(remote)
        )

    def backup(self, remote, local, timeout, progress):
        q = shlex.quote(remote)
        self.text(
            "test ! -e " + q + " && test ! -L " + q + " && (umask 077; config -e " + q + ")", timeout=300
        )
        expected = self.sha256(remote)
        partial = Path(str(local) + ".partial")
        fd = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        try:
            self.transfer(partial, remote, timeout, progress, download=True)
            os.chmod(partial, 0o600)
            if not partial.stat().st_size or digest(partial) != expected:
                raise DeviceError("downloaded configuration backup is empty or has a SHA-256 mismatch")
            with partial.open("rb") as stream:
                os.fsync(stream.fileno())
            os.replace(partial, local)
        finally:
            partial.unlink(missing_ok=True)
        self.text("rm -f " + q)

    def install_reload(self, path, timeout):
        # netflash performs its native image checks, writes firmware and reboots.
        # A disconnect is ambiguous; the runner verifies a new boot and never retries this write.
        try:
            return self.execute("netflash " + shlex.quote(path), timeout=timeout)["exit_code"]
        except (EOFError, OSError, paramiko.SSHException):
            self.close()
            raise DeviceError("Opengear flash connection interrupted; outcome unknown") from None

    def close(self):
        self.ssh.close()
        # A reconnect may authenticate as another account (local root after a TACACS outage).
        self._uid = None
