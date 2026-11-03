"""Native local-account operations. Raw account records and commands never enter job output."""

import re
import shlex
import time

import paramiko
from passlib.hash import md5_crypt, sha256_crypt, sha512_crypt

from .device import blocks, field
from .network_ssh import CLI_ERROR, NetworkSSH
from .pins import PinnedHostKeys
from .platforms import NETWORK_TYPES
from .ssh import SSH, DeviceError
from .store import Store

ERROR = re.compile(
    r"(?im)^\s*(?:%.*(?:error|invalid|cannot|failed|denied)|Command fail|Unknown action|command parse error|.*password.*(?:invalid|rejected|requirements|too short))"
)
IOS_PASSWORD = re.compile(r"[A-Za-z0-9!@#$%^&*()_+=.,:/~-]{1,128}")


class PasswordRejected(DeviceError):
    """Do not repeat a known-bad authentication and trigger an account lockout."""


def check_password_syntax(platform, password):
    # IOS uses a terminal command argument, with '?' invoking context-sensitive help.
    if platform == "cisco_ios" and not IOS_PASSWORD.fullmatch(password):
        raise ValueError(
            "Cisco IOS passwords require 1–128 supported ASCII token characters; whitespace, quotes, backslash, question mark, pipe and semicolon are unsupported"
        )


def quote(value):
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def crypt_matches(password, encoded):
    for algorithm, prefix in ((sha512_crypt, "$6$"), (sha256_crypt, "$5$"), (md5_crypt, "$1$")):
        if encoded.startswith(prefix):
            rounds = re.search(r"\$rounds=(\d+)\$", encoded)
            if rounds and int(rounds[1]) > 1_000_000:
                raise DeviceError("local password hash verification exceeds work limit")
            try:
                return algorithm.verify(password, encoded)
            except (ValueError, TypeError):
                break
    raise DeviceError("local password hash cannot be verified; use SSH login verification")


def password_prompt(ssh, command, password, timeout):
    """Fixed password/confirmation dialogue with a PTY; no prompt/output is persisted."""
    channel = ssh.connect().get_transport().open_session(timeout=15)
    deadline, answers, tail = time.monotonic() + timeout, 0, ""
    try:
        channel.get_pty()
        channel.exec_command(command)
        while True:
            ssh.guard()
            if time.monotonic() >= deadline:
                raise DeviceError("password prompt timed out; outcome unknown")
            if channel.recv_ready():
                tail += channel.recv(8192).decode(errors="replace")
                if len(tail) > 65536:
                    raise DeviceError("password prompt output exceeded limit")
                if re.search(r"(?i)(?:password|confirm)[^\r\n:]{0,80}:\s*$", tail):
                    if answers >= 2:
                        raise DeviceError(
                            "device repeated the password prompt; password may have been rejected"
                        )
                    channel.sendall((password + "\n").encode())
                    answers += 1
                    tail = ""
            if channel.exit_status_ready() and not channel.recv_ready():
                if channel.recv_exit_status() != 0 or not answers or ERROR.search(tail):
                    raise DeviceError("device did not acknowledge password change")
                return
            time.sleep(0.05)
    finally:
        channel.close()


def verify_login(settings, device, username, password, guard):
    """One fresh password-only authentication. Never try fallback credentials for verification."""
    guard()
    client = paramiko.SSHClient()
    pin = settings.ssh_host_keys == "pin"
    if not pin or settings.known_hosts.is_file():
        client.load_host_keys(str(settings.known_hosts))
    client.set_missing_host_key_policy(
        PinnedHostKeys(Store(settings.data_dir / "jobs.sqlite3"), f"ssh:{device.host}:{device.port}")
        if pin
        else paramiko.RejectPolicy()
    )
    try:
        client.connect(
            hostname=device.host,
            port=device.port,
            username=username,
            password=password,
            look_for_keys=False,
            allow_agent=False,
            timeout=10,
            auth_timeout=10,
            banner_timeout=10,
        )
        guard()
    except paramiko.AuthenticationException:
        raise PasswordRejected(
            "new-account SSH authentication was rejected; no automatic authentication retry"
        ) from None
    except (paramiko.SSHException, OSError):
        raise DeviceError(
            "new-account SSH authentication failed; check local AAA selection, SSH access and password policy"
        ) from None
    finally:
        client.close()


def network_account(output, username):
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if any(not line.startswith("username ") for line in lines):
        raise DeviceError("unrecognized local username configuration")
    selected = [line for line in lines if line.split()[1] == username]
    # Several NX-OS/EOS username lines can carry roles and SSH keys for the same account.
    return selected or None


def forti_accounts(output):
    records, current, opened, closed = {}, None, False, False
    for line in output.splitlines():
        try:
            words = shlex.split(line.strip())
        except ValueError:
            raise DeviceError("unrecognized FortiGate administrator configuration") from None
        if not words:
            continue
        if words == ["config", "system", "admin"] and not opened:
            opened = True
        elif words[0] == "edit" and len(words) == 2 and current is None and opened and not closed:
            current = words[1]
            if current in records:
                raise DeviceError("duplicate FortiGate account")
            records[current] = {}
        elif words[0] == "set" and len(words) >= 3 and current:
            records[current][words[1]] = words[2:]
        elif words == ["next"] and current:
            current = None
        elif words == ["end"] and opened and current is None:
            closed = True
        else:
            raise DeviceError("unrecognized FortiGate administrator configuration")
    if not opened or not closed or current:
        raise DeviceError("incomplete FortiGate administrator configuration")
    return records


class AccountDevice:
    def __init__(self, settings, device, request, password, guard, audit, ssh=None):
        self.settings, self.device, self.request = settings, device, request
        self.platform, self.password = request.device_type, password
        self.guard = guard
        self.ssh = ssh or (
            NetworkSSH(settings, device, guard, request.credential_profiles, audit, device_type=self.platform)
            if self.platform in NETWORK_TYPES
            else SSH(settings, device, guard, request.credential_profiles, audit)
        )
        self.ssh.selector.secrets.add(password)
        self.before = None
        self.vdoms = False
        self.index = self.total = None

    def shell(self, command, stdin=None):
        result = self.ssh.execute(command, timeout=self.request.command_timeout, stdin_text=stdin)
        if result["exit_code"] != 0:
            raise DeviceError("account command rejected; device output omitted")
        return result["stdout"].strip()

    def cli(self, command, config=False):
        result = self.ssh.execute(
            command, timeout=self.request.command_timeout, mode="config" if config else "exec", enable=True
        )
        if result["cli_error"] or CLI_ERROR.search(result["stdout"]) or ERROR.search(result["stdout"]):
            raise DeviceError("account command rejected; device output omitted")
        return result["stdout"]

    def tmsh(self, command):
        return self.ssh.tmsh(command, timeout=self.request.command_timeout, secret=True)

    def forti(self, command):
        if self.vdoms:
            self.cli("config global")
        try:
            return self.cli(command)
        finally:
            if self.vdoms:
                self.cli("end")

    def preflight(self):
        p = self.platform
        if p in ("linux", "opengear") and self.shell("id -u") != "0":
            raise DeviceError("local account management requires a root shell")
        if p == "linux":
            self.shell(
                "command -v useradd >/dev/null && command -v chpasswd >/dev/null && command -v getent >/dev/null"
            )
        elif p == "opengear":
            version = self.shell("cat /etc/version")
            if not re.search(r"OpenGear/(?:IM72|CM71|ACM7)", version, re.I):
                raise DeviceError("Opengear account management requires a legacy IM/CM/ACM config CLI device")
            self.shell("command -v config >/dev/null")
        elif p == "fortinet":
            output = self.cli("get system status")
            match = re.search(r"(?im)^Virtual domain configuration:\s*(.+)$", output)
            if not match:
                raise DeviceError("FortiGate VDOM mode could not be determined")
            self.vdoms = "disable" not in match[1].lower()
        self.before = self.read()
        if self.before is None:
            if not self.request.create_if_missing:
                raise DeviceError("local account is missing and create_if_missing is false")
            if self.request.new_account is None:
                raise DeviceError(
                    "local account is missing; new_account must explicitly specify its privileges"
                )
            if self.request.username == "root" and p in ("linux", "opengear", "f5"):
                raise DeviceError("missing built-in root account cannot be created by this job")
            if p in ("linux", "opengear"):
                groups = {line.split(":", 1)[0] for line in self.shell("cat /etc/group").splitlines()}
                if not set(self.request.new_account.groups or []) <= groups:
                    raise DeviceError("a requested account group does not exist")
            if p == "linux":
                result = self.ssh.execute("getent passwd " + self.request.username, timeout=30)
                if result["exit_code"] != 2:
                    raise DeviceError("username resolves outside the local passwd file or NSS lookup failed")
        if p == "cisco_ios" and self.before and any(" password " in line for line in self.before):
            raise DeviceError(
                "IOS account uses password instead of secret; migrate it explicitly before rotation"
            )
        if p == "fortinet" and self.before:
            if self.before.get("remote-auth", ["disable"]) != ["disable"] or self.before.get(
                "wildcard", ["disable"]
            ) != ["disable"]:
                raise DeviceError(
                    "remote or wildcard FortiGate administrators cannot be rotated as local accounts"
                )
        return self.before is not None

    def read(self):
        p, user = self.platform, self.request.username
        if p == "linux" or (p == "f5" and user == "root"):
            lines = self.shell("cat /etc/passwd").splitlines()
            if not lines or any(len(line.split(":")) != 7 for line in lines):
                raise DeviceError("local passwd file is unreadable")
            matches = [line for line in lines if line.split(":")[0] == user]
            if len(matches) > 1:
                raise DeviceError("duplicate local username")
            return matches[0] if matches else None
        if p == "f5":
            users = blocks(
                self.ssh.tmsh("list /auth user", timeout=self.request.command_timeout), "auth user"
            )
            return users.get(user, users.get("/Common/" + user))
        if p == "opengear":
            text = self.shell("config -g config.users")
            values = {}
            for line in text.splitlines():
                key, _, value = line.partition(" ")
                if not re.fullmatch(r"config\.users(?:\.[A-Za-z0-9_.-]+)?", key):
                    raise DeviceError("unrecognized Opengear user configuration")
                if key in values:
                    raise DeviceError("duplicate Opengear user field")
                values[key] = value.strip()
            total = values.get("config.users.total")
            if total is None or (total and not total.isdigit()):
                raise DeviceError("Opengear user count is unavailable")
            self.total = int(total or "0")
            if self.total > 4096:
                raise DeviceError("Opengear user count exceeds limit")
            indices = [
                int(m[1])
                for key, value in values.items()
                if (m := re.fullmatch(r"config\.users\.user(\d+)\.username", key)) and value == user
            ]
            if len(indices) > 1:
                raise DeviceError("duplicate Opengear username")
            self.index = indices[0] if indices else self.total + 1
            if not indices and any(key.startswith(f"config.users.user{self.index}.") for key in values):
                raise DeviceError("Opengear next account slot is already occupied")
            prefix = f"config.users.user{self.index}."
            return (
                {key[len(prefix) :]: value for key, value in values.items() if key.startswith(prefix)}
                if indices
                else None
            )
        if p == "fortinet":
            return forti_accounts(self.forti("show system admin")).get(user)
        return network_account(self.cli("show running-config | include ^username"), user)

    def apply(self):
        p, user, password, new = self.platform, self.request.username, self.password, self.request.new_account
        if self.read() != self.before:
            raise DeviceError("account changed since precheck; submit a new job")
        if p == "linux":
            if self.before is None:
                command = "useradd -m -s " + (new.shell or "/bin/bash")
                if new.groups:
                    command += " -G " + ",".join(new.groups)
                self.shell(command + " " + user)
            self.shell("chpasswd", user + ":" + password + "\n")
        elif p == "f5":
            if user == "root":
                password_prompt(
                    self.ssh, "tmsh modify /auth password root", password, self.request.command_timeout
                )
            else:
                command = ("modify" if self.before is not None else "create") + " /auth user " + user
                command += " password " + quote(password)
                if self.before is None:
                    command += (
                        " partition-access add { "
                        + new.partition
                        + " { role "
                        + new.role
                        + " } } shell "
                        + (new.shell or "tmsh")
                    )
                self.tmsh(command)
        elif p == "opengear":
            prefix = f"config.users.user{self.index}"
            if self.before is None:
                self.shell(f"config -s config.users.total={self.total + 1}")
                self.shell("config -s " + prefix + ".username=" + user)
                for index, group in enumerate(new.groups, 1):
                    self.shell("config -s " + prefix + f".groups.group{index}=" + group)
            password_prompt(
                self.ssh, "config -P " + prefix + ".password", password, self.request.command_timeout
            )
            self.shell("config -a")
        elif p == "fortinet":
            if self.vdoms:
                self.cli("config global")
            for command in ("config system admin", "edit " + quote(user)):
                self.cli(command, config=True)
            if self.before is None:
                self.cli("set accprofile " + quote(new.role), config=True)
                self.cli("set vdom " + quote(new.vdom), config=True)
            self.cli("set password " + quote(password), config=True)
            self.cli("next", config=True)
            self.cli("end", config=True)
            if self.vdoms:
                self.cli("end")
        else:
            command = "username " + user
            if p == "cisco_ios":
                if self.before is None:
                    command += " privilege " + str(new.privilege)
                algorithm = self.request.ios_algorithm
                command += (
                    (" algorithm-type " + algorithm if algorithm != "legacy" else "") + " secret " + password
                )
            else:
                # Native encrypted input avoids terminal metacharacters in EOS/NX-OS passwords.
                algorithm = sha512_crypt if p == "arista_eos" else sha256_crypt
                hashed = algorithm.using(rounds=5000).hash(password)
                self.ssh.selector.secrets.add(hashed)
                if self.before is None and p == "arista_eos":
                    if new.privilege is not None:
                        command += " privilege " + str(new.privilege)
                    command += " role " + new.role
                command += (" secret sha512 " if p == "arista_eos" else " password 5 ") + hashed
                if self.before is None and p == "cisco_nxos":
                    command += " role " + new.role
            self.cli(command, config=True)
        after = self.read()
        if after is None:
            raise DeviceError("account is not present after write")
        if self.before is not None and self.access(self.before) != self.access(after):
            raise DeviceError("account privileges changed unexpectedly; inspect before recovery")

    def access(self, record):
        """Compare access settings without retaining password/hash values in a report."""
        if self.platform == "linux" or (self.platform == "f5" and self.request.username == "root"):
            return record.split(":")[2:]
        if self.platform == "f5":
            tokens = list(record)
            start = tokens.index("partition-access") if "partition-access" in tokens else -1
            partition, depth = [], 0
            if start >= 0:
                for token in tokens[start + 1 :]:
                    partition.append(token)
                    depth += (token == "{") - (token == "}")
                    if depth == 0:
                        break
            return field(record, "shell"), partition
        if self.platform == "opengear":
            return {k: v for k, v in record.items() if k.startswith(("groups.", "port")) or k == "username"}
        if self.platform == "fortinet":
            return {
                k: v
                for k, v in record.items()
                if k in ("accprofile", "vdom", "remote-auth", "wildcard")
                or k.startswith(("trusthost", "ip6-trusthost"))
            }
        return sorted(
            (m[1], m[2])
            for line in record
            for m in re.finditer(r"\b(role|privilege) ([A-Za-z0-9_.-]+)", line)
        )

    def save(self):
        if self.platform == "f5":
            self.ssh.tmsh("save /sys config", timeout=self.request.command_timeout)
        elif self.platform in ("cisco_ios", "cisco_nxos", "arista_eos"):
            self.cli(
                "copy running-config startup-config" if self.platform == "cisco_nxos" else "write memory"
            )
            running = self.read()
            startup = network_account(
                self.cli("show startup-config | include ^username"), self.request.username
            )
            if running is None or sorted(running) != sorted(startup or []):
                raise DeviceError("account running and startup configuration do not match after save")

    def verify(self):
        if self.request.verification == "ssh_login":
            verify_login(self.settings, self.device, self.request.username, self.password, self.guard)
            return
        if self.platform == "f5" and self.request.username != "root":
            account = self.read()
            encoded = field(account, "encrypted-password") if account is not None else ""
            matched = crypt_matches(self.password, encoded or "")
        elif self.platform == "opengear":
            account = self.read()
            matched = crypt_matches(self.password, (account or {}).get("password", ""))
        else:
            # Linux's own crypt implementation supports its configured hash (including yescrypt).
            # Only a boolean exit status returns; the password goes on stdin, never argv.
            script = (
                "import crypt,hmac,spwd,sys; "
                "p=sys.stdin.readline().rstrip('\\n'); "
                "h=spwd.getspnam(sys.argv[1]).sp_pwdp; "
                "sys.exit(0 if hmac.compare_digest(crypt.crypt(p,h) or '',h) else 1)"
            )
            self.shell(
                "python3 -c " + shlex.quote(script) + " " + self.request.username, self.password + "\n"
            )
            matched = True
        if not matched:
            raise DeviceError("local password hash does not match the requested password")

    def close(self):
        self.ssh.close()
