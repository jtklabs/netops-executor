"""Rotation through sudo for TACACS logins (Linux, Opengear), on a real pseudo-terminal.

A stand-in `sudo` prompts and checks the login password the way a PAM/TACACS stack does,
then runs the root script, so the terminal modes, the secret line and prompt replies are
exercised for real; only the privilege change itself is simulated.
"""

import os
import select
import shlex
import subprocess
from types import SimpleNamespace

import pytest

from netops_executor.opengear_sudo import root_shell
from netops_executor.password_devices import AccountDevice, ChangeNotAccepted
from netops_executor.password_models import PasswordRotationOptions
from netops_executor.ssh import DeviceError

LOGIN = "tacacs-secret"
NEW = "N3w p@ss'word\"$(x)`;|\\"

FAKE_SUDO = """#!/bin/sh
# sudo -p PROMPT -- sh -c SCRIPT
prompt="$2"; shift 3
printf '%s' "$prompt"
stty -echo; IFS= read -r pw; stty echo; printf '\\n'
[ "$pw" = "{login}" ] || {{ echo "Sorry, try again."; exit 1; }}
# Stand in for the privilege change itself (the UID check), and put the test's stand-in
# tools ahead of the root PATH the script sets.
exec "$1" "$2" "$(printf '%s' "$3" | sed -e 's|test "$(id -u)" = 0|true|' -e "s|PATH=/bin:|PATH=$NETOPS_TOOLS:/bin:|")"
"""


class PtyChannel:
    """The subset of a paramiko channel run_as_root uses, backed by a local terminal."""

    def __init__(self, path):
        self.path, self.proc, self.master, self.done = path, None, None, False

    def settimeout(self, value):
        pass

    def get_pty(self, **kwargs):
        self.master, self.slave = os.openpty()

    def exec_command(self, command):
        env = {**os.environ, "PATH": self.path + ":" + os.environ["PATH"], "NETOPS_TOOLS": self.path}
        self.proc = subprocess.Popen(
            ["sh", "-c", command],
            stdin=self.slave,
            stdout=self.slave,
            stderr=self.slave,
            env=env,
            start_new_session=True,
        )
        os.close(self.slave)

    def recv_ready(self):
        return not self.done and bool(select.select([self.master], [], [], 0.05)[0])

    def recv(self, size):
        try:
            data = os.read(self.master, size)
        except OSError:
            data = b""
        if not data:
            self.done = True
        return data

    def sendall(self, data):
        os.write(self.master, data)

    def exit_status_ready(self):
        return self.proc.poll() is not None and not self.recv_ready()

    def recv_exit_status(self):
        return self.proc.wait(10)

    def close(self):
        if self.proc and self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait(10)
        os.close(self.master)


class Transport:
    def __init__(self, path):
        self.path, self.channels = path, []

    def open_session(self, timeout=None):
        self.channels.append(PtyChannel(self.path))
        return self.channels[-1]


@pytest.fixture
def transport(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    sudo = bin_dir / "sudo"
    sudo.write_text(FAKE_SUDO.format(login=LOGIN))
    sudo.chmod(0o755)
    return Transport(str(bin_dir))


def test_secret_line_reaches_the_command_without_echo_or_argv(transport, tmp_path):
    target = tmp_path / "chpasswd-input"
    result = root_shell(
        transport, "cat > " + shlex.quote(str(target)), LOGIN, lambda: None, 30, line="automation:" + NEW
    )
    assert result["exit_code"] == 0
    assert target.read_text() == "automation:" + NEW + "\n"
    assert NEW not in result["stdout"] and LOGIN not in result["stdout"]


def test_command_prompts_are_answered_twice_without_echo(transport, tmp_path):
    target = tmp_path / "config-password"
    script = (
        "printf 'Password: '; stty -echo; IFS= read -r a; printf '\\nConfirm: '; IFS= read -r b; "
        'stty echo; printf \'\\n\'; [ "$a" = "$b" ] && printf \'%s\' "$a" > ' + shlex.quote(str(target))
    )
    result = root_shell(transport, script, LOGIN, lambda: None, 30, answer=NEW)
    assert result["exit_code"] == 0 and result["answers"] == 2
    assert target.read_text() == NEW and NEW not in result["stdout"]


def test_a_rejected_sudo_password_stops_before_the_command(transport, tmp_path):
    target = tmp_path / "never"
    with pytest.raises(DeviceError, match="rejected"):
        root_shell(transport, "touch " + str(target), "wrong", lambda: None, 30, line="x")
    assert not target.exists() and len(transport.channels) == 1


def test_multiline_secret_input_is_refused():
    with pytest.raises(DeviceError, match="single line"):
        root_shell(None, "chpasswd", LOGIN, lambda: None, 30, line="a\nb")


class SudoSSH:
    """A TACACS login (UID 1001) whose root commands run through the terminal transport."""

    def __init__(self, transport, files):
        self.transport, self.files = transport, files
        self.selector = SimpleNamespace(secrets=set(), redact=lambda value: value, last=None)
        self.device = SimpleNamespace(host="192.0.2.5", id="host", password_env="NETOPS_TEST_LOGIN")
        self.guard = lambda: None
        self.direct = []

    def connect(self):
        return SimpleNamespace(get_transport=lambda: self.transport)

    def execute(self, command, timeout=120, stdin_text=None):
        self.direct.append(command)
        if command == "id -u":
            return {"exit_code": 0, "stdout": "1001\n", "stderr": ""}
        raise AssertionError("only the identity check runs without sudo: " + command)

    def close(self):
        pass


def linux_files(tmp_path, chpasswd_exit=0):
    """A fake root toolset for the account commands, run by the real root shell."""
    bin_dir = tmp_path / "tools"
    bin_dir.mkdir()
    shadow = tmp_path / "shadow"
    shadow.write_text("automation:$6$old$hash:19000:0:99999:7:::\n")
    tools = {
        "useradd": "exit 0",
        "chpasswd": (
            "IFS= read -r line; printf '%s' \"${line#*:}\" > "
            + str(tmp_path / "new")
            + '; sed -i "s|^automation:[^:]*:|automation:\\$6\\$new\\$hash:|" '
            + str(shadow)
            if chpasswd_exit == 0
            else "echo 'chpasswd: (user automation) pam_chauthtok() failed, error: Permission denied'; exit 1"
        ),
        "getent": (
            'case "$1" in passwd) grep "^$2:" '
            + str(tmp_path / "passwd")
            + ';; shadow) grep "^$2:" '
            + str(shadow)
            + ";; esac"
        ),
        "passwd": "echo 'automation P 2026-01-01 0 99999 7 -1'",
    }
    for name, body in tools.items():
        path = bin_dir / name
        path.write_text("#!/bin/sh\n" + body + "\n")
        path.chmod(0o755)
    (tmp_path / "passwd").write_text("automation:x:1000:1000::/home/automation:/bin/bash\n")
    return bin_dir


def rotation(tmp_path, transport, monkeypatch, chpasswd_exit=0):
    tools = linux_files(tmp_path, chpasswd_exit)
    transport.path = str(tools) + ":" + transport.path
    monkeypatch.setenv("NETOPS_TEST_LOGIN", LOGIN)
    request = PasswordRotationOptions.model_validate(
        {"device": "192.0.2.5", "device_type": "linux", "username": "automation"}
    )
    request.for_platform("linux")
    ssh = SudoSSH(transport, tmp_path)
    client = AccountDevice(None, None, request, NEW, lambda: None, None, ssh=ssh)
    passwd = (tmp_path / "passwd").read_text().strip()
    client.read = lambda: passwd
    return client, ssh


def test_tacacs_login_rotates_through_sudo_and_proves_the_change(transport, tmp_path, monkeypatch):
    client, ssh = rotation(tmp_path, transport, monkeypatch)
    assert client.preflight() is True and client.report["privilege"] == "sudo"
    client.apply()
    assert (tmp_path / "new").read_text() == NEW
    assert client.report["confirmed"] == ["account_changed"]
    # Only the identity check ran outside sudo; the password was never on a command line.
    assert ssh.direct == ["id -u"]
    assert all(NEW not in c.proc.args[-1] for c in transport.channels)


def test_refused_chpasswd_with_an_unchanged_shadow_entry_is_not_accepted(transport, tmp_path, monkeypatch):
    client, _ = rotation(tmp_path, transport, monkeypatch, chpasswd_exit=1)
    client.preflight()
    with pytest.raises(ChangeNotAccepted, match="privileges.*unchanged") as exc:
        client.apply()
    assert NEW not in str(exc.value)
