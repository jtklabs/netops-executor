import shlex
import socket
import threading
from contextlib import contextmanager
from types import SimpleNamespace

import paramiko
import pytest

from netops_executor.opengear import Opengear
from netops_executor.opengear_sudo import PROMPT, READY, run_as_root
from netops_executor.ssh import DeviceError


class LegacyShell:
    def __init__(self, uid="0"):
        self.uid, self.commands, self.stdin = uid, [], []

    def execute(self, command, timeout=120, stdin_text=None):
        self.commands.append(command)
        self.stdin.append(stdin_text)
        outputs = {
            "id -u": self.uid,
            "cat /etc/version": "OpenGear/IM72xx Version 4.13.6 bcdfa9f9 -- Tue Sep 26 17:09:47 UTC 2023",
            "config -g config.system.model": "config.system.model IM7248-2-DAC",
            "cat /sys/class/net/eth0/address": "00:13:c6:02:55:05",
            "cat /proc/sys/kernel/random/boot_id": "030c5f9c-ea04-4977-85d9-fc9ab524f060",
            "df -k /tmp": "Filesystem 1k-blocks Used Available Use% Mounted on\ntmpfs 127240 3116 124124 2% /var",
        }
        if command.startswith("if command -v sha256sum"):
            value = "SHA256(/etc/version)= " + "a" * 64
        else:
            value = outputs[command]
        return {"exit_code": 0, "stdout": value + "\n", "stderr": ""}

    def close(self):
        pass


def test_real_4136_version_model_hash_and_space():
    device = Opengear(None, None, None, None, None, ssh=LegacyShell())
    info = device.version()
    assert info["model"] == "IM7248-2-DAC" and info["version"] == "4.13.6"
    assert device.sha256("/etc/version") == "a" * 64
    assert device.free_bytes("/tmp") == 124124 * 1024
    assert "cat /etc/issue" not in device.ssh.commands


@pytest.mark.parametrize("bad", ["", "sudo: a password is required", "a" * 64, "SHA256(/wrong)= " + "a" * 64])
def test_hash_fails_closed(bad):
    device = Opengear(None, None, None, None, None, ssh=LegacyShell())
    device.text = lambda *_args, **_kwargs: bad
    with pytest.raises(DeviceError, match="SHA-256"):
        device.sha256("/etc/version")


LECTURE = (
    "\r\nWe trust you have received the usual lecture from the local System\r\n"
    "Administrator. It usually boils down to these three things:\r\n\r\n"
    "    #1) Respect the privacy of others.\r\n"
)


class Terminal:
    """A sudo session on an SSH terminal: each step's output follows one password answer."""

    def __init__(self, steps, code=0):
        self.steps, self.code = [s.encode() for s in steps], code
        self.buffer, self.sent, self.command, self.pty, self.closed = self.steps.pop(0), [], None, None, False

    def settimeout(self, value):
        pass

    def get_pty(self, **kwargs):
        self.pty = kwargs

    def exec_command(self, command):
        self.command = command

    def recv_ready(self):
        return bool(self.buffer)

    def recv(self, n):
        result, self.buffer = self.buffer[:n], self.buffer[n:]
        return result

    def sendall(self, value):
        self.sent.append(value)
        if self.steps:
            self.buffer += self.steps.pop(0)

    def exit_status_ready(self):
        return not self.buffer and not self.steps

    def recv_exit_status(self):
        return self.code

    def close(self):
        self.closed = True


def root(terminal, password="private-password", timeout=60):
    transport = SimpleNamespace(open_session=lambda timeout: terminal)
    clock = iter(range(0, 10**6))
    return run_as_root(
        transport, "id -u", password, lambda: None, timeout, lambda: next(clock), lambda s: None
    )


@pytest.mark.parametrize(
    "steps,answers",
    [
        # TACACS login: the lecture after a reboot, then PAM's own prompt wording.
        ([LECTURE + "TACACS Password: ", "\r\n" + READY + "\r\n0\r\n"], 1),
        ([PROMPT, "\r\n" + READY + "\r\n0\r\n"], 1),
        # A PAM stack that asks for the password twice.
        (["Password: ", "\r\nPassword: ", "\r\n" + READY + "\r\n0\r\n"], 2),
        # NOPASSWD or a cached ticket: the password is never sent.
        ([READY + "\r\n0\r\n"], 0),
    ],
)
def test_root_command_answers_prompts_on_a_terminal_and_returns_only_command_output(steps, answers):
    terminal = Terminal(steps)
    result = root(terminal)
    assert result == {"exit_code": 0, "stdout": "0\n", "stderr": ""}
    assert terminal.sent == [b"private-password\n"] * answers and terminal.pty is not None
    assert terminal.command.startswith("sudo -p ") and " -S " not in terminal.command
    assert "private-password" not in terminal.command and terminal.closed


@pytest.mark.parametrize(
    "steps,sent,message",
    [
        # A rejected password stops at once, so TACACS lockout counters advance by one.
        (["Password: ", "\r\nSorry, try again.\r\nPassword: "], 1, "rejected"),
        (["Password: ", "\r\nPassword: ", "\r\nPassword: "], 2, "repeated"),
        (["automation is not in the sudoers file.  This incident will be reported.\r\n"], 0, "rejected"),
        (["sudo: unable to execute /bin/sh\r\n"], 0, "root shell or working sudo"),
        # Root access without the marker, such as a policy that substitutes another command.
        (["0\r\n"], 0, "root shell or working sudo"),
    ],
)
def test_root_command_failures_never_return_output(steps, sent, message):
    terminal = Terminal(steps, code=1)
    with pytest.raises(DeviceError, match=message):
        root(terminal)
    assert len(terminal.sent) == sent and terminal.closed


def test_root_command_without_password_or_past_deadline_fails():
    with pytest.raises(DeviceError, match="has none"):
        root(Terminal(["Password: "]), password=None)
    terminal = Terminal(["Password: "])
    terminal.exit_status_ready = lambda: False
    terminal.sendall = lambda value: terminal.sent.append(value)
    with pytest.raises(DeviceError, match="timed out"):
        root(terminal, timeout=5)


class Session:
    """The login account's SSH connection: plain commands and a transport for root terminals."""

    def __init__(self, uid="1002"):
        self.uid, self.commands, self.terminals = uid, [], []
        self.selector = SimpleNamespace(redact=lambda text: text.replace("private-password", "[REDACTED]"))
        self.guard = lambda: None

    def execute(self, command, timeout=120, stdin_text=None):
        self.commands.append(command)
        if command == "id -u":
            return {"exit_code": 0, "stdout": self.uid + "\n", "stderr": ""}
        if command.startswith("umask 077; mktemp -d"):
            return {"exit_code": 0, "stdout": "/tmp/netops-transfer.Ab12Cd\n", "stderr": ""}
        return {"exit_code": 0, "stdout": "", "stderr": ""}

    def open_session(self, timeout):
        terminal = Terminal(["Password: ", "\r\n" + READY + "\r\n0\r\n"])
        self.terminals.append(terminal)
        return terminal

    def connect(self):
        return SimpleNamespace(get_transport=lambda: self)

    def close(self):
        pass


def test_tacacs_login_runs_commands_as_root_through_sudo():
    session = Session()
    device = Opengear(None, None, None, None, None, ssh=session)
    device.sudo_password = lambda: "private-password"
    assert device.text("id -u") == "0"
    assert session.commands == ["id -u"] and len(session.terminals) == 1
    script = shlex.split(session.terminals[0].command)[-1]
    assert script.startswith('test "$(id -u)" = 0 || exit 1;')
    assert script.endswith("exec sh -c 'id -u' < /dev/null")
    device.close()
    root_login = Session(uid="0")
    device = Opengear(None, None, None, None, None, ssh=root_login)
    assert device.text("id -u") == "0" and not root_login.terminals


@pytest.mark.parametrize("download", [False, True])
def test_sudo_transfers_copy_as_the_login_account_through_private_tmp(tmp_path, download):
    session = Session()
    device = Opengear(None, None, None, None, None, ssh=session)
    root_commands, copies = [], []
    device.text = lambda command, timeout=120: root_commands.append(command) or ""
    device.free_bytes = lambda directory: 10**9
    device.scp = lambda local, remote, timeout, progress, download=False: copies.append((remote, download))
    remote = "/tmp/netops-executor/image.flash.job.partial"
    local = tmp_path / "image.flash"
    local.write_bytes(b"image")
    device.transfer(local, remote, 60, lambda *_: None, download=download)
    staged = "/tmp/netops-transfer.Ab12Cd/" + ("download" if download else "upload")
    # The root-only staging path is never an SCP target; root moves the file in or out.
    assert copies == [(staged, download)]
    assert len(root_commands) == 1
    if download:
        assert (
            "cp " + remote + " " + staged in root_commands[0] and "chown 1002 " + staged in root_commands[0]
        )
    else:
        assert (
            "mv -f " + staged + " " + remote in root_commands[0] and "chown 0:0 " + remote in root_commands[0]
        )
    assert session.commands[-1] == "rm -rf /tmp/netops-transfer.Ab12Cd"


def test_sudo_transfer_cleans_up_after_failure_and_checks_tmp_space(tmp_path):
    session = Session()
    device = Opengear(None, None, None, None, None, ssh=session)
    device.text = lambda command, timeout=120: ""
    device.free_bytes = lambda directory: 10**9

    def broken(*args, **kwargs):
        raise DeviceError("Opengear SCP transfer failed; device output omitted")

    device.scp = broken
    local = tmp_path / "image.flash"
    local.write_bytes(b"image")
    with pytest.raises(DeviceError, match="SCP transfer failed"):
        device.transfer(local, "/tmp/netops-executor/x.partial", 60, lambda *_: None)
    assert session.commands[-1] == "rm -rf /tmp/netops-transfer.Ab12Cd"
    device.free_bytes = lambda directory: 1
    with pytest.raises(DeviceError, match="/tmp space"):
        device.transfer(local, "/tmp/netops-executor/x.partial", 60, lambda *_: None)


@contextmanager
def requiretty_sudo_server(password="tacacs-secret"):
    """Loopback SSH whose sudo, like a requiretty policy, works only on a terminal."""
    key = paramiko.RSAKey.generate(2048)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    state = {"ptys": 0, "answers": [], "handlers": []}

    class Server(paramiko.ServerInterface):
        def get_allowed_auths(self, username):
            return "password"

        def check_auth_password(self, username, value):
            return paramiko.AUTH_SUCCESSFUL if value == password else paramiko.AUTH_FAILED

        def check_channel_request(self, kind, chanid):
            return paramiko.OPEN_SUCCEEDED

        def check_channel_pty_request(self, channel, *args):
            state["ptys"] += 1
            return True

        def check_channel_exec_request(self, channel, command):
            def run():
                if not state["ptys"]:
                    channel.sendall_stderr(b"sudo: sorry, you must have a tty to run sudo\n")
                    channel.send_exit_status(1)
                    return
                channel.sendall(LECTURE.encode() + b"\r\nTACACS Password: ")
                line = b""
                while not line.endswith(b"\n"):
                    line += channel.recv(1)
                state["answers"].append(line.decode().strip())
                if line.decode().strip() != password:
                    # The client hangs up here instead of answering again.
                    channel.sendall(b"\r\nSorry, try again.\r\nTACACS Password: ")
                    channel.recv(1024)
                    return
                channel.sendall(b"\r\n" + READY.encode() + b"\r\n0\r\n")
                channel.send_exit_status(0)

            def sudo():
                # The client closes the session after a rejected password, possibly mid-reply.
                try:
                    run()
                    channel.close()
                except (EOFError, OSError, paramiko.SSHException):
                    pass

            handler = threading.Thread(target=sudo, daemon=True)
            state["handlers"].append(handler)
            handler.start()
            return True

    def serve():
        connection, _ = listener.accept()
        transport = paramiko.Transport(connection)
        transport.add_server_key(key)
        transport.start_server(server=Server())
        state["transport"] = transport

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        "127.0.0.1",
        port=listener.getsockname()[1],
        username="tacacs-user",
        password=password,
        look_for_keys=False,
        allow_agent=False,
    )
    try:
        yield client.get_transport(), state
    finally:
        # Let the simulated sudo finish before its transport goes away.
        for handler in state["handlers"]:
            handler.join(timeout=5)
        client.close()
        listener.close()


@pytest.mark.parametrize("password,ok", [("tacacs-secret", True), ("wrong-secret", False)])
def test_real_ssh_terminal_satisfies_requiretty_and_tacacs_prompt(password, ok):
    with requiretty_sudo_server() as (transport, state):
        if ok:
            result = run_as_root(transport, "id -u", password, lambda: None, 30)
            assert result == {"exit_code": 0, "stdout": "0\n", "stderr": ""}
        else:
            with pytest.raises(DeviceError, match="rejected"):
                run_as_root(transport, "id -u", password, lambda: None, 30)
        # One answer per command, even for a rejected password.
        assert state["ptys"] == 1 and state["answers"] == [password]
