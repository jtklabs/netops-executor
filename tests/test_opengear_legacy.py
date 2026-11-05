from types import SimpleNamespace

import pytest

from netops_executor.opengear import Opengear
from netops_executor.opengear_sudo import PROMPT, READY, SudoChannel, SudoSCPClient
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


def test_sudo_password_stays_off_command_line_and_false_success_is_rejected():
    calls = []

    def execute(command, timeout=120, stdin_text=None):
        calls.append((command, stdin_text))
        if command == "id -u":
            return {"exit_code": 0, "stdout": "1002", "stderr": ""}
        return {"exit_code": 0, "stdout": READY + "\n0\n", "stderr": PROMPT}

    device = Opengear(None, None, None, None, None, ssh=SimpleNamespace(execute=execute))
    device.sudo_password = lambda: "private-password"
    assert device.text("id -u") == "0"
    command, stdin = calls[-1]
    assert "private-password" not in command and stdin == "private-password\n"
    assert "< /dev/null" in command
    device.ssh.execute = lambda *_a, **_k: {
        "exit_code": 0,
        "stdout": "",
        "stderr": "sudo: a password is required",
    }
    with pytest.raises(DeviceError, match="root shell"):
        device.text("id -u")


class Channel:
    def __init__(self, prompt=True, output=None, error=b""):
        self.errors = (PROMPT.encode() if prompt else b"") + error
        self.output = (READY + "\n").encode() + b"\x00" if output is None else output
        self.sent, self.command = [], None

    def exec_command(self, command):
        self.command = command

    def recv_ready(self):
        return bool(self.output)

    def recv_stderr_ready(self):
        return bool(self.errors)

    def recv_stderr(self, n):
        result, self.errors = self.errors[:n], self.errors[n:]
        return result

    def recv(self, n):
        result, self.output = self.output[:n], self.output[n:]
        return result

    def sendall(self, value):
        self.sent.append(value)

    def exit_status_ready(self):
        return not self.output


@pytest.mark.parametrize("prompt", [True, False])
def test_sudo_scp_consumes_only_readiness_marker_and_answers_only_prompt(prompt):
    raw = Channel(prompt=prompt)
    channel = SudoChannel(raw, "private-password", lambda: None)
    channel.exec_command(b"scp -t /tmp/image.flash")
    assert raw.output == b"\x00"
    assert raw.sent == ([b"private-password\n"] if prompt else [])
    assert "private-password" not in raw.command
    assert channel.password is None


@pytest.mark.parametrize(
    "output,error,password", [(b"", b"sudo denied", "pw"), (b"not-root\n", b"", "pw"), (None, b"", None)]
)
def test_sudo_scp_failure_never_starts_file_protocol(output, error, password):
    channel = SudoChannel(Channel(output=output, error=error), password, lambda: None)
    with pytest.raises(DeviceError):
        channel.exec_command(b"scp -f /tmp/backup.opg")


def test_scp_context_and_transfer_reuse_one_wrapper():
    opened = []
    raw = SimpleNamespace(closed=False)

    def open_session(timeout):
        opened.append(timeout)
        return raw

    client = object.__new__(SudoSCPClient)
    client.transport = SimpleNamespace(open_session=open_session)
    client.channel, client.password, client.guard = None, "pw", lambda: None
    client.channel = client._open()
    assert client._open() is client.channel
    assert client.channel.channel is raw and opened == [15]
