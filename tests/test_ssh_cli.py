import hashlib
from unittest.mock import MagicMock, Mock

import paramiko
import pytest

from netops_executor.cli import parser
from netops_executor.ssh import SSH, DeviceError


def test_secret_command_goes_via_stdin(settings):
    ssh = SSH(settings, settings.devices["lab"])
    ssh.shell = Mock(return_value="")
    ssh.tmsh('save /sys ucs test.ucs passphrase "private"', secret=True)
    command, timeout, stdin = ssh.shell.call_args.args
    assert command == "tmsh -q" and "private" not in command
    assert "private" in stdin and stdin.endswith("quit\n")


def test_ssh_does_not_trust_unknown_hosts(settings, monkeypatch):
    client = Mock()
    client.connect.side_effect = paramiko.SSHException("sensitive remote text")
    factory = Mock(return_value=client)
    monkeypatch.setattr(paramiko, "SSHClient", factory)
    ssh = SSH(settings, settings.devices["lab"])
    with pytest.raises(DeviceError) as error:
        ssh.connect()
    assert "sensitive" not in str(error.value)
    assert isinstance(client.set_missing_host_key_policy.call_args.args[0], paramiko.RejectPolicy)
    assert client.connect.call_args.kwargs["allow_agent"] is False
    assert client.connect.call_args.kwargs["look_for_keys"] is False


@pytest.mark.parametrize(
    "code,stdout,stderr", [(1, b"", b"secret"), (0, b"Syntax Error: secret", b""), (0, b"", b"error")]
)
def test_failed_command_output_redacted(settings, code, stdout, stderr):
    ssh = SSH(settings, settings.devices["lab"])
    channel = Mock()
    channel.recv_ready.side_effect = [bool(stdout), False]
    channel.recv_stderr_ready.side_effect = [bool(stderr), False]
    channel.recv.return_value = stdout
    channel.recv_stderr.return_value = stderr
    channel.exit_status_ready.return_value = True
    channel.recv_exit_status.return_value = code
    ssh.connect = Mock()
    ssh.connect.return_value.get_transport.return_value.open_session.return_value = channel
    with pytest.raises(DeviceError) as error:
        ssh.shell("test")
    assert "secret" not in str(error.value)
    channel.close.assert_called_once()


def test_backup_download_checks_digest_and_permissions(settings, tmp_path):
    ssh = SSH(settings, settings.devices["lab"])
    sftp = MagicMock()
    sftp.stat.return_value.st_size = 3
    sftp.getfo.side_effect = lambda remote, stream, callback: stream.write(b"ucs")
    client = MagicMock()
    client.open_sftp.return_value.__enter__.return_value = sftp
    ssh.connect = Mock(return_value=client)
    ssh.remote_digest = Mock(return_value=hashlib.sha256(b"ucs").hexdigest())
    target = tmp_path / "archive.ucs"
    ssh.get("/var/local/ucs/archive.ucs", target)
    assert target.read_bytes() == b"ucs"
    assert target.stat().st_mode & 0o777 == 0o600
    ssh.remote_digest.return_value = "0" * 64
    with pytest.raises(DeviceError):
        ssh.get("/remote", tmp_path / "bad.ucs")
    assert not (tmp_path / "bad.ucs").exists()
    assert not (tmp_path / "bad.ucs.partial").exists()


def test_cli_step_flags():
    args = parser().parse_args(
        [
            "submit",
            "--device",
            "lab",
            "--install",
            "--images",
            "manifest.json",
            "--target-volume",
            "HD1.2",
            "--allowed-source-version",
            "16.1.5",
            "--reboot",
            "--drain-percent",
            "90",
            "--drain-timeout",
            "600",
            "--reboot-on-drain-timeout",
            "--ucs-unencrypted",
        ]
    )
    assert args.install and args.reboot and args.ucs_unencrypted
    assert args.drain_percent == 90 and args.drain_timeout == 600
    assert args.allowed_source_version == ["16.1.5"]
