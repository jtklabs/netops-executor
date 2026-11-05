"""Password-authenticated sudo for legacy Opengear SCP channels.

The readiness marker is consumed before SCP sees the channel. A password is sent
only in response to sudo's prompt, so cached/NOPASSWD sudo cannot feed it to SCP.
"""

import shlex
import time

from scp import SCPClient

from .ssh import DeviceError

READY = "__NETOPS_ROOT_READY__"
PROMPT = "__NETOPS_SUDO_PASSWORD__"


def root_command(command):
    script = 'test "$(id -u)" = 0 || exit 1; printf "' + READY + '\\n"; ' + command
    return "sudo -S -p " + shlex.quote(PROMPT) + " -- sh -c " + shlex.quote(script)


class SudoChannel:
    def __init__(self, channel, password, guard):
        self.channel, self.password, self.guard = channel, password, guard

    def __getattr__(self, name):
        return getattr(self.channel, name)

    def exec_command(self, command):
        command = command.decode() if isinstance(command, bytes) else command
        if not command.startswith("scp "):
            raise DeviceError("unexpected Opengear transfer command")
        self.channel.exec_command(root_command("exec " + command))
        deadline, output, errors, sent = time.monotonic() + 30, b"", b"", False
        while time.monotonic() < deadline:
            self.guard()
            if self.channel.recv_stderr_ready():
                errors += self.channel.recv_stderr(4096)
                if PROMPT.encode() in errors:
                    if sent or not self.password:
                        raise DeviceError("Opengear sudo authentication failed for SCP")
                    self.channel.sendall((self.password + "\n").encode())
                    sent = True
                    errors = errors.replace(PROMPT.encode(), b"", 1)
                if len(errors) > 8192:
                    raise DeviceError("Opengear sudo failed before SCP")
            if self.channel.recv_ready():
                # Do not consume any SCP protocol bytes following the marker.
                output += self.channel.recv(1)
                if output.endswith(b"\n"):
                    if output != (READY + "\n").encode() or errors.strip():
                        raise DeviceError("Opengear sudo did not establish a root SCP session")
                    self.password = None
                    return
                if len(output) > len(READY):
                    raise DeviceError("unexpected Opengear sudo response before SCP")
            elif self.channel.exit_status_ready():
                raise DeviceError("Opengear sudo exited before SCP")
            else:
                time.sleep(0.01)
        raise DeviceError("Opengear sudo timed out before SCP")


class SudoSCPClient(SCPClient):
    def __init__(self, *args, password, guard, **kwargs):
        super().__init__(*args, **kwargs)
        self.password, self.guard = password, guard

    def _open(self):
        # __enter__ and put/get both call _open. Never wrap an existing wrapper:
        # that would try to run sudo twice and corrupt the SCP handshake.
        if self.channel is None or self.channel.closed:
            return SudoChannel(self.transport.open_session(timeout=15), self.password, self.guard)
        return self.channel
