"""Root commands for Opengear accounts that log in without UID 0, such as TACACS users.

Each command runs on its own SSH channel with a terminal, as an operator's `sudo -i` does.
That satisfies `requiretty` policies, and sudo's lecture and any PAM/TACACS prompt wording
or second prompt appear on the terminal instead of being mistaken for command output.
The password is sent only in reply to a password prompt, never on a command line, and
at most twice, so a rejected password is not retried. Output is returned only after a
marker the root shell prints once UID 0 is confirmed. File transfers never run through
sudo: a terminal would corrupt the SCP protocol (see Opengear.transfer).
"""

import codecs
import re
import shlex
import time

import paramiko

from .ssh import DeviceError

READY = "__NETOPS_ROOT_READY__"
PROMPT = "[netops-sudo] password: "
# One PAM stack may ask twice (for example local, then TACACS). A third prompt means rejection.
ANSWERS = 2
PASSWORD_PROMPT = re.compile(r"(?i)(?:password|passcode)[^\r\n]{0,80}:\s*$")
REFUSED = re.compile(
    r"(?i)sorry, try again|incorrect password|authentication fail|not in the sudoers"
    r"|not allowed to (?:execute|run)|may not run sudo|a password is required"
)
LIMIT = 32 * 1024 * 1024
# Root's login PATH, as `sudo -i` would provide, ahead of whatever sudo preserved.
ROOT_PATH = "PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:$PATH; export PATH; "


def root_command(command):
    script = 'test "$(id -u)" = 0 || exit 1; ' + ROOT_PATH + 'printf "%s\\n" ' + READY + "; " + command
    return "sudo -p " + shlex.quote(PROMPT) + " -- sh -c " + shlex.quote(script)


def run_as_root(transport, command, password, guard, timeout, clock=time.monotonic, sleep=time.sleep):
    """Run one shell command as root through sudo on a terminal; return its exit code and output."""
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    pending, output, answers, ready = "", "", 0, False
    channel = None
    try:
        channel = transport.open_session(timeout=15)
        channel.settimeout(15)
        channel.get_pty(term="dumb", width=200, height=50)
        channel.exec_command(root_command(command))
        deadline = clock() + timeout
        while True:
            guard()
            if clock() >= deadline:
                raise DeviceError("Opengear root command timed out; outcome may be unknown")
            if channel.recv_ready():
                chunk = decoder.decode(channel.recv(65536))
                if ready:
                    output += chunk
                    if len(output) > LIMIT:
                        raise DeviceError("Opengear command output exceeds limit")
                    continue
                pending += chunk
                marker = re.search(re.escape(READY) + r"\r?\n", pending)
                if marker:
                    ready, output, pending = True, pending[marker.end() :], ""
                    continue
                if len(pending) > 65536:
                    raise DeviceError("Opengear sudo produced unexpected output before root access")
                if REFUSED.search(pending):
                    # Stop at the first rejection: another attempt could lock the TACACS account.
                    raise DeviceError(
                        "Opengear sudo rejected the selected SSH credential's password or sudo policy"
                    )
                if PASSWORD_PROMPT.search(pending):
                    if not password:
                        raise DeviceError(
                            "Opengear sudo asked for a password; the selected SSH credential has none"
                        )
                    if answers >= ANSWERS:
                        raise DeviceError("Opengear sudo repeated its password prompt; password rejected")
                    channel.sendall((password + "\n").encode())
                    answers += 1
                    pending = ""
                continue
            if channel.exit_status_ready():
                break
            sleep(0.05)
        code = channel.recv_exit_status()
    except (EOFError, OSError, paramiko.SSHException):
        raise DeviceError("Opengear SSH command interrupted; outcome may be unknown") from None
    finally:
        if channel is not None:
            channel.close()
    if not ready:
        raise DeviceError(
            "Opengear upgrades require a root shell or working sudo authentication; "
            "check the selected SSH credential's password and sudo policy"
        )
    # A terminal returns CRLF line endings, with stdout and stderr on one stream.
    return {"exit_code": code, "stdout": output.replace("\r\n", "\n"), "stderr": ""}
