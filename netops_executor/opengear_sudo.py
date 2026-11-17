"""Root commands for Opengear accounts that log in without UID 0, such as TACACS users.

Each command runs on its own SSH channel with a terminal, as an operator's `sudo -i` does.
That satisfies `requiretty` policies, and sudo's lecture and any PAM/TACACS prompt wording
or second prompt appear on the terminal instead of being mistaken for command output.
The password is sent only in reply to a password prompt, never on a command line, and
at most twice, so a rejected password is not retried. Output is returned only after a
marker the root shell prints once UID 0 is confirmed. File transfers never run through
sudo: a terminal would corrupt the SCP protocol (see Opengear.transfer).

Password rotation also needs a secret inside the root command (chpasswd's input, a hash
check, Opengear's `config -P` prompt). `root_shell` sends it only after the root shell has
switched the terminal to raw mode without echo, as one line the shell reads into memory and
pipes to the command, so it never appears in argv, the process list or the output.
"""

import codecs
import os
import re
import shlex
import time

import paramiko

from .ssh import DeviceError

READY = "__NETOPS_ROOT_READY__"
INPUT = "__NETOPS_INPUT_READY__"
PROMPT = "[netops-sudo] password: "
# One PAM stack may ask twice (for example local, then TACACS). A third prompt means rejection.
ANSWERS = 2
PASSWORD_PROMPT = re.compile(r"(?i)(?:password|passcode)[^\r\n]{0,80}:\s*$")
# A prompt printed by the root command itself (`config -P`: password, then confirmation).
PROMPT_REPLY = re.compile(r"(?i)(?:password|confirm)[^\r\n:]{0,80}:\s*$")
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


def login_password(ssh):
    """The password of the credential that authenticated this connection, for sudo."""
    ssh.connect()
    selector = ssh.selector
    if selector.last and not selector.last.startswith("legacy:"):
        candidates = selector.vault.candidates("ssh", [selector.last], (ssh.device.host, ssh.device.id))
        return candidates[0].get("password") if candidates else None
    return os.environ.get(ssh.device.password_env or "")


def root_shell(transport, command, password, guard, timeout, *, line=None, answer=None, **kwargs):
    """Run `command` as root. `line` is one secret line for its stdin; `answer` replies to
    password prompts the command itself prints (at most twice). Without either, stdin is empty."""
    if line is not None:
        if "\n" in line or "\r" in line:
            raise DeviceError("secret input must be a single line")
        command = (
            "stty raw -echo 2>/dev/null || exit 1; printf '%s\\n' "
            + INPUT
            + "; IFS= read -r netops_line; printf '%s\\n' \"$netops_line\" | sh -c "
            + shlex.quote(command)
        )
    elif answer is not None:
        # Echo off before the command runs, so an early answer to its prompt is never shown.
        command = "stty -echo 2>/dev/null || exit 1; " + command
    else:
        command = "exec sh -c " + shlex.quote(command) + " < /dev/null"
    return run_as_root(transport, command, password, guard, timeout, line=line, answer=answer, **kwargs)


def root_output(channel, output, chunk, sent, line, answer, tail, replies):
    """Handle output after root access: send the secret line once echo is off, or answer the
    command's own password prompts. Returns the updated (output, sent, tail, replies)."""
    if len(output) > LIMIT:
        raise DeviceError("root command output exceeds limit")
    if not sent:
        # Echo is off once the root shell prints this marker.
        marker = re.search(re.escape(INPUT) + r"\r?\n", output)
        if marker:
            output = output[marker.end() :]
            channel.sendall((line + "\n").encode())
            sent = True
    elif answer is not None:
        tail += chunk
        if len(tail) > 65536:
            raise DeviceError("password prompt output exceeded limit")
        if PROMPT_REPLY.search(tail):
            if replies >= ANSWERS:
                raise DeviceError("device repeated the password prompt; password may have been rejected")
            channel.sendall((answer + "\n").encode())
            replies += 1
            tail = ""
    return output, sent, tail, replies


def run_as_root(
    transport,
    command,
    password,
    guard,
    timeout,
    clock=time.monotonic,
    sleep=time.sleep,
    *,
    line=None,
    answer=None,
):
    """Run one shell command as root through sudo on a terminal; return its exit code and output."""
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    pending, output, answers, ready = "", "", 0, False
    sent, replies, tail = line is None, 0, ""
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
                    output, sent, tail, replies = root_output(
                        channel, output + chunk, chunk, sent, line, answer, tail, replies
                    )
                    continue
                pending += chunk
                marker = re.search(re.escape(READY) + r"\r?\n", pending)
                if marker:
                    ready, rest, pending = True, pending[marker.end() :], ""
                    output, sent, tail, replies = root_output(
                        channel, rest, rest, sent, line, answer, tail, replies
                    )
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
            "root commands require a root shell or working sudo authentication; "
            "check the selected SSH credential's password and sudo policy"
        )
    if not sent:
        raise DeviceError("the root shell did not accept secret input; outcome may be unknown")
    # A terminal returns CRLF line endings, with stdout and stderr on one stream.
    result = {"exit_code": code, "stdout": output.replace("\r\n", "\n"), "stderr": ""}
    if answer is not None:
        result["answers"] = replies
    return result
