"""Interactive network CLI over the same authenticated, audited SSH transport.

Netmiko handles prompts, paging and configuration modes. Authentication stays
in SSH so fallback, strict host keys and credential auditing are identical to
shell execution. An established command is never retried with another profile.
"""

import re
import time

from netmiko import ConnectHandler
from netmiko.channel import SSHChannel

from .ssh import SSH, DeviceError

# CLI protocols do not provide process exit codes. Report recognizable rejection
# text separately and retain output for the caller's own validation rules.
CLI_ERROR = re.compile(
    r"(?im)^\s*(?:%\s*(?:invalid|incomplete|ambiguous|error|unknown|unrecognized|"
    r"authorization|access denied)|(?:syntax error|error:|invalid command))"
)
# A question the CLI is waiting on; dialogue() answers only the ones it was given.
QUESTION = re.compile(
    r"(?:\[y/n(?:/q)?\]|\[confirm\]|\[yes/no[^\]]*\]|\[[^\]\r\n]*\]\?|[Pp]assword:|[Uu]sername:)\s*[:?]?\s*$"
)


class GuardedChannel(SSHChannel):
    def __init__(self, owner, **kwargs):
        super().__init__(**kwargs)
        self.owner = owner

    def read_buffer(self):
        # Bound each receive, including a peer that continuously streams data
        # and never allows Netmiko's read-until-empty loop to return.
        self.owner.check()
        value = super().read_buffer()
        self.owner.output_bytes += len(value.encode())
        if self.owner.output_bytes > 32 * 1024 * 1024:
            raise DeviceError("network CLI output exceeds limit")
        return value


class NetworkSSH(SSH):
    def __init__(self, *args, device_type, **kwargs):
        self.driver = None
        self.device_type = device_type
        self.operation_deadline = None
        self.output_bytes = 0
        super().__init__(*args, **kwargs)

    def check(self):
        self.guard()
        if self.operation_deadline and time.monotonic() >= self.operation_deadline:
            raise DeviceError("network CLI deadline exceeded; outcome may be unknown")

    def connect(self):
        if self.driver:
            # Never silently reconnect an established interactive session; its
            # current mode/context might have been changed by prior commands.
            if not self.client or not self.client.get_transport().is_active():
                raise DeviceError("network CLI session disconnected")
            return self.driver
        client = super().connect()
        driver = ConnectHandler(
            device_type=self.device_type,
            host=self.device.host,
            auto_connect=False,
            secret=self.enable_password or "",
            session_log=None,
            allow_auto_change=False,
            fast_cli=False,
        )
        self.driver = driver
        self.operation_deadline = time.monotonic() + 60
        try:
            # Attach the already authenticated Paramiko session. Pin Netmiko's
            # version because this adapter uses its channel/session interface.
            driver.remote_conn_pre = client
            driver.remote_conn = client.invoke_shell(term="vt100", width=511, height=1000)
            driver.remote_conn.settimeout(1)
            driver.channel = GuardedChannel(self, conn=driver.remote_conn, encoding="utf-8")
            read, write = driver.read_channel, driver.write_channel

            def guarded_read():
                self.check()
                return read()

            def guarded_write(value):
                self.check()
                return write(value)

            driver.read_channel, driver.write_channel = guarded_read, guarded_write
            driver.session_preparation()
            return driver
        except Exception:
            self.close()
            raise
        finally:
            self.operation_deadline = None

    def execute(self, command, timeout=120, *, mode="exec", enable=False):
        driver = self.connect()
        self.output_bytes = 0
        self.operation_deadline = time.monotonic() + timeout
        try:
            self.check()
            if enable or mode == "config":
                driver.enable()
            if mode == "config":
                # Preserve submode between entries (interface then description,
                # for example). Never save configuration implicitly.
                output = driver.send_config_set(
                    [command], exit_config_mode=False, read_timeout=timeout, cmd_verify=True
                )
            else:
                driver.exit_config_mode()
                output = driver.send_command(command, read_timeout=timeout, cmd_verify=True)
            self.check()
            return {
                "stdout": self.selector.redact(output),
                "stderr": "",
                "exit_code": None,
                "cli_error": bool(CLI_ERROR.search(output)),
                "mode": mode,
                "completion": "prompt",
            }
        except Exception:
            # No cleanup commands or retries on an uncertain session.
            self.close()
            raise
        finally:
            self.operation_deadline = None

    def dialogue(self, command, replies, timeout, *, progress=None, disconnect_ok=False):
        """Send one command and answer only recognized questions until the prompt returns.

        `replies` pairs a pattern for a question at the end of the unanswered output with
        its answer; any other question stops the dialogue. With disconnect_ok a dropped
        session (a reload) ends it, and the caller verifies the outcome from fresh reads.
        Returns (output, disconnected). The command is sent once and never retried.
        """
        driver = self.connect()
        self.output_bytes = 0
        self.operation_deadline = time.monotonic() + timeout
        output, answered, disconnected = "", 0, False
        try:
            self.check()
            driver.enable()
            driver.exit_config_mode()
            prompt = driver.find_prompt().strip()
            driver.write_channel(command + driver.RETURN)
            while True:
                try:
                    chunk = driver.read_channel()
                except (OSError, EOFError):
                    chunk = None
                if chunk is None or (not chunk and not self.alive()):
                    if not disconnect_ok:
                        raise DeviceError("network CLI session disconnected during " + command.split()[0])
                    disconnected = True
                    break
                output += chunk
                tail = output[answered:]
                if chunk and progress:
                    lines = [line.strip() for line in output.splitlines() if line.strip()]
                    progress(self.selector.redact(lines[-1])[:200] if lines else "")
                reply = next((answer for pattern, answer in replies if pattern.search(tail)), None)
                if reply is not None:
                    driver.write_channel(reply + driver.RETURN)
                    answered = len(output)
                elif QUESTION.search(tail):
                    raise DeviceError("unrecognized prompt during " + command.split()[0])
                elif re.search(r"\n" + re.escape(prompt) + r"\s*$", output):
                    break
                elif not chunk:
                    time.sleep(0.5)
        except Exception:
            self.close()
            raise
        finally:
            self.operation_deadline = None
        if disconnected:
            self.close()
        return self.selector.redact(output), disconnected

    def alive(self):
        transport = self.client.get_transport() if self.client else None
        channel = self.driver.remote_conn if self.driver else None
        return bool(transport and transport.is_active() and channel is not None and not channel.closed)

    def close(self):
        driver, self.driver = self.driver, None
        super().close()
        if driver:
            # Close transport first: Netmiko cleanup cannot issue extra commands.
            driver.disconnect()
