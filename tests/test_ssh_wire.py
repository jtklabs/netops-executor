"""Real Paramiko transport against a loopback-only in-process test server."""

import socket
import threading
from contextlib import contextmanager

import paramiko
import pytest
from test_controls_credentials import vault_for

from netops_executor.config import Device
from netops_executor.credentials import Credential
from netops_executor.ssh import SSH, DeviceError


@contextmanager
def ssh_server(cli=False):
    key = paramiko.RSAKey.generate(2048)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(0.2)
    state = {"user": "tacacs", "password": "tacacs-secret", "commands": [], "attempts": []}
    stop = threading.Event()
    transports, threads = [], []

    class Server(paramiko.ServerInterface):
        def get_allowed_auths(self, username):
            return "password"

        def check_auth_password(self, username, password):
            state["attempts"].append(username)
            return (
                paramiko.AUTH_SUCCESSFUL
                if (username, password) == (state["user"], state["password"])
                else paramiko.AUTH_FAILED
            )

        def check_channel_request(self, kind, chanid):
            return (
                paramiko.OPEN_SUCCEEDED
                if kind == "session"
                else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
            )

        def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
            return cli

        def check_channel_shell_request(self, channel):
            if not cli:
                return False

            def interact():
                prompt = "switch#"
                channel.sendall(prompt.encode())
                buffer = ""
                try:
                    while not stop.is_set():
                        chunk = channel.recv(1024)
                        if not chunk:
                            break
                        buffer += chunk.decode().replace("\r", "\n")
                        while "\n" in buffer:
                            command, buffer = buffer.split("\n", 1)
                            state["commands"].append(command)
                            channel.sendall((command + "\r\n").encode())
                            if command == "hang":
                                continue
                            if command == "configure terminal":
                                prompt = "switch(config)#"
                            elif command.startswith("interface "):
                                prompt = "switch(config-if)#"
                            elif command == "end":
                                prompt = "switch#"
                            if command.startswith("terminal width"):
                                channel.sendall(b"Width set to 511 columns.\r\n")
                            if command == "terminal length 0":
                                channel.sendall(b"Pagination disabled.\r\n")
                            if command == "show version":
                                channel.sendall(("version test " + state["password"] + "\r\n").encode())
                            elif command == "bad-command":
                                channel.sendall(b"% Invalid input detected at '^' marker.\r\n")
                            channel.sendall(prompt.encode())
                except (OSError, EOFError):
                    pass

            thread = threading.Thread(target=interact, daemon=True)
            threads.append(thread)
            thread.start()
            return True

        def check_channel_exec_request(self, channel, command):
            def reply():
                state["commands"].append(command.decode())
                channel.sendall((state["password"] + "\n").encode())
                channel.send_exit_status(0)
                channel.shutdown_write()

            thread = threading.Thread(target=reply, daemon=True)
            threads.append(thread)
            thread.start()
            return True

    def serve_connection(client):
        transport = paramiko.Transport(client)
        transports.append(transport)
        try:
            transport.add_server_key(key)
            transport.start_server(server=Server())
            channels = []
            while not stop.is_set() and transport.is_active():
                channel = transport.accept(0.2)
                if channel:
                    channels.append(channel)
        except (EOFError, OSError, paramiko.SSHException):
            pass
        finally:
            transport.close()

    def listen():
        while not stop.is_set():
            try:
                client, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            thread = threading.Thread(target=serve_connection, args=(client,), daemon=True)
            threads.append(thread)
            thread.start()

    thread = threading.Thread(target=listen, daemon=True)
    thread.start()
    try:
        yield listener.getsockname()[1], key, state
    finally:
        stop.set()
        listener.close()
        for transport in transports:
            transport.close()
        thread.join(timeout=2)
        for child in threads:
            child.join(timeout=2)


def test_ssh_reconnect_falls_from_tacacs_to_local_and_redacts(settings, store):
    vault = vault_for(settings, store)
    vault.put("tacacs", Credential(kind="ssh", username="tacacs", password="tacacs-secret", priority=1))
    vault.put("local", Credential(kind="ssh", username="root", password="local-secret", priority=2))
    with ssh_server() as (port, key, state):
        settings.known_hosts.write_text(f"[127.0.0.1]:{port} {key.get_name()} {key.get_base64()}\n")
        device = Device(id="test", host="127.0.0.1", port=port)
        audit = []
        ssh = SSH(settings, device, audit=audit.append)
        try:
            assert ssh.execute("first")["stdout"] == "[REDACTED]\n"
            ssh.close()
            state.update(user="root", password="local-secret")
            assert ssh.execute("after-reboot")["stdout"] == "[REDACTED]\n"
            assert state["commands"] == ["first", "after-reboot"]
            assert [e["outcome"] for e in audit] == ["authenticated", "rejected", "authenticated"]
            assert audit[-1]["profile"] == "local" and audit[-1]["previous"] == "tacacs"
        finally:
            ssh.close()


def test_unknown_host_key_never_attempts_credentials(settings, store):
    vault = vault_for(settings, store)
    vault.put("local", Credential(kind="ssh", username="root", password="secret"))
    settings.known_hosts.write_text("")
    with ssh_server() as (port, key, state):
        ssh = SSH(settings, Device(id="test", host="127.0.0.1", port=port))
        with pytest.raises(DeviceError):
            ssh.connect()
        assert not state["attempts"]
