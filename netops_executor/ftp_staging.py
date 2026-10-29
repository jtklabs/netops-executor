"""One-time FTP for staging firmware: one file, one login, one client address.

FortiOS stages firmware into its alternate partition only by pulling it over FTP, TFTP or
USB. For one operation the executor serves the verified image itself: a random login, the
single file read-only, passive mode only, connections accepted only from the device being
staged, and the server closed when the operation ends.
"""

import secrets
import socket
import threading
import time


class FTPError(Exception):
    pass


class OneShotFTP:
    def __init__(self, path, client, bind, ports, timeout=3600):
        self.path, self.name, self.client = path, path.name, client
        self.bind, self.ports, self.timeout = bind, ports, timeout
        self.size = path.stat().st_size
        self.user = "netops" + secrets.token_hex(4)
        self.password = secrets.token_hex(16)
        self.sent = 0
        self.completed = threading.Event()
        self.stopping = threading.Event()
        self.control = self.thread = None
        self.port = None

    def __enter__(self):
        self.control, self.port = self.listen()
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.stopping.set()
        self.control.close()
        self.thread.join(timeout=10)

    @property
    def address(self):
        return f"{self.bind}:{self.port}"

    def listen(self, exclude=None):
        for port in self.ports:
            if port == exclude:
                continue
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.bind((self.bind, port))
            except OSError:
                sock.close()
                continue
            sock.listen(1)
            sock.settimeout(1)
            return sock, port
        raise FTPError("no free staging port in NETOPS_STAGING_PORTS")

    def accept(self, sock, seconds):
        deadline = time.monotonic() + seconds
        while not self.stopping.is_set() and time.monotonic() < deadline:
            try:
                conn, peer = sock.accept()
            except (TimeoutError, socket.timeout):
                continue
            if peer[0] == self.client:
                conn.settimeout(60)
                return conn
            conn.close()
        return None

    def serve(self):
        deadline = time.monotonic() + self.timeout
        while not self.stopping.is_set() and not self.completed.is_set() and time.monotonic() < deadline:
            conn = self.accept(self.control, 5)
            if conn:
                try:
                    self.session(conn)
                except OSError:
                    pass
                finally:
                    conn.close()

    def session(self, conn):
        reader = conn.makefile("rb")

        def reply(text):
            conn.sendall((text + "\r\n").encode())

        reply("220 NetOps staging")
        user, authenticated, failures, passive = None, False, 0, None
        try:
            while not self.stopping.is_set():
                line = reader.readline(1024)
                if not line:
                    return
                command, _, argument = line.decode("utf-8", "replace").strip().partition(" ")
                command = command.upper()
                if command == "USER":
                    user, authenticated = argument, False
                    reply("331 Password required")
                elif command == "PASS":
                    authenticated = user == self.user and secrets.compare_digest(argument, self.password)
                    if authenticated:
                        reply("230 Logged in")
                    else:
                        failures += 1
                        reply("530 Login incorrect")
                        if failures >= 3:
                            return
                elif command == "QUIT":
                    reply("221 Bye")
                    return
                elif not authenticated:
                    reply("530 Not logged in")
                elif command == "SYST":
                    reply("215 UNIX Type: L8")
                elif command == "FEAT":
                    reply("211-Features:\r\n SIZE\r\n PASV\r\n EPSV\r\n211 End")
                elif command == "PWD":
                    reply('257 "/"')
                elif command == "CWD":
                    reply("250 OK" if argument in ("", "/", ".") else "550 No such directory")
                elif command in ("TYPE", "MODE", "STRU", "OPTS", "NOOP"):
                    reply("200 OK")
                elif command == "SIZE":
                    reply(f"213 {self.size}" if argument.lstrip("/") == self.name else "550 Not found")
                elif command in ("PASV", "EPSV"):
                    if passive:
                        passive.close()
                    passive, port = self.listen(exclude=self.port)
                    if command == "EPSV":
                        reply(f"229 Entering Extended Passive Mode (|||{port}|)")
                    else:
                        h = self.bind.replace(".", ",")
                        reply(f"227 Entering Passive Mode ({h},{port // 256},{port % 256})")
                elif command == "RETR":
                    if argument.lstrip("/") != self.name:
                        reply("550 Not found")
                        continue
                    if not passive:
                        reply("425 Use PASV first")
                        continue
                    data = self.accept(passive, 60)
                    passive.close()
                    passive = None
                    if not data:
                        reply("425 No data connection")
                        continue
                    reply("150 Opening binary connection")
                    try:
                        with self.path.open("rb") as stream, data:
                            for chunk in iter(lambda: stream.read(256 * 1024), b""):
                                if self.stopping.is_set():
                                    raise FTPError("staging stopped")
                                data.sendall(chunk)
                                self.sent += len(chunk)
                    except (OSError, FTPError):
                        reply("426 Transfer aborted")
                        continue
                    reply("226 Transfer complete")
                    self.completed.set()
                else:
                    reply("502 Not implemented")
        finally:
            if passive:
                passive.close()
