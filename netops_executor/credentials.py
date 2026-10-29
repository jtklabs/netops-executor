"""Encrypted, versioned local credentials and bounded authentication selection."""

import json
import os
import time
from pathlib import Path
from typing import Literal

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from pydantic import Field, SecretStr, model_validator

from .models import Model, Name
from .store import Conflict


class Credential(Model):
    kind: Literal["ssh", "snmp", "http", "ucs", "f5_admin"]
    username: str = Field(default="", max_length=128)
    password: SecretStr | None = None
    private_key: SecretStr | None = None
    passphrase: SecretStr | None = None
    enable_password: SecretStr | None = None
    token: SecretStr | None = None
    header: str = Field(default="Authorization", pattern=r"^[A-Za-z0-9-]{1,80}$")
    # keygen: username and password exchanged for a PAN-OS API key (type=keygen) at connect time.
    scheme: Literal["bearer", "basic", "header", "keygen"] = "bearer"
    security_level: Literal["authPriv", "authNoPriv", "noAuthNoPriv"] = "authPriv"
    auth_protocol: Literal["SHA", "SHA224", "SHA256", "SHA384", "SHA512"] = "SHA256"
    auth_password: SecretStr | None = None
    priv_password: SecretStr | None = None
    context_name: str = Field(default="", max_length=32)
    priority: int = Field(default=100, ge=0, le=10000)
    enabled: bool = True
    # Empty means usable for any target of this protocol; use exact addresses/IDs to restrict.
    targets: list[str] = Field(default_factory=list, max_length=1000)

    @model_validator(mode="after")
    def valid(self):
        for key, value in self.plaintext().items():
            if (
                key
                in (
                    "password",
                    "private_key",
                    "enable_password",
                    "passphrase",
                    "token",
                    "auth_password",
                    "priv_password",
                )
                and value
                and len(value) > 65536
            ):
                raise ValueError("credential field exceeds 64 KiB")
        if self.kind == "ssh" and (not self.username or not (self.password or self.private_key)):
            raise ValueError("SSH requires username and password or private_key")
        if self.kind == "http" and not (
            self.username and self.password if self.scheme in ("basic", "keygen") else self.token
        ):
            raise ValueError("HTTP requires credentials for the selected scheme")
        if self.kind == "f5_admin":
            if self.username not in ("", "admin") or not self.password:
                raise ValueError("f5_admin requires the local admin account password")
            self.username = "admin"
            value = self.password.get_secret_value()
            if len(value.encode()) > 1024 or any(c in value for c in "\r\n\x00"):
                raise ValueError("admin password must be at most 1024 bytes without newline or NUL")
        if self.kind == "ucs" and not self.passphrase:
            raise ValueError("UCS requires passphrase")
        if self.kind == "snmp":
            if len(self.context_name.encode()) > 32:
                raise ValueError("SNMP context must contain at most 32 bytes")
            if not self.username or len(self.username.encode()) > 32:
                raise ValueError("SNMP requires a username of at most 32 bytes")
            for needed, value in (
                (self.security_level != "noAuthNoPriv", self.auth_password),
                (self.security_level == "authPriv", self.priv_password),
            ):
                if needed and (not value or len(value.get_secret_value().encode()) < 8):
                    raise ValueError("SNMP authentication/privacy passphrases require 8 bytes")
        return self

    def plaintext(self):
        return {
            key: value.get_secret_value() if isinstance(value, SecretStr) else value
            for key, value in self.__dict__.items()
        }


class Vault:
    def __init__(self, store, key_file):
        self.store = store
        self.key_file = key_file

    def cipher(self):
        if not self.key_file:
            raise Conflict("credential store requires NETOPS_CREDENTIAL_KEY_FILE")
        path = Path(self.key_file)
        try:
            if path.stat().st_mode & 0o077:
                raise Conflict("credential key file must be owner-only")
            return MultiFernet(
                [Fernet(line.strip()) for line in path.read_bytes().splitlines() if line.strip()]
            )
        except (ValueError, TypeError, OSError):
            raise Conflict("credential key file is invalid") from None

    @staticmethod
    def decrypt(cipher, secret):
        try:
            return cipher.decrypt(secret)
        except InvalidToken:
            raise Conflict("credential decryption failed; check the keyring") from None

    def put(self, name: Name, credential):
        cipher = self.cipher()
        payload = credential.plaintext()
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            old = db.execute("SELECT * FROM credentials WHERE id=?", (name,)).fetchone()
            if old and json.loads(self.decrypt(cipher, old["secret"])) == payload:
                return self.metadata(old)
            revision = old["revision"] + 1 if old else 1
            db.execute(
                """INSERT INTO credentials(id,kind,priority,enabled,revision,secret,updated)
                VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET kind=excluded.kind,
                priority=excluded.priority,enabled=excluded.enabled,revision=excluded.revision,
                secret=excluded.secret,updated=excluded.updated""",
                (
                    name,
                    credential.kind,
                    credential.priority,
                    credential.enabled,
                    revision,
                    cipher.encrypt(json.dumps(payload).encode()),
                    time.time(),
                ),
            )
        return next(r for r in self.list() if r["id"] == name)

    @staticmethod
    def metadata(row):
        return {k: row[k] for k in ("id", "kind", "priority", "enabled", "revision", "updated")}

    def list(self):
        with self.store.connect() as db:
            return [self.metadata(r) for r in db.execute("SELECT * FROM credentials ORDER BY priority,id")]

    def candidates(self, kind, names=None, targets=()):
        with self.store.connect() as db:
            rows = db.execute(
                "SELECT * FROM credentials WHERE kind=? AND enabled=1 ORDER BY priority,id", (kind,)
            ).fetchall()
        if names is not None:
            indexed = {r["id"]: r for r in rows}
            if any(n not in indexed for n in names):
                raise Conflict("specified credential is missing, disabled, or has the wrong protocol")
            rows = [indexed[n] for n in names]
        if not rows:
            return []
        cipher = self.cipher()
        result = []
        for row in rows:
            payload = json.loads(self.decrypt(cipher, row["secret"]))
            if not payload["targets"] or set(payload["targets"]) & set(targets):
                result.append({**payload, "id": row["id"], "revision": row["revision"]})
        return result

    def rotate(self):
        cipher = self.cipher()
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            for row in db.execute("SELECT id,secret FROM credentials").fetchall():
                db.execute(
                    "UPDATE credentials SET secret=? WHERE id=?", (cipher.rotate(row["secret"]), row["id"])
                )
        return {"rotated": True}


class AuthenticationRejected(Exception):
    pass


class Selector:
    def __init__(self, vault, kind, target, names=None, audit=None, max_attempts=None):
        self.vault, self.kind, self.target, self.names = vault, kind, target, names
        self.audit = audit or (lambda _: None)
        self.last = None
        self.max_attempts = max_attempts
        self.secrets = set()

    def run(self, authenticate, aliases=()):
        candidates = self.vault.candidates(self.kind, self.names, (self.target, *aliases))
        if self.last:
            candidates.sort(key=lambda c: c["id"] != self.last)
        attempted = 0
        for c in candidates:
            key = f"{self.kind}:{self.target}:{c['id']}:{c['revision']}"
            with self.vault.store.connect() as db:
                cool = db.execute("SELECT until FROM credential_cooldowns WHERE key=?", (key,)).fetchone()
                if cool and cool["until"] > time.time():
                    continue
            if self.max_attempts is not None and attempted >= self.max_attempts:
                break
            attempted += 1
            self.secrets.update(
                str(c[k])
                for k in (
                    "password",
                    "private_key",
                    "enable_password",
                    "passphrase",
                    "token",
                    "auth_password",
                    "priv_password",
                )
                if c.get(k)
            )
            event = {
                "profile": c["id"],
                "revision": c["revision"],
                "transport": self.kind,
                "target": self.target,
            }
            try:
                value = authenticate(c)
            except AuthenticationRejected:
                with self.vault.store.connect() as db:
                    db.execute(
                        "INSERT OR REPLACE INTO credential_cooldowns VALUES (?,?)", (key, time.time() + 60)
                    )
                self.audit({**event, "outcome": "rejected"})
                continue
            self.audit({**event, "outcome": "authenticated", "previous": self.last})
            self.last = c["id"]
            return value
        raise AuthenticationRejected("eligible credentials rejected, unavailable, or cooling down")

    async def run_async(self, authenticate, aliases=()):
        candidates = self.vault.candidates(self.kind, self.names, (self.target, *aliases))
        if self.last:
            candidates.sort(key=lambda c: c["id"] != self.last)
        attempted = 0
        for c in candidates:
            key = f"{self.kind}:{self.target}:{c['id']}:{c['revision']}"
            with self.vault.store.connect() as db:
                cool = db.execute("SELECT until FROM credential_cooldowns WHERE key=?", (key,)).fetchone()
                if cool and cool["until"] > time.time():
                    continue
            if self.max_attempts is not None and attempted >= self.max_attempts:
                break
            attempted += 1
            self.secrets.update(
                str(c[k])
                for k in (
                    "password",
                    "private_key",
                    "enable_password",
                    "passphrase",
                    "token",
                    "auth_password",
                    "priv_password",
                )
                if c.get(k)
            )
            event = {
                "profile": c["id"],
                "revision": c["revision"],
                "transport": self.kind,
                "target": self.target,
            }
            try:
                value = await authenticate(c)
            except AuthenticationRejected:
                with self.vault.store.connect() as db:
                    db.execute(
                        "INSERT OR REPLACE INTO credential_cooldowns VALUES (?,?)", (key, time.time() + 60)
                    )
                self.audit({**event, "outcome": "rejected"})
                continue
            self.audit({**event, "outcome": "authenticated", "previous": self.last})
            self.last = c["id"]
            return value
        raise AuthenticationRejected("eligible credentials rejected, unavailable, or cooling down")

    def redact(self, text):
        for value in sorted(self.secrets, key=len, reverse=True):
            text = text.replace(value, "[REDACTED]")
        return text


def initialize_key(path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(Fernet.generate_key() + b"\n")
        stream.flush()
        os.fsync(stream.fileno())
