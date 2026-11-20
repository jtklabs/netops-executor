"""Encrypted, versioned local credentials and bounded authentication selection."""

import hashlib
import hmac
import json
import os
import time
from pathlib import Path
from typing import Literal

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from pydantic import Field, SecretStr, field_validator, model_validator

from .models import Model, Name
from .store import Conflict

# Salted scrypt parameters for the one-way job secret digest (16 MiB, tens of milliseconds).
DIGEST = ("scrypt", 2**14, 8, 1)


def secret_digest(value: bytes) -> str:
    """One-way, salted digest kept after a job's encrypted secret is purged, for idempotency only."""
    scheme, n, r, p = DIGEST
    salt = os.urandom(16)
    derived = hashlib.scrypt(value, salt=salt, n=n, r=r, p=p, dklen=32)
    return "$".join((scheme, str(n), str(r), str(p), salt.hex(), derived.hex()))


def digest_matches(digest: str, value: bytes) -> bool:
    try:
        scheme, n, r, p, salt, expected = digest.split("$")
        if (scheme, int(n), int(r), int(p)) != DIGEST:
            return False
        derived = hashlib.scrypt(value, salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p), dklen=32)
    except ValueError:
        return False
    return hmac.compare_digest(derived.hex(), expected)


# SNMP versions and USM protocols, shared by saved profiles and request credentials.
SnmpVersion = Literal["1", "2c", "3"]
SnmpSecurityLevel = Literal["authPriv", "authNoPriv", "noAuthNoPriv"]
SnmpAuthProtocol = Literal["MD5", "SHA", "SHA224", "SHA256", "SHA384", "SHA512"]
# AES192/AES256 use the standard (Blumenthal) key extension, as net-snmp does by default.
# AES192C/AES256C use the Reeder key extension that Cisco devices implement for AES-192/256.
SnmpPrivProtocol = Literal["DES", "3DES", "AES", "AES192", "AES256", "AES192C", "AES256C"]
SECRET_FIELDS = (
    "password",
    "private_key",
    "enable_password",
    "passphrase",
    "token",
    "auth_password",
    "priv_password",
    "community",
)


def snmp_version(value):
    """Accept 1, "v1", 2, "2", "v2c", 3, "v3" and so on."""
    text = str(value).strip().lower().removeprefix("v")
    return {"1": "1", "2": "2c", "2c": "2c", "3": "3"}.get(text, value)


def check_snmp(c):
    """Shared SNMP credential rules on a plaintext dict (saved profile or request credential)."""
    if len((c.get("context_name") or "").encode()) > 32:
        raise ValueError("SNMP context must contain at most 32 bytes")
    if c["version"] in ("1", "2c"):
        community = c.get("community") or ""
        if (
            not community
            or len(community.encode()) > 256
            or any(ord(ch) < 32 or ord(ch) == 127 for ch in community)
        ):
            raise ValueError("SNMP v1/v2c requires a community of 1-256 bytes without control characters")
        if c.get("username") or c.get("auth_password") or c.get("priv_password"):
            raise ValueError("SNMP v1/v2c uses only a community; remove the v3 user settings")
        return
    if c.get("community"):
        raise ValueError("SNMP v3 does not use a community")
    if not c.get("username") or len(c["username"].encode()) > 32:
        raise ValueError("SNMP requires a username of at most 32 bytes")
    level = c["security_level"]
    for needed, value in (
        (level != "noAuthNoPriv", c.get("auth_password")),
        (level == "authPriv", c.get("priv_password")),
    ):
        if needed and (not value or not 8 <= len(value.encode()) <= 256):
            raise ValueError("SNMP authentication/privacy passphrases require 8-256 bytes")
    if level == "noAuthNoPriv" and (c.get("auth_password") or c.get("priv_password")):
        raise ValueError("noAuthNoPriv does not use passphrases")
    if level == "authNoPriv" and c.get("priv_password"):
        raise ValueError("authNoPriv does not use a privacy passphrase")


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
    # oauth2: username and password are an API client's ID and secret, exchanged at token_path
    # for a bearer token (client credentials grant, as ClearPass uses).
    scheme: Literal["bearer", "basic", "header", "keygen", "oauth2"] = "bearer"
    token_path: str = Field(default="/api/oauth", pattern=r"^/[A-Za-z0-9/._-]{0,200}$")
    version: SnmpVersion = Field(default="3", description="SNMP only: 1, 2c or 3")
    community: SecretStr | None = Field(default=None, description="SNMP v1/v2c community")
    security_level: SnmpSecurityLevel = Field(default="authPriv", description="SNMP v3")
    auth_protocol: SnmpAuthProtocol = Field(default="SHA256", description="SNMP v3 authentication")
    auth_password: SecretStr | None = None
    priv_protocol: SnmpPrivProtocol = Field(
        default="AES",
        description="SNMP v3 privacy. AES is AES-128; AES192/AES256 use the standard key extension, "
        "AES192C/AES256C the one Cisco devices use for AES-192/256.",
    )
    priv_password: SecretStr | None = None
    context_name: str = Field(default="", max_length=32, description="SNMP v3 context")
    priority: int = Field(default=100, ge=0, le=10000)
    enabled: bool = True
    # Empty means usable for any target of this protocol; use exact addresses/IDs to restrict.
    targets: list[str] = Field(default_factory=list, max_length=1000)
    # SNMP discovery can reach hosts that are not in the inventory and that identified their own
    # vendor. Only profiles opted in here (or naming the address in targets) are sent to them.
    discovery: bool = False

    @field_validator("version", mode="before")
    @classmethod
    def normalize_version(cls, value):
        return snmp_version(value)

    @model_validator(mode="after")
    def valid(self):
        for key, value in self.plaintext().items():
            if key in SECRET_FIELDS and value and len(value) > 65536:
                raise ValueError("credential field exceeds 64 KiB")
        if self.kind == "ssh" and (not self.username or not (self.password or self.private_key)):
            raise ValueError("SSH requires username and password or private_key")
        if self.kind == "http" and not (
            self.username and self.password if self.scheme in ("basic", "keygen", "oauth2") else self.token
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
            check_snmp(self.plaintext())
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

    def candidates(self, kind, names=None, targets=(), discovery=False):
        """Enabled profiles for these targets. With discovery, an unrestricted profile must also
        be opted in for discovered hosts; a profile listing the address is always eligible."""
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
            if payload["targets"]:
                eligible = bool(set(payload["targets"]) & set(targets))
            else:
                eligible = not discovery or payload.get("discovery", False)
            if eligible:
                result.append({**payload, "id": row["id"], "revision": row["revision"]})
        return result

    def job_password(self, job_id):
        with self.store.connect() as db:
            row = db.execute("SELECT secret FROM job_secrets WHERE job=?", (job_id,)).fetchone()
        # Purged once the job can no longer run or resume.
        if row is None or not row["secret"]:
            raise Conflict("job password is unavailable")
        return self.decrypt(self.cipher(), row["secret"]).decode()

    def rotate(self):
        cipher = self.cipher()
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            for row in db.execute("SELECT id,secret FROM credentials").fetchall():
                db.execute(
                    "UPDATE credentials SET secret=? WHERE id=?", (cipher.rotate(row["secret"]), row["id"])
                )
            for row in db.execute("SELECT job,secret FROM job_secrets WHERE length(secret)>0").fetchall():
                db.execute(
                    "UPDATE job_secrets SET secret=? WHERE job=?", (cipher.rotate(row["secret"]), row["job"])
                )
        return {"rotated": True}


class CredentialUnanswered(Exception):
    """The target never answered this credential. Some protocols cannot tell that apart from a
    rejection: an SNMPv3 agent drops requests from a user it does not know or does not allow."""


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
            self.secrets.update(str(c[k]) for k in SECRET_FIELDS if c.get(k))
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

    async def run_async(self, authenticate, aliases=(), extra=(), vault=True):
        """Try eligible credentials in order. A rejection, or no answer at all (CredentialUnanswered),
        moves on to the next one; no answer does not start a cooldown. Raises CredentialUnanswered
        when no credential got an answer.

        `extra` candidates (credentials sent with the request, or a file-based profile) come first,
        in their order, and never get cooldowns. `vault=False` skips saved profiles."""
        candidates = list(extra)
        if vault:
            candidates += self.vault.candidates(self.kind, self.names, (self.target, *aliases))
        if self.last:
            candidates.sort(key=lambda c: c["id"] != self.last)
        attempted = unanswered = 0
        for c in candidates:
            key = f"{self.kind}:{self.target}:{c['id']}:{c['revision']}"
            transient = c.get("transient", False)
            with self.vault.store.connect() as db:
                cool = db.execute("SELECT until FROM credential_cooldowns WHERE key=?", (key,)).fetchone()
                if cool and cool["until"] > time.time() and not transient:
                    continue
            if self.max_attempts is not None and attempted >= self.max_attempts:
                break
            attempted += 1
            self.secrets.update(str(c[k]) for k in SECRET_FIELDS if c.get(k))
            event = {
                "profile": c["id"],
                "revision": c["revision"],
                "transport": self.kind,
                "target": self.target,
            }
            try:
                value = await authenticate(c)
            except CredentialUnanswered:
                unanswered += 1
                self.audit({**event, "outcome": "no_response"})
                continue
            except AuthenticationRejected:
                if not transient:
                    with self.vault.store.connect() as db:
                        db.execute(
                            "INSERT OR REPLACE INTO credential_cooldowns VALUES (?,?)",
                            (key, time.time() + 60),
                        )
                self.audit({**event, "outcome": "rejected"})
                continue
            self.audit({**event, "outcome": "authenticated", "previous": self.last})
            self.last = c["id"]
            return value
        if attempted and unanswered == attempted:
            raise CredentialUnanswered()
        raise AuthenticationRejected(
            "eligible credentials rejected, unanswered, unavailable, or cooling down"
        )

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
