"""SNMP requests, request credentials and server-side credential references."""

from typing import Annotated, Literal

from pydantic import Field, IPvAnyAddress, SecretStr, field_validator, model_validator

from .credentials import (
    SnmpAuthProtocol,
    SnmpPrivProtocol,
    SnmpSecurityLevel,
    SnmpVersion,
    check_snmp,
    snmp_version,
)
from .discovery_overrides import IdentityRule, ManualFallback
from .models import Model, Name, ScheduledRequest

EnvName = Annotated[str, Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]*$", max_length=128)]


PollerInstance = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9-]{0,79}$")]


class SnmpProfile(Model):
    id: Name
    username: str = Field(min_length=1, max_length=32)
    security_level: Literal["noAuthNoPriv", "authNoPriv", "authPriv"] = "authPriv"
    auth_protocol: Literal["SHA", "SHA224", "SHA256", "SHA384", "SHA512"] = "SHA256"
    auth_password_env: EnvName | None = None
    priv_protocol: Literal["AES128"] = "AES128"
    priv_password_env: EnvName | None = None
    context_name: str = Field(default="", max_length=32)

    @model_validator(mode="after")
    def credentials(self):
        if (self.security_level != "noAuthNoPriv") != bool(self.auth_password_env):
            raise ValueError("auth_password_env must match the selected security level")
        if (self.security_level == "authPriv") != bool(self.priv_password_env):
            raise ValueError("priv_password_env must match the selected security level")
        if len(self.username.encode()) > 32 or len(self.context_name.encode()) > 32:
            raise ValueError("username and context_name must be at most 32 UTF-8 bytes")
        return self


class SnmpCredential(Model):
    """An SNMP credential sent with one request. It is encrypted apart from the job and erased
    when the job finishes; the job itself records only how many were sent."""

    model_config = {
        "json_schema_extra": {
            "examples": [
                {"version": "2c", "community": "REPLACE_WITH_COMMUNITY"},
                {
                    "version": "3",
                    "username": "netops",
                    "auth_protocol": "SHA256",
                    "auth_password": "REPLACE_WITH_AUTH_PASSPHRASE",
                    "priv_protocol": "AES256C",
                    "priv_password": "REPLACE_WITH_PRIV_PASSPHRASE",
                },
            ]
        }
    }

    version: SnmpVersion = Field(default="3", description="1, 2c or 3 (v1, v2, v2c, v3 are accepted too)")
    community: SecretStr | None = Field(default=None, description="v1/v2c community")
    username: str | None = Field(default=None, max_length=32, description="v3 USM user")
    security_level: SnmpSecurityLevel | None = Field(
        default=None,
        description="v3. Omitted: authPriv with a privacy passphrase, authNoPriv with only an "
        "authentication passphrase, otherwise noAuthNoPriv",
    )
    auth_protocol: SnmpAuthProtocol | None = Field(
        default=None, description="v3, required with an authentication passphrase"
    )
    auth_password: SecretStr | None = None
    priv_protocol: SnmpPrivProtocol | None = Field(
        default=None,
        description="v3, required with a privacy passphrase. AES is AES-128. AES192/AES256 use the "
        "standard key extension; AES192C/AES256C the one Cisco devices use for AES-192/256.",
    )
    priv_password: SecretStr | None = None
    context_name: str = Field(default="", max_length=32)

    @field_validator("version", mode="before")
    @classmethod
    def normalize_version(cls, value):
        return snmp_version(value)

    @model_validator(mode="after")
    def valid(self):
        if self.version == "3" and self.security_level is None:
            self.security_level = (
                "authPriv" if self.priv_password else "authNoPriv" if self.auth_password else "noAuthNoPriv"
            )
        plain = self.plaintext()
        if self.version != "3" and (self.security_level or self.auth_protocol or self.priv_protocol):
            raise ValueError("SNMP v1/v2c uses only a community; remove the v3 settings")
        check_snmp(plain)
        if self.version == "3":
            level = self.security_level
            if (level != "noAuthNoPriv") != (self.auth_protocol is not None):
                raise ValueError("auth_protocol is required with authentication, and only then")
            if (level == "authPriv") != (self.priv_protocol is not None):
                raise ValueError("priv_protocol is required with privacy, and only then")
        return self

    def plaintext(self):
        return {
            key: value.get_secret_value() if isinstance(value, SecretStr) else value
            for key, value in self.__dict__.items()
        }


def numeric_oid_list(values):
    normalized = []
    for value in values:
        parts = value.removeprefix(".").split(".")
        if not 2 <= len(parts) <= 128 or any(
            not p.isascii() or not p.isdecimal() or len(p) > 10 for p in parts
        ):
            raise ValueError("use numeric OIDs with 2 to 128 arcs")
        arcs = [int(p) for p in parts]
        if arcs[0] > 2 or (arcs[0] < 2 and arcs[1] > 39) or max(arcs) > 4294967295:
            raise ValueError("OID arcs are out of range")
        normalized.append(".".join(map(str, arcs)))
    if len(set(normalized)) != len(normalized):
        raise ValueError("duplicate OIDs")
    return normalized


class SnmpWalkRequest(ScheduledRequest):
    device_ip: IPvAnyAddress
    site: str | None = Field(
        default=None,
        min_length=1,
        max_length=100,
        pattern=r"^[^\x00-\x1f\x7f]+$",
        description="NetBox site name. Supplying a site enables basic device discovery and sync.",
        examples=["Sydney"],
    )
    poller_instance: PollerInstance | None = Field(
        default=None,
        description="Collecting instance tag. Defaults to the executor's configured instance.",
        examples=["checkmk-au"],
    )
    oids: list[str] = Field(
        default_factory=list,
        max_length=64,
        description="Subtree roots to walk. A root with an empty subtree is read with GET, so a scalar instance such as 1.3.6.1.2.1.1.5.0 also works.",
    )
    get_oids: list[str] = Field(
        default_factory=list,
        max_length=256,
        description="Exact instance OIDs read with GET, several per request. Absent instances are reported as missing.",
    )
    credentials: list[SnmpCredential] = Field(
        default_factory=list,
        max_length=10,
        exclude=True,
        description="SNMP credentials to try first, in order, before any saved or configured "
        "profile. Held encrypted apart from the job (requires NETOPS_CREDENTIAL_KEY_FILE) and erased "
        "when it finishes. The job's result.request_credentials shows them with secrets masked "
        "to their first three characters.",
    )
    use_profiles: bool = Field(
        default=True,
        description="After request credentials, also try saved and configured profiles. false tries "
        "only the request's credentials.",
    )
    credential_count: int = Field(
        default=0,
        ge=0,
        le=10,
        description="Set by the executor: how many request credentials the job holds encrypted. "
        "Ignored in requests.",
        json_schema_extra={"readOnly": True},
    )
    profile: Name | None = None
    credential_profiles: list[Name] | None = Field(default=None, min_length=1, max_length=10)
    manual_fallback: ManualFallback = Field(
        default_factory=ManualFallback,
        description="Values used only for blank identity fields. Can seed NetBox after a failed poll; no discovered tag is added.",
    )
    identity_rules: list[IdentityRule] = Field(
        default_factory=list,
        max_length=20,
        description="Per-job OID/regex identity rules, applied after the deployed YAML rules.",
    )
    collect_neighbors: bool = Field(
        default=True, description="Collect bounded LLDP/CDP neighbor tables during discovery."
    )
    enrich_ssh: bool = Field(
        default=True, description="Read licenses, HA and readiness with eligible saved SSH profiles."
    )
    backup_config: bool = Field(
        default=False, description="Save a private read-only configuration backup during SSH enrichment."
    )
    port: int = Field(default=161, ge=1, le=65535)
    timeout: float = Field(default=2, ge=0.1, le=30)
    retries: int = Field(default=1, ge=0, le=5)
    job_timeout: int = Field(default=300, ge=1, le=3600)
    max_rows: int = Field(default=10000, ge=1, le=100000)
    walk_mode: Literal["auto", "bulk", "next"] = Field(
        default="auto",
        description="auto: GETBULK, lowering max_repetitions after tooBig or a timeout and falling back to GETNEXT. bulk: GETBULK with size reduction only. next: GETNEXT only.",
    )
    max_repetitions: int = Field(
        default=25, ge=1, le=100, description="GETBULK rows requested per round trip before any reduction."
    )
    request_interval: float = Field(
        default=0, ge=0, le=10, description="Seconds to wait between requests, for agents that rate-limit."
    )

    @model_validator(mode="after")
    def select_profiles(self):
        if (self.manual_fallback.model_dump(exclude_none=True) or self.identity_rules) and not self.site:
            raise ValueError("manual_fallback and identity_rules require a discovery site")
        if self.profile and self.credential_profiles:
            raise ValueError("use profile or credential_profiles, not both")
        if not self.use_profiles:
            if self.profile or self.credential_profiles:
                raise ValueError("profile and credential_profiles need use_profiles")
            if not self.credentials and not self.credential_count:
                raise ValueError("use_profiles false needs credentials")
        if self.poller_instance and not self.site:
            raise ValueError("poller_instance requires a site")
        if not self.site and not self.oids and not self.get_oids:
            raise ValueError("request a site for discovery or at least one OID in oids or get_oids")
        return self

    @field_validator("site", mode="before")
    @classmethod
    def strip_site(cls, value):
        return value.strip() if isinstance(value, str) else value

    @field_validator("device_ip")
    @classmethod
    def unscoped_ip(cls, value):
        if "%" in str(value):
            raise ValueError("IPv6 scope identifiers are not supported")
        return value

    @field_validator("oids", "get_oids")
    @classmethod
    def numeric_oids(cls, values):
        return numeric_oid_list(values)


class SnmpRow(Model):
    seq: int
    root_oid: str
    oid: str
    type: str
    value: str
    encoding: Literal["text", "base64"]


class SnmpResults(Model):
    id: str
    status: str
    finished: bool
    rows: list[SnmpRow]
    next_cursor: int
    has_more: bool
