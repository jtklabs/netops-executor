"""SNMP v3 requests and server-side credential references."""

from typing import Annotated, Literal

from pydantic import Field, IPvAnyAddress, field_validator, model_validator

from .models import Model, Name, ScheduledRequest

EnvName = Annotated[str, Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]*$", max_length=128)]


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
    profile: Name | None = None
    credential_profiles: list[Name] | None = Field(default=None, min_length=1, max_length=10)
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
        if self.profile and self.credential_profiles:
            raise ValueError("use profile or credential_profiles, not both")
        if not self.oids and not self.get_oids:
            raise ValueError("request at least one OID in oids or get_oids")
        return self

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
