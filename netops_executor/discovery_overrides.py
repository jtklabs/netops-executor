"""Validated, bounded identity rules loaded alongside the executor."""

import hashlib
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Annotated, Literal

import regex
import yaml
from pydantic import Field, field_validator, model_validator

from .models import Model, Name

IdentityField = Literal["name", "manufacturer", "model", "platform", "serial", "software_version"]
IdentityValue = Annotated[str, Field(min_length=1, max_length=200, pattern=r"^[^\x00-\x1f\x7f]+$")]


class ManualFallback(Model):
    name: IdentityValue | None = None
    manufacturer: IdentityValue | None = None
    model: IdentityValue | None = None
    platform: IdentityValue | None = None
    serial: IdentityValue | None = None
    software_version: IdentityValue | None = None

    @field_validator("*", mode="before")
    @classmethod
    def trim(cls, value):
        return value.strip() if isinstance(value, str) else value


class IdentityMatch(Model):
    sys_object_id_prefix: str | None = Field(default=None, max_length=1024)
    manufacturer: str | None = Field(default=None, max_length=200)
    platform: str | None = Field(default=None, max_length=200)
    sys_descr_regex: str | None = Field(default=None, max_length=1024)
    hostname_regex: str | None = Field(default=None, max_length=1024)
    network: str | None = Field(default=None, max_length=64)

    @model_validator(mode="after")
    def valid(self):
        if not any(self.model_dump().values()):
            raise ValueError("A rule needs at least one match condition")
        for value in (self.sys_descr_regex, self.hostname_regex):
            if value:
                try:
                    regex.compile(value)
                except regex.error:
                    raise ValueError("Invalid match regex") from None
        if self.network:
            ip_network(self.network)
        if self.sys_object_id_prefix:
            self.sys_object_id_prefix = numeric_oid(self.sys_object_id_prefix)
        return self


class IdentityReader(Model):
    value: IdentityValue | None = None
    oid: str | None = Field(default=None, max_length=1024)
    source: Literal["sysDescr", "sysName", "sysObjectID"] | None = None
    walk: bool = False
    regex: str | None = Field(default=None, max_length=1024)
    group: int | str = 1

    @field_validator("oid")
    @classmethod
    def valid_oid(cls, value):
        return numeric_oid(value) if value else value

    @model_validator(mode="after")
    def valid(self):
        if sum(v is not None for v in (self.value, self.oid, self.source)) != 1:
            raise ValueError("Choose exactly one of value, oid or source")
        if self.walk and not self.oid:
            raise ValueError("walk requires an oid")
        if self.value and self.regex:
            raise ValueError("A fixed value does not use a regex")
        if self.regex:
            try:
                compiled = regex.compile(self.regex)
            except regex.error:
                raise ValueError("Invalid extraction regex") from None
            if isinstance(self.group, int):
                if not 0 <= self.group <= compiled.groups:
                    raise ValueError("Regex group does not exist")
            elif self.group not in compiled.groupindex:
                raise ValueError("Named regex group does not exist")
        return self


class IdentityRule(Model):
    id: Name
    match: IdentityMatch
    mode: Literal["fallback", "replace"] = "fallback"
    fields: dict[IdentityField, IdentityReader] = Field(min_length=1, max_length=6)


class OverrideFile(Model):
    version: Literal[1]
    rules: list[IdentityRule] = Field(max_length=100)

    @field_validator("rules")
    @classmethod
    def unique_ids(cls, rules):
        if len({r.id for r in rules}) != len(rules):
            raise ValueError("Duplicate rule IDs")
        return rules


def numeric_oid(value):
    parts = value.removeprefix(".").split(".")
    if not 2 <= len(parts) <= 128 or any(not p.isascii() or not p.isdecimal() or len(p) > 10 for p in parts):
        raise ValueError("Use a numeric OID")
    arcs = [int(p) for p in parts]
    if arcs[0] > 2 or (arcs[0] < 2 and arcs[1] > 39) or max(arcs) > 4294967295:
        raise ValueError("Invalid OID arcs")
    return ".".join(map(str, arcs))


class UniqueSafeLoader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        keys = [self.construct_object(k, deep=deep) for k, _ in node.value]
        if len(keys) != len(set(keys)):
            raise ValueError("Duplicate YAML key")
        return super().construct_mapping(node, deep)


def load_rules(path):
    if not path:
        return [], None
    try:
        with Path(path).open("rb") as handle:
            data = handle.read(1024 * 1024 + 1)
        if len(data) > 1024 * 1024:
            raise ValueError("Override file exceeds 1 MiB")
        parsed = OverrideFile.model_validate(yaml.load(data, Loader=UniqueSafeLoader))
        return parsed.rules, hashlib.sha256(data).hexdigest()
    except (OSError, ValueError, TypeError, yaml.YAMLError, RecursionError):
        # Validation errors can embed the original values; keep diagnostics structural.
        raise ValueError(
            "Invalid discovery overrides file; check YAML, rule fields, OIDs and regex groups"
        ) from None


def matches(rule, facts, system, address):
    match = rule.match
    if match.sys_object_id_prefix:
        oid = system.get("sysObjectID", "").removeprefix(".")
        if oid != match.sys_object_id_prefix and not oid.startswith(match.sys_object_id_prefix + "."):
            return False
    if match.manufacturer and facts.get("manufacturer", "").casefold() != match.manufacturer.casefold():
        return False
    if match.platform and facts.get("platform", "").casefold() != match.platform.casefold():
        return False
    if match.network and ip_address(address) not in ip_network(match.network):
        return False
    for pattern, value in (
        (match.sys_descr_regex, system.get("sysDescr", "")),
        (match.hostname_regex, facts.get("name", "")),
    ):
        if pattern and not regex.search(pattern, value[:8192], timeout=0.05):
            return False
    return True


def extracted(reader, value):
    if reader.regex:
        match = regex.search(reader.regex, value[:8192], timeout=0.05)
        value = match.group(reader.group) if match else ""
    value = (value or "").strip()
    if not value or len(value) > 200 or any(ord(c) < 32 or ord(c) == 127 for c in value):
        return ""
    return value


async def apply_rules(facts, system, address, get, walk_column, rules):
    sources = facts.setdefault(
        "field_sources",
        {
            k: "observed"
            for k in ("name", "manufacturer", "model", "platform", "serial", "software_version")
            if facts.get(k)
        },
    )
    details = []
    for rule in rules:
        try:
            applies = matches(rule, facts, system, address)
        except TimeoutError:
            details.append({"rule": rule.id, "status": "failed", "reason": "Match regex exceeded time limit"})
            continue
        if not applies:
            continue
        for key, reader in rule.fields.items():
            if rule.mode == "fallback" and facts.get(key):
                continue
            try:
                value = ""
                if reader.value is not None:
                    value = reader.value
                elif reader.source:
                    value = extracted(reader, system.get(reader.source, ""))
                elif reader.walk:
                    async for _, raw in walk_column(reader.oid, bulk=True, limit=256):
                        if value := extracted(reader, raw):
                            break
                else:
                    value = extracted(reader, (await get([reader.oid])).get(reader.oid, ""))
            except Exception as error:
                # Cancellation/lost ownership must propagate, never become a per-field gap.
                from .store import CancelRequested, LostOwnership

                if isinstance(error, (CancelRequested, LostOwnership)):
                    raise
                details.append(
                    {
                        "rule": rule.id,
                        "field": key,
                        "status": "failed",
                        "reason": "Regex exceeded time limit"
                        if isinstance(error, TimeoutError)
                        else "OID read or extraction failed",
                    }
                )
                continue
            if value:
                facts[key] = value
                sources[key] = "manual" if reader.value is not None else "observed"
                details.append(
                    {
                        "rule": rule.id,
                        "field": key,
                        "status": "applied",
                        "source": sources[key],
                        "oid": reader.oid,
                        "mode": rule.mode,
                    }
                )
            else:
                details.append(
                    {
                        "rule": rule.id,
                        "field": key,
                        "status": "missing",
                        "reason": "No usable value or regex match",
                    }
                )
    facts["identity_rules"] = details


def apply_manual_fallback(facts, fallback):
    sources = facts.setdefault(
        "field_sources",
        {
            k: "observed"
            for k in ("name", "manufacturer", "model", "platform", "serial", "software_version")
            if facts.get(k)
        },
    )
    for key, value in fallback.model_dump(exclude_none=True).items():
        if not facts.get(key):
            facts[key] = value
            sources[key] = "manual"
