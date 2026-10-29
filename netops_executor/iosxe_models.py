"""Cisco IOS XE switch upgrades over SSH: requests, policies and batches."""

import re
from pathlib import PurePosixPath
from typing import Annotated, ClassVar, Literal
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator

from .models import Model, Name, ScheduledRequest
from .panos_models import merged, within_window

IosxeVersion = Annotated[str, Field(pattern=r"^\d{1,2}\.\d{1,2}\.\d{1,2}[a-z]?$")]
Pattern = Annotated[str, Field(min_length=1, max_length=500)]


def compiles(value):
    try:
        re.compile(value)
    except re.error as exc:
        raise ValueError("invalid regular expression: " + str(exc)) from None
    return value


def release(value):
    """`17.09.05` and `17.9.5` are the same release; the letter suffix is part of it."""
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)([a-z]?)", str(value))
    if not match:
        raise ValueError("invalid IOS XE release: " + str(value))
    return tuple(int(x) for x in match.groups()[:3]) + (match[4],)


class IosxeImage(Model):
    """The install-mode .bin. sha256 verifies the executor's copy; the switch verifies sha512 or md5."""

    name: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,159}\.bin$")]
    sha256: Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
    verify: Literal["sha512", "md5"] = Field(
        default="sha512", description="Checksum the switch computes with verify /<algorithm>"
    )
    sha512: Annotated[str, Field(pattern=r"^[a-f0-9]{128}$")] | None = Field(
        default=None,
        description="Cisco-published SHA-512; default computed from the executor's verified copy",
    )
    md5: Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")] | None = Field(
        default=None, description="Cisco-published MD5; default computed from the executor's verified copy"
    )
    source_url: str | None = Field(
        default=None, max_length=4096, description="Optional HTTPS source the executor downloads from"
    )
    device_url: str | None = Field(
        default=None,
        max_length=1024,
        description="Optional http, https, ftp or tftp URL the switch copies from itself; SCP from the executor is the fallback",
    )

    @field_validator("sha256", "sha512", "md5", mode="before")
    @classmethod
    def lower(cls, value):
        return value.lower() if isinstance(value, str) else value

    @field_validator("device_url")
    @classmethod
    def device_source(cls, value):
        if value is not None:
            parsed = urlsplit(value)
            if (
                parsed.scheme not in ("http", "https", "ftp", "tftp")
                or not parsed.hostname
                or parsed.username
                or parsed.password
                or parsed.query
                or re.search(r"\s", value)
            ):
                raise ValueError(
                    "device_url must be an http, https, ftp or tftp URL without credentials or query"
                )
        return value


class ConfigIgnore(Model):
    name: str | None = Field(default=None, max_length=80)
    line: Pattern = Field(
        description="Regex for a canonical line; a matching section is ignored with its children"
    )
    parent: Pattern | None = Field(default=None, description="Only under a parent line matching this regex")

    @field_validator("line", "parent")
    @classmethod
    def regex(cls, value):
        return value if value is None else compiles(value)


class ConfigRewrite(ConfigIgnore):
    replace: str = Field(max_length=500, description="Replacement; \\1 refers to a group in line")


class IosxeConfigPolicy(Model):
    """How the post-upgrade running configuration is compared with the baseline."""

    builtin_rules: bool = Field(
        default=True,
        description="Apply the built-in IOS XE rewrites, generated-section ignores and ordered sections",
    )
    ignore: list[ConfigIgnore] = Field(default_factory=list, max_length=200)
    rewrite: list[ConfigRewrite] = Field(default_factory=list, max_length=200)
    ordered_sections: list[Pattern] = Field(
        default_factory=list,
        max_length=50,
        description="Extra parent-line regexes whose children are compared in order",
    )
    added: Literal["ignore", "warn", "critical"] = "warn"
    removed: Literal["ignore", "warn", "critical"] = "warn"

    @field_validator("ordered_sections")
    @classmethod
    def regexes(cls, value):
        return [compiles(p) for p in value]


class IosxeValidationPolicy(Model):
    noncritical_differences: Literal["warn", "require_review"] = "warn"
    on_timeout: Literal["needs_review", "fail"] = "needs_review"
    consecutive_passes: int = Field(default=2, ge=1, le=10)
    settling_seconds: int = Field(default=180, ge=0, le=3600)
    sample_interval_seconds: int = Field(default=20, ge=1, le=300)
    restore_required: bool = Field(
        default=True,
        description="Interfaces that were up/up, CDP and LLDP neighbors, Established BGP peers, FULL OSPF neighbors and bundled port-channel members must recover; false reports them as warnings.",
    )
    min_route_percent: float | None = Field(default=90, ge=0, le=100)
    min_mac_percent: float | None = Field(default=None, ge=0, le=100)
    min_arp_percent: float | None = Field(default=None, ge=0, le=100)
    min_access_session_percent: float | None = Field(default=None, ge=0, le=100)


class IosxeUpgradeRequest(ScheduledRequest):
    device: str = Field(min_length=1, max_length=253, description="Switch inventory ID or management IP")
    credential_profiles: list[Name] | None = Field(default=None, min_length=1, max_length=10)
    target_version: IosxeVersion
    image: IosxeImage
    allowed_source_versions: list[IosxeVersion] = Field(min_length=1, max_length=200)
    approved_models: list[str] = Field(
        default_factory=list, max_length=100, description="Optional exact show version model allowlist"
    )
    peers: list[str] = Field(
        default_factory=list,
        max_length=10,
        description="Inventory IDs or IPs reserved for the whole job so they never reload at the same time (HSRP partners, redundant uplinks)",
    )
    stage_only: bool = Field(
        default=False,
        description="Preload: copy and verify the image ahead of the window; no backups, boot changes or install.",
    )
    config_backup: bool = True
    tech_support: bool = Field(default=True, description="Save show tech-support before changes.")
    save_config: bool = Field(
        default=True, description="write memory when running and startup configuration differ before install"
    )
    save_after_validation: bool = Field(
        default=True,
        description="write memory once validation passes so startup-config uses the new release's syntax; skipped when lines were removed",
    )
    remove_inactive: bool = Field(
        default=True,
        description="Run install remove inactive before copying when inactive packages exist or flash is short",
    )
    allow_bundle_conversion: bool = Field(
        default=False, description="Allow a BUNDLE-mode switch to be converted to INSTALL mode by the install"
    )
    config_policy: IosxeConfigPolicy = Field(default_factory=IosxeConfigPolicy)
    backup_directory: str | None = Field(default=None, max_length=240)
    minimum_free_bytes: int = Field(
        default=1_500_000_000,
        ge=0,
        description="Flash kept free beyond the image on every member, for expansion",
    )
    validation_policy: IosxeValidationPolicy = Field(default_factory=IosxeValidationPolicy)
    upload_timeout: int = Field(default=5400, ge=60, le=14400)
    install_timeout: int = Field(default=3600, ge=300, le=7200)
    reboot_timeout: int = Field(default=2700, ge=300, le=7200)
    validation_timeout: int = Field(default=1200, ge=0, le=86400)

    @model_validator(mode="after")
    def coherent(self):
        if self.backup_directory is not None:
            p = PurePosixPath(self.backup_directory)
            if p.is_absolute() or ".." in p.parts or not p.parts:
                raise ValueError("backup_directory must be a relative directory under BACKUP_ROOT")
        if self.device in self.peers:
            raise ValueError("peers must be other devices")
        found = re.search(r"\.(\d+\.\d+\.\d+[a-z]?)\.", self.image.name)
        if not found or release(found[1]) != release(self.target_version):
            raise ValueError("image filename release must match target_version")
        return self

    def plan(self):
        steps = [
            "reserve_switch_and_peers",
            "prevalidate",
            "remove_inactive_if_needed",
            "flash_image_copy_and_verify",
        ]
        if self.stage_only:
            return steps
        return (
            steps[:2]
            + (["backup"] if self.config_backup or self.tech_support else [])
            + steps[2:]
            + [
                "write_memory_if_unsaved",
                "boot_packages_conf_if_needed",
                "install_add_activate_commit",
                "verify_stack_on_target",
                "validate_system_and_config",
                "validate_traffic",
            ]
            + (["write_memory_after_validation"] if self.save_after_validation else [])
        )


class IosxeWave(Model):
    wave: int = Field(ge=1)
    upgrade_at_a_time: int = Field(default=1, ge=1, le=100)
    devices: list[str] = Field(min_length=1, max_length=1000)

    @property
    def members(self):
        return self.devices


class IosxeBatch(ScheduledRequest):
    request_model: ClassVar = None
    name: str = Field(min_length=1, max_length=160)
    defaults: dict = Field(default_factory=dict)
    overrides: dict[str, dict] = Field(default_factory=dict)
    waves: list[IosxeWave] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def valid(self):
        numbers = [w.wave for w in self.waves]
        if numbers != sorted(set(numbers)):
            raise ValueError("waves must be unique and increasing")
        devices = [d for w in self.waves for d in w.devices]
        if len(devices) != len(set(devices)) or len(devices) > 1000:
            raise ValueError("batch must contain at most 1000 unique devices")
        if not set(self.overrides) <= set(devices):
            raise ValueError("overrides must reference devices in this batch")
        for device in devices:
            self.request_for(device)
        return self

    def request_for(self, device):
        request = self.request_model.model_validate(
            {**merged(self.defaults, self.overrides.get(device, {})), "device": device}
        )
        return within_window(self, request)


IosxeBatch.request_model = IosxeUpgradeRequest


class ConfigComparison(Model):
    before: str = Field(min_length=1, max_length=8_000_000, description="Baseline show running-config")
    after: str = Field(min_length=1, max_length=8_000_000, description="Post-upgrade show running-config")
    config_policy: IosxeConfigPolicy = Field(default_factory=IosxeConfigPolicy)
