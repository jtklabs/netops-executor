"""Arista EOS upgrades over SSH: requests, policies and batches."""

from pathlib import PurePosixPath
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

from .models import Model, Name, ScheduledRequest
from .panos_models import merged, within_window

EosVersion = Annotated[str, Field(pattern=r"^\d{1,2}\.\d{1,3}\.\d{1,3}(?:\.\d{1,3})?[A-Z]{0,3}$")]


class EosImage(Model):
    """The .swi the switch boots. sha256 verifies the executor's copy; the switch verifies SHA-512."""

    name: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,159}\.swi$")]
    sha256: Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
    sha512: Annotated[str, Field(pattern=r"^[a-f0-9]{128}$")] | None = Field(
        default=None,
        description="Expected switch-side SHA-512; default computed from the executor's verified copy",
    )
    source_url: str | None = Field(
        default=None, max_length=4096, description="Optional HTTPS download source"
    )

    @field_validator("sha256", "sha512", mode="before")
    @classmethod
    def lower(cls, value):
        return value.lower() if isinstance(value, str) else value


class EosValidationPolicy(Model):
    noncritical_differences: Literal["warn", "require_review"] = "warn"
    on_timeout: Literal["needs_review", "fail"] = "needs_review"
    consecutive_passes: int = Field(default=2, ge=1, le=10)
    settling_seconds: int = Field(default=120, ge=0, le=3600)
    sample_interval_seconds: int = Field(default=15, ge=1, le=300)
    restore_required: bool = Field(
        default=True,
        description="Interfaces that were connected, LLDP neighbors, Established BGP peers, FULL OSPF neighbors and active port-channel members must recover; false reports them as warnings.",
    )
    min_route_percent: float | None = Field(default=90, ge=0, le=100)
    min_mac_percent: float | None = Field(default=None, ge=0, le=100)
    min_arp_percent: float | None = Field(default=None, ge=0, le=100)


class EosUpgradeRequest(ScheduledRequest):
    device: str = Field(min_length=1, max_length=253, description="Switch inventory ID or management IP")
    credential_profiles: list[Name] | None = Field(default=None, min_length=1, max_length=10)
    target_version: EosVersion
    image: EosImage
    allowed_source_versions: list[EosVersion] = Field(min_length=1, max_length=200)
    approved_models: list[str] = Field(default_factory=list, max_length=100)
    mlag_peer: str | None = Field(
        default=None,
        max_length=253,
        description="MLAG peer inventory ID or IP: reserved so it never reloads at the same time, and checked healthy before this reload",
    )
    stage_only: bool = Field(
        default=False,
        description="Preload: copy and verify the image ahead of the window; no backups, saves, install or reload.",
    )
    config_backup: bool = True
    tech_support: bool = Field(default=True, description="Save show tech-support before changes.")
    save_config: bool = Field(
        default=True, description="write memory when running and startup configuration differ before install"
    )
    backup_directory: str | None = Field(default=None, max_length=240)
    minimum_free_bytes: int = Field(
        default=500_000_000, ge=0, description="Flash reserve kept free after the image"
    )
    validation_policy: EosValidationPolicy = Field(default_factory=EosValidationPolicy)
    upload_timeout: int = Field(default=3600, ge=60, le=14400)
    install_timeout: int = Field(default=1800, ge=60, le=7200)
    reboot_timeout: int = Field(default=1800, ge=300, le=7200)
    validation_timeout: int = Field(default=900, ge=0, le=86400)

    @model_validator(mode="after")
    def coherent(self):
        if self.backup_directory is not None:
            p = PurePosixPath(self.backup_directory)
            if p.is_absolute() or ".." in p.parts or not p.parts:
                raise ValueError("backup_directory must be a relative directory under BACKUP_ROOT")
        if self.mlag_peer is not None and self.mlag_peer == self.device:
            raise ValueError("mlag_peer must be the other switch")
        return self

    def plan(self):
        steps = ["reserve_switch_and_mlag_peer", "prevalidate", "flash_image_upload_and_sha512"]
        if self.stage_only:
            return steps
        steps = steps[:2] + (["backup"] if self.config_backup or self.tech_support else []) + steps[2:]
        return steps + [
            "write_memory_if_unsaved",
            "install_source_now_reload",
            "verify_new_boot",
            "validate_system",
            "validate_traffic",
        ]


class EosWave(Model):
    wave: int = Field(ge=1)
    upgrade_at_a_time: int = Field(default=1, ge=1, le=100)
    devices: list[str] = Field(min_length=1, max_length=1000)

    @property
    def members(self):
        return self.devices


class EosBatch(ScheduledRequest):
    name: str = Field(min_length=1, max_length=160)
    defaults: dict = Field(default_factory=dict)
    overrides: dict[str, dict] = Field(default_factory=dict)
    waves: list[EosWave] = Field(min_length=1, max_length=100)

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
        request = EosUpgradeRequest.model_validate(
            {**merged(self.defaults, self.overrides.get(device, {})), "device": device}
        )
        return within_window(self, request)
