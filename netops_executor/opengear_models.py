"""Legacy IM7200 console-server firmware upgrades over SSH (not OM/ogcli)."""

from pathlib import PurePosixPath
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

from .models import Model, Name, ScheduledRequest
from .panos_models import merged, within_window

OpengearVersion = Annotated[str, Field(pattern=r"^\d{1,2}\.\d{1,3}\.\d{1,3}(?:u\d{1,3})?$")]


class OpengearImage(Model):
    name: Annotated[str, Field(pattern=r"^im72xx(?:[-_.][A-Za-z0-9._-]{1,120})?\.flash$")]
    sha256: Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
    source_url: str | None = Field(default=None, max_length=4096, description="Optional HTTPS image source")

    @field_validator("sha256", mode="before")
    @classmethod
    def lower(cls, value):
        return value.lower() if isinstance(value, str) else value


class OpengearValidationPolicy(Model):
    noncritical_differences: Literal["warn", "require_review"] = "warn"
    on_timeout: Literal["needs_review", "fail"] = "needs_review"
    consecutive_passes: int = Field(default=2, ge=1, le=10)
    settling_seconds: int = Field(default=60, ge=0, le=3600)
    sample_interval_seconds: int = Field(default=15, ge=1, le=300)
    restore_interfaces: bool = Field(
        default=False, description="Require previously up physical Ethernet links to return; otherwise warn"
    )


class OpengearUpgradeRequest(ScheduledRequest):
    device: str = Field(min_length=1, max_length=253, description="IM7200 inventory ID or management IP")
    credential_profiles: list[Name] | None = Field(default=None, min_length=1, max_length=10)
    target_version: OpengearVersion
    allowed_source_versions: list[OpengearVersion] = Field(min_length=1, max_length=200)
    image: OpengearImage
    approved_models: list[str] = Field(default_factory=list, max_length=100)
    stage_only: bool = Field(
        default=False, description="Copy and verify firmware only; no backup, netflash or reboot"
    )
    config_backup: bool = Field(default=True, description="Download a private .opg backup before flashing")
    backup_directory: str | None = Field(default=None, max_length=240)
    staging_directory: str = Field(
        default="/tmp",
        max_length=200,
        description="Existing device directory; /tmp is lost on reboot. Use mounted /var/mnt/storage.usb for persistent preloads.",
    )
    minimum_free_bytes: int = Field(default=32 * 1024**2, ge=0, le=2**40)
    upload_timeout: int = Field(default=3600, ge=60, le=14400)
    install_timeout: int = Field(default=900, ge=60, le=7200)
    reboot_timeout: int = Field(default=900, ge=60, le=7200)
    validation_timeout: int = Field(default=600, ge=0, le=86400)
    validation_policy: OpengearValidationPolicy = Field(default_factory=OpengearValidationPolicy)

    @model_validator(mode="after")
    def coherent(self):
        if self.backup_directory is not None:
            p = PurePosixPath(self.backup_directory)
            if p.is_absolute() or ".." in p.parts or not p.parts:
                raise ValueError("backup_directory must be relative to BACKUP_ROOT")
        p = PurePosixPath(self.staging_directory)
        if (
            not p.is_absolute()
            or ".." in p.parts
            or str(p) == "/"
            or any(
                c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/._-"
                for c in self.staging_directory
            )
        ):
            raise ValueError("staging_directory must be a non-root absolute path without traversal")
        self.staging_directory = str(p)
        return self

    def plan(self):
        steps = ["reserve_device", "prevalidate"]
        if self.config_backup and not self.stage_only:
            steps.append("backup")
        steps.append("stage_and_verify_sha256")
        if not self.stage_only:
            steps += ["netflash_and_reboot", "verify_new_boot", "settle", "validate_system"]
        return steps


class OpengearWave(Model):
    wave: int = Field(ge=1)
    upgrade_at_a_time: int = Field(default=1, ge=1, le=100)
    devices: list[str] = Field(min_length=1, max_length=1000)

    @property
    def members(self):
        return self.devices


class OpengearBatch(ScheduledRequest):
    name: str = Field(min_length=1, max_length=160)
    defaults: dict = Field(default_factory=dict)
    overrides: dict[str, dict] = Field(default_factory=dict)
    waves: list[OpengearWave] = Field(min_length=1, max_length=100)

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
        request = OpengearUpgradeRequest.model_validate(
            {**merged(self.defaults, self.overrides.get(device, {})), "device": device}
        )
        return within_window(self, request)
