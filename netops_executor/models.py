from pathlib import PurePosixPath
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

Name = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,159}$")]
Version = Annotated[str, Field(pattern=r"^\d+(?:\.\d+){1,5}$")]
Volume = Annotated[str, Field(pattern=r"^(?:HD|MD)\d+\.\d+$")]


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Image(Model):
    name: Name
    sha256: Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
    version: Version
    build: Version
    kind: Literal["image", "hotfix"] = "image"
    source_url: str | None = Field(default=None, max_length=4096)


class ValidationPolicy(Model):
    noncritical_differences: Literal["warn", "require_review"] = "warn"
    on_timeout: Literal["needs_review", "fail"] = "needs_review"
    consecutive_passes: int = Field(default=2, ge=1, le=10)
    settling_seconds: int = Field(default=30, ge=0, le=3600)
    waf_request_check: bool = False
    ltm_min_unchanged_percent: float = Field(default=100, ge=0, le=100)
    waf_min_unchanged_percent: float = Field(default=100, ge=0, le=100)


class HAPolicy(Model):
    allow_active_first: bool = True
    require_healthy_peer: Literal[True] = True
    sync_after_upgrade: bool = True


class StandaloneDrain(Model):
    enabled: bool = True
    remaining_connections: int | None = Field(default=None, ge=0)
    reduction_percent: float | None = Field(default=None, ge=0, le=100)
    timeout_seconds: int = Field(default=600, ge=0, le=86400)
    reboot_on_timeout: bool = False


class JobRequest(Model):
    device: str = Field(min_length=1, max_length=253)
    credential_profiles: list[Name] | None = Field(default=None, min_length=1, max_length=10)
    ucs_credential: Name | None = None
    validation_policy: ValidationPolicy = Field(default_factory=ValidationPolicy)
    ha_policy: HAPolicy = Field(default_factory=HAPolicy)
    standalone_drain: StandaloneDrain | None = None
    approved_models: list[str] = Field(default_factory=list)
    license_check_date: str | None = Field(default=None, pattern=r"^\d{4}-\d{2}-\d{2}$")
    minimum_free_bytes: int = Field(default=1500000000, ge=0)
    cleanup_images: bool = False
    transfer: bool = False
    images_on_device: bool = False
    images: list[Image] = Field(default_factory=list, max_length=10)
    create_ucs: bool = False
    ucs_unencrypted: bool = False
    backup_directory: str | None = Field(default=None, max_length=240)
    install: bool = False
    target_volume: Volume | None = None
    allowed_source_versions: list[Version] = Field(default_factory=list, max_length=100)
    expected_version: Version | None = None
    expected_build: Version | None = None
    reboot: bool = False
    drain: bool = False
    drain_connections: int | None = Field(default=None, ge=0)
    drain_percent: float | None = Field(default=None, ge=0, le=100)
    drain_timeout: int = Field(default=300, ge=0, le=86400)
    reboot_on_drain_timeout: bool = False
    install_timeout: int = Field(default=3600, ge=60, le=86400)
    reboot_timeout: int = Field(default=900, ge=60, le=7200)
    validation_timeout: int = Field(default=600, ge=0, le=86400)

    @model_validator(mode="after")
    def coherent(self):
        if self.standalone_drain and self.standalone_drain.enabled:
            d = self.standalone_drain
            self.drain = True
            self.drain_connections, self.drain_percent = d.remaining_connections, d.reduction_percent
            self.drain_timeout, self.reboot_on_drain_timeout = d.timeout_seconds, d.reboot_on_timeout
        if self.backup_directory is not None:
            p = PurePosixPath(self.backup_directory)
            if p.is_absolute() or ".." in p.parts or not p.parts:
                raise ValueError("backup_directory must be a relative directory under BACKUP_ROOT")
        if self.drain_connections is not None and self.drain_percent is not None:
            raise ValueError("choose a connection count or a percent to drain, not both")
        if self.drain_connections is not None or self.drain_percent is not None:
            self.drain = True
        if self.validation_policy.waf_request_check and not self.reboot:
            raise ValueError("WAF request validation requires reboot")
        if self.drain and not self.reboot:
            raise ValueError("drain requires reboot")
        if self.reboot_on_drain_timeout and not self.drain:
            raise ValueError("reboot_on_drain_timeout requires drain")
        if self.images_on_device and self.transfer:
            raise ValueError("images_on_device conflicts with transfer")
        if (self.install or self.transfer) and not self.images:
            raise ValueError("install and transfer require images with SHA-256, version and build")
        if len({i.name for i in self.images}) != len(self.images):
            raise ValueError("image names must be unique")
        if self.install or self.reboot:
            if not self.allowed_source_versions:
                raise ValueError("install/reboot require allowed_source_versions")
        if self.install:
            final = self.images[-1]
            if self.expected_version and self.expected_version != final.version:
                raise ValueError("expected_version must match final image")
            if self.expected_build and self.expected_build != final.build:
                raise ValueError("expected_build must match final image")
            self.expected_version, self.expected_build = final.version, final.build
        if self.reboot and (not self.expected_version or not self.expected_build):
            raise ValueError("reboot requires expected_version and expected_build")
        return self

    def plan(self):
        steps = ["prevalidate"]
        if self.create_ucs or self.ucs_unencrypted or self.backup_directory or self.install or self.reboot:
            steps += ["save_config", "create_ucs", "copy_ucs"]
        if self.transfer or (self.install and not self.images_on_device):
            steps += ["transfer"]
        if self.install:
            steps += ["verify_images", "install"]
        if self.reboot:
            steps += ["ha_failover_if_active"]
        if self.drain:
            steps += ["drain_standalone"]
        if self.install or self.reboot:
            steps += ["copy_config"]
        if self.reboot:
            steps += ["reboot", "postvalidate", "restore_virtual_addresses"]
        else:
            steps += ["postvalidate_no_reboot"]
        return steps


class RollbackRequest(Model):
    worker_stopped: bool = False
    reboot_timeout: int = Field(default=900, ge=60, le=7200)
    validation_timeout: int = Field(default=600, ge=0, le=86400)


class RecoveryResolution(Model):
    worker_stopped: Literal[True]
    device_inspected: Literal[True]
    note: str = Field(min_length=10, max_length=1000)
