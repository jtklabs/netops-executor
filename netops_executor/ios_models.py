"""Cisco Catalyst 2960-X and 2960-XR upgrades on classic IOS 15.2: requests and batches."""

import re
from pathlib import PurePosixPath
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .iosxe_models import IosxeBatch, IosxeConfigPolicy, IosxeImage, IosxeValidationPolicy
from .models import Name, ScheduledRequest

IosVersion = Annotated[str, Field(pattern=r"^\d{2}\.\d{1,2}\(\d{1,3}[a-z]?\)[A-Z]{1,3}\d{0,3}[a-z]?$")]


def version_token(release):
    """`15.2(7)E10` is written `152-7.E10` in image names."""
    match = re.fullmatch(r"(\d+)\.(\d+)\((\d+[a-z]?)\)(\S+)", release)
    if not match:
        raise ValueError("invalid IOS release: " + release)
    return f"{match[1]}{match[2]}-{match[3]}.{match[4]}"


class IosImage(IosxeImage):
    """The archive download-sw .tar. sha256 verifies the executor's copy; the switch verifies md5 or sha512."""

    name: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,159}\.tar$")]
    verify: Literal["sha512", "md5"] = Field(
        default="md5", description="Checksum the switch computes with verify /<algorithm>"
    )


class IosUpgradeRequest(ScheduledRequest):
    device: str = Field(min_length=1, max_length=253, description="Switch inventory ID or management IP")
    credential_profiles: list[Name] | None = Field(default=None, min_length=1, max_length=10)
    target_version: IosVersion
    image: IosImage
    allowed_source_versions: list[IosVersion] = Field(min_length=1, max_length=200)
    approved_models: list[str] = Field(
        default_factory=list, max_length=100, description="Optional exact show version model allowlist"
    )
    peers: list[str] = Field(
        default_factory=list,
        max_length=10,
        description="Inventory IDs or IPs reserved for the whole job so they never reload at the same time",
    )
    stage_only: bool = Field(
        default=False,
        description="Preload: copy and verify the .tar on flash ahead of the window; no backups, install or reload.",
    )
    tech_support: bool = Field(default=True, description="Save show tech-support before changes.")
    save_config: bool = Field(
        default=True, description="write memory when running and startup configuration differ before install"
    )
    save_after_validation: bool = Field(
        default=True,
        description="write memory once validation passes; skipped when configuration lines were removed",
    )
    config_policy: IosxeConfigPolicy = Field(default_factory=IosxeConfigPolicy)
    backup_directory: str | None = Field(default=None, max_length=240)
    minimum_free_bytes: int = Field(
        default=3_000_000, ge=0, description="Flash kept free on every member beyond the copy and extraction"
    )
    validation_policy: IosxeValidationPolicy = Field(default_factory=IosxeValidationPolicy)
    upload_timeout: int = Field(default=3600, ge=60, le=14400)
    install_timeout: int = Field(default=3600, ge=300, le=7200)
    reboot_timeout: int = Field(default=1800, ge=300, le=7200)
    validation_timeout: int = Field(default=1200, ge=0, le=86400)

    @model_validator(mode="after")
    def coherent(self):
        if self.backup_directory is not None:
            p = PurePosixPath(self.backup_directory)
            if p.is_absolute() or ".." in p.parts or not p.parts:
                raise ValueError("backup_directory must be a relative directory under BACKUP_ROOT")
        if self.device in self.peers:
            raise ValueError("peers must be other devices")
        if not self.image.name.endswith("-tar." + version_token(self.target_version) + ".tar"):
            raise ValueError(
                "image must be the target release's .tar, such as c2960x-universalk9-tar.152-7.E10.tar"
            )
        return self

    def plan(self):
        steps = ["reserve_switch_and_peers", "prevalidate", "flash_tar_copy_and_verify"]
        if self.stage_only:
            return steps
        return (
            steps[:2]
            + (["backup"] if self.tech_support else [])
            + steps[2:]
            + [
                "write_memory_if_unsaved",
                "archive_download_sw",
                "verify_boot_path",
                "reload",
                "verify_stack_on_target",
                "validate_system_and_config",
                "validate_traffic",
            ]
            + (["write_memory_after_validation"] if self.save_after_validation else [])
        )


class IosBatch(IosxeBatch):
    request_model = IosUpgradeRequest
