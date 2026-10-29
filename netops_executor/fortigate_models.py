"""FortiGate (FortiOS 7.4) upgrades: requests, policies and batches."""

from pathlib import PurePosixPath
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .iosxe_models import IosxeBatch, IosxeConfigPolicy, IosxeValidationPolicy
from .models import Model, Name, ScheduledRequest

FortiOSVersion = Annotated[str, Field(pattern=r"^\d{1,2}\.\d{1,2}\.\d{1,3}$")]


class FortigateImage(Model):
    """The model's .out firmware. sha256 verifies the executor's copy; FortiOS checks its signature."""

    name: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,159}\.out$")]
    sha256: Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
    version: FortiOSVersion
    build: int = Field(ge=1, le=99999)
    source_url: str | None = Field(
        default=None, max_length=4096, description="Optional HTTPS download source"
    )


class FortigateValidationPolicy(IosxeValidationPolicy):
    restore_required: bool = Field(
        default=True,
        description="Interfaces that were up, IPsec tunnels that were up, Established BGP peers and Full OSPF neighbors must recover; false reports them as warnings.",
    )
    min_session_percent: float | None = Field(default=None, ge=0, le=100)


class FortigateUpgradeRequest(ScheduledRequest):
    device: str = Field(
        min_length=1,
        max_length=253,
        description="FortiGate inventory ID or management IP; for a cluster, its primary's",
    )
    credential_profiles: list[Name] | None = Field(default=None, min_length=1, max_length=10)
    software_source: Literal["executor", "fortimanager"] = Field(
        default="executor",
        description="executor: the job drives the FortiGate directly. fortimanager: the image is also checked on FortiManager, which runs cluster upgrades and retrieves the configuration afterwards.",
    )
    fortimanager: Name | None = Field(default=None, description="FortiManager HTTP target ID")
    fortimanager_credential_profiles: list[Name] | None = Field(default=None, min_length=1, max_length=10)
    adom: Name = "root"
    image: FortigateImage
    allowed_source_versions: list[FortiOSVersion] = Field(min_length=1, max_length=200)
    approved_models: list[str] = Field(default_factory=list, max_length=100)
    stage_only: bool = Field(
        default=False,
        description="Preload: put the image in the alternate partition (and check it on FortiManager) ahead of the window; no reboot or upgrade.",
    )
    staging_source_address: str | None = Field(
        default=None,
        max_length=45,
        description="Address the FortiGate's FTP connection to the executor comes from, when not its management IP",
    )
    config_policy: IosxeConfigPolicy = Field(default_factory=IosxeConfigPolicy)
    backup_directory: str | None = Field(default=None, max_length=240)
    validation_policy: FortigateValidationPolicy = Field(default_factory=FortigateValidationPolicy)
    stage_timeout: int = Field(default=3600, ge=60, le=14400)
    reboot_timeout: int = Field(default=1800, ge=300, le=7200)
    cluster_timeout: int = Field(default=5400, ge=600, le=14400)
    validation_timeout: int = Field(default=1200, ge=0, le=86400)

    @model_validator(mode="after")
    def coherent(self):
        if self.backup_directory is not None:
            p = PurePosixPath(self.backup_directory)
            if p.is_absolute() or ".." in p.parts or not p.parts:
                raise ValueError("backup_directory must be a relative directory under BACKUP_ROOT")
        if self.software_source == "fortimanager" and not self.fortimanager:
            raise ValueError("software_source fortimanager requires fortimanager")
        if f"-build{self.image.build:04d}" not in self.image.name:
            raise ValueError("image name must carry the image build, such as -build2702-")
        return self

    def plan(self):
        steps = ["reserve_firewall", "prevalidate"]
        if self.software_source == "fortimanager":
            steps.append("fortimanager_upgrade_preview")
        steps.append("stage_alternate_partition_over_one_time_ftp")
        if self.stage_only:
            return steps
        return (
            steps
            + [
                "standalone: set_next_reboot_and_reboot; cluster: fgcp_cluster_upgrade_from_primary",
                "verify_target_and_ha_sync",
                "validate_system_and_config",
                "validate_traffic",
            ]
            + (["fortimanager_retrieve_config"] if self.software_source == "fortimanager" else [])
        )


class FortigateBatch(IosxeBatch):
    request_model = FortigateUpgradeRequest
