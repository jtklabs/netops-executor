"""Secret-bearing API requests and public metadata for local account rotation."""

import unicodedata
from typing import Annotated, Literal

from pydantic import Field, SecretStr, field_serializer, model_validator

from .models import Model, Name, ScheduledRequest
from .platforms import DeviceType

Username = Annotated[str, Field(pattern=r"^[A-Za-z_][A-Za-z0-9_.-]{0,31}$")]


class AccountCreation(Model):
    role: Name | None = None
    privilege: int | None = Field(default=None, ge=0, le=15)
    groups: list[Name] | None = Field(default=None, max_length=20)
    shell: Literal["/bin/bash", "/bin/sh", "bash", "tmsh", "none"] | None = None
    partition: Name = "all-partitions"
    vdom: Name = "root"

    @classmethod
    def administrator(cls, platform, linux_group=None):
        if platform == "linux":
            if linux_group not in ("sudo", "wheel"):
                raise ValueError("Linux administrator group must be resolved on the device")
            return cls(groups=[linux_group], shell="/bin/bash")
        return cls.model_validate(
            {
                "opengear": {"groups": ["admin"]},
                "f5": {"role": "admin", "partition": "all-partitions", "shell": "bash"},
                "cisco_ios": {"privilege": 15},
                "cisco_nxos": {"role": "network-admin"},
                "arista_eos": {"role": "network-admin", "privilege": 15},
                "fortinet": {"role": "super_admin", "vdom": "root"},
            }[platform]
        )

    def for_platform(self, platform):
        allowed = {
            "linux": {"groups", "shell"},
            "opengear": {"groups"},
            "f5": {"role", "shell", "partition"},
            "cisco_ios": {"privilege"},
            "cisco_nxos": {"role"},
            "arista_eos": {"role", "privilege"},
            "fortinet": {"role", "vdom"},
        }[platform]
        if self.model_fields_set - allowed:
            raise ValueError("new_account contains options for a different device_type")
        required = (
            "groups"
            if platform in ("linux", "opengear")
            else "privilege"
            if platform == "cisco_ios"
            else "role"
        )
        if getattr(self, required) is None:
            raise ValueError("new_account requires " + required + " for " + platform)
        if platform == "linux" and self.shell not in (None, "/bin/bash", "/bin/sh"):
            raise ValueError("Linux account shell must be /bin/bash or /bin/sh")
        if platform == "f5" and self.shell not in (None, "bash", "tmsh", "none"):
            raise ValueError("F5 account shell must be bash, tmsh or none")
        if platform == "opengear" and not self.groups:
            raise ValueError("Opengear new accounts require at least one group")


class RotationValidation(Model):
    noncritical_differences: Literal["warn"] = "warn"
    on_timeout: Literal["needs_review", "fail"] = "needs_review"
    consecutive_passes: Literal[1] = 1
    settling_seconds: Literal[0] = 0
    sample_interval_seconds: int = Field(default=15, ge=5, le=60)


class PasswordRotationOptions(ScheduledRequest):
    device: str = Field(min_length=1, max_length=253)
    device_type: DeviceType | None = None
    username: Username
    credential_profiles: list[Name] | None = Field(default=None, min_length=1, max_length=10)
    create_if_missing: bool = True
    new_account: AccountCreation | None = Field(
        default=None,
        description="Creation privileges for a missing account. Omitted/null defaults to full administrator access for the platform; existing accounts keep their privileges. Linux defaults use sudo on Ubuntu/Debian or wheel on RHEL-family systems, with full sudo access checked after creation.",
    )
    verification: Literal["ssh_login", "local_hash"] = Field(
        default="ssh_login",
        description="Fresh password-only SSH authentication, or local hash comparison on Linux/F5/Opengear",
    )
    ios_algorithm: Literal["scrypt", "sha256", "legacy"] = Field(
        default="scrypt",
        description="Cisco IOS secret algorithm; legacy explicitly opts into the device default",
    )
    command_timeout: int = Field(default=60, ge=10, le=300)
    validation_timeout: int = Field(default=60, ge=0, le=600)
    validation_policy: RotationValidation = Field(default_factory=RotationValidation)

    @field_serializer("new_account")
    def serialize_creation(self, value):
        # Preserve which platform-specific options were explicitly supplied across queue/review round trips.
        return value.model_dump(exclude_unset=True) if value is not None else None

    def for_platform(self, platform):
        if self.new_account:
            self.new_account.for_platform(platform)
        if self.verification == "local_hash" and platform not in ("linux", "f5", "opengear"):
            raise ValueError("local_hash verification is supported on linux, f5 and opengear only")


class PasswordRotationRequest(PasswordRotationOptions):
    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "device": "192.0.2.72",
                    "device_type": "opengear",
                    "username": "automation",
                    "password": "REPLACE_WITH_DESIRED_PASSWORD",
                    "verification": "ssh_login",
                    "queue": "priority",
                }
            ]
        }
    }

    password: SecretStr = Field(
        exclude=True, description="Desired password; encrypted separately from public job metadata"
    )

    @model_validator(mode="after")
    def safe_password(self):
        value = self.password.get_secret_value()
        if (
            not value
            or len(value.encode()) > 256
            or any(unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp") for c in value)
        ):
            raise ValueError("password must contain 1–256 bytes without control characters")
        return self
