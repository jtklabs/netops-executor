"""API contract for single-target Nmap cipher enumeration."""

import re
from typing import Literal

from pydantic import ConfigDict, Field, IPvAnyAddress, field_validator, model_validator

from .models import Model


class CipherScanRequest(Model):
    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "device_ip": "192.0.2.10",
                    "protocol": "https",
                    "port": 8443,
                    "server_name": "management.example.com",
                    "job_timeout": 300,
                },
                {"device_ip": "192.0.2.10", "protocol": "ssh"},
            ]
        }
    )

    device_ip: IPvAnyAddress = Field(description="One IPv4 or IPv6 address; no hostnames or ranges.")
    protocol: Literal["ssh", "https"] = Field(description="Enumerate SSH algorithms or HTTPS TLS ciphers.")
    port: int | None = Field(
        default=None, ge=1, le=65535, description="Defaults to 22 for SSH or 443 for HTTPS."
    )
    server_name: str | None = Field(
        default=None,
        max_length=253,
        description="Optional DNS name sent as TLS SNI; HTTPS only. Target stays device_ip.",
    )
    job_timeout: int = Field(
        default=300, ge=1, le=3600, description="Maximum worker scan duration in seconds."
    )

    @field_validator("device_ip")
    @classmethod
    def unscoped_ip(cls, value):
        if "%" in str(value):
            raise ValueError("IPv6 scope identifiers are not supported")
        return value

    @field_validator("server_name")
    @classmethod
    def hostname(cls, value):
        if value is not None:
            value = value.lower().rstrip(".")
            if not value or any(
                not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in value.split(".")
            ):
                raise ValueError("server_name must be a DNS name (use ASCII/punycode)")
        return value

    @model_validator(mode="after")
    def defaults(self):
        if self.server_name is not None and self.protocol != "https":
            raise ValueError("server_name is only supported for HTTPS")
        if self.port is None:
            self.port = 22 if self.protocol == "ssh" else 443
        return self


class CipherScanResult(Model):
    nmap_version: str | None = None
    script: str | None = None
    port_state: str | None = None
    port_reason: str | None = None
    data: dict = Field(
        default_factory=dict,
        description="NSE structured output. SSH: algorithm group names map to lists. HTTPS: TLS version names map to cipher lists, preference, compressors and warnings; scalar metadata is preserved. Values are as reported by the installed Nmap version.",
    )
    output: str = Field(default="", description="Human-readable NSE output, including warnings.")
    stderr: str = ""
    exit_code: int | None = None
    error_code: str | None = None
    error: str | None = None
