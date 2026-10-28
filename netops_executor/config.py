import json
import os
from dataclasses import dataclass, field
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlsplit

from dotenv import load_dotenv
from pydantic import Field, model_validator

from .models import Model, Name
from .platforms import DeviceType
from .snmp_models import SnmpProfile


def env(name, default=None):
    """Generic names take precedence; existing F5_* deployments keep working."""
    return os.getenv(name, os.getenv(name.replace("NETOPS_", "F5_", 1), default))


class Device(Model):
    device_type: DeviceType = "linux"
    waf_request_command: str | None = Field(default=None, max_length=4096)
    id: str = Field(min_length=1, max_length=253)
    host: str = Field(pattern=r"^[A-Za-z0-9:._-]+$", max_length=253)
    port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(default="root", pattern=r"^[a-zA-Z0-9_.-]+$")
    key_file: str | None = None
    password_env: str | None = None
    key_passphrase_env: str | None = None
    ucs_passphrase_env: str = "F5_UCS_PASSPHRASE"
    lock_group: Name | None = None
    credential_profiles: list[Name] | None = None


class HTTPTarget(Model):
    id: Name
    base_url: str
    credential_profiles: list[Name] | None = None
    ca_file: str | None = None
    auth_probe_path: str | None = None
    auth_probe_method: str = "GET"
    auth_probe_params: dict[str, str] = Field(default_factory=dict)
    # A configured read-only probe is required before trying credentials for writes.

    @model_validator(mode="after")
    def valid(self):
        parsed = urlsplit(self.base_url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("HTTP target requires HTTPS without URL credentials, query or fragment")
        if self.auth_probe_method not in ("GET", "HEAD", "POST"):
            raise ValueError("auth probe must be a read-only GET, HEAD or configured POST")
        if self.auth_probe_path and (
            not self.auth_probe_path.startswith("/")
            or self.auth_probe_path.startswith("//")
            or "\\" in self.auth_probe_path
        ):
            raise ValueError("auth probe must be a relative path on the configured target")
        return self


@dataclass
class Settings:
    token: str
    data_dir: Path
    image_root: Path
    backup_root: Path
    known_hosts: Path
    devices: dict[str, Device]
    stale_seconds: int = 120
    snmp_profiles: dict[str, SnmpProfile] = field(default_factory=dict)

    credential_key_file: Path | None = None
    http_targets: dict[str, HTTPTarget] = field(default_factory=dict)

    def device(self, identifier):
        if identifier in self.devices:
            return self.devices[identifier]
        ip = str(ip_address(identifier))
        return next((d for d in self.devices.values() if d.host == ip), Device(id=ip, host=ip))

    @classmethod
    def load(cls):
        load_dotenv(env("NETOPS_ENV_FILE", ".env"))
        if env("NETOPS_UCS_PASSPHRASE") is not None:
            os.environ["F5_UCS_PASSPHRASE"] = env("NETOPS_UCS_PASSPHRASE")
        token = env("NETOPS_API_TOKEN", "")
        if len(token) < 32:
            raise ValueError("NETOPS_API_TOKEN must contain at least 32 characters")
        inventory = json.loads(Path(env("NETOPS_DEVICES_FILE", "devices.json")).read_text())
        devices = [Device.model_validate(d) for d in inventory]
        if len({d.id for d in devices}) != len(devices):
            raise ValueError("duplicate device IDs")
        endpoints = {(d.host.lower().rstrip("."), d.port) for d in devices}
        if len(endpoints) != len(devices):
            raise ValueError("use one inventory ID per device endpoint")
        result = cls(
            token,
            Path(env("NETOPS_DATA_DIR", "data")),
            Path(env("NETOPS_IMAGE_ROOT", "images")),
            Path(env("NETOPS_BACKUP_ROOT", "backups")),
            Path(env("NETOPS_KNOWN_HOSTS", "known_hosts")),
            {d.id: d for d in devices},
        )
        profile_file = env("NETOPS_SNMP_PROFILES_FILE")
        if profile_file:
            profiles = [SnmpProfile.model_validate(p) for p in json.loads(Path(profile_file).read_text())]
            if len({p.id for p in profiles}) != len(profiles):
                raise ValueError("duplicate SNMP profile IDs")
            result.snmp_profiles = {p.id: p for p in profiles}
        result.credential_key_file = (
            Path(env("NETOPS_CREDENTIAL_KEY_FILE")) if env("NETOPS_CREDENTIAL_KEY_FILE") else None
        )
        if env("NETOPS_HTTP_TARGETS_FILE"):
            targets = [
                HTTPTarget.model_validate(t)
                for t in json.loads(Path(env("NETOPS_HTTP_TARGETS_FILE")).read_text())
            ]
            if len({t.id for t in targets}) != len(targets):
                raise ValueError("duplicate HTTP target IDs")
            for t in targets:
                parsed = urlsplit(t.base_url)
                if (
                    parsed.scheme != "https"
                    or not parsed.hostname
                    or parsed.username
                    or parsed.password
                    or parsed.query
                    or parsed.fragment
                ):
                    raise ValueError("HTTP target requires HTTPS without URL credentials, query or fragment")
            result.http_targets = {t.id: t for t in targets}
        result.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        result.backup_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        return result


def under(root: Path, relative: str) -> Path:
    root = root.resolve()
    path = (root / relative).resolve()
    if not path.is_relative_to(root) or path == root:
        raise ValueError("path must remain under its configured root")
    return path
