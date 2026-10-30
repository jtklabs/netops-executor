import json
from ipaddress import ip_address
from typing import Literal

from pydantic import Field, field_validator, model_validator

from .models import JobRequest, Model, Name, Queue, ScheduledRequest
from .panos_models import within_window
from .platforms import DeviceType


class SSHCommand(Model):
    mode: Literal["exec", "config"] = "exec"
    command: str = Field(min_length=1, max_length=65536)
    timeout_seconds: int = Field(default=120, ge=1, le=7200)


class SSHJob(ScheduledRequest):
    device_type: DeviceType | None = None
    enable: bool = False
    job_timeout: int = Field(default=7200, ge=1, le=86400)
    parent_job_id: str | None = Field(default=None, max_length=36)
    device: str = Field(min_length=1, max_length=253)
    credential_profiles: list[Name] | None = Field(default=None, min_length=1, max_length=10)
    commands: list[SSHCommand] = Field(min_length=1, max_length=100)
    stop_on_error: bool = True


class HTTPRequest(Model):
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"] = "GET"
    path: str = Field(default="/", max_length=4096)
    headers: dict[str, str] = Field(default_factory=dict)
    params: dict[str, str] = Field(default_factory=dict)
    form: dict[str, str] | None = None
    json_body: dict | list | None = None
    body: str | None = Field(default=None, max_length=1048576)
    timeout_seconds: int = Field(default=60, ge=1, le=7200)

    @model_validator(mode="after")
    def valid(self):
        if (
            not self.path.startswith("/")
            or self.path.startswith("//")
            or "\\" in self.path
            or "://" in self.path
        ):
            raise ValueError("path must be relative to the configured HTTP target")
        if sum(v is not None for v in (self.form, self.json_body, self.body)) > 1:
            raise ValueError("choose form, json_body, or body")
        if any(
            k.lower() in ("authorization", "proxy-authorization", "host", "cookie", "x-pan-key")
            for k in self.headers
        ):
            raise ValueError("authentication must use a credential profile")
        if len(json.dumps(self.model_dump()).encode()) > 1048576:
            raise ValueError("HTTP operation exceeds 1 MiB")
        return self


class HTTPJob(ScheduledRequest):
    job_timeout: int = Field(default=7200, ge=1, le=86400)
    parent_job_id: str | None = Field(default=None, max_length=36)
    target: Name
    credential_profiles: list[Name] | None = Field(default=None, min_length=1, max_length=10)
    requests: list[HTTPRequest] = Field(min_length=1, max_length=100)
    stop_on_error: bool = True


class Wave(Model):
    wave: int = Field(ge=1)
    upgrade_at_a_time: int = Field(default=1, ge=1, le=100)
    ips: list[str] = Field(min_length=1, max_length=1000)

    @field_validator("ips")
    @classmethod
    def ips_valid(cls, values):
        return [str(ip_address(v)) for v in values]

    @property
    def members(self):
        return self.ips


class Batch(ScheduledRequest):
    name: str = Field(min_length=1, max_length=160)
    defaults: dict = Field(default_factory=dict)
    overrides: dict[str, dict] = Field(default_factory=dict)
    waves: list[Wave] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def valid(self):
        numbers = [w.wave for w in self.waves]
        if numbers != sorted(set(numbers)):
            raise ValueError("waves must be unique and increasing")
        ips = [ip for w in self.waves for ip in w.ips]
        if len(ips) != len(set(ips)) or len(ips) > 1000:
            raise ValueError("batch must contain at most 1000 unique IPs")
        self.overrides = {str(ip_address(ip)): options for ip, options in self.overrides.items()}
        if not set(self.overrides) <= set(ips):
            raise ValueError("overrides must reference IPs in this batch")
        for ip in ips:
            self.request_for(ip)
        return self

    def request_for(self, ip):
        request = JobRequest.model_validate({**self.defaults, **self.overrides.get(ip, {}), "device": ip})
        return within_window(self, request)


class ValidationDecision(Model):
    action: Literal["accept", "retry"] = "accept"
    gate_id: str
    validation_revision: int = Field(ge=1)
    operator: str = Field(min_length=1, max_length=128)
    reason: str = Field(min_length=5, max_length=1000)
    queue: Queue | None = Field(
        default=None,
        description="Worker queue the resumed job waits in. Omitted: the queue it was submitted to.",
    )


class ManualCompletion(Model):
    operator: str = Field(min_length=1, max_length=128)
    reason: str = Field(min_length=5, max_length=1000)
