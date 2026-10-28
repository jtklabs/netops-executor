"""Generic sequential execution: results, never automatic remediation decisions."""

import base64
import json
import ssl
import time
import xml.etree.ElementTree as ET

import httpx

from .credentials import AuthenticationRejected, Selector, Vault
from .execution_models import HTTPJob, SSHJob
from .network_ssh import NetworkSSH
from .platforms import NETWORK_TYPES, validate_commands
from .ssh import SSH
from .store import CancelRequested, Deferred, LostOwnership


class ExecutionRunner:
    def __init__(self, settings, store, job, worker):
        self.settings, self.store, self.job, self.worker = settings, store, job, worker
        self.result = {"operations": []}
        self.uncertain = False
        self.phase = "connect"
        self.deadline = time.monotonic() + job["request"].get("job_timeout", 7200)

    def guard(self):
        self.store.checkpoint(self.job["id"], self.worker)
        if time.monotonic() > self.deadline:
            raise TimeoutError("job deadline exceeded")

    def audit(self, data):
        self.store.credential_event(self.job["id"], self.worker, {**data, "phase": self.phase})

    def record(self, step):
        if len(json.dumps(self.result).encode()) > 32 * 1024 * 1024:
            self.result["operations"][-1] = {"error": "job result exceeded 32 MiB; output omitted"}
            raise ValueError("result limit")
        self.store.record(self.job["id"], self.worker, step, result=self.result)

    def run(self):
        try:
            if self.job["kind"] == "ssh":
                success = self.ssh()
            else:
                success = self.http()
            self.store.finish(self.job["id"], self.worker, "succeeded" if success else "failed")
        except (Deferred, LostOwnership):
            return
        except CancelRequested:
            self.result["error"] = "cancelled; inspect any operation with an uncertain outcome"
            self.terminal_error("cancelled", "cancelled")
        except Exception:
            self.result["error"] = "execution failed; inspect credential attempts and the last operation"
            self.terminal_error("execution_failed", "failed")

    def terminal_error(self, event, status):
        try:
            self.record(event)
            self.store.finish(self.job["id"], self.worker, "recovery_required" if self.uncertain else status)
        except LostOwnership:
            pass

    def ssh(self):
        request = SSHJob.model_validate(self.job["request"])
        device = self.settings.device(request.device)
        if not self.store.reserve(self.job["id"], self.worker, ["endpoint:" + device.host]):
            self.store.defer(self.job["id"], self.worker)
        device_type = request.device_type or device.device_type
        validate_commands(request, device_type)
        self.result["device_type"] = device_type
        args = (self.settings, device, self.guard, request.credential_profiles, self.audit)
        ssh = NetworkSSH(*args, device_type=device_type) if device_type in NETWORK_TYPES else SSH(*args)
        success = True
        try:
            for index, command in enumerate(request.commands):
                self.phase = "command_" + str(index)
                self.guard()
                ssh.connect()  # Authentication may fall back before a command is issued.
                self.uncertain = True
                self.result["in_flight"] = index
                self.record("command_started")
                start = time.monotonic()
                if device_type in NETWORK_TYPES:
                    result = ssh.execute(
                        command.command, command.timeout_seconds, mode=command.mode, enable=request.enable
                    )
                else:
                    result = ssh.execute(command.command, command.timeout_seconds)
                self.uncertain = False
                self.result.pop("in_flight", None)
                self.result["operations"].append(
                    {
                        "command_index": index,
                        **result,
                        "credential_profile": ssh.selector.last,
                        "duration_seconds": time.monotonic() - start,
                    }
                )
                self.record("command_finished")
                if result.get("cli_error") or result["exit_code"] not in (0, None):
                    success = False
                    if request.stop_on_error:
                        break
        finally:
            ssh.close()
        return success

    def http(self):
        request = HTTPJob.model_validate({k: v for k, v in self.job["request"].items() if k != "device"})
        target = self.settings.http_targets[request.target]
        selector = Selector(
            Vault(self.store, self.settings.credential_key_file),
            "http",
            target.id,
            request.credential_profiles
            if request.credential_profiles is not None
            else target.credential_profiles,
            self.audit,
        )
        if not self.store.reserve(self.job["id"], self.worker, ["http:" + target.id]):
            self.store.defer(self.job["id"], self.worker)
        verify = ssl.create_default_context(cafile=target.ca_file) if target.ca_file else True
        success = True

        def options(c):
            if c["scheme"] == "basic":
                selector.secrets.add(
                    base64.b64encode((c["username"] + ":" + c["password"]).encode()).decode()
                )
                return {"auth": (c["username"], c["password"])}
            return {"headers": {c["header"]: ("Bearer " if c["scheme"] == "bearer" else "") + c["token"]}}

        with httpx.Client(
            base_url=target.base_url, verify=verify, follow_redirects=False, trust_env=False
        ) as client:
            for index, operation in enumerate(request.requests):
                self.phase = "request_" + str(index)
                self.guard()
                if not target.auth_probe_path:
                    raise ValueError("HTTP execution requires a configured read-only authentication probe")
                selected = {}

                def authenticate(c):
                    # Probe separately so a write is never used to test a series of credentials.
                    path = target.auth_probe_path or operation.path
                    params = target.auth_probe_params if target.auth_probe_path else operation.params
                    with client.stream(
                        target.auth_probe_method if target.auth_probe_path else "GET",
                        path,
                        params=params,
                        timeout=min(operation.timeout_seconds, 30),
                        **options(c),
                    ) as response:
                        content = bytearray()
                        probe_deadline = time.monotonic() + 30
                        for chunk in response.iter_bytes():
                            self.guard()
                            content.extend(chunk)
                            if len(content) > 4 * 1024 * 1024 or time.monotonic() > probe_deadline:
                                raise ValueError("authentication probe exceeded bounds")
                        if response.status_code == 401:
                            raise AuthenticationRejected()
                        if not 200 <= response.status_code < 300:
                            raise ValueError("HTTP authentication probe did not succeed")
                        if content.lstrip().startswith(b"<"):
                            try:
                                root = ET.fromstring(content)
                            except ET.ParseError:
                                raise ValueError("authentication probe returned malformed XML") from None
                            if root.tag == "response" and root.get("status") == "error":
                                if root.get("code") in ("403", "16"):
                                    raise AuthenticationRejected()
                                raise ValueError(
                                    "Panorama authentication probe reported an application error"
                                )
                    selected.update(c)
                    return True

                selector.run(authenticate)
                auth_options = options(selected)
                auth_options["headers"] = {**operation.headers, **auth_options.get("headers", {})}
                self.uncertain = True
                self.result["in_flight"] = index
                self.record("http_request_started")
                start = time.monotonic()
                with client.stream(
                    operation.method,
                    operation.path,
                    params=operation.params,
                    data=operation.form,
                    json=operation.json_body,
                    content=operation.body,
                    timeout=operation.timeout_seconds,
                    **auth_options,
                ) as response:
                    chunks = bytearray()
                    deadline = start + operation.timeout_seconds
                    for chunk in response.iter_bytes():
                        self.guard()
                        chunks.extend(chunk)
                        if len(chunks) > 4 * 1024 * 1024 or time.monotonic() > deadline:
                            raise ValueError("HTTP response exceeded size or duration limit")
                    result = {
                        "request_index": index,
                        "status_code": response.status_code,
                        "body": selector.redact(chunks.decode("utf-8", errors="replace")),
                        "headers": {
                            k: selector.redact(v)
                            for k, v in response.headers.items()
                            if k.lower() in ("content-type", "location", "retry-after")
                        },
                        "duration_seconds": time.monotonic() - start,
                        "credential_profile": selector.last,
                    }
                self.uncertain = False
                self.result.pop("in_flight", None)
                self.result["operations"].append(result)
                self.record("http_request_finished")
                if not 200 <= result["status_code"] < 300:
                    success = False
                    if request.stop_on_error:
                        break
        return success
