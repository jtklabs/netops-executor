import hmac
import json
import os
import smtplib
import threading
from contextlib import asynccontextmanager
from ipaddress import ip_address
from pathlib import Path
from typing import Annotated, Literal

from fastapi import Body, Depends, FastAPI, Header, HTTPException, Query
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from httpx import HTTPError
from pydantic import AwareDatetime, Field

from . import __version__
from .cipher_models import CipherScanRequest, CipherScanResult
from .config import Settings, under
from .credentials import Credential, Vault, digest_matches, secret_digest
from .eos_models import EosBatch, EosUpgradeRequest
from .execution_models import Batch, HTTPJob, ManualCompletion, SSHJob, ValidationDecision
from .fortigate_models import FortigateBatch, FortigateUpgradeRequest
from .ios_models import IosBatch, IosUpgradeRequest
from .iosxe_config import compare as compare_configs
from .iosxe_models import ConfigComparison, IosxeBatch, IosxeUpgradeRequest
from .metrics import render_metrics
from .models import Email, JobRequest, Model, Name, Queue, RecoveryResolution, RollbackRequest
from .notify import EmailSender, Permanent
from .opengear_models import OpengearBatch, OpengearUpgradeRequest
from .panos_models import PanosBatch, PanosUpgradeRequest
from .password_devices import check_password_syntax
from .password_models import (
    API_PLATFORMS,
    PanoramaRotationOptions,
    PanoramaRotationRequest,
    PasswordRotationOptions,
    PasswordRotationRequest,
)
from .platforms import DEVICE_TYPES, NETWORK_TYPES, validate_commands
from .snmp_models import SnmpResults, SnmpWalkRequest
from .store import Conflict, Store
from .webhooks import Rejected, WebhookSender, redacted


class JobResponse(Model):
    id: str
    device: str
    lock_key: str
    lock_held: bool
    kind: Literal[
        "upgrade",
        "rollback",
        "snmp_walk",
        "ssh",
        "http",
        "cipher_scan",
        "panos_upgrade",
        "eos_upgrade",
        "iosxe_upgrade",
        "ios_upgrade",
        "fortigate_upgrade",
        "opengear_upgrade",
        "password_rotation",
        "panorama_password_rotation",
    ]
    queue: Queue
    parent: str | None
    request: dict
    status: Literal[
        "queued",
        "expired",
        "running",
        "succeeded",
        "failed",
        "cancelled",
        "recovery_required",
        "resolved",
        "needs_review",
        "completed_with_warnings",
        "manually_completed",
    ]
    created: float
    updated: float
    worker: str | None
    heartbeat: float | None
    start_at: AwareDatetime | None = None
    latest_start_at: AwareDatetime | None = None
    started_at: float | None = Field(
        default=None,
        description="First admitted worker start as Unix seconds; null while not started. Resource deferral before work clears it; continuations preserve it.",
    )
    result: dict
    idempotency_key: str | None
    credential_usage: list[dict] = Field(default_factory=list)
    credential_summary: dict = Field(default_factory=dict)
    control: dict = Field(default_factory=dict)
    validation_gates: list[dict] = Field(default_factory=list)


class QueueStatus(Model):
    queue: Queue
    queued: int = Field(description="Queued jobs, including those waiting for a future start_at")
    due: int = Field(description="Queued jobs whose start_at has passed or is unset")
    running: int
    oldest_due_wait_seconds: float | None = Field(
        description="Age of the oldest due queued job; null when none is waiting"
    )
    workers: int = Field(description="Online workers in this queue's pool (this queue is their first choice)")
    busy_workers: int = Field(description="Pool workers running a job from any queue")
    fallback_workers: int = Field(
        description="Other online workers that claim from this queue when theirs is empty"
    )


class CipherScanJobResponse(JobResponse):
    request: CipherScanRequest
    result: CipherScanResult


class BatchItem(Model):
    id: str
    device: str
    kind: str = "upgrade"
    queue: Queue = "upgrade"
    status: str
    result: dict
    wave: int
    ordinal: int
    start_at: AwareDatetime | None = None
    latest_start_at: AwareDatetime | None = None
    started_at: float | None = None


class BatchResponse(Model):
    id: str
    kind: Literal[
        "upgrade",
        "panos_upgrade",
        "eos_upgrade",
        "iosxe_upgrade",
        "ios_upgrade",
        "fortigate_upgrade",
        "opengear_upgrade",
    ] = "upgrade"
    name: str
    notify_email: list[str] | None = None
    status: Literal["completed", "needs_attention", "in_progress"]
    device_count: int
    jobs: list[BatchItem]
    waves: list[dict]
    status_url: str
    start_at: AwareDatetime | None = None
    latest_start_at: AwareDatetime | None = None


class EmailTest(Model):
    to: list[Email] = Field(min_length=1, max_length=20)


class CredentialMetadata(Model):
    id: str
    kind: Literal["ssh", "http", "snmp", "ucs", "f5_admin"]
    priority: int
    enabled: bool
    revision: int
    updated: float


class EventResponse(Model):
    seq: int
    job: str
    time: float
    step: str
    data: dict


class PlanResponse(Model):
    request: JobRequest
    steps: list[str]
    lock_key: str


class PanosPlanResponse(Model):
    request: PanosUpgradeRequest
    steps: list[str]
    lock_key: str


class EosPlanResponse(Model):
    request: EosUpgradeRequest
    steps: list[str]
    lock_key: str


JobStatus = Literal[
    "queued",
    "expired",
    "running",
    "succeeded",
    "failed",
    "cancelled",
    "recovery_required",
    "resolved",
    "needs_review",
    "completed_with_warnings",
    "manually_completed",
]
# Job statuses that still need attention: waiting to run, running, or holding a device.
ACTIVE_STATUSES = ("queued", "running", "needs_review", "recovery_required")


class ActivityJob(Model):
    id: str
    device: str | None
    kind: str
    queue: str
    status: JobStatus
    created: float
    updated: float | None
    started_at: float | None
    step: str | None = Field(default=None, description="Current step of a running or paused job")
    percent: float | None = None
    error: str | None = Field(default=None, description="Why a job needs recovery, when it recorded one")


class Waiting(Model):
    reason: Literal[
        "blocked", "takeover", "scheduled", "earlier_wave", "wave_limit", "retrying", "worker"
    ] = Field(
        description="blocked: another job holds its device or resource (see blocked_by). takeover: a "
        "rollback waiting for its source job. scheduled: start_at is in the future. earlier_wave / "
        "wave_limit: batch ordering. retrying: a reservation conflict, retried every few seconds. "
        "worker: ready, waiting for a free worker on its queue."
    )
    detail: str
    blocked_by: str | None = Field(default=None, description="ID of the job holding what it needs")
    until: str | None = Field(default=None, description="Scheduled start (ISO 8601), for scheduled jobs")


class QueuedActivity(ActivityJob):
    waiting: Waiting


class HeldDevice(Model):
    device: str | None
    state: JobStatus = Field(
        description="running, needs_review, recovery_required, or another status still holding a lock"
    )
    job: ActivityJob
    holds: list[str] = Field(
        description="Lock and reservation keys the job holds, such as device:fw1 or panos:<serial>"
    )
    gate: str | None = Field(default=None, description="Open review gate, for needs_review")
    detail: str = Field(description="What is happening and what releases the device")
    action: Literal["review", "resolve"] | None = Field(
        default=None,
        description="review: decide the validation gate (POST /api/v1/jobs/{id}/validation-decisions). "
        "resolve: inspect the device, then release it (POST /api/v1/jobs/{id}/resolve).",
    )
    blocking: list[QueuedActivity] = Field(
        description="Queued jobs that cannot start until this one releases its hold"
    )


class ActivitySummary(Model):
    running: int
    needs_review: int
    recovery_required: int
    held: int = Field(description="Jobs not running that still hold a device")
    queued: int
    blocked: int = Field(description="Queued jobs waiting on another job's hold")


class ActivityResponse(Model):
    summary: ActivitySummary
    held: list[HeldDevice] = Field(
        description="Running jobs and jobs holding a device, needing attention first"
    )
    queued: list[QueuedActivity] = Field(description="Every queued job, oldest first, with why it is waiting")


class PasswordRotationPlanResponse(Model):
    request: PasswordRotationOptions
    steps: list[str]
    lock_key: str


class PanoramaRotationPlanResponse(Model):
    request: PanoramaRotationOptions
    steps: list[str]
    lock_key: str


class OpengearPlanResponse(Model):
    request: OpengearUpgradeRequest
    steps: list[str]
    lock_key: str


class IosxePlanResponse(Model):
    request: IosxeUpgradeRequest
    steps: list[str]
    lock_key: str


class IosPlanResponse(Model):
    request: IosUpgradeRequest
    steps: list[str]
    lock_key: str


class FortigatePlanResponse(Model):
    request: FortigateUpgradeRequest
    steps: list[str]
    lock_key: str


def create_app(settings=None):
    os.umask(0o077)
    settings = settings or Settings.load()
    store = Store(settings.data_dir / "jobs.sqlite3")
    webhooks = WebhookSender(settings, store) if settings.webhook_url else None
    store.set_webhooks(webhooks is not None)
    email = EmailSender(settings, store) if settings.smtp_host else None
    store.set_email(email is not None)

    @asynccontextmanager
    async def lifespan(app):
        # The API delivers webhooks and email reports for jobs that workers finish; deliveries
        # wait while it is down.
        stop = threading.Event()
        senders = [
            threading.Thread(target=sender.run, args=(stop,), daemon=True)
            for sender in (webhooks, email)
            if sender
        ]
        for sender in senders:
            sender.start()
        yield
        stop.set()
        for sender in senders:
            sender.join(15)

    # Behind a reverse proxy at a sub-path, root_path makes /docs and status URLs include the prefix.
    app = FastAPI(
        title="NetOps Executor API",
        version=__version__,
        docs_url="/docs",
        redoc_url=None,
        root_path=settings.root_path,
        lifespan=lifespan,
    )
    app.state.store = store
    app.state.webhooks = webhooks
    app.state.email = email
    vault = Vault(store, settings.credential_key_file)
    bearer = HTTPBearer(auto_error=False)

    def auth(credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)]):
        if not credentials or not hmac.compare_digest(
            credentials.credentials.encode(), settings.token.encode()
        ):
            raise HTTPException(401, "valid bearer token required", headers={"WWW-Authenticate": "Bearer"})

    authenticated = [Depends(auth)]

    def scrape_auth(credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)]):
        # The metrics token opens /metrics only; the API token still works for existing scrapers.
        offered = credentials.credentials.encode() if credentials else b""
        allowed = [settings.token] + ([settings.metrics_token] if settings.metrics_token else [])
        if not credentials or not any(hmac.compare_digest(offered, token.encode()) for token in allowed):
            raise HTTPException(401, "valid bearer token required", headers={"WWW-Authenticate": "Bearer"})

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        # Pydantic's default response echoes submitted values, including passwords.
        return JSONResponse(
            {"detail": [{"loc": e["loc"], "type": e["type"], "msg": e["msg"]} for e in exc.errors()]},
            status_code=422,
        )

    @app.exception_handler(KeyError)
    async def missing(request, exc):
        return JSONResponse({"detail": "not found"}, status_code=404)

    @app.exception_handler(Conflict)
    async def conflict(request, exc):
        return JSONResponse({"detail": str(exc)}, status_code=409)

    @app.middleware("http")
    async def headers(request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        # A proxy may or may not strip the prefix before forwarding.
        path = request.scope["path"]
        if settings.root_path and path.startswith(settings.root_path + "/"):
            path = path[len(settings.root_path) :]
        if path == "/" or path.startswith("/static/"):
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; "
                "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
            )
        return response

    def published(batch):
        return {**batch, "status_url": settings.root_path + batch["status_url"]}

    def lock_key(device_id):
        try:
            d = settings.device(device_id)
        except ValueError:
            raise HTTPException(422, "device must be an inventory ID or IP address") from None
        return "group:" + d.lock_group if d.lock_group else "device:" + d.id

    def planned(request):
        key = lock_key(request.device)
        if request.backup_directory:
            try:
                under(settings.backup_root, request.backup_directory)
            except ValueError:
                raise HTTPException(422, "backup directory escapes BACKUP_ROOT") from None
        return PlanResponse(request=request, steps=request.plan(), lock_key=key)

    def panos_planned(request):
        target = settings.http_targets.get(request.panorama)
        if target is None:
            raise HTTPException(422, "unknown Panorama HTTP target")
        if not target.auth_probe_path:
            raise HTTPException(422, "Panorama target requires a read-only authentication probe")
        if request.backup_directory:
            try:
                under(settings.backup_root, request.backup_directory)
            except ValueError:
                raise HTTPException(422, "backup directory escapes BACKUP_ROOT") from None
        if request.f5_drain:
            try:
                settings.device(request.f5_drain.device)
            except ValueError:
                raise HTTPException(422, "f5_drain.device must be an inventory ID or IP address") from None
        return PanosPlanResponse(request=request, steps=request.plan(), lock_key="panos:" + request.serial)

    def eos_planned(request):
        try:
            device = settings.device(request.device)
            peer = settings.device(request.mlag_peer) if request.mlag_peer else None
        except ValueError:
            raise HTTPException(422, "device and mlag_peer must be inventory IDs or IP addresses") from None
        if device.id in settings.devices and device.device_type not in ("linux", "arista_eos"):
            raise HTTPException(422, "device is not an arista_eos device")
        if peer is not None and peer.id == device.id:
            raise HTTPException(422, "mlag_peer must be the other switch")
        if request.backup_directory:
            try:
                under(settings.backup_root, request.backup_directory)
            except ValueError:
                raise HTTPException(422, "backup directory escapes BACKUP_ROOT") from None
        return EosPlanResponse(request=request, steps=request.plan(), lock_key=lock_key(request.device))

    def opengear_planned(request):
        try:
            device = settings.device(request.device)
            if request.backup_directory:
                under(settings.backup_root, request.backup_directory)
        except ValueError:
            raise HTTPException(422, "invalid device or backup directory") from None
        if device.id in settings.devices and device.device_type not in ("linux", "opengear"):
            raise HTTPException(422, "device is not an opengear device")
        return OpengearPlanResponse(request=request, steps=request.plan(), lock_key=lock_key(request.device))

    def fortigate_planned(request):
        try:
            device = settings.device(request.device)
        except ValueError:
            raise HTTPException(422, "device must be an inventory ID or IP address") from None
        if device.id in settings.devices and device.device_type not in ("linux", "fortinet"):
            raise HTTPException(422, "device is not a fortinet device")
        if not settings.staging_address:
            raise HTTPException(422, "FortiGate staging requires NETOPS_STAGING_ADDRESS on the executor")
        if request.software_source == "fortimanager" and request.fortimanager not in settings.http_targets:
            raise HTTPException(422, "unknown FortiManager HTTP target")
        if request.backup_directory:
            try:
                under(settings.backup_root, request.backup_directory)
            except ValueError:
                raise HTTPException(422, "backup directory escapes BACKUP_ROOT") from None
        return FortigatePlanResponse(request=request, steps=request.plan(), lock_key=lock_key(request.device))

    def iosxe_planned(request, response=IosxePlanResponse):
        try:
            device = settings.device(request.device)
            peers = [settings.device(p) for p in request.peers]
        except ValueError:
            raise HTTPException(422, "device and peers must be inventory IDs or IP addresses") from None
        if device.id in settings.devices and device.device_type not in ("linux", "cisco_ios"):
            raise HTTPException(422, "device is not a cisco_ios device")
        if any(p.id == device.id for p in peers):
            raise HTTPException(422, "peers must be other devices")
        if request.backup_directory:
            try:
                under(settings.backup_root, request.backup_directory)
            except ValueError:
                raise HTTPException(422, "backup directory escapes BACKUP_ROOT") from None
        return response(request=request, steps=request.plan(), lock_key=lock_key(request.device))

    @app.get("/healthz")
    def healthz():
        return {"status": "ok", "api_version": "v1", "version": __version__}

    @app.get("/metrics", dependencies=[Depends(scrape_auth)], tags=["Metrics"], response_class=Response)
    def metrics():
        from prometheus_client import CONTENT_TYPE_LATEST

        # Without workers or other API traffic, stale running jobs would otherwise stay counted.
        store.reap(settings.stale_seconds)

        return Response(
            render_metrics(store, settings),
            headers={"Content-Type": CONTENT_TYPE_LATEST, "Cache-Control": "no-store"},
        )

    @app.get("/api/v1/devices", dependencies=authenticated)
    def devices() -> list[dict]:
        return [
            {
                "id": d.id,
                "host": d.host,
                "port": d.port,
                "lock_group": d.lock_group,
                "device_type": d.device_type,
            }
            for d in settings.devices.values()
        ]

    @app.post("/api/v1/plan", dependencies=authenticated, response_model=PlanResponse)
    def plan(request: JobRequest):
        return planned(request)

    @app.post("/api/v1/jobs", dependencies=authenticated, status_code=202, response_model=JobResponse)
    def submit(
        request: JobRequest,
        idempotency_key: Annotated[str | None, Header(min_length=1, max_length=160)] = None,
    ):
        p = planned(request)
        return store.submit(request.model_dump(), p.lock_key, idempotency_key)

    @app.post(
        "/api/v1/cipher-scans",
        dependencies=authenticated,
        status_code=202,
        response_model=CipherScanJobResponse,
        tags=["Cipher scans"],
        summary="Queue an SSH or HTTPS cipher scan",
        description="Runs Nmap on one IP and TCP port without device credentials. Defaults to port 22 for SSH or 443 for HTTPS. Returns a job ID immediately; poll GET /api/v1/cipher-scans/{job_id}. Results include structured NSE data and readable output. Supports Idempotency-Key. HTTPS enumeration makes multiple TLS connections; this is not a compliance verdict. Cancel through POST /api/v1/jobs/{job_id}/cancel.",
    )
    def submit_cipher_scan(
        request: CipherScanRequest,
        idempotency_key: Annotated[str | None, Header(min_length=1, max_length=160)] = None,
    ):
        return store.submit(
            request.model_dump(mode="json"),
            f"cipher:{request.device_ip}:{request.port}",
            idempotency_key,
            kind="cipher_scan",
        )

    @app.get(
        "/api/v1/cipher-scans/{job_id}",
        dependencies=authenticated,
        response_model=CipherScanJobResponse,
        tags=["Cipher scans"],
        summary="Read cipher scan status and results",
        description="Poll while queued or running. The result contains Nmap version, port state, structured data, readable output and errors. A failed or empty scan is never reported as a clean cipher assessment. Generic job polling and events endpoints also support these jobs.",
    )
    def cipher_scan(job_id: str):
        store.reap(settings.stale_seconds)
        result = store.get(job_id)
        if result["kind"] != "cipher_scan":
            raise HTTPException(404, "cipher scan job not found")
        return result

    @app.post(
        "/api/v1/snmp/walks",
        dependencies=authenticated,
        status_code=202,
        response_model=JobResponse,
        tags=["SNMP"],
        summary="Queue an SNMP walk, GET or discovery (SNMP v1, v2c or v3)",
        description="Walks `oids` subtrees and reads `get_oids`; with `site`, also discovers the device "
        "into NetBox. **Credentials are tried in this order:** the request's `credentials` (in the order "
        "given), then the `snmp-profiles.json` profile or the saved SNMP profiles "
        "(`PUT /api/v1/credentials/{profile}` with `kind: snmp`), unless `use_profiles` is false. A "
        "credential the agent rejects, or never answers, moves on to the next; once the agent has "
        "answered, a timeout is not retried with another credential.\n\n"
        "**Request credentials** support `version` 1, 2c (`community`) and 3 (`username`, "
        "`security_level`, `auth_protocol` MD5/SHA/SHA224/SHA256/SHA384/SHA512, `priv_protocol` "
        "DES/3DES/AES/AES192/AES256/AES192C/AES256C). For AES-192/256 on Cisco devices use "
        "AES192C/AES256C (Cisco's key extension). They require NETOPS_CREDENTIAL_KEY_FILE (409 "
        "without it), are encrypted apart from the job and erased when it finishes. The job's "
        "`result.request_credentials` lists each one with every setting and its community and "
        "passphrases masked (`abc*****`: the first three characters, or one for a secret shorter than "
        "eight); `credential_usage` reports each one's outcome under the same `request:1`, `request:2` "
        "IDs. Poll `GET /api/v1/snmp/walks/{id}`.",
    )
    def submit_walk(
        request: Annotated[
            SnmpWalkRequest,
            Body(
                openapi_examples={
                    "profiles": {
                        "summary": "Walk with saved profiles",
                        "value": {"device_ip": "192.0.2.10", "oids": ["1.3.6.1.2.1.1"]},
                    },
                    "v2c": {
                        "summary": "SNMP v2c community, then saved profiles",
                        "value": {
                            "device_ip": "192.0.2.10",
                            "oids": ["1.3.6.1.2.1.1"],
                            "credentials": [{"version": "2c", "community": "REPLACE_WITH_COMMUNITY"}],
                        },
                    },
                    "v3": {
                        "summary": "SNMP v3 (SHA-256, Cisco AES-256), then saved profiles",
                        "value": {
                            "device_ip": "192.0.2.10",
                            "get_oids": ["1.3.6.1.2.1.1.5.0"],
                            "credentials": [
                                {
                                    "version": "3",
                                    "username": "netops",
                                    "auth_protocol": "SHA256",
                                    "auth_password": "REPLACE_WITH_AUTH_PASSPHRASE",
                                    "priv_protocol": "AES256C",
                                    "priv_password": "REPLACE_WITH_PRIV_PASSPHRASE",
                                }
                            ],
                        },
                    },
                    "only": {
                        "summary": "Only the request's credentials, with discovery",
                        "value": {
                            "device_ip": "192.0.2.10",
                            "site": "Sydney",
                            "use_profiles": False,
                            "credentials": [
                                {"version": "2c", "community": "REPLACE_WITH_COMMUNITY"},
                                {
                                    "version": "3",
                                    "username": "netops",
                                    "auth_protocol": "SHA256",
                                    "auth_password": "REPLACE_WITH_AUTH_PASSPHRASE",
                                    "priv_protocol": "AES256C",
                                    "priv_password": "REPLACE_WITH_PRIV_PASSPHRASE",
                                },
                            ],
                        },
                    },
                }
            ),
        ],
        idempotency_key: Annotated[str | None, Header(min_length=1, max_length=160)] = None,
    ):
        if (
            request.profile
            and request.profile not in settings.snmp_profiles
            and not any(p["id"] == request.profile and p["kind"] == "snmp" for p in vault.list())
        ):
            raise HTTPException(422, "unknown SNMP v3 profile")
        payload = request.model_dump(mode="json")
        if request.site:
            if not settings.netbox_url or not settings.netbox_token:
                raise HTTPException(422, "NetBox SNMP discovery is not configured on this executor")
            instance = request.poller_instance or settings.poller_instance
            if not instance:
                raise HTTPException(422, "supply poller_instance or configure NETOPS_POLLER_INSTANCE")
            payload["poller_instance"] = instance
        else:
            # Preserve saved requests and idempotency for ordinary walks.
            del payload["site"], payload["poller_instance"]
        # The count is the executor's to set; the credentials themselves never enter the job.
        payload["credential_count"] = len(request.credentials)
        if not request.use_profiles and not request.credentials:
            raise HTTPException(422, "use_profiles false needs credentials")
        for key, unused in (("credential_count", 0), ("use_profiles", True)):
            if payload[key] == unused:
                del payload[key]
        lock = f"snmp:{request.device_ip}:{request.port}"
        if not request.credentials:
            return store.submit(payload, lock, idempotency_key, kind="snmp_walk")
        secret = json.dumps([c.plaintext() for c in request.credentials], sort_keys=True).encode()
        return submit_with_secret(payload, lock, idempotency_key, "snmp_walk", secret)

    @app.get(
        "/api/v1/snmp/walks/{job_id}",
        dependencies=authenticated,
        response_model=JobResponse,
        tags=["SNMP"],
        summary="SNMP walk status, per-root progress and credential usage",
    )
    def walk_job(job_id: str):
        store.reap(settings.stale_seconds)
        result = store.get(job_id)
        if result["kind"] != "snmp_walk":
            raise HTTPException(404, "SNMP job not found")
        return result

    @app.get(
        "/api/v1/snmp/walks/{job_id}/results",
        dependencies=authenticated,
        response_model=SnmpResults,
        tags=["SNMP"],
        summary="SNMP walk rows, paginated",
    )
    def walk_results(
        job_id: str,
        after: int = Query(default=0, ge=0),
        limit: int = Query(default=500, ge=1, le=1000),
    ):
        store.reap(settings.stale_seconds)
        return store.snmp_results(job_id, after, limit)

    @app.get(
        "/api/v1/jobs",
        dependencies=authenticated,
        response_model=list[JobResponse],
        summary="List jobs, newest first, optionally filtered by device or status",
    )
    def jobs(
        limit: int = Query(default=100, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
        search: str | None = Query(
            default=None,
            min_length=1,
            max_length=200,
            description="An IP, device name, kind or job ID. An IP matches exactly, and also matches "
            "jobs submitted with the inventory ID that has that address (and the reverse); other text "
            "matches part of the device, kind or the start of a job ID.",
            examples=["192.0.2.10"],
        ),
        status: str | None = Query(
            default=None,
            description="Comma-separated statuses, or `active` for queued, running, needs_review and "
            "recovery_required.",
            examples=["active", "needs_review,recovery_required"],
        ),
    ):
        store.reap(settings.stale_seconds)
        statuses = None
        if status:
            statuses = [s.strip() for s in status.split(",") if s.strip()]
            statuses = list(ACTIVE_STATUSES) if statuses == ["active"] else statuses
            if not set(statuses) <= set(JobStatus.__args__):
                raise HTTPException(422, "unknown job status")
        devices = []
        if search:
            search = search.strip()
            try:
                address = str(ip_address(search))
            except ValueError:
                address = None
            # An address also finds jobs submitted with its inventory ID, and an inventory ID its address.
            for device in settings.devices.values():
                if address and device.host == address:
                    devices.append(device.id)
                elif device.id == search:
                    devices.append(device.host)
            if address:
                devices.append(address)
                return store.list(limit, offset, search=None, statuses=statuses, devices=devices, exact=True)
        return store.list(limit, offset, search=search or None, statuses=statuses, devices=devices)

    @app.get(
        "/api/v1/activity",
        dependencies=authenticated,
        response_model=ActivityResponse,
        summary="What is running, what is held, and what each queued job is waiting for",
        description="A job keeps its device locked while it runs, while it waits for a review decision "
        "(needs_review) and while it needs recovery (recovery_required). Queued jobs for that device "
        "wait until the hold is released. `held` lists each holding job with an explanation, the action "
        "that releases it, and the queued jobs it is blocking; `queued` gives every queued job's reason.",
    )
    def activity():
        store.reap(settings.stale_seconds)
        return store.activity()

    @app.get("/api/v1/jobs/{job_id}", dependencies=authenticated, response_model=JobResponse)
    def job(job_id: str):
        store.reap(settings.stale_seconds)
        return store.get(job_id)

    @app.get("/api/v1/jobs/{job_id}/events", dependencies=authenticated, response_model=list[EventResponse])
    def events(
        job_id: str, after: int = Query(default=0, ge=0), limit: int = Query(default=500, ge=1, le=1000)
    ):
        return store.events(job_id, after, limit)

    @app.post("/api/v1/jobs/{job_id}/cancel", dependencies=authenticated, response_model=JobResponse)
    def cancel(job_id: str):
        store.get(job_id)
        return store.cancel(job_id)

    @app.post("/api/v1/jobs/{job_id}/resolve", dependencies=authenticated, response_model=JobResponse)
    def resolve(job_id: str, resolution: RecoveryResolution):
        return store.resolve(job_id, resolution.model_dump())

    @app.post(
        "/api/v1/jobs/{job_id}/rollback",
        dependencies=authenticated,
        status_code=202,
        response_model=JobResponse,
    )
    def rollback(
        job_id: str,
        request: RollbackRequest,
        idempotency_key: Annotated[str | None, Header(min_length=1, max_length=160)] = None,
    ):
        original = store.get(job_id)
        if original["kind"] != "upgrade":
            raise Conflict("only F5 upgrades have a rollback target")
        if (
            original["status"] in ("recovery_required", "manually_completed")
            and original["lock_held"]
            and not request.worker_stopped
        ):
            raise Conflict("rollback of an uncertain job requires worker_stopped=true")
        payload = {
            **request.model_dump(),
            "device": original["device"],
            "credential_profiles": original["request"].get("credential_profiles"),
        }
        return store.submit(
            payload, lock_key(original["device"]), idempotency_key, kind="rollback", parent=job_id
        )

    @app.get("/api/v1/jobs/{job_id}/backup", dependencies=authenticated)
    def backup(job_id: str):
        result = store.get(job_id)["result"].get("backup")
        if not result:
            raise HTTPException(404, "no completed backup")
        path = under(settings.backup_root, result["path"])
        if not path.is_file():
            raise HTTPException(404, "backup file is unavailable")
        return FileResponse(path, filename=job_id + path.suffix, media_type="application/octet-stream")

    @app.get("/api/v1/jobs/{job_id}/artifacts/{name}", dependencies=authenticated)
    def artifact(job_id: str, name: str):
        """Download a saved pre-upgrade file such as a PAN-OS running config or tech support file."""
        item = next((a for a in store.get(job_id)["result"].get("artifacts", []) if a["name"] == name), None)
        if not item:
            raise HTTPException(404, "no such artifact")
        path = under(settings.backup_root, item["path"])
        if not path.is_file():
            raise HTTPException(404, "artifact file is unavailable")
        return FileResponse(path, filename=item["name"], media_type="application/octet-stream")

    @app.get("/api/v1/credentials", dependencies=authenticated, response_model=list[CredentialMetadata])
    def credentials():
        return vault.list()

    @app.put(
        "/api/v1/credentials/{profile}",
        dependencies=authenticated,
        response_model=CredentialMetadata,
        summary="Create or replace a saved credential profile",
        description="Full replacement: send every field, secrets included. Secrets are encrypted with "
        "the credential keyring and never returned. SNMP profiles (`kind: snmp`) take `version` 1, 2c "
        "(`community`) or 3 (`username`, `security_level`, `auth_protocol`, `priv_protocol`).",
    )
    def credential(
        profile: Name,
        request: Annotated[
            Credential,
            Body(
                openapi_examples={
                    "ssh": {
                        "summary": "SSH",
                        "value": {"kind": "ssh", "username": "netops", "password": "SECRET", "priority": 20},
                    },
                    "snmp_v3": {
                        "summary": "SNMP v3",
                        "value": {
                            "kind": "snmp",
                            "username": "reader",
                            "security_level": "authPriv",
                            "auth_protocol": "SHA256",
                            "auth_password": "SECRET_AT_LEAST_8_BYTES",
                            "priv_protocol": "AES256C",
                            "priv_password": "SECRET_AT_LEAST_8_BYTES",
                        },
                    },
                    "snmp_v2c": {
                        "summary": "SNMP v2c community",
                        "value": {"kind": "snmp", "version": "2c", "community": "SECRET_COMMUNITY"},
                    },
                }
            ),
        ],
    ):
        return vault.put(profile, request)

    @app.post("/api/v1/credentials/rotate", dependencies=authenticated)
    def rotate():
        return vault.rotate()

    @app.get("/api/v1/host-keys/alerts", dependencies=authenticated, tags=["Trust"])
    def host_key_alerts(state: Literal["open", "trusted", "resolved"] | None = None):
        """SSH host keys that changed: one alert per endpoint and presented key."""
        return store.host_key_alerts(state)

    @app.post("/api/v1/host-keys/alerts/{alert_id}/trust", dependencies=authenticated, tags=["Trust"])
    def trust_host_key(alert_id: str):
        """Pin the key this alert reports for its endpoint. Pinned (NETOPS_SSH_HOST_KEYS=pin) only."""
        return store.trust_host_key(alert_id)

    @app.get("/api/v1/pins", dependencies=authenticated, tags=["Trust"])
    def pins():
        """Pinned device TLS certificates (tls:host:port) and SSH host keys (ssh:host:port)."""
        return store.pins()

    @app.delete("/api/v1/pins/{key}", dependencies=authenticated, status_code=204, tags=["Trust"])
    def unpin(key: str):
        """Forget a pin after inspecting a legitimately replaced certificate or host key."""
        store.unpin(key)

    @app.get("/api/v1/http/targets", dependencies=authenticated)
    def http_targets():
        return [
            {
                "id": t.id,
                "base_url": t.base_url,
                "auth_probe_configured": bool(t.auth_probe_path),
                "tls": t.tls,
            }
            for t in settings.http_targets.values()
        ]

    @app.get("/api/v1/workers", dependencies=authenticated)
    def workers():
        return store.worker_list(settings.stale_seconds)

    @app.get("/api/v1/webhooks", dependencies=authenticated, tags=["Webhooks"])
    def webhook_status() -> dict:
        return {
            "enabled": webhooks is not None,
            "url": redacted(settings.webhook_url) if webhooks else None,
            "max_rows": settings.webhook_max_rows,
            **store.webhook_summary(),
        }

    @app.post("/api/v1/webhooks/retry", dependencies=authenticated, tags=["Webhooks"])
    def webhook_retry() -> dict:
        if not webhooks:
            raise Conflict("no webhook is configured")
        return {"requeued": store.webhook_retry()}

    @app.post("/api/v1/webhooks/test", dependencies=authenticated, tags=["Webhooks"])
    def webhook_test() -> dict:
        if not webhooks:
            raise Conflict("no webhook is configured")
        try:
            return {"delivered": True, "status_code": webhooks.ping(), "error": None}
        except (HTTPError, Rejected) as exc:
            return {
                "delivered": False,
                "error": str(exc) if isinstance(exc, Rejected) else type(exc).__name__,
            }

    @app.get("/api/v1/email", dependencies=authenticated, tags=["Email"])
    def email_status() -> dict:
        return {
            "enabled": email is not None,
            "host": settings.smtp_host,
            "port": settings.smtp_port if email else None,
            "security": settings.smtp_security if email else None,
            "from": settings.smtp_from,
            **store.email_summary(),
        }

    @app.post("/api/v1/email/retry", dependencies=authenticated, tags=["Email"])
    def email_retry() -> dict:
        if not email:
            raise Conflict("no SMTP relay is configured")
        return {"requeued": store.email_retry()}

    @app.post("/api/v1/email/test", dependencies=authenticated, tags=["Email"])
    def email_test(request: EmailTest) -> dict:
        if not email:
            raise Conflict("no SMTP relay is configured")
        try:
            refused = email.test(request.to)
        except (Permanent, smtplib.SMTPException, OSError) as exc:
            code = getattr(exc, "smtp_code", None)
            error = str(exc) if isinstance(exc, Permanent) else type(exc).__name__
            return {"sent": False, "refused": [], "error": error + (f" {code}" if code else "")}
        return {"sent": True, "refused": refused, "error": None}

    @app.get("/api/v1/queues", dependencies=authenticated, response_model=list[QueueStatus])
    def queues():
        store.reap(settings.stale_seconds)
        return store.queue_summary(settings.stale_seconds)

    @app.get("/api/v1/ssh/device-types", dependencies=authenticated)
    def ssh_device_types():
        return [
            {"device_type": name, "modes": ["exec", "config"] if name in NETWORK_TYPES else ["exec"]}
            for name in DEVICE_TYPES
        ]

    def password_planned(request):
        try:
            if request.device_type in API_PLATFORMS:
                # ClearPass and Infoblox are reached through their HTTP target, not the inventory.
                request.for_platform(request.device_type)
                if request.http_target not in settings.http_targets:
                    raise ValueError("unknown HTTP target")
            else:
                device = settings.device(request.device)
                request.device_type = request.device_type or device.device_type
                request.for_platform(request.device_type)
            if request.panorama and request.panorama not in settings.http_targets:
                raise ValueError("unknown Panorama HTTP target")
            check_password_syntax(request.device_type, request.password.get_secret_value())
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
        return PasswordRotationPlanResponse(
            request=PasswordRotationOptions.model_validate(request.model_dump()),
            steps=[
                "reserve_device",
                "read_local_account",
                "create_or_update_password",
                "save_configuration",
                "verify_account",
            ],
            lock_key=(
                "http:" + request.http_target
                if request.device_type in API_PLATFORMS
                else lock_key(request.device)
            ),
        )

    def submit_secret(request, plan, idempotency_key, kind):
        return submit_with_secret(
            plan.request.model_dump(mode="json"),
            plan.lock_key,
            idempotency_key,
            kind,
            request.password.get_secret_value().encode(),
        )

    def submit_with_secret(payload, lock, idempotency_key, kind, secret):
        """Queue a job whose secret is encrypted apart from its public request (409 without a
        credential key file)."""
        cipher = vault.cipher()

        def matches(saved):
            if saved["digest"]:
                return digest_matches(saved["digest"], secret)
            # Jobs submitted before digests existed still hold their encrypted secret until they
            # finish; once purged, a replay of such a job's key conflicts rather than guessing.
            return bool(saved["secret"]) and hmac.compare_digest(
                vault.decrypt(cipher, saved["secret"]), secret
            )

        return store.submit(
            payload,
            lock,
            idempotency_key,
            kind=kind,
            secret=cipher.encrypt(secret),
            secret_digest=secret_digest(secret),
            secret_matches=matches,
        )

    def panorama_planned(request):
        if request.panorama not in settings.http_targets:
            raise HTTPException(422, "unknown Panorama HTTP target")
        return PanoramaRotationPlanResponse(
            request=PanoramaRotationOptions.model_validate(request.model_dump()),
            steps=[
                "discover_templates_and_firewalls",
                *(["rotate_templates_and_commit_on_panorama"] if request.templates else []),
                *(["rotate_firewall_local_accounts"] if request.firewalls else []),
            ],
            lock_key="panorama:" + request.panorama,
        )

    @app.post(
        "/api/v1/password-rotation/panorama/plan",
        dependencies=authenticated,
        response_model=PanoramaRotationPlanResponse,
        tags=["Password rotation"],
        summary="Validate a Panorama-wide administrator rotation without device access",
    )
    def panorama_rotation_plan(request: PanoramaRotationRequest):
        return panorama_planned(request)

    @app.post(
        "/api/v1/password-rotation/panorama/jobs",
        dependencies=authenticated,
        status_code=202,
        response_model=JobResponse,
        tags=["Password rotation"],
        summary="Rotate an administrator in Panorama templates and on every firewall that has it locally",
        description="Templates and template stacks that define the account get the new password and "
        "Panorama commits (nothing is pushed; result.push_required lists the firewalls that need a "
        "push). Every connected firewall with a local copy of the account is then rotated through "
        "Panorama, one at a time, each proven by its committed hash. result.templates and "
        "result.firewalls report each one's outcome.",
    )
    def panorama_rotation_job(
        request: PanoramaRotationRequest,
        idempotency_key: Annotated[str | None, Header(min_length=1, max_length=160)] = None,
    ):
        return submit_secret(
            request, panorama_planned(request), idempotency_key, "panorama_password_rotation"
        )

    @app.post(
        "/api/v1/password-rotation/plan",
        dependencies=authenticated,
        response_model=PasswordRotationPlanResponse,
        tags=["Password rotation"],
        summary="Validate a local-account rotation request without device access",
    )
    def password_plan(request: PasswordRotationRequest):
        return password_planned(request)

    @app.post(
        "/api/v1/password-rotation/jobs",
        dependencies=authenticated,
        status_code=202,
        response_model=JobResponse,
        tags=["Password rotation"],
        summary="Create or update a local account password over SSH or through Panorama",
        description="Existing privileges are preserved. Missing accounts default to full administrator access when new_account is omitted; supply new_account to override creation privileges. Passwords are encrypted with the credential keyring, never included in public job metadata. Poll GET /api/v1/jobs/{id}. Verification gates resume without replaying a password write. Existing credential profiles are not modified.",
    )
    def password_job(
        request: PasswordRotationRequest,
        idempotency_key: Annotated[str | None, Header(min_length=1, max_length=160)] = None,
    ):
        return submit_secret(request, password_planned(request), idempotency_key, "password_rotation")

    @app.post("/api/v1/ssh/jobs", dependencies=authenticated, status_code=202, response_model=JobResponse)
    def ssh_job(
        request: SSHJob, idempotency_key: Annotated[str | None, Header(min_length=1, max_length=160)] = None
    ):
        try:
            device = settings.device(request.device)
            request.device_type = request.device_type or device.device_type
            validate_commands(request, request.device_type)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
        return store.submit(
            request.model_dump(),
            lock_key(request.device),
            idempotency_key,
            kind="ssh",
            parent=request.parent_job_id,
        )

    @app.post("/api/v1/http/jobs", dependencies=authenticated, status_code=202, response_model=JobResponse)
    def http_job(
        request: HTTPJob, idempotency_key: Annotated[str | None, Header(min_length=1, max_length=160)] = None
    ):
        if request.target not in settings.http_targets:
            raise HTTPException(422, "unknown HTTP target")
        return store.submit(
            {**request.model_dump(), "device": request.target},
            "http:" + request.target,
            idempotency_key,
            kind="http",
            parent=request.parent_job_id,
        )

    @app.post(
        "/api/v1/upgrade-batches", dependencies=authenticated, status_code=202, response_model=BatchResponse
    )
    def batch(
        request: Batch, idempotency_key: Annotated[str | None, Header(min_length=1, max_length=160)] = None
    ):
        for wave in request.waves:
            for ip in wave.ips:
                planned(request.request_for(ip))
        return published(store.create_batch(request, idempotency_key, lock_key))

    @app.get("/api/v1/upgrade-batches", dependencies=authenticated, response_model=list[BatchResponse])
    def batches(limit: int = Query(default=50, ge=1, le=500)):
        store.reap(settings.stale_seconds)
        with store.connect() as db:
            return [
                store._batch(db, row[0])
                for row in db.execute("SELECT id FROM batches ORDER BY created DESC LIMIT ?", (limit,))
            ]

    @app.get("/api/v1/upgrade-batches/{batch_id}", dependencies=authenticated, response_model=BatchResponse)
    def batch_status(batch_id: str):
        store.reap(settings.stale_seconds)
        return published(store.batch(batch_id))

    panos_tags = ["PAN-OS upgrades"]

    @app.post(
        "/api/v1/panos/plan",
        dependencies=authenticated,
        response_model=PanosPlanResponse,
        tags=panos_tags,
        summary="Normalize a PAN-OS upgrade and show its steps without device access",
    )
    def panos_plan(request: PanosUpgradeRequest):
        return panos_planned(request)

    @app.post(
        "/api/v1/panos/jobs",
        dependencies=authenticated,
        status_code=202,
        response_model=JobResponse,
        tags=panos_tags,
        summary="Queue one PAN-OS firewall upgrade through Panorama",
        description="Prechecks, software staging, HA suspend, install, reboot and post-validation run on a worker. Poll GET /api/v1/jobs/{job_id}. Supports Idempotency-Key.",
    )
    def panos_job(
        request: PanosUpgradeRequest,
        idempotency_key: Annotated[str | None, Header(min_length=1, max_length=160)] = None,
    ):
        p = panos_planned(request)
        return store.submit(
            request.model_dump(mode="json"), p.lock_key, idempotency_key, kind="panos_upgrade"
        )

    @app.post(
        "/api/v1/panos/upgrade-batches",
        dependencies=authenticated,
        status_code=202,
        response_model=BatchResponse,
        tags=panos_tags,
        summary="Queue ordered waves of PAN-OS firewall upgrades by serial",
        description="Each wave starts only after every earlier item passed validation or was marked done. upgrade_at_a_time bounds concurrency within a wave; HA peers never overlap.",
    )
    def panos_batch(
        request: PanosBatch,
        idempotency_key: Annotated[str | None, Header(min_length=1, max_length=160)] = None,
    ):
        for wave in request.waves:
            for serial in wave.serials:
                panos_planned(request.request_for(serial))
        return published(
            store.create_batch(
                request, idempotency_key, lambda serial: "panos:" + serial, kind="panos_upgrade"
            )
        )

    eos_tags = ["EOS upgrades"]

    @app.post(
        "/api/v1/eos/plan",
        dependencies=authenticated,
        response_model=EosPlanResponse,
        tags=eos_tags,
        summary="Normalize an Arista EOS upgrade and show its steps without device access",
    )
    def eos_plan(request: EosUpgradeRequest):
        return eos_planned(request)

    @app.post(
        "/api/v1/eos/jobs",
        dependencies=authenticated,
        status_code=202,
        response_model=JobResponse,
        tags=eos_tags,
        summary="Queue one Arista EOS upgrade over SSH",
        description="Prechecks, image copy and SHA-512 check, write memory, install source ... now reload, and post-validation run on a worker. Poll GET /api/v1/jobs/{job_id}. Supports Idempotency-Key.",
    )
    def eos_job(
        request: EosUpgradeRequest,
        idempotency_key: Annotated[str | None, Header(min_length=1, max_length=160)] = None,
    ):
        p = eos_planned(request)
        return store.submit(request.model_dump(mode="json"), p.lock_key, idempotency_key, kind="eos_upgrade")

    @app.post(
        "/api/v1/eos/upgrade-batches",
        dependencies=authenticated,
        status_code=202,
        response_model=BatchResponse,
        tags=eos_tags,
        summary="Queue ordered waves of Arista EOS upgrades",
        description="Each wave starts only after every earlier item passed validation or was marked done. Put MLAG peers in different waves or set mlag_peer so they never reload together.",
    )
    def eos_batch(
        request: EosBatch,
        idempotency_key: Annotated[str | None, Header(min_length=1, max_length=160)] = None,
    ):
        for wave in request.waves:
            for device in wave.devices:
                eos_planned(request.request_for(device))
        return published(store.create_batch(request, idempotency_key, lock_key, kind="eos_upgrade"))

    opengear_tags = ["Opengear IM7200 upgrades"]

    @app.post(
        "/api/v1/opengear/plan",
        dependencies=authenticated,
        response_model=OpengearPlanResponse,
        tags=opengear_tags,
        summary="Normalize an Opengear IM7200 upgrade and show its steps without device access",
    )
    def opengear_plan(request: OpengearUpgradeRequest):
        return opengear_planned(request)

    @app.post(
        "/api/v1/opengear/jobs",
        dependencies=authenticated,
        status_code=202,
        response_model=JobResponse,
        tags=opengear_tags,
        summary="Queue one Opengear IM7200 upgrade over SSH",
        description="Root-shell prechecks, configuration backup, SCP and SHA-256 verification, netflash with reboot, and post-validation. stage_only preloads without reboot. No automatic rollback. Poll GET /api/v1/jobs/{job_id}. Supports Idempotency-Key.",
    )
    def opengear_job(
        request: OpengearUpgradeRequest,
        idempotency_key: Annotated[str | None, Header(min_length=1, max_length=160)] = None,
    ):
        p = opengear_planned(request)
        return store.submit(
            request.model_dump(mode="json"), p.lock_key, idempotency_key, kind="opengear_upgrade"
        )

    @app.post(
        "/api/v1/opengear/upgrade-batches",
        dependencies=authenticated,
        status_code=202,
        response_model=BatchResponse,
        tags=opengear_tags,
        summary="Queue ordered waves of Opengear IM7200 upgrades",
        description="Each wave starts only after every earlier item passed validation or was marked done.",
    )
    def opengear_batch(
        request: OpengearBatch,
        idempotency_key: Annotated[str | None, Header(min_length=1, max_length=160)] = None,
    ):
        for wave in request.waves:
            for device in wave.devices:
                opengear_planned(request.request_for(device))
        return published(store.create_batch(request, idempotency_key, lock_key, kind="opengear_upgrade"))

    iosxe_tags = ["IOS XE upgrades"]

    @app.post(
        "/api/v1/iosxe/plan",
        dependencies=authenticated,
        response_model=IosxePlanResponse,
        tags=iosxe_tags,
        summary="Normalize a Cisco IOS XE upgrade and show its steps without device access",
    )
    def iosxe_plan(request: IosxeUpgradeRequest):
        return iosxe_planned(request)

    @app.post(
        "/api/v1/iosxe/jobs",
        dependencies=authenticated,
        status_code=202,
        response_model=JobResponse,
        tags=iosxe_tags,
        summary="Queue one Cisco IOS XE switch or stack upgrade over SSH",
        description="Prechecks, image copy and checksum, install add file ... activate commit, stack verification and post-validation with release-tolerant configuration comparison run on a worker. Poll GET /api/v1/jobs/{job_id}. Supports Idempotency-Key.",
    )
    def iosxe_job(
        request: IosxeUpgradeRequest,
        idempotency_key: Annotated[str | None, Header(min_length=1, max_length=160)] = None,
    ):
        p = iosxe_planned(request)
        return store.submit(
            request.model_dump(mode="json"), p.lock_key, idempotency_key, kind="iosxe_upgrade"
        )

    @app.post(
        "/api/v1/iosxe/upgrade-batches",
        dependencies=authenticated,
        status_code=202,
        response_model=BatchResponse,
        tags=iosxe_tags,
        summary="Queue ordered waves of Cisco IOS XE upgrades",
        description="Each wave starts only after every earlier item passed validation or was marked done. Put redundant switches in different waves or list them in peers so they never reload together.",
    )
    def iosxe_batch(
        request: IosxeBatch,
        idempotency_key: Annotated[str | None, Header(min_length=1, max_length=160)] = None,
    ):
        for wave in request.waves:
            for device in wave.devices:
                iosxe_planned(request.request_for(device))
        return published(store.create_batch(request, idempotency_key, lock_key, kind="iosxe_upgrade"))

    ios_tags = ["Classic IOS upgrades (2960-X)"]

    @app.post(
        "/api/v1/ios/plan",
        dependencies=authenticated,
        response_model=IosPlanResponse,
        tags=ios_tags,
        summary="Normalize a Catalyst 2960-X classic IOS upgrade and show its steps without device access",
    )
    def ios_plan(request: IosUpgradeRequest):
        return iosxe_planned(request, IosPlanResponse)

    @app.post(
        "/api/v1/ios/jobs",
        dependencies=authenticated,
        status_code=202,
        response_model=JobResponse,
        tags=ios_tags,
        summary="Queue one Catalyst 2960-X switch or stack upgrade over SSH",
        description="Prechecks, .tar copy and checksum, archive download-sw, reload, stack verification and post-validation with release-tolerant configuration comparison run on a worker. Poll GET /api/v1/jobs/{job_id}. Supports Idempotency-Key.",
    )
    def ios_job(
        request: IosUpgradeRequest,
        idempotency_key: Annotated[str | None, Header(min_length=1, max_length=160)] = None,
    ):
        p = iosxe_planned(request, IosPlanResponse)
        return store.submit(request.model_dump(mode="json"), p.lock_key, idempotency_key, kind="ios_upgrade")

    @app.post(
        "/api/v1/ios/upgrade-batches",
        dependencies=authenticated,
        status_code=202,
        response_model=BatchResponse,
        tags=ios_tags,
        summary="Queue ordered waves of Catalyst 2960-X upgrades",
        description="Each wave starts only after every earlier item passed validation or was marked done.",
    )
    def ios_batch(
        request: IosBatch,
        idempotency_key: Annotated[str | None, Header(min_length=1, max_length=160)] = None,
    ):
        for wave in request.waves:
            for device in wave.devices:
                iosxe_planned(request.request_for(device), IosPlanResponse)
        return published(store.create_batch(request, idempotency_key, lock_key, kind="ios_upgrade"))

    fortigate_tags = ["FortiGate upgrades"]

    @app.post(
        "/api/v1/fortigate/plan",
        dependencies=authenticated,
        response_model=FortigatePlanResponse,
        tags=fortigate_tags,
        summary="Normalize a FortiGate upgrade and show its steps without device access",
    )
    def fortigate_plan(request: FortigateUpgradeRequest):
        return fortigate_planned(request)

    @app.post(
        "/api/v1/fortigate/jobs",
        dependencies=authenticated,
        status_code=202,
        response_model=JobResponse,
        tags=fortigate_tags,
        summary="Queue one FortiGate or FGCP cluster upgrade",
        description="Prechecks, alternate-partition staging from a one-time FTP server on the executor, then a reboot into it (standalone) or the FGCP cluster upgrade from the primary, and post-validation. Poll GET /api/v1/jobs/{job_id}. Supports Idempotency-Key.",
    )
    def fortigate_job(
        request: FortigateUpgradeRequest,
        idempotency_key: Annotated[str | None, Header(min_length=1, max_length=160)] = None,
    ):
        p = fortigate_planned(request)
        return store.submit(
            request.model_dump(mode="json"), p.lock_key, idempotency_key, kind="fortigate_upgrade"
        )

    @app.post(
        "/api/v1/fortigate/upgrade-batches",
        dependencies=authenticated,
        status_code=202,
        response_model=BatchResponse,
        tags=fortigate_tags,
        summary="Queue ordered waves of FortiGate upgrades",
        description="Each wave starts only after every earlier item passed validation or was marked done. List each FGCP cluster once, by its primary.",
    )
    def fortigate_batch(
        request: FortigateBatch,
        idempotency_key: Annotated[str | None, Header(min_length=1, max_length=160)] = None,
    ):
        for wave in request.waves:
            for device in wave.devices:
                fortigate_planned(request.request_for(device))
        return published(store.create_batch(request, idempotency_key, lock_key, kind="fortigate_upgrade"))

    @app.post(
        "/api/v1/iosxe/config-compare",
        dependencies=authenticated,
        tags=iosxe_tags,
        summary="Compare two IOS XE running configurations the way upgrade validation does",
        description="Paste a pre- and post-upgrade show running-config to see what the built-in and your config_policy rules tolerate, and what would still be reported. Nothing is stored and no device is contacted.",
    )
    def iosxe_config_compare(request: ConfigComparison) -> dict:
        return compare_configs(request.before, request.after, request.config_policy)

    @app.post("/api/v1/jobs/{job_id}/validation-decisions", dependencies=authenticated, status_code=202)
    def decision(
        job_id: str,
        request: ValidationDecision,
        idempotency_key: Annotated[str | None, Header(min_length=1, max_length=160)] = None,
    ):
        return store.decide(job_id, request, idempotency_key)

    @app.post("/api/v1/jobs/{job_id}/mark-done", dependencies=authenticated, response_model=JobResponse)
    def mark_done(job_id: str, request: ManualCompletion):
        return store.mark_done(job_id, request)

    static = Path(__file__).parent / "static"
    app.mount("/static", StaticFiles(directory=static), name="static")

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(static / "index.html")

    if settings.root_path:
        app.add_middleware(PrefixedPath, prefix=settings.root_path)
    return app


class PrefixedPath:
    """Give every request the proxy prefix, whether or not the proxy stripped it.

    Routing and static files then see one form of path, and direct requests to the
    listener (health checks, the CLI) keep working.
    """

    def __init__(self, app, prefix):
        self.app, self.prefix = app, prefix

    async def __call__(self, scope, receive, send):
        path = scope.get("path", "")
        if (
            scope["type"] in ("http", "websocket")
            and path != self.prefix
            and not path.startswith(self.prefix + "/")
        ):
            scope = {
                **scope,
                "path": self.prefix + path,
                "raw_path": self.prefix.encode() + (scope.get("raw_path") or path.encode()),
            }
        await self.app(scope, receive, send)
