import hmac
import os
import threading
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from httpx import HTTPError
from pydantic import AwareDatetime, Field

from . import __version__
from .cipher_models import CipherScanRequest, CipherScanResult
from .config import Settings, under
from .credentials import Credential, Vault
from .eos_models import EosBatch, EosUpgradeRequest
from .execution_models import Batch, HTTPJob, ManualCompletion, SSHJob, ValidationDecision
from .fortigate_models import FortigateBatch, FortigateUpgradeRequest
from .ios_models import IosBatch, IosUpgradeRequest
from .iosxe_config import compare as compare_configs
from .iosxe_models import ConfigComparison, IosxeBatch, IosxeUpgradeRequest
from .models import JobRequest, Model, Name, Queue, RecoveryResolution, RollbackRequest
from .panos_models import PanosBatch, PanosUpgradeRequest
from .platforms import NETWORK_TYPES, validate_commands
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
        "upgrade", "panos_upgrade", "eos_upgrade", "iosxe_upgrade", "ios_upgrade", "fortigate_upgrade"
    ] = "upgrade"
    name: str
    status: Literal["completed", "needs_attention", "in_progress"]
    device_count: int
    jobs: list[BatchItem]
    waves: list[dict]
    status_url: str
    start_at: AwareDatetime | None = None
    latest_start_at: AwareDatetime | None = None


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

    @asynccontextmanager
    async def lifespan(app):
        # The API delivers webhooks for jobs that workers finish; deliveries wait while it is down.
        stop = threading.Event()
        sender = threading.Thread(target=webhooks.run, args=(stop,), daemon=True) if webhooks else None
        if sender:
            sender.start()
        yield
        stop.set()
        if sender:
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
    vault = Vault(store, settings.credential_key_file)
    bearer = HTTPBearer(auto_error=False)

    def auth(credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)]):
        if not credentials or not hmac.compare_digest(
            credentials.credentials.encode(), settings.token.encode()
        ):
            raise HTTPException(401, "valid bearer token required", headers={"WWW-Authenticate": "Bearer"})

    authenticated = [Depends(auth)]

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

    @app.post("/api/v1/snmp/walks", dependencies=authenticated, status_code=202, response_model=JobResponse)
    def submit_walk(
        request: SnmpWalkRequest,
        idempotency_key: Annotated[str | None, Header(min_length=1, max_length=160)] = None,
    ):
        if (
            request.profile
            and request.profile not in settings.snmp_profiles
            and not any(p["id"] == request.profile and p["kind"] == "snmp" for p in vault.list())
        ):
            raise HTTPException(422, "unknown SNMP v3 profile")
        return store.submit(
            request.model_dump(mode="json"),
            f"snmp:{request.device_ip}:{request.port}",
            idempotency_key,
            kind="snmp_walk",
        )

    @app.get("/api/v1/snmp/walks/{job_id}", dependencies=authenticated, response_model=JobResponse)
    def walk_job(job_id: str):
        store.reap(settings.stale_seconds)
        result = store.get(job_id)
        if result["kind"] != "snmp_walk":
            raise HTTPException(404, "SNMP job not found")
        return result

    @app.get("/api/v1/snmp/walks/{job_id}/results", dependencies=authenticated, response_model=SnmpResults)
    def walk_results(
        job_id: str,
        after: int = Query(default=0, ge=0),
        limit: int = Query(default=500, ge=1, le=1000),
    ):
        store.reap(settings.stale_seconds)
        return store.snmp_results(job_id, after, limit)

    @app.get("/api/v1/jobs", dependencies=authenticated, response_model=list[JobResponse])
    def jobs(limit: int = Query(default=100, ge=1, le=500), offset: int = Query(default=0, ge=0)):
        store.reap(settings.stale_seconds)
        return store.list(limit, offset)

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

    @app.put("/api/v1/credentials/{profile}", dependencies=authenticated, response_model=CredentialMetadata)
    def credential(profile: Name, request: Credential):
        return vault.put(profile, request)

    @app.post("/api/v1/credentials/rotate", dependencies=authenticated)
    def rotate():
        return vault.rotate()

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

    @app.get("/api/v1/queues", dependencies=authenticated, response_model=list[QueueStatus])
    def queues():
        store.reap(settings.stale_seconds)
        return store.queue_summary(settings.stale_seconds)

    @app.get("/api/v1/ssh/device-types", dependencies=authenticated)
    def ssh_device_types():
        return [
            {"device_type": name, "modes": ["exec", "config"] if name in NETWORK_TYPES else ["exec"]}
            for name in ["linux", "f5", "cisco_ios", "cisco_nxos", "arista_eos", "fortinet"]
        ]

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
