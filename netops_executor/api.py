import hmac
import os
from pathlib import Path
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import AwareDatetime, Field

from . import __version__
from .cipher_models import CipherScanRequest, CipherScanResult
from .config import Settings, under
from .credentials import Credential, Vault
from .eos_models import EosBatch, EosUpgradeRequest
from .execution_models import Batch, HTTPJob, ManualCompletion, SSHJob, ValidationDecision
from .models import JobRequest, Model, Name, RecoveryResolution, RollbackRequest
from .panos_models import PanosBatch, PanosUpgradeRequest
from .platforms import NETWORK_TYPES, validate_commands
from .snmp_models import SnmpResults, SnmpWalkRequest
from .store import Conflict, Store


class JobResponse(Model):
    id: str
    device: str
    lock_key: str
    lock_held: bool
    kind: Literal[
        "upgrade", "rollback", "snmp_walk", "ssh", "http", "cipher_scan", "panos_upgrade", "eos_upgrade"
    ]
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


class CipherScanJobResponse(JobResponse):
    request: CipherScanRequest
    result: CipherScanResult


class BatchItem(Model):
    id: str
    device: str
    kind: str = "upgrade"
    status: str
    result: dict
    wave: int
    ordinal: int
    start_at: AwareDatetime | None = None
    latest_start_at: AwareDatetime | None = None
    started_at: float | None = None


class BatchResponse(Model):
    id: str
    kind: Literal["upgrade", "panos_upgrade", "eos_upgrade"] = "upgrade"
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


def create_app(settings=None):
    os.umask(0o077)
    settings = settings or Settings.load()
    store = Store(settings.data_dir / "jobs.sqlite3")
    app = FastAPI(title="NetOps Executor API", version=__version__, docs_url="/docs", redoc_url=None)
    app.state.store = store
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
        if request.url.path == "/" or request.url.path.startswith("/static/"):
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; "
                "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
            )
        return response

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

    @app.get("/healthz")
    def healthz():
        return {"status": "ok", "api_version": "v1"}

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

    @app.get("/api/v1/ssh/device-types", dependencies=authenticated)
    def ssh_device_types():
        return [
            {"device_type": name, "modes": ["exec", "config"] if name in NETWORK_TYPES else ["exec"]}
            for name in ["linux", "f5", "cisco_ios", "cisco_nxos", "arista_eos"]
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
        return store.create_batch(request, idempotency_key, lock_key)

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
        return store.batch(batch_id)

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
        return store.create_batch(
            request, idempotency_key, lambda serial: "panos:" + serial, kind="panos_upgrade"
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
        return store.create_batch(request, idempotency_key, lock_key, kind="eos_upgrade")

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

    return app
