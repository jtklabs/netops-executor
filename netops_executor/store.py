"""SQLite queue. No automatic replay of ambiguous device operations."""

import fcntl
import json
import sqlite3
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone

from . import __version__
from .models import QUEUES, ScheduledRequest

UPGRADE_KINDS = (
    "upgrade",
    "panos_upgrade",
    "eos_upgrade",
    "iosxe_upgrade",
    "ios_upgrade",
    "fortigate_upgrade",
)


def default_queue(kind):
    """Rollbacks are operator recovery; upgrades get their own pool; everything else is bulk."""
    return "priority" if kind == "rollback" else "upgrade" if kind in UPGRADE_KINDS else "scheduled"


class Conflict(Exception):
    pass


class LostOwnership(Exception):
    pass


class CancelRequested(Exception):
    pass


class Deferred(Exception):
    pass


class NeedsReview(Exception):
    pass


class Store:
    def __init__(self, path):
        self.path = str(path)
        # Initialize one process at a time. A new database switches to WAL under an exclusive lock,
        # and SQLite fails that switch with "database is locked" instead of waiting while another
        # process creates the schema, so an API and workers starting together could crash. The lock
        # is a separate file: closing any descriptor of the database would drop SQLite's own locks.
        with open(self.path + ".init-lock", "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            self.initialize()

    def initialize(self):
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY, device TEXT NOT NULL, lock_key TEXT NOT NULL,
                    kind TEXT NOT NULL, parent TEXT, request TEXT NOT NULL,
                    status TEXT NOT NULL, created REAL NOT NULL, updated REAL NOT NULL,
                    worker TEXT, heartbeat REAL, result TEXT NOT NULL DEFAULT '{}',
                    idempotency_key TEXT UNIQUE
                );
                CREATE TABLE IF NOT EXISTS locks (key TEXT PRIMARY KEY, job TEXT NOT NULL UNIQUE);
                CREATE TABLE IF NOT EXISTS events (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT, job TEXT NOT NULL,
                    time REAL NOT NULL, step TEXT NOT NULL, data TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS snmp_rows (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT, job TEXT NOT NULL,
                    root_oid TEXT NOT NULL, oid TEXT NOT NULL, type TEXT NOT NULL,
                    value TEXT NOT NULL, encoding TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS snmp_rows_job ON snmp_rows(job, seq);
                CREATE TABLE IF NOT EXISTS credentials (
                    id TEXT PRIMARY KEY, kind TEXT NOT NULL, priority INTEGER NOT NULL,
                    enabled INTEGER NOT NULL, revision INTEGER NOT NULL, secret BLOB NOT NULL, updated REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS credential_cooldowns (key TEXT PRIMARY KEY, until REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS credential_attempts (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT, job TEXT NOT NULL, time REAL NOT NULL, data TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS resources (key TEXT PRIMARY KEY, job TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS controls (
                    job TEXT PRIMARY KEY, cancel INTEGER DEFAULT 0, waive INTEGER DEFAULT 0,
                    next_attempt REAL DEFAULT 0, continuation TEXT, operator TEXT, reason TEXT);
                CREATE TABLE IF NOT EXISTS batches (id TEXT PRIMARY KEY, request TEXT NOT NULL, key TEXT UNIQUE, created REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS batch_members (job TEXT PRIMARY KEY, batch TEXT NOT NULL, wave INTEGER NOT NULL, ordinal INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS gates (
                    id TEXT PRIMARY KEY, job TEXT NOT NULL, revision INTEGER NOT NULL,
                    phase TEXT NOT NULL, findings TEXT NOT NULL, state TEXT NOT NULL, decision TEXT, decision_key TEXT UNIQUE);
                CREATE TABLE IF NOT EXISTS workers (id TEXT PRIMARY KEY, heartbeat REAL, job TEXT, state TEXT);
                CREATE TABLE IF NOT EXISTS pins (
                    key TEXT PRIMARY KEY, kind TEXT NOT NULL, fingerprint TEXT NOT NULL,
                    first_seen REAL NOT NULL, last_seen REAL NOT NULL);
                CREATE INDEX IF NOT EXISTS resources_job ON resources(job);
                CREATE INDEX IF NOT EXISTS gates_job ON gates(job);
                CREATE INDEX IF NOT EXISTS batch_members_batch ON batch_members(batch,wave);
                CREATE INDEX IF NOT EXISTS credential_attempts_job ON credential_attempts(job,seq);
                CREATE INDEX IF NOT EXISTS events_job ON events(job, seq);
                CREATE INDEX IF NOT EXISTS jobs_queue ON jobs(status, created);
            """)

            # Serialize additive migration so concurrent API/worker starts cannot race ALTER TABLE.
            db.execute("BEGIN IMMEDIATE")
            columns = {row["name"] for row in db.execute("PRAGMA table_info(jobs)")}
            for column in ("start_at", "latest_start_at", "started_at"):
                if column not in columns:
                    db.execute(f"ALTER TABLE jobs ADD COLUMN {column} REAL")
            if "started_at" not in columns:
                # Legacy jobs have no start window. Preserve continuations as already started.
                db.execute("""UPDATE jobs SET started_at=created WHERE status!='queued' OR worker IS NOT NULL
                    OR EXISTS(SELECT 1 FROM gates WHERE gates.job=jobs.id)""")
            db.execute(
                "CREATE INDEX IF NOT EXISTS jobs_start_window ON jobs(status,started_at,latest_start_at)"
            )
            if "queue" not in columns:
                db.execute("ALTER TABLE jobs ADD COLUMN queue TEXT NOT NULL DEFAULT 'scheduled'")
                db.execute(
                    "UPDATE jobs SET queue=CASE WHEN kind='rollback' THEN 'priority' "
                    f"WHEN kind IN ({','.join('?' * len(UPGRADE_KINDS))}) THEN 'upgrade' ELSE 'scheduled' END",
                    UPGRADE_KINDS,
                )
            db.execute("CREATE INDEX IF NOT EXISTS jobs_queue_order ON jobs(status,queue,created)")
            worker_columns = {row["name"] for row in db.execute("PRAGMA table_info(workers)")}
            for column in ("queues", "version"):
                if column not in worker_columns:
                    db.execute(f"ALTER TABLE workers ADD COLUMN {column} TEXT")

    @staticmethod
    def scheduled_request(request):
        request = dict(request)
        window = ScheduledRequest.model_validate(
            {key: request.get(key) for key in ("start_at", "latest_start_at", "queue")}
        )
        for key, value in window.model_dump().items():
            if value is None:
                request.pop(key, None)
            else:
                request[key] = value
        return (
            request,
            window.start_at.timestamp() if window.start_at is not None else None,
            window.latest_start_at.timestamp() if window.latest_start_at is not None else None,
        )

    @staticmethod
    def expire_pending(db, now):
        # Only unstarted jobs expire. Active operations and manual-review continuations keep their locks.
        rows = db.execute(
            """SELECT id,result FROM jobs WHERE status='queued' AND started_at IS NULL
            AND latest_start_at < ?""",
            (now,),
        ).fetchall()
        for row in rows:
            result = json.loads(row["result"])
            result.update(
                error_code="start_window_expired", error="latest_start_at passed before the job could start"
            )
            db.execute(
                "UPDATE jobs SET status='expired',result=?,updated=? WHERE id=?",
                (json.dumps(result), now, row["id"]),
            )
            db.execute(
                "INSERT INTO events(job,time,step,data) VALUES (?,?,?,?)",
                (row["id"], now, "start_window_expired", json.dumps({"latest_start_at_passed": True})),
            )

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=30)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA synchronous=FULL")
        try:
            with db:
                yield db
        finally:
            db.close()

    @staticmethod
    def schedule_metadata(item):
        for key in ("start_at", "latest_start_at"):
            if item.get(key) is not None:
                item[key] = datetime.fromtimestamp(item[key], timezone.utc).isoformat().replace("+00:00", "Z")
        return item

    @staticmethod
    def decode(row):
        if row is None:
            raise KeyError("job not found")
        item = Store.schedule_metadata(dict(row))
        item["lock_held"] = bool(item.get("lock_held", False))
        for field in ("request", "result"):
            item[field] = json.loads(item[field])
        return item

    def get(self, job_id):
        with self.connect() as db:
            item = self.decode(
                db.execute(
                    "SELECT jobs.*, EXISTS(SELECT 1 FROM locks WHERE job=jobs.id) AS lock_held FROM jobs WHERE id=?",
                    (job_id,),
                ).fetchone()
            )
            item["credential_usage"] = [
                json.loads(r["data"]) | {"time": r["time"]}
                for r in db.execute("SELECT * FROM credential_attempts WHERE job=? ORDER BY seq", (job_id,))
            ]
            used = list(
                dict.fromkeys(
                    r["profile"] for r in item["credential_usage"] if r["outcome"] == "authenticated"
                )
            )
            item["credential_summary"] = {
                "profiles_used": used,
                "multiple_profiles_used": len(used) > 1,
                "current_profile": next(
                    (
                        r["profile"]
                        for r in reversed(item["credential_usage"])
                        if r["outcome"] == "authenticated"
                    ),
                    None,
                ),
            }
            control = db.execute("SELECT * FROM controls WHERE job=?", (job_id,)).fetchone()
            item["control"] = dict(control) if control else {}
            item["validation_gates"] = [
                {
                    **dict(r),
                    "findings": json.loads(r["findings"]),
                    "decision": json.loads(r["decision"]) if r["decision"] else None,
                }
                for r in db.execute("SELECT * FROM gates WHERE job=? ORDER BY revision", (job_id,))
            ]
            return item

    def list(self, limit=100, offset=0):
        with self.connect() as db:
            return [
                self.get(r["id"])
                for r in db.execute(
                    "SELECT jobs.*, EXISTS(SELECT 1 FROM locks WHERE job=jobs.id) AS lock_held FROM jobs ORDER BY created DESC LIMIT ? OFFSET ?",
                    (limit, offset),
                )
            ]

    def submit(self, request, lock_key, key=None, kind="upgrade", parent=None):
        request, start_at, latest_start_at = self.scheduled_request(request)
        payload = json.dumps(request, sort_keys=True)
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self.expire_pending(db, time.time())
            if key:
                existing = db.execute(
                    "SELECT jobs.*, EXISTS(SELECT 1 FROM locks WHERE job=jobs.id) AS lock_held FROM jobs WHERE idempotency_key=?",
                    (key,),
                ).fetchone()
                if existing:
                    if (
                        existing["request"] != payload
                        or existing["kind"] != kind
                        or existing["parent"] != parent
                    ):
                        raise Conflict("idempotency key was used with different parameters")
                    return self.decode(existing)
            if parent and kind == "rollback":
                source = self.decode(db.execute("SELECT * FROM jobs WHERE id=?", (parent,)).fetchone())
                if source["status"] not in (
                    "succeeded",
                    "completed_with_warnings",
                    "failed",
                    "resolved",
                    "recovery_required",
                    "manually_completed",
                ):
                    raise Conflict("finish or resolve the source job before requesting rollback")
                if "rollback" not in source["result"]:
                    raise Conflict("source job has no recorded rollback target")
            if parent and kind != "rollback":
                if not db.execute("SELECT 1 FROM jobs WHERE id=?", (parent,)).fetchone():
                    raise KeyError("parent job not found")
            now, job_id = time.time(), str(uuid.uuid4())
            db.execute(
                """INSERT INTO jobs
                (id,device,lock_key,kind,parent,request,status,created,updated,idempotency_key,start_at,latest_start_at,queue)
                VALUES (?,?,?,?,?,?,'queued',?,?,?,?,?,?)""",
                (
                    job_id,
                    request.get("device", request.get("device_ip", request.get("serial"))),
                    lock_key,
                    kind,
                    parent,
                    payload,
                    now,
                    now,
                    key,
                    start_at,
                    latest_start_at,
                    request.get("queue") or default_queue(kind),
                ),
            )
            self.expire_pending(db, now)
        return self.get(job_id)

    def claim(self, worker, queues=QUEUES):
        """Claim the oldest eligible job, trying the worker's queues in the order given."""
        queues = tuple(queues)
        if not queues or not set(queues) <= set(QUEUES):
            raise ValueError("unknown worker queue")
        order = "".join(f" WHEN ? THEN {rank}" for rank in range(len(queues)))
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self.expire_pending(db, time.time())
            for row in db.execute(
                f"""SELECT * FROM jobs WHERE status='queued' AND queue IN ({",".join("?" * len(queues))})
                ORDER BY CASE queue{order} END,created,id""",
                queues + queues,
            ).fetchall():
                now = time.time()
                if row["started_at"] is None:
                    if row["latest_start_at"] is not None and row["latest_start_at"] < now:
                        self.expire_pending(db, now)
                        continue
                    if row["start_at"] is not None and row["start_at"] > now:
                        continue
                control = db.execute("SELECT * FROM controls WHERE job=?", (row["id"],)).fetchone()
                if control and control["next_attempt"] > time.time():
                    continue
                member = db.execute("SELECT * FROM batch_members WHERE job=?", (row["id"],)).fetchone()
                if member:
                    prior = db.execute(
                        """SELECT 1 FROM batch_members m JOIN jobs j ON j.id=m.job
                        WHERE m.batch=? AND m.wave<? AND j.status NOT IN ('succeeded','completed_with_warnings','manually_completed') LIMIT 1""",
                        (member["batch"], member["wave"]),
                    ).fetchone()
                    if prior:
                        continue
                    payload = json.loads(
                        db.execute("SELECT request FROM batches WHERE id=?", (member["batch"],)).fetchone()[0]
                    )
                    maximum = next(
                        w["upgrade_at_a_time"] for w in payload["waves"] if w["wave"] == member["wave"]
                    )
                    running = db.execute(
                        "SELECT count(*) FROM batch_members m JOIN jobs j ON j.id=m.job WHERE m.batch=? AND m.wave=? AND j.status='running'",
                        (member["batch"], member["wave"]),
                    ).fetchone()[0]
                    if running >= maximum:
                        continue
                reserved = db.execute("SELECT job FROM resources WHERE key=?", (row["lock_key"],)).fetchone()
                if (
                    reserved
                    and reserved[0] != row["id"]
                    and not (row["kind"] == "rollback" and reserved[0] == row["parent"])
                ):
                    continue
                held = db.execute("SELECT job FROM locks WHERE key=?", (row["lock_key"],)).fetchone()
                takeover = row["kind"] == "rollback" and held and held[0] == row["parent"]
                if held and held[0] != row["id"] and not takeover:
                    continue
                now = time.time()
                if (
                    row["started_at"] is None
                    and row["latest_start_at"] is not None
                    and row["latest_start_at"] < now
                ):
                    self.expire_pending(db, now)
                    continue
                if takeover:
                    source = db.execute("SELECT status FROM jobs WHERE id=?", (row["parent"],)).fetchone()
                    if source[0] not in ("failed", "recovery_required", "manually_completed"):
                        continue
                    # API requires an explicit stopped-worker attestation for uncertain outcomes.
                    if source[0] in ("recovery_required", "manually_completed") and not json.loads(
                        row["request"]
                    ).get("worker_stopped"):
                        continue
                    db.execute("UPDATE resources SET job=? WHERE job=?", (row["id"], row["parent"]))
                    db.execute("DELETE FROM locks WHERE job=?", (row["parent"],))
                    db.execute(
                        "UPDATE jobs SET result=? WHERE id=?",
                        (json.dumps({"inherited_lock": True}), row["id"]),
                    )
                db.execute("INSERT OR REPLACE INTO locks VALUES (?,?)", (row["lock_key"], row["id"]))
                db.execute(
                    "UPDATE jobs SET status='running',worker=?,heartbeat=?,updated=?,started_at=coalesce(started_at,?) WHERE id=?",
                    (worker, now, now, now, row["id"]),
                )
                chosen = row["id"]
                break
            else:
                return None
        return self.get(chosen)

    def reserve(self, job, worker, keys):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self._owned(db, job, worker)
            for key in sorted(set(keys)):
                legacy = db.execute("SELECT job FROM locks WHERE key=?", (key,)).fetchone()
                if legacy and legacy[0] != job:
                    return False
                owner = db.execute("SELECT job FROM resources WHERE key=?", (key,)).fetchone()
                if owner and owner[0] != job:
                    return False
            db.executemany("INSERT OR IGNORE INTO resources VALUES (?,?)", [(key, job) for key in set(keys)])
        return True

    @staticmethod
    def _owned(db, job, worker):
        row = db.execute("SELECT * FROM jobs WHERE id=?", (job,)).fetchone()
        if not row or row["status"] != "running" or row["worker"] != worker:
            raise LostOwnership("job ownership revoked")
        return row

    def checkpoint(self, job, worker):
        self.guard(job, worker)
        with self.connect() as db:
            control = db.execute("SELECT cancel FROM controls WHERE job=?", (job,)).fetchone()
            if control and control[0]:
                raise CancelRequested("cancellation requested")

    def defer(self, job, worker):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self._owned(db, job, worker)
            db.execute(
                "INSERT INTO controls(job,next_attempt) VALUES (?,?) ON CONFLICT(job) DO UPDATE SET next_attempt=excluded.next_attempt",
                (job, time.time() + 3 + (int(uuid.UUID(job)) % 3000) / 1000),
            )
            # A reservation-only attempt has not begun work. Keep the original start on review continuations.
            db.execute(
                """UPDATE jobs SET status='queued',worker=NULL,heartbeat=NULL,
                started_at=CASE WHEN EXISTS(SELECT 1 FROM controls WHERE job=? AND continuation IS NOT NULL)
                THEN started_at ELSE NULL END WHERE id=?""",
                (job, job),
            )
            db.execute("DELETE FROM locks WHERE job=?", (job,))
            db.execute("DELETE FROM resources WHERE job=?", (job,))
        raise Deferred()

    def guard(self, job, worker):
        with self.connect() as db:
            row = db.execute("SELECT status,worker FROM jobs WHERE id=?", (job,)).fetchone()
            if not row or row["status"] != "running" or row["worker"] != worker:
                raise LostOwnership("job ownership was revoked; device requires inspection")

    def heartbeat(self, job, worker):
        with self.connect() as db:
            return (
                db.execute(
                    "UPDATE jobs SET heartbeat=? WHERE id=? AND worker=? AND status='running'",
                    (time.time(), job, worker),
                ).rowcount
                == 1
            )

    def reap(self, seconds):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self.expire_pending(db, time.time())
            stale = db.execute(
                "SELECT id,kind,result FROM jobs WHERE kind IN ('snmp_walk','cipher_scan') AND status='running' AND heartbeat<?",
                (time.time() - seconds,),
            ).fetchall()
            for row in stale:
                result = json.loads(row["result"])
                result["error"] = "SNMP worker heartbeat expired; partial results retained"
                if row["kind"] == "cipher_scan":
                    result.update(error_code="worker_lost", error="cipher scan worker heartbeat expired")
                for item in result.get("oids", []):
                    if item["status"] in ("pending", "running"):
                        item.update(status="failed", error="worker heartbeat expired")
                db.execute(
                    "UPDATE jobs SET status='failed',result=?,updated=? WHERE id=?",
                    (json.dumps(result), time.time(), row["id"]),
                )
                db.execute("DELETE FROM locks WHERE job=?", (row["id"],))
                db.execute("DELETE FROM resources WHERE job=?", (row["id"],))
            # Locks deliberately survive stale SSH workers: do not run a second job on an ambiguous device.
            db.execute(
                """UPDATE jobs SET status='recovery_required',updated=?
                WHERE status='running' AND kind NOT IN ('snmp_walk','cipher_scan') AND heartbeat<?""",
                (time.time(), time.time() - seconds),
            )

    def record(self, job, worker, step, data=None, result=None):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM jobs WHERE id=?", (job,)).fetchone()
            if row["status"] != "running" or row["worker"] != worker:
                raise LostOwnership("job is no longer owned")
            db.execute(
                "INSERT INTO events(job,time,step,data) VALUES (?,?,?,?)",
                (job, time.time(), step, json.dumps(data or {})),
            )
            if result is not None:
                db.execute(
                    "UPDATE jobs SET result=?,updated=? WHERE id=?", (json.dumps(result), time.time(), job)
                )

    def finish(self, job, worker, status, retain_lock=False):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            changed = db.execute(
                "UPDATE jobs SET status=?,updated=? WHERE id=? AND worker=? AND status='running'",
                (status, time.time(), job, worker),
            ).rowcount
            if changed:
                control = db.execute("SELECT waive FROM controls WHERE job=?", (job,)).fetchone()
                if control and control[0]:
                    db.execute("UPDATE jobs SET status='manually_completed' WHERE id=?", (job,))
            if changed and status not in ("recovery_required", "needs_review") and not retain_lock:
                db.execute("DELETE FROM locks WHERE job=?", (job,))
                db.execute("DELETE FROM resources WHERE job=?", (job,))

    def events(self, job, after=0, limit=500):
        self.get(job)
        with self.connect() as db:
            return [
                {**dict(r), "data": json.loads(r["data"])}
                for r in db.execute(
                    "SELECT * FROM events WHERE job=? AND seq>? ORDER BY seq LIMIT ?", (job, after, limit)
                )
            ]

    def cancel(self, job):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT status FROM jobs WHERE id=?", (job,)).fetchone()
            if not row:
                raise KeyError(job)
            if row[0] == "queued":
                held = db.execute("SELECT 1 FROM locks WHERE job=?", (job,)).fetchone()
                db.execute(
                    "UPDATE jobs SET status=?,updated=? WHERE id=?",
                    ("recovery_required" if held else "cancelled", time.time(), job),
                )
            elif row[0] == "running":
                db.execute(
                    "INSERT INTO controls(job,cancel) VALUES (?,1) ON CONFLICT(job) DO UPDATE SET cancel=1",
                    (job,),
                )
            elif row[0] == "needs_review":
                db.execute(
                    "UPDATE jobs SET status='recovery_required',updated=? WHERE id=?", (time.time(), job)
                )
            else:
                raise Conflict("job is not cancellable")
        return self.get(job)

    def resolve(self, job, resolution):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT status FROM jobs WHERE id=?", (job,)).fetchone()
            held = db.execute("SELECT 1 FROM locks WHERE job=?", (job,)).fetchone()
            if (
                not row
                or row["status"] not in ("recovery_required", "failed", "manually_completed")
                or not held
            ):
                raise Conflict("only failed or recovery_required jobs holding a lock can be resolved")
            db.execute(
                "UPDATE jobs SET status=?,updated=? WHERE id=?",
                (
                    "manually_completed" if row["status"] == "manually_completed" else "resolved",
                    time.time(),
                    job,
                ),
            )
            db.execute("DELETE FROM locks WHERE job=?", (job,))
            db.execute("DELETE FROM resources WHERE job=?", (job,))
            db.execute(
                "INSERT INTO events(job,time,step,data) VALUES (?,?,?,?)",
                (job, time.time(), "operator_resolution", json.dumps(resolution)),
            )
        return self.get(job)

    def append_snmp_rows(self, job, worker, rows, result):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            owned = db.execute(
                "SELECT 1 FROM jobs WHERE id=? AND worker=? AND status='running' AND kind='snmp_walk'",
                (job, worker),
            ).fetchone()
            if not owned:
                raise LostOwnership("job is no longer owned")
            db.executemany(
                "INSERT INTO snmp_rows(job,root_oid,oid,type,value,encoding) VALUES (?,?,?,?,?,?)",
                [(job, r["root_oid"], r["oid"], r["type"], r["value"], r["encoding"]) for r in rows],
            )
            db.execute(
                "UPDATE jobs SET result=?,updated=? WHERE id=?", (json.dumps(result), time.time(), job)
            )

    def snmp_results(self, job, after=0, limit=500):
        # Read status and rows from one snapshot: terminal=true must include all committed rows.
        with self.connect() as db:
            db.execute("BEGIN")
            state = db.execute("SELECT kind,status FROM jobs WHERE id=?", (job,)).fetchone()
            if state is None or state["kind"] != "snmp_walk":
                raise KeyError("SNMP job not found")
            rows = [
                dict(r)
                for r in db.execute(
                    "SELECT seq,root_oid,oid,type,value,encoding FROM snmp_rows WHERE job=? AND seq>? ORDER BY seq LIMIT ?",
                    (job, after, limit + 1),
                )
            ]
            more = len(rows) > limit
            rows = rows[:limit]
            return {
                "id": job,
                "status": state["status"],
                "finished": state["status"] not in ("queued", "running"),
                "rows": rows,
                "next_cursor": rows[-1]["seq"] if rows else after,
                "has_more": more,
            }

    def credential_event(self, job, worker, data):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self._owned(db, job, worker)
            db.execute(
                "INSERT INTO credential_attempts(job,time,data) VALUES (?,?,?)",
                (job, time.time(), json.dumps(data)),
            )

    def create_batch(self, batch, key, lock_key, kind="upgrade"):
        payload = batch.model_dump_json(
            exclude={key for key in ("start_at", "latest_start_at", "queue") if getattr(batch, key) is None}
        )
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self.expire_pending(db, time.time())
            if key:
                old = db.execute("SELECT * FROM batches WHERE key=?", (key,)).fetchone()
                if old:
                    if old["request"] != payload:
                        raise Conflict("batch idempotency key has different parameters")
                    batch_id = old["id"]
                    return self._batch(db, batch_id)
            batch_id, now = str(uuid.uuid4()), time.time()
            db.execute("INSERT INTO batches VALUES (?,?,?,?)", (batch_id, payload, key, now))
            ordinal = 0
            for wave in batch.waves:
                for member in wave.members:
                    request, start_at, latest_start_at = self.scheduled_request(
                        batch.request_for(member).model_dump(mode="json")
                    )
                    job = str(uuid.uuid4())
                    db.execute(
                        "INSERT INTO jobs(id,device,lock_key,kind,request,status,created,updated,start_at,latest_start_at,queue) VALUES (?,?,?,?,?,'queued',?,?,?,?,?)",
                        (
                            job,
                            member,
                            lock_key(member),
                            kind,
                            json.dumps(request),
                            now + ordinal * 0.000001,
                            now,
                            start_at,
                            latest_start_at,
                            request.get("queue") or batch.queue or default_queue(kind),
                        ),
                    )
                    db.execute(
                        "INSERT INTO batch_members VALUES (?,?,?,?)", (job, batch_id, wave.wave, ordinal)
                    )
                    ordinal += 1
            self.expire_pending(db, now)
            return self._batch(db, batch_id)

    def _batch(self, db, batch):
        row = db.execute("SELECT * FROM batches WHERE id=?", (batch,)).fetchone()
        if not row:
            raise KeyError(batch)
        jobs = [
            dict(r)
            for r in db.execute(
                "SELECT j.id,j.device,j.kind,j.queue,j.status,j.result,j.start_at,j.latest_start_at,j.started_at,m.wave,m.ordinal FROM jobs j JOIN batch_members m ON m.job=j.id WHERE m.batch=? ORDER BY m.ordinal",
                (batch,),
            )
        ]
        for job in jobs:
            self.schedule_metadata(job)
            job["result"] = json.loads(job["result"])
        done = all(
            j["status"] in ("succeeded", "completed_with_warnings", "manually_completed") for j in jobs
        )
        waves = []
        for wave in json.loads(row["request"])["waves"]:
            members = [j for j in jobs if j["wave"] == wave["wave"]]
            completed = sum(
                j["status"] in ("succeeded", "completed_with_warnings", "manually_completed") for j in members
            )
            waves.append(
                {
                    "wave": wave["wave"],
                    "upgrade_at_a_time": wave["upgrade_at_a_time"],
                    "total": len(members),
                    "completed": completed,
                    "running": sum(j["status"] == "running" for j in members),
                }
            )
        return {
            "waves": waves,
            "id": batch,
            "kind": jobs[0]["kind"] if jobs else "upgrade",
            "name": json.loads(row["request"])["name"],
            "start_at": json.loads(row["request"]).get("start_at"),
            "latest_start_at": json.loads(row["request"]).get("latest_start_at"),
            "status": "completed"
            if done
            else (
                "needs_attention"
                if any(
                    j["status"]
                    in ("needs_review", "failed", "recovery_required", "cancelled", "resolved", "expired")
                    for j in jobs
                )
                else "in_progress"
            ),
            "device_count": len(jobs),
            "jobs": jobs,
            "status_url": "/api/v1/upgrade-batches/" + batch,
        }

    def batch(self, batch):
        with self.connect() as db:
            return self._batch(db, batch)

    def open_gate(self, job, worker, phase, findings, result):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self._owned(db, job, worker)
            revision = db.execute(
                "SELECT coalesce(max(revision),0)+1 FROM gates WHERE job=?", (job,)
            ).fetchone()[0]
            gate = str(uuid.uuid4())
            db.execute(
                "INSERT INTO gates(id,job,revision,phase,findings,state) VALUES (?,?,?,?,?,'open')",
                (gate, job, revision, phase, json.dumps(findings)),
            )
            db.execute(
                "INSERT INTO controls(job,continuation) VALUES (?,?) ON CONFLICT(job) DO UPDATE SET continuation=excluded.continuation",
                (job, phase),
            )
            db.execute(
                "UPDATE jobs SET status='needs_review',result=?,updated=? WHERE id=?",
                (json.dumps(result), time.time(), job),
            )
        raise NeedsReview()

    def decide(self, job, decision, key=None):
        payload = decision.model_dump_json()
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            gate = db.execute("SELECT * FROM gates WHERE id=? AND job=?", (decision.gate_id, job)).fetchone()
            if not gate or gate["revision"] != decision.validation_revision:
                raise Conflict("validation gate/revision does not match")
            if gate["decision"] == payload and gate["state"] in ("pending", "applied"):
                return {"gate_id": gate["id"], "state": gate["state"]}
            status = db.execute("SELECT status FROM jobs WHERE id=?", (job,)).fetchone()[0]
            if gate["state"] != "open" or status != "needs_review":
                raise Conflict("validation gate is not open")
            if key and db.execute("SELECT 1 FROM gates WHERE decision_key=?", (key,)).fetchone():
                raise Conflict("decision key already used")
            db.execute(
                "UPDATE gates SET state='pending',decision=?,decision_key=? WHERE id=?",
                (payload, key, gate["id"]),
            )
            db.execute("UPDATE jobs SET status='queued',worker=NULL,heartbeat=NULL WHERE id=?", (job,))
        return {"gate_id": decision.gate_id, "state": "pending"}

    def apply_decision(self, job, worker):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            self._owned(db, job, worker)
            gate = db.execute(
                "SELECT * FROM gates WHERE job=? AND state='pending' ORDER BY revision DESC LIMIT 1", (job,)
            ).fetchone()
            if not gate:
                return None
            db.execute("UPDATE gates SET state='applied' WHERE id=?", (gate["id"],))
            return {**dict(gate), "decision": json.loads(gate["decision"])}

    def mark_done(self, job, request):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT status FROM jobs WHERE id=?", (job,)).fetchone()
            if not row:
                raise KeyError(job)
            if row[0] in ("succeeded", "completed_with_warnings", "manually_completed"):
                return self.decode(db.execute("SELECT * FROM jobs WHERE id=?", (job,)).fetchone())
            db.execute(
                "INSERT INTO controls(job,cancel,waive,operator,reason) VALUES (?,1,1,?,?) ON CONFLICT(job) DO UPDATE SET cancel=1,waive=1,operator=excluded.operator,reason=excluded.reason",
                (job, request.operator, request.reason),
            )
            if row[0] != "running":
                db.execute(
                    "UPDATE jobs SET status='manually_completed',updated=? WHERE id=?", (time.time(), job)
                )
            db.execute(
                "INSERT INTO events(job,time,step,data) VALUES (?,?,?,?)",
                (job, time.time(), "manual_completion_requested", request.model_dump_json()),
            )
        return self.get(job)

    def validated_peer(self, current, cluster, active, peer_name):
        with self.connect() as db:
            rows = db.execute(
                "SELECT status,result FROM jobs WHERE kind='upgrade' AND id!=? AND status IN ('succeeded','completed_with_warnings','manually_completed') AND NOT EXISTS(SELECT 1 FROM locks WHERE job=jobs.id) ORDER BY updated DESC",
                (current,),
            ).fetchall()
            for row in rows:
                result = json.loads(row["result"])
                if (
                    result.get("ha", {}).get("cluster") == cluster
                    and result.get("ha", {}).get("self") == peer_name
                ):
                    # Manual completion advances a wave; it does not prove the peer passed validation.
                    if row["status"] == "manually_completed" and not result.get("validation_accepted"):
                        continue
                    verified = result.get("boot_verified", {})
                    if not verified:
                        continue
                    return all(verified.get(k) == active.get(k) for k in ("volume", "version", "build"))
        return False

    def pin(self, key, kind, fingerprint):
        """Trust on first use: record a first fingerprint, then accept only a match."""
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT fingerprint FROM pins WHERE key=?", (key,)).fetchone()
            now = time.time()
            if row is None:
                db.execute("INSERT INTO pins VALUES (?,?,?,?,?)", (key, kind, fingerprint, now, now))
                return True
            if row["fingerprint"] != fingerprint:
                return False
            db.execute("UPDATE pins SET last_seen=? WHERE key=?", (now, key))
            return True

    def pins(self):
        with self.connect() as db:
            return [dict(r) for r in db.execute("SELECT * FROM pins ORDER BY key")]

    def unpin(self, key):
        with self.connect() as db:
            if not db.execute("DELETE FROM pins WHERE key=?", (key,)).rowcount:
                raise KeyError(key)

    def worker_seen(self, worker, job=None, state="available", queues=None):
        # Each heartbeat carries the release of the code running in that worker process.
        with self.connect() as db:
            db.execute(
                """INSERT INTO workers(id,heartbeat,job,state,queues,version) VALUES (?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET heartbeat=excluded.heartbeat,job=excluded.job,
                state=excluded.state,queues=coalesce(excluded.queues,workers.queues),version=excluded.version""",
                (worker, time.time(), job, state, json.dumps(list(queues)) if queues else None, __version__),
            )

    def worker_list(self, seconds=120):
        with self.connect() as db:
            return [
                {
                    **dict(row),
                    # Workers from releases before queues claimed from every queue.
                    "queues": json.loads(row["queues"]) if row["queues"] else list(QUEUES),
                    "online": row["state"] != "stopped" and row["heartbeat"] >= time.time() - seconds,
                }
                for row in db.execute("SELECT * FROM workers ORDER BY id")
            ]

    def queue_summary(self, seconds=120):
        """Backlog and workers per queue. due excludes jobs waiting for a future start_at; workers are
        the queue's pool (first choice) and fallback_workers the other online workers that claim from it."""
        now = time.time()
        summary = {
            q: {"queue": q, "queued": 0, "due": 0, "running": 0, "oldest_due_wait_seconds": None}
            for q in QUEUES
        }
        with self.connect() as db:
            for row in db.execute(
                """SELECT queue,status,count(*) AS jobs,
                min(CASE WHEN start_at IS NULL OR start_at<=? THEN created END) AS oldest,
                sum(start_at IS NULL OR start_at<=?) AS due
                FROM jobs WHERE status IN ('queued','running') GROUP BY queue,status""",
                (now, now),
            ):
                item = summary[row["queue"]]
                if row["status"] == "running":
                    item["running"] = row["jobs"]
                else:
                    item.update(
                        queued=row["jobs"],
                        due=row["due"],
                        oldest_due_wait_seconds=round(now - row["oldest"], 1) if row["oldest"] else None,
                    )
        workers = [w for w in self.worker_list(seconds) if w["online"]]
        for item in summary.values():
            pool = [w for w in workers if w["queues"][0] == item["queue"]]
            item.update(
                workers=len(pool),
                busy_workers=sum(w["state"] == "busy" for w in pool),
                fallback_workers=sum(item["queue"] in w["queues"][1:] for w in workers),
            )
        return list(summary.values())
