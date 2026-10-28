"""SQLite queue. No automatic replay of ambiguous device operations."""

import json
import sqlite3
import time
import uuid
from contextlib import contextmanager


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
                CREATE INDEX IF NOT EXISTS resources_job ON resources(job);
                CREATE INDEX IF NOT EXISTS gates_job ON gates(job);
                CREATE INDEX IF NOT EXISTS batch_members_batch ON batch_members(batch,wave);
                CREATE INDEX IF NOT EXISTS credential_attempts_job ON credential_attempts(job,seq);
                CREATE INDEX IF NOT EXISTS events_job ON events(job, seq);
                CREATE INDEX IF NOT EXISTS jobs_queue ON jobs(status, created);
            """)

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
    def decode(row):
        if row is None:
            raise KeyError("job not found")
        item = dict(row)
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
        payload = json.dumps(request, sort_keys=True)
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
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
                (id,device,lock_key,kind,parent,request,status,created,updated,idempotency_key)
                VALUES (?,?,?,?,?,?,'queued',?,?,?)""",
                (
                    job_id,
                    request.get("device", request.get("device_ip")),
                    lock_key,
                    kind,
                    parent,
                    payload,
                    now,
                    now,
                    key,
                ),
            )
        return self.get(job_id)

    def claim(self, worker):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            for row in db.execute("SELECT * FROM jobs WHERE status='queued' ORDER BY created,id").fetchall():
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
                    "UPDATE jobs SET status='running',worker=?,heartbeat=?,updated=? WHERE id=?",
                    (worker, time.time(), time.time(), row["id"]),
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
            db.execute("UPDATE jobs SET status='queued',worker=NULL,heartbeat=NULL WHERE id=?", (job,))
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
            stale = db.execute(
                "SELECT id,result FROM jobs WHERE kind='snmp_walk' AND status='running' AND heartbeat<?",
                (time.time() - seconds,),
            ).fetchall()
            for row in stale:
                result = json.loads(row["result"])
                result["error"] = "SNMP worker heartbeat expired; partial results retained"
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
                WHERE status='running' AND kind!='snmp_walk' AND heartbeat<?""",
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

    def create_batch(self, batch, key, lock_key):
        payload = batch.model_dump_json()
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
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
                for ip in wave.ips:
                    request = batch.request_for(ip).model_dump(mode="json")
                    job = str(uuid.uuid4())
                    db.execute(
                        "INSERT INTO jobs(id,device,lock_key,kind,request,status,created,updated) VALUES (?,?,?,'upgrade',?,'queued',?,?)",
                        (job, ip, lock_key(ip), json.dumps(request), now + ordinal * 0.000001, now),
                    )
                    db.execute(
                        "INSERT INTO batch_members VALUES (?,?,?,?)", (job, batch_id, wave.wave, ordinal)
                    )
                    ordinal += 1
            return self._batch(db, batch_id)

    def _batch(self, db, batch):
        row = db.execute("SELECT * FROM batches WHERE id=?", (batch,)).fetchone()
        if not row:
            raise KeyError(batch)
        jobs = [
            dict(r)
            for r in db.execute(
                "SELECT j.id,j.device,j.status,j.result,m.wave,m.ordinal FROM jobs j JOIN batch_members m ON m.job=j.id WHERE m.batch=? ORDER BY m.ordinal",
                (batch,),
            )
        ]
        for job in jobs:
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
            "name": json.loads(row["request"])["name"],
            "status": "completed"
            if done
            else (
                "needs_attention"
                if any(
                    j["status"] in ("needs_review", "failed", "recovery_required", "cancelled", "resolved")
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
                "SELECT result FROM jobs WHERE kind='upgrade' AND id!=? AND status IN ('succeeded','completed_with_warnings','manually_completed') AND NOT EXISTS(SELECT 1 FROM locks WHERE job=jobs.id) ORDER BY updated DESC",
                (current,),
            ).fetchall()
            for row in rows:
                result = json.loads(row[0])
                if (
                    result.get("ha", {}).get("cluster") == cluster
                    and result.get("ha", {}).get("self") == peer_name
                ):
                    verified = result.get("boot_verified", {})
                    if not verified:
                        continue
                    return all(verified.get(k) == active.get(k) for k in ("volume", "version", "build"))
        return False

    def worker_seen(self, worker, job=None, state="available"):
        with self.connect() as db:
            db.execute(
                "INSERT INTO workers(id,heartbeat,job,state) VALUES (?,?,?,?) ON CONFLICT(id) DO UPDATE SET heartbeat=excluded.heartbeat,job=excluded.job,state=excluded.state",
                (worker, time.time(), job, state),
            )

    def worker_list(self, seconds=120):
        with self.connect() as db:
            return [
                {
                    **dict(row),
                    "online": row["state"] != "stopped" and row["heartbeat"] >= time.time() - seconds,
                }
                for row in db.execute("SELECT * FROM workers ORDER BY id")
            ]
