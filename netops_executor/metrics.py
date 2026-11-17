"""Database-backed Prometheus metrics shared by every API and worker process."""

import json
import time
from collections import defaultdict

from . import __version__
from .models import QUEUES
from .store import EMAIL_STATUSES, UPGRADE_KINDS

JOB_KINDS = (
    *UPGRADE_KINDS,
    "rollback",
    "snmp_walk",
    "ssh",
    "http",
    "cipher_scan",
    "password_rotation",
    "panorama_password_rotation",
)
RESULTS = {
    "succeeded": "pass",
    "completed_with_warnings": "warning",
    "failed": "fail",
    "recovery_required": "fail",
    "cancelled": "cancelled",
    "expired": "expired",
    "manually_completed": "manual",
    "resolved": "resolved",
}
BUCKETS = (1, 5, 10, 30, 60, 120, 300, 600, 1800, 3600, 7200, 14400)


def initialize_metrics(db):
    """Keep one durable observation per job, including work executed by older workers."""
    terminal = ",".join(f"'{status}'" for status in EMAIL_STATUSES)
    new_table = (
        db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='job_metrics'").fetchone() is None
    )
    db.execute("""CREATE TABLE IF NOT EXISTS job_metrics (
        job_id TEXT PRIMARY KEY, kind TEXT NOT NULL, submitted_queue TEXT NOT NULL,
        created_at REAL NOT NULL, eligible_at REAL NOT NULL,
        finished_queue TEXT, started_at REAL, finished_at REAL, finished_status TEXT
    )""")
    db.execute("""CREATE INDEX IF NOT EXISTS job_metrics_submitted
        ON job_metrics(submitted_queue,kind)""")
    db.execute("""CREATE INDEX IF NOT EXISTS job_metrics_finished
        ON job_metrics(finished_queue,kind,finished_status,finished_at,started_at,eligible_at)
        WHERE finished_at IS NOT NULL""")
    if new_table:
        db.execute(f"""INSERT OR IGNORE INTO job_metrics
            (job_id,kind,submitted_queue,created_at,eligible_at,finished_queue,started_at,finished_at,finished_status)
            SELECT id,kind,queue,created,max(created,coalesce(start_at,created)),
            CASE WHEN status IN ({terminal}) THEN queue END,started_at,
            CASE WHEN status IN ({terminal}) THEN updated END,
            CASE WHEN status IN ({terminal}) THEN status END FROM jobs""")
    # Finished jobs are folded into these totals, so a scrape reads only unfinished and newly
    # finished jobs instead of the whole history. Totals only grow: counters stay monotonic.
    db.execute("""CREATE TABLE IF NOT EXISTS job_metrics_submitted_rollup (
        queue TEXT NOT NULL, kind TEXT NOT NULL, count INTEGER NOT NULL, PRIMARY KEY(queue,kind))""")
    db.execute("""CREATE TABLE IF NOT EXISTS job_metrics_finished_rollup (
        queue TEXT NOT NULL, kind TEXT NOT NULL, status TEXT NOT NULL, count INTEGER NOT NULL,
        last_finished REAL, PRIMARY KEY(queue,kind,status))""")
    buckets = ",".join(f"bucket_{index} INTEGER NOT NULL DEFAULT 0" for index in range(len(BUCKETS)))
    db.execute(f"""CREATE TABLE IF NOT EXISTS job_metrics_duration_rollup (
        metric TEXT NOT NULL, queue TEXT NOT NULL, kind TEXT NOT NULL, count INTEGER NOT NULL,
        total REAL NOT NULL, {buckets}, PRIMARY KEY(metric,queue,kind))""")
    db.execute("""CREATE INDEX IF NOT EXISTS job_metrics_finished_at
        ON job_metrics(finished_at) WHERE finished_at IS NOT NULL""")
    # Recreated on every start, like the store's other triggers, so fixes reach existing databases.
    db.execute("DROP TRIGGER IF EXISTS jobs_metrics_submitted")
    db.execute("DROP TRIGGER IF EXISTS jobs_metrics_finished")
    db.execute("""CREATE TRIGGER jobs_metrics_submitted AFTER INSERT ON jobs
        BEGIN
            INSERT OR IGNORE INTO job_metrics(job_id,kind,submitted_queue,created_at,eligible_at)
            VALUES(NEW.id,NEW.kind,NEW.queue,NEW.created,max(NEW.created,coalesce(NEW.start_at,NEW.created)));
        END""")
    db.execute(f"""CREATE TRIGGER jobs_metrics_finished AFTER UPDATE OF status ON jobs
        WHEN NEW.status IS NOT OLD.status AND NEW.status IN ({terminal})
        BEGIN
            UPDATE job_metrics SET finished_queue=NEW.queue,started_at=NEW.started_at,
                finished_at=NEW.updated,finished_status=NEW.status
            WHERE job_id=NEW.id AND finished_at IS NULL;
        END""")


DURATIONS = {"duration": "max(0,finished_at-started_at)", "wait": "max(0,started_at-eligible_at)"}


def rollup_metrics(db):
    """Fold finished observations into the rollup totals and drop their rows (one transaction)."""
    db.execute("BEGIN IMMEDIATE")
    db.execute("""INSERT INTO job_metrics_submitted_rollup(queue,kind,count)
        SELECT submitted_queue,kind,count(*) FROM job_metrics WHERE finished_at IS NOT NULL
        GROUP BY submitted_queue,kind
        ON CONFLICT(queue,kind) DO UPDATE SET count=count+excluded.count""")
    db.execute("""INSERT INTO job_metrics_finished_rollup(queue,kind,status,count,last_finished)
        SELECT finished_queue,kind,finished_status,count(*),max(finished_at) FROM job_metrics
        WHERE finished_at IS NOT NULL GROUP BY finished_queue,kind,finished_status
        ON CONFLICT(queue,kind,status) DO UPDATE SET count=count+excluded.count,
        last_finished=max(coalesce(last_finished,0),excluded.last_finished)""")
    columns = ",".join(f"bucket_{index}" for index in range(len(BUCKETS)))
    updates = ",".join(
        f"bucket_{index}=bucket_{index}+excluded.bucket_{index}" for index in range(len(BUCKETS))
    )
    for metric, expression in DURATIONS.items():
        sums = ",".join(f"sum(({expression})<={limit})" for limit in BUCKETS)
        db.execute(
            f"""INSERT INTO job_metrics_duration_rollup(metric,queue,kind,count,total,{columns})
            SELECT ?,finished_queue,kind,count(*),sum({expression}),{sums} FROM job_metrics
            WHERE finished_at IS NOT NULL AND started_at IS NOT NULL GROUP BY finished_queue,kind
            ON CONFLICT(metric,queue,kind) DO UPDATE SET count=count+excluded.count,
            total=total+excluded.total,{updates}""",
            (metric,),
        )
    db.execute("DELETE FROM job_metrics WHERE finished_at IS NOT NULL")
    db.execute("COMMIT")


def duration_rows(db, expression):
    buckets = ",".join(
        f"sum(({expression})<={limit}) AS bucket_{index}" for index, limit in enumerate(BUCKETS)
    )
    return {
        (row["queue"], row["kind"]): dict(row)
        for row in db.execute(f"""SELECT finished_queue AS queue,kind,count(*) AS count,
            sum({expression}) AS total,{buckets}
            FROM job_metrics WHERE finished_at IS NOT NULL AND started_at IS NOT NULL
            GROUP BY finished_queue,kind""")
    }


def add_rows(target, rows, keys):
    for row in rows:
        key = tuple(row[k] for k in keys)
        current = target.get(key)
        if current is None:
            target[key] = dict(row)
            continue
        for name, value in dict(row).items():
            if name in keys or value is None:
                continue
            if name == "last_finished":
                current[name] = max(current.get(name) or 0, value)
            else:
                current[name] = (current.get(name) or 0) + value


def snapshot(store, stale_seconds):
    now = time.time()
    with store.connect() as db:
        rollup_metrics(db)
        db.execute("BEGIN")
        counts = {}
        add_rows(
            counts,
            db.execute("""SELECT submitted_queue AS queue,kind,count(*) AS count
                FROM job_metrics GROUP BY submitted_queue,kind"""),
            ("queue", "kind"),
        )
        add_rows(
            counts, db.execute("SELECT queue,kind,count FROM job_metrics_submitted_rollup"), ("queue", "kind")
        )
        submitted = {key: row["count"] for key, row in counts.items()}
        completed = {}
        add_rows(
            completed,
            db.execute("""SELECT finished_queue AS queue,kind,finished_status AS status,
                count(*) AS count,max(finished_at) AS last_finished
                FROM job_metrics WHERE finished_at IS NOT NULL GROUP BY finished_queue,kind,finished_status"""),
            ("queue", "kind", "status"),
        )
        add_rows(
            completed,
            db.execute("SELECT queue,kind,status,count,last_finished FROM job_metrics_finished_rollup"),
            ("queue", "kind", "status"),
        )
        current = {
            (row["queue"], row["kind"], row["status"]): row["count"]
            for row in db.execute("""SELECT queue,kind,status,count(*) AS count FROM jobs
                WHERE status IN ('queued','running','needs_review','recovery_required') GROUP BY queue,kind,status""")
        }
        running = {
            (row["queue"], row["kind"]): row["age"]
            for row in db.execute(
                """SELECT queue,kind,max(max(0,?-started_at)) AS age FROM jobs
                WHERE status='running' AND started_at IS NOT NULL GROUP BY queue,kind""",
                (now,),
            )
        }
        # A job is due once its start window opened and no earlier batch wave holds it. A job
        # resumed after a review gate (already started) has waited only since the decision.
        queues = {
            row["queue"]: dict(row)
            for row in db.execute(
                """SELECT queue,count(*) AS queued,sum(due) AS due,
                min(CASE WHEN due THEN eligible END) AS oldest FROM (
                    SELECT queue,
                    (start_at IS NULL OR start_at<=?) AND NOT EXISTS(
                        SELECT 1 FROM batch_members m JOIN batch_members p
                            ON p.batch=m.batch AND p.wave<m.wave JOIN jobs pj ON pj.id=p.job
                        WHERE m.job=jobs.id
                        AND pj.status NOT IN ('succeeded','completed_with_warnings','manually_completed')
                    ) AS due,
                    CASE WHEN started_at IS NOT NULL THEN updated
                        ELSE max(created,coalesce(start_at,created)) END AS eligible
                    FROM jobs WHERE status='queued'
                ) GROUP BY queue""",
                (now,),
            )
        }
        workers = defaultdict(lambda: [0, 0])
        for queue in QUEUES:
            workers[(queue, "unknown")]
        for row in db.execute("SELECT heartbeat,state,queues,version FROM workers"):
            if row["state"] == "stopped" or row["heartbeat"] < now - stale_seconds:
                continue
            pool = (json.loads(row["queues"]) if row["queues"] else list(QUEUES))[0]
            counts = workers[(pool, row["version"] or "unknown")]
            counts[0] += 1
            counts[1] += row["state"] == "busy"
        duration = duration_rows(db, DURATIONS["duration"])
        wait = duration_rows(db, DURATIONS["wait"])
        for metric, target in (("duration", duration), ("wait", wait)):
            add_rows(
                target,
                db.execute(
                    "SELECT queue,kind,count,total,"
                    + ",".join(f"bucket_{index}" for index in range(len(BUCKETS)))
                    + " FROM job_metrics_duration_rollup WHERE metric=?",
                    (metric,),
                ),
                ("queue", "kind"),
            )
    return {
        "submitted": submitted,
        "completed": completed,
        "current": current,
        "running": running,
        "queues": queues,
        "workers": workers,
        "duration": duration,
        "wait": wait,
        "now": now,
    }


class JobCollector:
    def __init__(self, store, settings):
        self.store, self.settings = store, settings

    def collect(self):
        from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily, HistogramMetricFamily

        data = snapshot(self.store, self.settings.stale_seconds)
        poller = self.settings.poller_instance or "default"
        kinds = sorted(set(JOB_KINDS) | {kind for _, kind in data["submitted"]})
        labels = ["poller", "queue", "job_type"]
        submitted = CounterMetricFamily(
            "netops_jobs_submitted", "Unique jobs submitted to this executor.", labels=labels
        )
        completed = CounterMetricFamily(
            "netops_jobs_completed",
            "Unique jobs reaching their first terminal result.",
            labels=[*labels, "status", "result"],
        )
        current = GaugeMetricFamily(
            "netops_jobs_current",
            "Jobs currently in an active or attention state.",
            labels=[*labels, "status"],
        )
        last = GaugeMetricFamily(
            "netops_job_last_completed_timestamp_seconds",
            "Most recent first completion as Unix seconds.",
            labels=[*labels, "status", "result"],
        )
        running = GaugeMetricFamily(
            "netops_running_job_age_seconds",
            "Age of the longest-running job from its admitted start.",
            labels=labels,
        )
        duration = HistogramMetricFamily(
            "netops_job_duration_seconds",
            "Elapsed time from admitted start to first completion, including review time.",
            labels=labels,
        )
        wait = HistogramMetricFamily(
            "netops_job_queue_wait_seconds",
            "Wait before admitted start, excluding a future scheduled start.",
            labels=labels,
        )
        for queue in QUEUES:
            for kind in kinds:
                values = [poller, queue, kind]
                submitted.add_metric(values, data["submitted"].get((queue, kind), 0))
                running.add_metric(values, data["running"].get((queue, kind), 0))
                for status in ("queued", "running", "needs_review", "recovery_required"):
                    current.add_metric([*values, status], data["current"].get((queue, kind, status), 0))
                for status, result in RESULTS.items():
                    row = data["completed"].get((queue, kind, status), {})
                    completed.add_metric([*values, status, result], row.get("count", 0))
                    last.add_metric([*values, status, result], row.get("last_finished", 0))
                for family, observations in ((duration, data["duration"]), (wait, data["wait"])):
                    row = observations.get((queue, kind), {})
                    buckets = [
                        (str(limit), row.get(f"bucket_{index}", 0)) for index, limit in enumerate(BUCKETS)
                    ]
                    buckets.append(("+Inf", row.get("count", 0)))
                    family.add_metric(values, buckets=buckets, sum_value=row.get("total", 0))
        yield submitted
        yield completed
        yield current
        yield last
        yield running
        yield duration
        yield wait
        backlog = GaugeMetricFamily(
            "netops_queue_jobs",
            "Queue backlog by due or future scheduled work.",
            labels=["poller", "queue", "state"],
        )
        oldest = GaugeMetricFamily(
            "netops_queue_oldest_due_wait_seconds",
            "Wait of the oldest due queued job, excluding its scheduled delay.",
            labels=["poller", "queue"],
        )
        for queue in QUEUES:
            row = data["queues"].get(queue, {})
            due = row.get("due", 0)
            backlog.add_metric([poller, queue, "due"], due)
            backlog.add_metric([poller, queue, "future"], row.get("queued", 0) - due)
            oldest.add_metric(
                [poller, queue], max(0, data["now"] - row["oldest"]) if row.get("oldest") is not None else 0
            )
        yield backlog
        yield oldest
        online = GaugeMetricFamily(
            "netops_workers_online",
            "Workers with a recent heartbeat, grouped by primary pool and version.",
            labels=["poller", "queue", "version"],
        )
        busy = GaugeMetricFamily(
            "netops_workers_busy",
            "Online workers running a job from any queue.",
            labels=["poller", "queue", "version"],
        )
        for (queue, version), counts in sorted(data["workers"].items()):
            online.add_metric([poller, queue, version], counts[0])
            busy.add_metric([poller, queue, version], counts[1])
        yield online
        yield busy
        build = GaugeMetricFamily(
            "netops_executor_build_info",
            "Executor API release and poller identity.",
            labels=["poller", "version"],
        )
        build.add_metric([poller, __version__], 1)
        yield build


def render_metrics(store, settings):
    from prometheus_client import CollectorRegistry, generate_latest

    registry = CollectorRegistry()
    registry.register(JobCollector(store, settings))
    return generate_latest(registry)
