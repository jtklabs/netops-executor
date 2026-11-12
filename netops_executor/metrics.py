"""Database-backed Prometheus metrics shared by every API and worker process."""

import json
import time
from collections import defaultdict

from . import __version__
from .models import QUEUES
from .store import EMAIL_STATUSES, UPGRADE_KINDS

JOB_KINDS = (*UPGRADE_KINDS, "rollback", "snmp_walk", "ssh", "http", "cipher_scan", "password_rotation")
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
    db.execute("""CREATE TRIGGER IF NOT EXISTS jobs_metrics_submitted AFTER INSERT ON jobs
        BEGIN
            INSERT OR IGNORE INTO job_metrics(job_id,kind,submitted_queue,created_at,eligible_at)
            VALUES(NEW.id,NEW.kind,NEW.queue,NEW.created,max(NEW.created,coalesce(NEW.start_at,NEW.created)));
        END""")
    db.execute(f"""CREATE TRIGGER IF NOT EXISTS jobs_metrics_finished AFTER UPDATE OF status ON jobs
        WHEN NEW.status IS NOT OLD.status AND NEW.status IN ({terminal})
        BEGIN
            UPDATE job_metrics SET finished_queue=NEW.queue,started_at=NEW.started_at,
                finished_at=NEW.updated,finished_status=NEW.status
            WHERE job_id=NEW.id AND finished_at IS NULL;
        END""")


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


def snapshot(store, stale_seconds):
    now = time.time()
    with store.connect() as db:
        db.execute("BEGIN")
        submitted = {
            (row["queue"], row["kind"]): row["count"]
            for row in db.execute("""SELECT submitted_queue AS queue,kind,count(*) AS count
                FROM job_metrics GROUP BY submitted_queue,kind""")
        }
        completed = {
            (row["queue"], row["kind"], row["status"]): dict(row)
            for row in db.execute("""SELECT finished_queue AS queue,kind,finished_status AS status,
                count(*) AS count,max(finished_at) AS last_finished
                FROM job_metrics WHERE finished_at IS NOT NULL GROUP BY finished_queue,kind,finished_status""")
        }
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
        queues = {
            row["queue"]: dict(row)
            for row in db.execute(
                """SELECT queue,count(*) AS queued,
                sum(start_at IS NULL OR start_at<=?) AS due,
                min(CASE WHEN start_at IS NULL OR start_at<=? THEN max(created,coalesce(start_at,created)) END) AS oldest
                FROM jobs WHERE status='queued' GROUP BY queue""",
                (now, now),
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
        duration = duration_rows(db, "max(0,finished_at-started_at)")
        wait = duration_rows(db, "max(0,started_at-eligible_at)")
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
