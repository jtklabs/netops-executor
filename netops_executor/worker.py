import os
import re
import signal
import socket
import threading
import uuid

from .cipher_scan import CipherScanRunner
from .config import Settings
from .engine import Runner
from .eos_engine import EosRunner
from .execution import ExecutionRunner
from .fortigate_engine import FortigateRunner
from .ios_engine import IosRunner
from .iosxe_engine import IosxeRunner
from .models import POOLS, QUEUES
from .panos_engine import PanosRunner
from .snmp import SnmpRunner
from .store import Store


def worker_queues(queue=None, pool=None, instance=None):
    """Queues to claim from, in order. --queue is the exact order. --pool, or a systemd instance
    named <pool>-<n>, claims from that queue first, then the other pool's queue, then scheduled.
    A bare instance number, or no option, uses the default order."""
    if queue:
        names = [name.strip() for name in queue.split(",")]
    else:
        if instance and not instance.isdigit():
            match = re.fullmatch(r"([a-z]+)-\d+", instance)
            pool = match[1] if match else instance
        if pool and pool not in POOLS:
            raise ValueError("worker pool must be one of: " + ", ".join(POOLS))
        names = [pool, *(q for q in QUEUES if q != pool)] if pool else list(QUEUES)
    if not names or not set(names) <= set(QUEUES) or len(set(names)) != len(names):
        raise ValueError("worker queues must be distinct names from: " + ", ".join(QUEUES))
    return tuple(names)


def process(settings, store, job, worker):
    done = threading.Event()

    def heartbeat():
        while not done.wait(10):
            store.worker_seen(worker, job["id"], "busy")
            if not store.heartbeat(job["id"], worker):
                return

    store.worker_seen(worker, job["id"], "busy")
    thread = threading.Thread(target=heartbeat, daemon=True)
    thread.start()
    try:
        runner = (
            CipherScanRunner
            if job["kind"] == "cipher_scan"
            else SnmpRunner
            if job["kind"] == "snmp_walk"
            else ExecutionRunner
            if job["kind"] in ("ssh", "http")
            else PanosRunner
            if job["kind"] == "panos_upgrade"
            else EosRunner
            if job["kind"] == "eos_upgrade"
            else IosxeRunner
            if job["kind"] == "iosxe_upgrade"
            else IosRunner
            if job["kind"] == "ios_upgrade"
            else FortigateRunner
            if job["kind"] == "fortigate_upgrade"
            else Runner
        )
        runner(settings, store, job, worker).run()
    finally:
        done.set()
        thread.join(timeout=15)
        store.worker_seen(worker)


def main(queues=QUEUES):
    os.umask(0o077)
    settings = Settings.load()
    store = Store(settings.data_dir / "jobs.sqlite3")
    worker = f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}"
    stop = threading.Event()
    # SIGTERM drains the current job before exiting; SIGKILL leaves a fenced recovery job.
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    while not stop.is_set():
        store.worker_seen(worker, queues=queues)
        store.reap(settings.stale_seconds)
        job = store.claim(worker, queues)
        if job:
            process(settings, store, job, worker)
        else:
            stop.wait(2)
    store.worker_seen(worker, state="stopped")


if __name__ == "__main__":
    main()
