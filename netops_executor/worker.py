import os
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
from .panos_engine import PanosRunner
from .snmp import SnmpRunner
from .store import Store


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


def main():
    os.umask(0o077)
    settings = Settings.load()
    store = Store(settings.data_dir / "jobs.sqlite3")
    worker = f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}"
    stop = threading.Event()
    # SIGTERM drains the current job before exiting; SIGKILL leaves a fenced recovery job.
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    while not stop.is_set():
        store.worker_seen(worker)
        store.reap(settings.stale_seconds)
        job = store.claim(worker)
        if job:
            process(settings, store, job, worker)
        else:
            stop.wait(2)
    store.worker_seen(worker, state="stopped")


if __name__ == "__main__":
    main()
