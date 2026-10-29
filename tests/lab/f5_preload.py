"""Run the real F5 preload (stage_only) against a lab BIG-IP over SSH.

The production Runner, SSH client and BigIP readers run unchanged; only the inventory is
built here, with the lab's key-file login. Not collected by pytest.

    python tests/lab/f5_preload.py --device 10.50.10.159 --images ~/Downloads \\
        --image BIGIP-17.5.1.9-0.0.12.iso

Without --as the device usually already holds the image, so this exercises the checks, the
on-device SHA-256 and catalog verification, and the skip. --as NAME uploads the same file
under a new name (writes; needs --allow-writes), and --cleanup deletes that test copy again.
"""

import argparse
import hashlib
import json
import re
import shutil
import sys
import threading
import time
from pathlib import Path

from netops_executor.config import Device, Settings
from netops_executor.device import BigIP
from netops_executor.engine import Runner
from netops_executor.models import JobRequest
from netops_executor.ssh import SSH
from netops_executor.store import Store


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--device", required=True)
    p.add_argument("--images", type=Path, required=True)
    p.add_argument("--image", required=True)
    p.add_argument("--as", dest="upload_as")
    p.add_argument("--key", default="~/.ssh/id_rsa")
    p.add_argument("--known-hosts", type=Path, required=True)
    p.add_argument("--workdir", type=Path, default=Path("~/.config/netops-lab/run-f5").expanduser())
    p.add_argument("--minimum-free-bytes", type=int, default=1_500_000_000)
    p.add_argument("--allowed-source-version", action="append", default=[])
    p.add_argument("--allow-writes", action="store_true")
    p.add_argument("--cleanup", action="store_true")
    p.add_argument("--cancel-after", type=int, help="request cancellation this many seconds into the upload")
    args = p.parse_args()
    if args.upload_as and not args.allow_writes:
        sys.exit("--as uploads a new file; pass --allow-writes")
    match = re.fullmatch(r"BIGIP-(\d+(?:\.\d+){2,3})-(\d+\.\d+\.\d+)\.iso", args.image)
    if not match:
        sys.exit("expected BIGIP-<version>-<build>.iso")
    work = args.workdir
    for folder in ("data", "images", "backups"):
        (work / folder).mkdir(parents=True, exist_ok=True, mode=0o700)
    source = args.images.expanduser() / args.image
    name = args.upload_as or args.image
    local = work / "images" / name
    if not local.exists():
        try:
            local.hardlink_to(source)
        except OSError:
            shutil.copyfile(source, local)
    known = work / "known_hosts"
    known.write_text(args.known_hosts.expanduser().read_text())
    device = Device(
        id="lab-f5", host=args.device, device_type="f5", key_file=str(Path(args.key).expanduser())
    )
    settings = Settings(
        "lab-token-" + "x" * 40, work / "data", work / "images", work / "backups", known, {"lab-f5": device}
    )
    store = Store(settings.data_dir / "jobs.sqlite3")
    print("hashing", local.name, file=sys.stderr)
    image = {"name": name, "sha256": sha256(local), "version": match[1], "build": match[2], "kind": "image"}
    request = JobRequest(
        device=args.device,
        stage_only=True,
        images=[image],
        minimum_free_bytes=args.minimum_free_bytes,
        allowed_source_versions=args.allowed_source_version,
    )
    job = store.submit(request.model_dump(mode="json"), "device:lab-f5")
    claimed = store.claim("lab-worker")
    seen, done = [0], threading.Event()

    def watch():
        uploading = None
        while not done.wait(5):
            for e in store.events(job["id"], seen[0], 500):
                seen[0] = e["seq"]
                if e["step"] == "transfer_started":
                    uploading = time.monotonic()
                if e["step"] == "transfer_progress":
                    d = e["data"]
                    print(f"  upload {d['percent']}% ({d['bytes']}/{d['total_bytes']})", file=sys.stderr)
            if args.cancel_after and uploading and time.monotonic() - uploading >= args.cancel_after:
                print("  requesting cancellation", file=sys.stderr)
                store.cancel(job["id"])
                uploading = None

    thread = threading.Thread(target=watch, daemon=True)
    thread.start()
    start = time.monotonic()
    Runner(settings, store, claimed, "lab-worker").run()
    done.set()
    final = store.get(job["id"])
    steps = [(round(e["time"] - final["created"], 1), e["step"]) for e in store.events(job["id"], 0, 2000)]
    report = {
        "status": final["status"],
        "seconds": round(time.monotonic() - start),
        "error": final["result"].get("error"),
        "source": final["result"].get("source"),
        "preloaded": final["result"].get("preloaded"),
        "transfer_progress": final["result"].get("transfer_progress"),
        "steps": [s for s in steps if s[1] != "transfer_progress"],
        "progress_events": sum(1 for s in steps if s[1] == "transfer_progress"),
    }
    f5 = BigIP(SSH(settings, device))
    report["partial_files"] = [
        f for f in f5.ssh.shell("ls -a /shared/images/").split() if f.endswith(".partial")
    ]
    if args.cleanup and args.upload_as:
        f5.ssh.tmsh("delete /sys software image " + args.upload_as)
        listing = f5.ssh.shell("ls /shared/images/")
        report["cleanup"] = {"deleted": args.upload_as, "still_present": args.upload_as in listing.split()}
    f5.ssh.close()
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
