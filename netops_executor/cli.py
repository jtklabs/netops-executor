import argparse
import json
import os
import sys
import uuid
from pathlib import Path

import httpx
from dotenv import load_dotenv

from .config import env
from .models import JobRequest


def parser():
    p = argparse.ArgumentParser(description="NetOps Executor: SSH, HTTP, SNMP and F5 upgrade jobs")
    p.add_argument("--url")
    p.add_argument("--env-file", default=".env")
    commands = p.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", default=8080, type=int)
    commands.add_parser("worker")
    commands.add_parser("devices")
    commands.add_parser("jobs")
    commands.add_parser("credentials")
    commands.add_parser("workers")
    commands.add_parser("rotate-credentials")
    key = commands.add_parser("init-key")
    key.add_argument("path", type=Path)
    credential = commands.add_parser("credential-put")
    credential.add_argument("profile")
    credential.add_argument("--file", required=True, help="JSON file, or - for stdin")
    request = commands.add_parser("request")
    request.add_argument(
        "--kind",
        required=True,
        choices=["upgrade", "batch", "ssh", "http", "snmp", "panos", "panos-batch", "eos", "eos-batch"],
    )
    request.add_argument("--file", required=True, help="JSON file, or - for stdin")
    request.add_argument("--idempotency-key")
    batch = commands.add_parser("batch")
    batch.add_argument("id")
    for action in ("validation", "mark-done"):
        control = commands.add_parser(action)
        control.add_argument("id")
        control.add_argument("--operator", required=True)
        control.add_argument("--reason", required=True)
        if action == "validation":
            control.add_argument("--action", choices=["accept", "retry"], required=True)
            control.add_argument("--gate-id", required=True)
            control.add_argument("--revision", type=int, required=True)
            control.add_argument("--idempotency-key")
    for command in ("job", "events", "cancel", "rollback", "resolve"):
        sub = commands.add_parser(command)
        sub.add_argument("id")
        if command == "rollback":
            sub.add_argument("--idempotency-key")
            sub.add_argument("--worker-stopped", action="store_true")
            sub.add_argument("--start-at")
            sub.add_argument("--latest-start-at")
        if command == "resolve":
            sub.add_argument("--worker-stopped", required=True, action="store_true")
            sub.add_argument("--device-inspected", required=True, action="store_true")
            sub.add_argument("--note", required=True)
    for command in ("plan", "submit"):
        sub = commands.add_parser(command)
        sub.add_argument("--device", required=True)
        sub.add_argument("--start-at", help="Earliest start, ISO 8601 with timezone")
        sub.add_argument("--latest-start-at", help="Latest allowed start, ISO 8601 with timezone")
        sub.add_argument("--credential-profile", action="append", dest="credential_profiles")
        sub.add_argument("--ucs-credential")
        sub.add_argument("--images", type=Path, help="JSON array of image name, sha256, version, build, kind")
        for flag in (
            "transfer",
            "images-on-device",
            "create-ucs",
            "ucs-unencrypted",
            "install",
            "reboot",
            "drain",
            "reboot-on-drain-timeout",
        ):
            sub.add_argument("--" + flag, action=argparse.BooleanOptionalAction, default=False)
        for flag in ("backup-directory", "target-volume", "expected-version", "expected-build"):
            sub.add_argument("--" + flag)
        sub.add_argument("--allowed-source-version", action="append", default=[])
        drain = sub.add_mutually_exclusive_group()
        drain.add_argument("--drain-connections", type=int)
        drain.add_argument(
            "--drain-percent", type=float, help="percentage of initial connections to remove (0-100)"
        )
        for flag, default in (
            ("drain-timeout", 300),
            ("install-timeout", 3600),
            ("reboot-timeout", 900),
            ("validation-timeout", 600),
        ):
            sub.add_argument("--" + flag, type=int, default=default)
        sub.add_argument("--idempotency-key")
    return p


def main():
    args = parser().parse_args()
    os.environ["NETOPS_ENV_FILE"] = args.env_file
    load_dotenv(args.env_file)
    args.url = args.url or env("NETOPS_API_URL", "http://127.0.0.1:8080")
    if args.command == "serve":
        import uvicorn

        uvicorn.run("netops_executor.api:create_app", factory=True, host=args.host, port=args.port)
        return
    if args.command == "worker":
        from .worker import main as worker

        worker()
        return
    if args.command == "init-key":
        from .credentials import initialize_key

        initialize_key(args.path)
        print("Created owner-only credential key file: " + str(args.path))
        return
    token = env("NETOPS_API_TOKEN")
    if not token:
        raise SystemExit("NETOPS_API_TOKEN is required")
    method, body, path = "GET", None, "/api/v1/" + args.command
    headers = {"Authorization": "Bearer " + token}
    try:
        if args.command in ("plan", "submit"):
            values = {k: v for k, v in vars(args).items() if k in JobRequest.model_fields and v is not None}
            values["images"] = json.loads(args.images.read_text()) if args.images else []
            values["allowed_source_versions"] = args.allowed_source_version
            body = JobRequest.model_validate(values).model_dump()
            method, path = "POST", "/api/v1/plan" if args.command == "plan" else "/api/v1/jobs"
        elif args.command == "request":
            body = json.loads(sys.stdin.read() if args.file == "-" else Path(args.file).read_text())
            method, path = (
                "POST",
                "/api/v1/"
                + {
                    "upgrade": "jobs",
                    "batch": "upgrade-batches",
                    "ssh": "ssh/jobs",
                    "http": "http/jobs",
                    "snmp": "snmp/walks",
                    "panos": "panos/jobs",
                    "panos-batch": "panos/upgrade-batches",
                    "eos": "eos/jobs",
                    "eos-batch": "eos/upgrade-batches",
                }[args.kind],
            )
        elif args.command == "credential-put":
            body = json.loads(sys.stdin.read() if args.file == "-" else Path(args.file).read_text())
            from pydantic import TypeAdapter

            from .models import Name

            profile = TypeAdapter(Name).validate_python(args.profile)
            method, path = "PUT", "/api/v1/credentials/" + profile
        elif args.command == "rotate-credentials":
            method, body, path = "POST", {}, "/api/v1/credentials/rotate"
        elif args.command == "batch":
            path = "/api/v1/upgrade-batches/" + args.id
        elif args.command in ("validation", "mark-done"):
            method = "POST"
            body = {"operator": args.operator, "reason": args.reason}
            path = (
                "/api/v1/jobs/"
                + args.id
                + "/"
                + ("validation-decisions" if args.command == "validation" else "mark-done")
            )
            if args.command == "validation":
                body.update(action=args.action, gate_id=args.gate_id, validation_revision=args.revision)
        elif args.command == "job":
            path = "/api/v1/jobs/" + args.id
        elif args.command in ("events", "rollback", "cancel", "resolve"):
            path = "/api/v1/jobs/" + args.id + "/" + args.command
            if args.command != "events":
                method, body = "POST", {}
            if args.command == "rollback":
                body["worker_stopped"] = args.worker_stopped
                body.update(start_at=args.start_at, latest_start_at=args.latest_start_at)
            if args.command == "resolve":
                body = {
                    "worker_stopped": args.worker_stopped,
                    "device_inspected": args.device_inspected,
                    "note": args.note,
                }
        if method == "POST" and args.command in ("submit", "rollback", "request", "validation"):
            key = args.idempotency_key or str(uuid.uuid4())
            headers["Idempotency-Key"] = key
            print("Idempotency-Key: " + key + " (reuse this key if the response is lost)", file=sys.stderr)
        response = httpx.request(method, args.url.rstrip("/") + path, headers=headers, json=body, timeout=60)
        print(json.dumps(response.json(), indent=2))
        if response.is_error:
            raise SystemExit(1)
    except (ValueError, OSError, httpx.HTTPError) as exc:
        raise SystemExit(
            "Request failed (" + type(exc).__name__ + "); check the input or server availability"
        ) from None


if __name__ == "__main__":
    main()
