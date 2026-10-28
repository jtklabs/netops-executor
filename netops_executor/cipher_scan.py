"""Bounded, unprivileged Nmap scans with durable worker ownership and cancellation."""

import os
import selectors
import signal
import subprocess
import time
import xml.etree.ElementTree as ET

from .cipher_models import CipherScanRequest
from .store import CancelRequested, LostOwnership

MAX_OUTPUT_BYTES = 4 * 1024 * 1024
SCRIPTS = {"ssh": "ssh2-enum-algos", "https": "ssl-enum-ciphers"}


class ScanError(Exception):
    def __init__(self, code, message):
        self.code = code
        super().__init__(message)


def command(request):
    # '+' runs the selected script on nonstandard ports, without general service probing.
    args = [
        "nmap",
        "--unprivileged",
        "-sT",
        "-Pn",
        "-n",
        "-v",
        "-p",
        str(request.port),
        "--script",
        "+" + SCRIPTS[request.protocol],
        "--host-timeout",
        f"{request.job_timeout}s",
        "--script-timeout",
        f"{request.job_timeout}s",
        "--max-retries",
        "1",
        "-oX",
        "-",
    ]
    if request.device_ip.version == 6:
        args.append("-6")
    if request.server_name:
        args.extend(["--script-args", "tls.servername=" + request.server_name])
    args.append(str(request.device_ip))
    return args


def execute(request, checkpoint):
    checkpoint()
    deadline = time.monotonic() + request.job_timeout
    try:
        process = subprocess.Popen(
            command(request),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except FileNotFoundError:
        raise ScanError("nmap_unavailable", "Nmap is not installed on this worker") from None
    chunks = {"stdout": bytearray(), "stderr": bytearray()}
    total = 0
    try:
        with selectors.DefaultSelector() as selector:
            for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, name)
            while selector.get_map() or process.poll() is None:
                checkpoint()
                if time.monotonic() >= deadline:
                    raise ScanError("timeout", "cipher scan exceeded job_timeout")
                for key, _ in selector.select(timeout=0.2):
                    data = os.read(key.fileobj.fileno(), 65536)
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    total += len(data)
                    if total > MAX_OUTPUT_BYTES:
                        raise ScanError("output_limit", "Nmap output exceeded the 4 MiB limit")
                    chunks[key.data].extend(data)
            checkpoint()
            return (
                bytes(chunks["stdout"]),
                chunks["stderr"].decode("utf-8", errors="replace"),
                process.returncode,
            )
    finally:
        # Kill the entire child group on cancellation, timeout, or ownership loss.
        # Also clean up descendants if the main Nmap process has already exited.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=5)
        process.stdout.close()
        process.stderr.close()


def structured(element, depth=0):
    if depth > 32:
        raise ScanError("invalid_output", "Nmap XML nesting limit exceeded")
    children = [child for child in element if child.tag in ("table", "elem")]
    if not children:
        return [] if element.tag == "table" else (element.text or "")
    if all("key" in child.attrib for child in children):
        return {child.attrib["key"]: structured(child, depth + 1) for child in children}
    if all("key" not in child.attrib for child in children):
        return [structured(child, depth + 1) for child in children]
    # Keep uncommon mixed tables lossless rather than dropping unnamed entries.
    return [{"key": child.get("key"), "value": structured(child, depth + 1)} for child in children]


def parse_output(xml, request):
    if len(xml) > MAX_OUTPUT_BYTES or b"<!ENTITY" in xml.upper():
        raise ScanError("invalid_output", "invalid or oversized Nmap XML")
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        raise ScanError("invalid_output", "Nmap did not return valid XML") from None
    finished = root.find("runstats/finished")
    if root.tag != "nmaprun" or finished is None or finished.get("exit") != "success":
        raise ScanError("nmap_failed", "Nmap did not report a completed scan")
    result = {"nmap_version": root.get("version"), "script": SCRIPTS[request.protocol]}
    port = root.find(f"./host/ports/port[@protocol='tcp'][@portid='{request.port}']")
    if port is None:
        return {
            **result,
            "error_code": "no_port_result",
            "error": "Nmap returned no port result; host may have timed out",
        }
    state = port.find("state")
    result.update(
        port_state=state.get("state") if state is not None else None,
        port_reason=state.get("reason") if state is not None else None,
    )
    script = port.find(f"script[@id='{result['script']}']")
    if script is not None:
        result.update(output=script.get("output", ""), data=structured(script))
    data = result.get("data", {})
    if not isinstance(data, dict):
        data = {}
        result["data"] = data
    if result["port_state"] != "open":
        return {**result, "error_code": "port_not_open", "error": "target TCP port is not open"}
    if request.protocol == "ssh":
        found = any(
            key.startswith("encryption_algorithms") and isinstance(value, list) and value
            for key, value in data.items()
        )
    else:
        found = any(
            key.startswith(("TLS", "SSL")) and isinstance(value, dict) and value.get("ciphers")
            for key, value in data.items()
        )
    if not found:
        result.update(
            error_code="no_cipher_data",
            error="no cipher data returned; service may be incompatible or the script timed out",
        )
    return result


class CipherScanRunner:
    def __init__(self, settings, store, job, worker):
        self.store, self.job, self.worker = store, job, worker
        self.request = CipherScanRequest.model_validate(job["request"])
        self.result = {"script": SCRIPTS[self.request.protocol]}

    def checkpoint(self):
        self.store.checkpoint(self.job["id"], self.worker)

    def run(self):
        try:
            self.checkpoint()
            self.store.record(self.job["id"], self.worker, "cipher_scan_started", result=self.result)
            xml, stderr, exit_code = execute(self.request, self.checkpoint)
            self.result.update(stderr=stderr, exit_code=exit_code)
            if exit_code:
                raise ScanError("nmap_failed", "Nmap exited unsuccessfully; see stderr")
            self.result.update(parse_output(xml, self.request))
            self.checkpoint()
            status = "failed" if self.result.get("error_code") else "succeeded"
        except LostOwnership:
            return
        except CancelRequested:
            self.result.update(error_code="cancelled", error="cipher scan cancelled")
            status = "cancelled"
        except ScanError as exc:
            self.result.update(error_code=exc.code, error=str(exc))
            status = "failed"
        except Exception:
            self.result.update(error_code="worker_error", error="cipher scan worker failed")
            status = "failed"
        try:
            self.store.record(self.job["id"], self.worker, "cipher_scan_" + status, result=self.result)
            self.store.finish(self.job["id"], self.worker, status)
        except LostOwnership:
            pass
