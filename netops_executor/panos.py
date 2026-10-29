"""Panorama XML API client. Firewall operations are proxied with target=<serial>."""

import os
import re
import ssl
import time
import xml.etree.ElementTree as ET

import httpx

from .credentials import AuthenticationRejected, Selector, Vault
from .execution import credential_options, probe
from .pins import PinnedContext, tls_key
from .store import Conflict

DEVICES = "<show><devices><all></all></devices></show>"
SYSTEM_INFO = "<show><system><info></info></system></show>"
CHASSIS_READY = "<show><chassis-ready></chassis-ready></show>"
HA_STATE = "<show><high-availability><state></state></high-availability></show>"
PENDING_CHANGES = "<check><pending-changes></pending-changes></check>"
JOBS = "<show><jobs><all></all></jobs></show>"
SOFTWARE_CHECK = "<request><system><software><check></check></software></system></request>"
SOFTWARE_INFO = "<request><system><software><info></info></software></system></request>"
INTERFACES = "<show><interface>hardware</interface></show>"
ROUTES = "<show><routing><route></route></routing></show>"
BGP_PEERS = "<show><routing><protocol><bgp><peer></peer></bgp></protocol></routing></show>"
TUNNELS = "<show><running><tunnel><flow><all></all></flow></tunnel></running></show>"
SESSIONS = "<show><session><info></info></session></show>"
ARP = "<show><arp><entry name='all'/></arp></show>"
RUNNING_CONFIG = "<show><config><running></running></config></show>"
SUSPEND = "<request><high-availability><state><suspend></suspend></state></high-availability></request>"
FUNCTIONAL = (
    "<request><high-availability><state><functional></functional></state></high-availability></request>"
)
RESTART = "<request><restart><system></system></restart></request>"
# Firewall-local HA election settings. HA settings are not synchronized between peers.
HA_ELECTION = "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/high-availability/group/election-option"
COMMIT = "<commit></commit>"
# Panorama's software repository for managed firewalls ("Panorama > Device Deployment > Software").
REPOSITORY_INFO = "<request><batch><software><info></info></software></batch></request>"
REPOSITORY_CHECK = "<request><batch><software><check></check></software></batch></request>"


def show_job(job_id):
    return "<show><jobs><id>" + str(int(job_id)) + "</id></jobs></show>"


def download(version):
    # Versions are validated against a strict pattern before reaching XML.
    return (
        "<request><system><software><download><version>"
        + version
        + "</version></download></software></system></request>"
    )


def install(version):
    return (
        "<request><system><software><install><version>"
        + version
        + "</version></install></software></system></request>"
    )


def repository_download(filename):
    # Filenames are built only from validated family and version patterns.
    return (
        "<request><batch><software><download><file>"
        + filename
        + "</file></download></software></batch></request>"
    )


def repository_upload(filename, serial):
    return (
        "<request><batch><software><upload><file>"
        + filename
        + "</file><devices>"
        + serial
        + "</devices></upload></software></batch></request>"
    )


class PanosError(Exception):
    """Panorama or the firewall rejected an operation, or its output could not be read."""


class PanosUnavailable(PanosError):
    """No API response: the request may or may not have reached the firewall."""


def text(element, path, default=""):
    found = element.find(path) if element is not None else None
    return found.text.strip() if found is not None and found.text else default


def message(root):
    return (
        " ".join(t.strip() for t in root.find("msg").itertext() if t.strip())
        if root.find("msg") is not None
        else ""
    )


def uptime_seconds(value):
    match = re.fullmatch(r"\s*(?:(\d+)\s+days?,\s*)?(\d+):(\d{2}):(\d{2})\s*", value or "")
    if not match:
        return None
    days, hours, minutes, seconds = (int(v or 0) for v in match.groups())
    return ((days * 24 + hours) * 60 + minutes) * 60 + seconds


def job_id(result):
    value = text(result, "job")
    if not value.isdigit():
        raise PanosError("operation was accepted without a job ID: " + "".join(result.itertext())[:300])
    return int(value)


class Jobs:
    """Job helpers shared by Panorama's own operations and proxied firewall operations."""

    @staticmethod
    def parse_job(job):
        return {
            "id": int(text(job, "id", "0") or 0),
            "type": text(job, "type"),
            "status": text(job, "status").upper(),
            "result": text(job, "result").upper(),
            "progress": text(job, "progress"),
            "details": " ".join(t.strip() for t in job.find("details").itertext() if t.strip())[:2000]
            if job.find("details") is not None
            else "",
        }

    def jobs(self):
        return [self.parse_job(job) for job in self.op(JOBS).findall("job")]

    def job(self, job_id):
        job = self.op(show_job(job_id)).find("job")
        if job is None:
            raise PanosError("job " + str(job_id) + " was not reported")
        return self.parse_job(job)

    def enqueue(self, cmd, timeout=600):
        """Send a job-producing write once and return the job ID.

        PA-VM 12.1.6 took 104 seconds to answer an install request (license check), so the
        default leaves room; a lost answer leaves an uncertain outcome that is never replayed.
        """
        return job_id(self.op(cmd, timeout=timeout))

    def command(self, cmd):
        return " ".join(t.strip() for t in self.op(cmd, timeout=120).itertext() if t.strip())[:1000]


class Counting:
    """File wrapper reporting bytes read, so an upload's progress is visible while it streams."""

    def __init__(self, stream, callback):
        self.stream, self.callback, self.done = stream, callback, 0

    def read(self, size=-1):
        chunk = self.stream.read(size)
        self.done += len(chunk)
        self.callback(self.done)
        return chunk

    def __getattr__(self, name):
        return getattr(self.stream, name)


class Panorama(Jobs):
    """XML API client for Panorama, or, given an HTTPTarget, for one firewall's own management API."""

    def __init__(self, settings, store, target, profiles, guard, audit, aliases=()):
        self.target = settings.http_targets[target] if isinstance(target, str) else target
        self.aliases, self.store = aliases, store
        if not self.target.auth_probe_path:
            raise PanosError("Panorama target requires a configured read-only authentication probe")
        self.selector = Selector(
            Vault(store, settings.credential_key_file),
            "http",
            self.target.id,
            profiles if profiles is not None else self.target.credential_profiles,
            audit,
        )
        self.guard = guard
        self.client = None
        self.auth = None

    def connect(self):
        if self.client is None:
            verify = (
                PinnedContext(self.store, tls_key(self.target.base_url))
                if self.target.tls == "pin"
                else ssl.create_default_context(cafile=self.target.ca_file)
                if self.target.ca_file
                else True
            )
            self.client = httpx.Client(
                base_url=self.target.base_url, verify=verify, follow_redirects=False, trust_env=False
            )
        if self.auth is None:

            def authenticate(c):
                options = credential_options(self.selector, c, self.client)
                probe(self.client, self.target, options, 30, self.guard)
                return options

            try:
                self.auth = self.selector.run(authenticate, self.aliases)
            except httpx.HTTPError as exc:
                raise PanosUnavailable("Panorama probe failed (" + type(exc).__name__ + ")") from None
            except AuthenticationRejected:
                raise PanosError("Panorama rejected every eligible HTTP credential") from None
            except (Conflict, ValueError) as exc:
                raise PanosError("Panorama authentication failed: " + str(exc)) from None
        return self.auth

    def op(self, cmd, target=None, **kwargs):
        return self.request({"type": "op", "cmd": cmd, **({"target": target} if target else {})}, **kwargs)

    def request(self, form, timeout=60, limit=16 * 1024 * 1024, destination=None):
        """POST one API request. With destination, a binary attachment streams to that file."""
        options = self.connect()
        try:
            with self.client.stream("POST", "/api/", data=form, timeout=timeout, **options) as response:
                status = response.status_code
                binary = (
                    destination is not None
                    and 200 <= status < 300
                    and "xml" not in response.headers.get("content-type", "")
                )
                stream = (
                    os.fdopen(os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb")
                    if binary
                    else None
                )
                content, size = bytearray(), 0
                deadline = time.monotonic() + timeout
                try:
                    for chunk in response.iter_bytes():
                        self.guard()
                        size += len(chunk)
                        if size > limit or time.monotonic() > deadline:
                            raise PanosUnavailable("Panorama response exceeded size or duration limit")
                        if stream:
                            stream.write(chunk)
                        else:
                            content.extend(chunk)
                finally:
                    if stream:
                        stream.flush()
                        os.fsync(stream.fileno())
                        stream.close()
        except httpx.HTTPError as exc:
            # Connection errors carry the TLS pin message; nothing in them comes from the device body.
            raise PanosUnavailable(
                "request to "
                + self.target.id
                + " failed ("
                + type(exc).__name__
                + ": "
                + str(exc)[:200]
                + ")"
            ) from None
        if status in (401, 403):
            # The key may have rotated; select again before the next request.
            self.auth = None
            raise PanosError("Panorama rejected the API credential (HTTP " + str(status) + ")")
        if not 200 <= status < 300:
            raise PanosError("Panorama returned HTTP " + str(status))
        if binary:
            return size
        try:
            root = ET.fromstring(content)
        except ET.ParseError:
            raise PanosError("Panorama returned malformed XML") from None
        if root.tag != "response" or root.get("status") != "success":
            detail = message(root) or "operation rejected"
            raise PanosError(self.selector.redact(detail)[:500])
        result = root.find("result")
        return result if result is not None else ET.Element("result")

    def import_software(self, path, timeout=3600, progress=None):
        """Upload an image file into this endpoint's software repository (type=import).

        progress(bytes_sent) is called as the request body is read; it may raise to cancel.
        """
        options = self.connect()
        try:
            with path.open("rb") as stream:
                response = self.client.post(
                    "/api/",
                    params={"type": "import", "category": "software"},
                    files={"file": (path.name, Counting(stream, progress) if progress else stream)},
                    timeout=timeout,
                    **options,
                )
        except httpx.HTTPError as exc:
            return {"ok": False, "message": "upload failed (" + type(exc).__name__ + ")"}
        if response.status_code in (401, 403):
            self.auth = None
            raise PanosError("firewall rejected the API credential (HTTP " + str(response.status_code) + ")")
        try:
            root = ET.fromstring(response.content)
        except ET.ParseError:
            return {"ok": False, "message": "HTTP " + str(response.status_code)}
        detail = self.selector.redact(message(root) or "")[:500]
        return {"ok": root.tag == "response" and root.get("status") == "success", "message": detail}

    def device(self, serial):
        for entry in self.op(DEVICES).findall("devices/entry"):
            if (text(entry, "serial") or entry.get("name")) == serial:
                return {
                    "serial": serial,
                    "connected": text(entry, "connected") == "yes",
                    "hostname": text(entry, "hostname"),
                    "model": text(entry, "model"),
                    "sw_version": text(entry, "sw-version"),
                    "family": text(entry, "family"),
                    "address": text(entry, "ip-address"),
                    "ha_state": text(entry, "ha/state").lower(),
                    "ha_peer": text(entry, "ha/peer/serial") or None,
                }
        return None

    def repository(self, refresh=False):
        """Firewall software files held by Panorama, keyed by filename."""
        files = {}
        for entry in self.op(REPOSITORY_CHECK if refresh else REPOSITORY_INFO, timeout=300).iter("entry"):
            filename = text(entry, "filename") or entry.get("name") or ""
            if filename.startswith("PanOS_"):
                files[filename] = {
                    "version": text(entry, "version"),
                    "base": text(entry, "release-type").lower() == "base",
                    # Manually uploaded files can report uploaded rather than downloaded.
                    "available": "yes" in (text(entry, "downloaded"), text(entry, "uploaded")),
                }
        return files

    def close(self):
        if self.client is not None:
            self.client.close()
            self.client = None


class Firewall(Jobs):
    def __init__(self, panorama, serial):
        self.panorama, self.serial = panorama, serial

    def request(self, form, **kwargs):
        return self.panorama.request({**form, "target": self.serial}, **kwargs)

    def op(self, cmd, **kwargs):
        return self.request({"type": "op", "cmd": cmd}, **kwargs)

    def set_config(self, xpath, element):
        self.request({"type": "config", "action": "set", "xpath": xpath, "element": element}, timeout=120)

    def commit(self):
        """Commit the candidate configuration once and return the commit job ID."""
        return job_id(self.request({"type": "commit", "cmd": COMMIT}, timeout=120))

    def tech_support(self, destination, timeout, wait, clock=time.monotonic):
        """Generate a tech support file and stream it to destination; return its size."""
        export = {"type": "export", "category": "tech-support"}
        job = job_id(self.request(export, timeout=120))
        deadline = clock() + timeout
        while True:
            status = text(
                self.request({**export, "action": "status", "job-id": str(job)}), "job/status"
            ).upper()
            if status == "FIN":
                break
            if clock() > deadline:
                raise PanosError("tech support generation did not finish before timeout")
            wait(15)
        size = self.request(
            {**export, "action": "get", "job-id": str(job)},
            timeout=timeout,
            limit=4 * 1024**3,
            destination=destination,
        )
        if not isinstance(size, int) or size == 0:
            raise PanosError("tech support export returned no file")
        return size

    def system_info(self):
        system = self.op(SYSTEM_INFO).find("system")
        if system is None:
            raise PanosError("show system info returned no system element")
        info = {
            key.replace("-", "_"): text(system, key)
            for key in (
                "hostname",
                "serial",
                "model",
                "sw-version",
                "app-version",
                "threat-version",
                "av-version",
                "uptime",
                "operational-mode",
                "multi-vsys",
            )
        }
        if not info["sw_version"]:
            raise PanosError("show system info returned no sw-version")
        info["uptime_seconds"] = uptime_seconds(info["uptime"])
        return info

    def chassis_ready(self):
        return "".join(self.op(CHASSIS_READY).itertext()).strip().lower() == "yes"

    def ha_state(self):
        result = self.op(HA_STATE)
        group = result.find("group")
        return {
            "enabled": text(result, "enabled") == "yes",
            "mode": text(group, "mode").lower(),
            "local": text(group, "local-info/state").lower(),
            "local_version": text(group, "local-info/build-rel"),
            "preemptive": text(group, "local-info/preemptive"),
            "peer_state": text(group, "peer-info/state").lower(),
            "peer_conn": text(group, "peer-info/conn-status").lower(),
            "peer_version": text(group, "peer-info/build-rel"),
            "running_sync": text(group, "running-sync").lower(),
            # "no" when HA configuration synchronization is disabled; running-sync then never converges.
            "sync_enabled": text(group, "running-sync-enabled").lower(),
            "peer_mgmt_ip": text(group, "peer-info/mgmt-ip").split("/")[0],
        }

    def pending_changes(self):
        value = "".join(self.op(PENDING_CHANGES).itertext()).strip().lower()
        if value not in ("yes", "no"):
            raise PanosError("check pending-changes returned an unrecognized value")
        return value == "yes"

    def software(self, refresh=False):
        try:
            result = self.op(SOFTWARE_CHECK if refresh else SOFTWARE_INFO, timeout=300)
        except PanosUnavailable:
            raise
        except PanosError as exc:
            # A firewall that never reached an update server has no list yet (seen on PAN-OS 12.1.6).
            if not refresh and "no update information available" in str(exc).lower():
                return {}
            raise
        versions = {}
        for entry in result.iter("entry"):
            version = text(entry, "version")
            if version:
                versions[version] = {
                    "filename": text(entry, "filename"),
                    # A manually imported image can report uploaded rather than downloaded.
                    "downloaded": "yes" in (text(entry, "downloaded"), text(entry, "uploaded")),
                    "current": text(entry, "current") == "yes",
                    "sha256": text(entry, "sha256").lower(),
                    "base": text(entry, "release-type").lower() == "base",
                }
        return versions

    def interfaces(self):
        hw = self.op(INTERFACES).find("hw")
        if hw is None:
            raise PanosError("show interface hardware returned no hw table")
        return {text(e, "name"): text(e, "state").lower() for e in hw.findall("entry") if text(e, "name")}

    def routes(self):
        return sorted(
            {
                "|".join(text(e, k) for k in ("virtual-router", "destination", "nexthop", "interface"))
                for e in self.op(ROUTES).findall("entry")
            }
        )

    def bgp_peers(self):
        return {
            (e.get("vr") or "") + "|" + (e.get("peer") or text(e, "peer-address")): text(e, "status").lower()
            for e in self.op(BGP_PEERS).findall("entry")
        }

    def tunnels(self):
        ipsec = self.op(TUNNELS).find("IPSec")
        if ipsec is None:
            return {}
        return {text(e, "name"): text(e, "state").lower() for e in ipsec.findall("entry") if text(e, "name")}

    def session_count(self):
        value = text(self.op(SESSIONS), "num-active")
        if not value.isdigit():
            raise PanosError("show session info returned no num-active")
        return int(value)

    def arp_count(self):
        value = text(self.op(ARP), "total")
        if not value.isdigit():
            raise PanosError("show arp returned no total")
        return int(value)

    def running_config(self):
        result = self.op(RUNNING_CONFIG, timeout=300, limit=64 * 1024 * 1024)
        if result.find("config") is None:
            raise PanosError("running configuration export returned no config element")
        return ET.tostring(result.find("config"), encoding="utf-8")
