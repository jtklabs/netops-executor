import hashlib
import json
import re
from urllib.parse import parse_qs

import httpx
import pytest
from conftest import Clock, FakeDevice
from fastapi.testclient import TestClient
from test_controls_credentials import vault_for

from netops_executor import panos
from netops_executor.api import create_app
from netops_executor.config import HTTPTarget
from netops_executor.credentials import Credential, Vault
from netops_executor.execution_models import ValidationDecision
from netops_executor.panos_engine import PanosRunner, compare
from netops_executor.panos_models import PanosBatch, PanosUpgradeRequest, PanosValidationPolicy

TARGET = "11.1.6-h3"
LABELS = {panos.SUSPEND: "suspend", panos.FUNCTIONAL: "functional", panos.RESTART: "restart"}


def field(cmd, name):
    return cmd.split("<" + name + ">")[1].split("<")[0]


class FakeFirewall:
    jobs_issued = 100

    def __init__(self, serial, version="10.2.9-h1", preemptive="no"):
        self.serial, self.version, self.model, self.family = serial, version, "PA-3220", "3200"
        self.uptime = 10 * 86400
        self.software = {v: v == version for v in ("10.2.9-h1", "11.1.0", TARGET)}
        self.internet = False
        self.update_info = True
        self.mgmt_ip = "198.51.100." + str(10 + int(serial[-2:]))
        self.sha = {}
        self.import_status = 200
        self.corrupt = False
        self.sync_enabled, self.sync_override = "yes", None
        self.installed = None
        self.jobs = {}
        self.pending = False
        self.rebooting = 0
        self.boot_polls = 3
        self.install_result = "OK"
        self.download_polls = 0
        self.on_download = None
        self.preemptive = self.candidate_preemptive = preemptive
        self.pair = self.peer = None
        self.interfaces = {"ethernet1/1": "up", "ethernet1/2": "up", "ethernet1/3": "down"}
        self.routes = [
            ("default", "0.0.0.0/0", "192.0.2.1", "ethernet1/1"),
            ("default", "10.0.0.0/8", "", "ae1"),
        ]
        self.bgp = {"isp1": "Established"}
        self.bgp_after_upgrade = None
        self.tunnels = {"branch-1": "active"}
        self.writes = []
        self.log = []

    def write(self, label):
        self.writes.append(label)
        self.log.append((self.serial, label))

    def job(self, kind, result="OK", polls=0):
        FakeFirewall.jobs_issued += 1
        self.jobs[FakeFirewall.jobs_issued] = {"type": kind, "result": result, "polls": polls}
        return FakeFirewall.jobs_issued

    def job_xml(self, job_id):
        job = self.jobs[job_id]
        running = job["polls"] > 0
        job["polls"] -= 1
        return (
            f"<job><id>{job_id}</id><type>{job['type']}</type><status>{'ACT' if running else 'FIN'}</status>"
            f"<result>{'PEND' if running else job['result']}</result><progress>{50 if running else 100}</progress>"
            f"<details><line>{job['type']} {job['result']}</line></details></job>"
        )

    def ha_xml(self):
        if not self.pair:
            return "<enabled>no</enabled>"
        state, peer = self.pair.state, self.peer
        sync = self.sync_override or ("synchronized" if self.version == peer.version else "not synchronized")
        return (
            f"<enabled>yes</enabled><group><mode>{self.pair.mode}</mode>"
            f"<local-info><state>{state[self.serial]}</state><build-rel>{self.version}</build-rel>"
            f"<preemptive>{self.preemptive}</preemptive></local-info>"
            f"<peer-info><mgmt-ip>{peer.mgmt_ip}/24</mgmt-ip><conn-status>{'down' if peer.rebooting else 'up'}</conn-status>"
            f"<state>{state[peer.serial]}</state><build-rel>{peer.version}</build-rel></peer-info>"
            f"<running-sync>{sync}</running-sync>"
            f"<running-sync-enabled>{self.sync_enabled}</running-sync-enabled></group>"
        )

    def handle_form(self, form):
        if self.rebooting:
            self.rebooting -= 1
            if not self.rebooting:
                self.version, self.uptime = self.installed, 30
                self.job("AutoCom")
                if self.pair and not self.pair.keep_suspended and self.pair.state[self.serial] == "suspended":
                    # PAN-OS 12.1.6 (lab): a suspended member boots back into service.
                    self.pair.functional(self)
            return None
        if form["type"] == "config":
            assert form["action"] == "set" and form["xpath"] == panos.HA_ELECTION
            self.candidate_preemptive = field(form["element"], "preemptive")
            self.write("preemptive-" + self.candidate_preemptive)
            return ""
        if form["type"] == "commit":
            self.preemptive = self.candidate_preemptive
            self.write("commit")
            return f"<job>{self.job('Commit')}</job>"
        if form["type"] == "export":
            assert form["category"] == "tech-support"
            if form.get("action") == "status":
                return "<job><status>FIN</status><resultfile>//tmp/techsupport.tgz</resultfile></job>"
            if form.get("action") == "get":
                return b"tech-support-archive"
            return f"<job>{self.job('TechSupport')}</job>"
        return self.handle(form["cmd"])

    def handle(self, cmd):
        if cmd in LABELS:
            self.write(LABELS[cmd])
        if cmd == panos.SYSTEM_INFO:
            days, rest = divmod(self.uptime, 86400)
            hours, rest = divmod(rest, 3600)
            uptime = f"{days} days, {hours}:{rest // 60:02}:{rest % 60:02}"
            return (
                f"<system><hostname>fw-{self.serial}</hostname><serial>{self.serial}</serial>"
                f"<model>{self.model}</model><sw-version>{self.version}</sw-version>"
                f"<app-version>8800-8000</app-version><family>{self.family}</family><uptime>{uptime}</uptime>"
                "<operational-mode>normal</operational-mode></system>"
            )
        if cmd == panos.CHASSIS_READY:
            return "yes"
        if cmd == panos.HA_STATE:
            return self.ha_xml()
        if cmd == panos.PENDING_CHANGES:
            return "yes" if self.pending else "no"
        if cmd == panos.JOBS:
            return "".join(self.job_xml(j) for j in self.jobs)
        if cmd.startswith("<show><jobs><id>"):
            return self.job_xml(int(field(cmd, "id")))
        if cmd == panos.SOFTWARE_CHECK and not self.internet:
            return None
        if cmd == panos.SOFTWARE_INFO and not self.update_info:
            return ("error", "No update information available")
        if cmd in (panos.SOFTWARE_CHECK, panos.SOFTWARE_INFO):
            return (
                "<sw-updates><versions>"
                + "".join(
                    f"<entry><version>{v}</version><downloaded>{'yes' if d else 'no'}</downloaded>"
                    f"<sha256>{self.sha.get(v, '(null)')}</sha256></entry>"
                    for v, d in self.software.items()
                )
                + "</versions></sw-updates>"
            )
        if cmd.startswith("<request><system><software><download>"):
            version = field(cmd, "version")
            self.write("download " + version)
            self.software[version] = True
            if self.on_download:
                self.on_download()
            return f"<job>{self.job('Downld', polls=self.download_polls)}</job>"
        if cmd.startswith("<request><system><software><install>"):
            self.write("install " + field(cmd, "version"))
            if self.install_result == "OK":
                self.installed = field(cmd, "version")
            return f"<job>{self.job('SWInstall', self.install_result)}</job>"
        if cmd == panos.RESTART:
            self.rebooting = self.boot_polls
            return "<msg>restarting</msg>"
        if cmd == panos.SUSPEND:
            self.pair.suspend(self)
            return "Successfully changed HA state to suspended"
        if cmd == panos.FUNCTIONAL:
            self.pair.functional(self)
            return "Successfully changed HA state to functional"
        if cmd == panos.INTERFACES:
            return (
                "<hw>"
                + "".join(
                    f"<entry><name>{n}</name><state>{s}</state></entry>" for n, s in self.interfaces.items()
                )
                + "</hw>"
            )
        if cmd == panos.ROUTES:
            return "".join(
                f"<entry><virtual-router>{vr}</virtual-router><destination>{d}</destination>"
                f"<nexthop>{n}</nexthop><interface>{i}</interface></entry>"
                for vr, d, n, i in self.routes
            )
        if cmd == panos.BGP_PEERS:
            bgp = self.bgp
            if self.bgp_after_upgrade and self.version == TARGET:
                bgp = {p: self.bgp_after_upgrade for p in bgp}
            return "".join(
                f'<entry peer="{p}" vr="default"><status>{s}</status></entry>' for p, s in bgp.items()
            )
        if cmd == panos.TUNNELS:
            return (
                "<IPSec>"
                + "".join(
                    f"<entry><name>{n}</name><state>{s}</state></entry>" for n, s in self.tunnels.items()
                )
                + "</IPSec>"
            )
        if cmd == panos.SESSIONS:
            return "<num-active>1000</num-active>"
        if cmd == panos.ARP:
            return "<max>2000</max><total>50</total>"
        if cmd == panos.RUNNING_CONFIG:
            return '<config version="10.2.0"><devices/></config>'
        raise AssertionError("unexpected command " + cmd)


class FakePair:
    def __init__(self, a, b, mode="Active-Passive"):
        self.mode = mode
        self.keep_suspended = True
        self.roles = (
            {a.serial: "active", b.serial: "passive"}
            if mode == "Active-Passive"
            else {a.serial: "active-primary", b.serial: "active-secondary"}
        )
        self.state = dict(self.roles)
        a.pair = b.pair = self
        a.peer, b.peer = b, a

    def suspend(self, fw):
        if self.mode == "Active-Passive" and self.state[fw.serial] == "active":
            self.state[fw.peer.serial] = "active"
        self.state[fw.serial] = "suspended"

    def functional(self, fw):
        if self.mode == "Active-Active":
            self.state[fw.serial] = self.roles[fw.serial]
        else:
            self.state[fw.serial] = "passive" if self.state[fw.peer.serial] == "active" else "active"


class FakePanorama:
    def __init__(self):
        self.firewalls = {}
        self.reject_probe = False
        self.internet = True
        self.repository = {"PanOS_3200-" + TARGET: True}
        self.offered = {"PanOS_3200-11.1.0", "PanOS_3200-" + TARGET, "PanOS_vm-11.1.0", "PanOS_vm-" + TARGET}
        self.jobs = {}
        self.writes = []
        self.log = []
        self.busy = False
        self.base_files = set()
        self.download_wait = None
        self.upload_result = "OK"

    def add(self, *firewalls):
        for fw in firewalls:
            fw.log = self.log
            self.firewalls[fw.serial] = fw
        return firewalls[0] if len(firewalls) == 1 else firewalls

    def job(self, kind, result="OK", polls=0, done=None):
        FakeFirewall.jobs_issued += 1
        self.jobs[FakeFirewall.jobs_issued] = {"type": kind, "result": result, "polls": polls, "done": done}
        return FakeFirewall.jobs_issued

    def job_xml(self, job_id):
        job = self.jobs[job_id]
        if job["polls"] <= 0 and job["done"]:
            job["done"]()
            job["done"] = None
        return FakeFirewall.job_xml(self, job_id)

    def devices(self):
        entries = []
        for fw in self.firewalls.values():
            ha = ""
            if fw.pair:
                ha = f"<ha><state>{fw.pair.state[fw.serial]}</state><peer><serial>{fw.peer.serial}</serial></peer></ha>"
            entries.append(
                f'<entry name="{fw.serial}"><serial>{fw.serial}</serial>'
                f"<connected>{'no' if fw.rebooting else 'yes'}</connected><model>{fw.model}</model>"
                f"<sw-version>{fw.version}</sw-version><family>{fw.family}</family>"
                f"<ip-address>{fw.mgmt_ip}</ip-address>{ha}</entry>"
            )
        return "<devices>" + "".join(entries) + "</devices>"

    def repository_xml(self):
        if self.download_wait:
            # Another job's repository download finishes after a few polls.
            filename, job_id, polls = self.download_wait
            self.download_wait = (filename, job_id, polls - 1) if polls > 1 else None
            if polls <= 1:
                self.repository[filename], self.jobs[job_id]["polls"] = True, 0
        return (
            "<sw-updates><versions>"
            + "".join(
                f"<entry><version>{f.split('-', 1)[1]}</version><filename>{f}</filename>"
                f"<downloaded>{'yes' if a else 'no'}</downloaded>"
                f"<release-type>{'Base' if f in self.base_files else ''}</release-type></entry>"
                for f, a in self.repository.items()
            )
            + "</versions></sw-updates>"
        )

    def handle_form(self, form):
        cmd = form["cmd"]
        if cmd == panos.DEVICES:
            return self.devices()
        if cmd == panos.REPOSITORY_INFO:
            return self.repository_xml()
        if cmd == panos.REPOSITORY_CHECK:
            if not self.internet:
                return None
            self.repository.update({f: self.repository.get(f, False) for f in self.offered})
            return self.repository_xml()
        if cmd.startswith("<request><batch><software><download>"):
            filename = field(cmd, "file")
            self.writes.append("download " + filename)
            if self.busy:
                self.download_wait = (filename, self.job("Downld", polls=10**6), 3)
                return None
            self.repository[filename] = True
            return f"<job>{self.job('Downld')}</job>"
        if cmd.startswith("<request><batch><software><upload>"):
            filename, serial = field(cmd, "file"), field(cmd, "devices")
            self.writes.append("upload " + filename + " " + serial)
            fw = self.firewalls[serial]
            assert self.repository.get(filename) and filename.startswith("PanOS_" + fw.family + "-")
            if self.upload_result == "OK":
                fw.software[filename.split("-", 1)[1]] = True
            return f"<job>{self.job('SWUpload', self.upload_result)}</job>"
        if cmd == panos.JOBS:
            return "".join(self.job_xml(j) for j in self.jobs)
        if cmd.startswith("<show><jobs><id>"):
            return self.job_xml(int(field(cmd, "id")))
        raise AssertionError("unexpected Panorama command " + cmd)

    def direct(self, request):
        """A firewall's own management API, reached by its management address."""
        fw = next(f for f in self.firewalls.values() if f.mgmt_ip == request.url.host)
        form = parse_qs(request.content.decode(errors="replace")) if request.method == "POST" else {}
        if form.get("type") == ["keygen"]:
            if form.get("user") == ["admin"] and form.get("password") == ["lab-password"]:
                return httpx.Response(
                    200,
                    text='<response status="success"><result><key>firewall-secret</key></result></response>',
                )
            return httpx.Response(
                403,
                text='<response status="error" code="403"><result><msg>Invalid Credential</msg></result></response>',
            )
        if request.headers.get("x-pan-key") != "firewall-secret":
            return httpx.Response(
                200, text='<response status="error" code="403"><msg>Invalid credential</msg></response>'
            )
        if request.method == "GET":
            return httpx.Response(200, text='<response status="success"><result/></response>')
        assert request.url.params["type"] == "import" and request.url.params["category"] == "software"
        filename = re.search(rb'filename="([^"]+)"', request.content).group(1).decode()
        payload = request.content.split(b"\r\n\r\n", 1)[1].rsplit(b"\r\n--", 1)[0]
        version = filename.split("-", 1)[1]
        fw.write("import " + filename)
        fw.software[version] = True
        fw.sha[version] = "0" * 64 if fw.corrupt else hashlib.sha256(payload).hexdigest()
        if fw.import_status != 200:
            return httpx.Response(fw.import_status, text="<html>Gateway Time-out</html>")
        return httpx.Response(200, text='<response status="success"><msg>uploaded</msg></response>')

    def __call__(self, request):
        if request.url.host != "panorama.example":
            return self.direct(request)
        if request.method == "GET":
            assert request.headers["x-pan-key"] == "panorama-secret"
            if self.reject_probe:
                return httpx.Response(401)
            return httpx.Response(
                200,
                text='<response status="success"><result><sw-version>11.1.4</sw-version></result></response>',
            )
        form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
        body = (self.firewalls[form["target"]] if "target" in form else self).handle_form(form)
        if body is None or isinstance(body, tuple):
            detail = body[1] if body else "operation failed"
            return httpx.Response(
                200,
                text=f'<response status="error"><msg><line>{detail}</line></msg></response>',
            )
        if isinstance(body, bytes):
            return httpx.Response(200, content=body, headers={"content-type": "application/octet-stream"})
        return httpx.Response(200, text=f'<response status="success"><result>{body}</result></response>')


@pytest.fixture
def panorama(settings, store, monkeypatch):
    vault = vault_for(settings, store)
    vault.put(
        "panorama-key", Credential(kind="http", scheme="header", header="X-PAN-KEY", token="panorama-secret")
    )
    settings.http_targets["panorama"] = HTTPTarget(
        id="panorama",
        base_url="https://panorama.example",
        auth_probe_path="/api/",
        auth_probe_params={"type": "version"},
    )
    fake = FakePanorama()
    client = httpx.Client
    monkeypatch.setattr(
        "netops_executor.panos.httpx.Client",
        lambda **kwargs: client(transport=httpx.MockTransport(fake), **kwargs),
    )
    return fake


def submit(store, serial, **options):
    request = PanosUpgradeRequest(
        serial=serial, target_version=TARGET, allowed_source_versions=["10.2.9-h1"], **options
    )
    return store.submit(request.model_dump(mode="json"), "panos:" + serial, kind="panos_upgrade")


def work(settings, store, worker="w", f5=None):
    job = store.claim(worker)
    clock = Clock()
    PanosRunner(settings, store, job, worker, sleep=clock.sleep, clock=clock.clock, f5=f5).run()
    return store.get(job["id"])


def run(settings, store, serial, **options):
    submit(store, serial, **options)
    return work(settings, store)


def decide(store, job, action="accept"):
    gate = job["validation_gates"][-1]
    store.decide(
        job["id"],
        ValidationDecision(
            action=action,
            gate_id=gate["id"],
            validation_revision=gate["revision"],
            operator="jason",
            reason="Checked by the operator",
        ),
    )


def pair(panorama, mode="Active-Passive", **options):
    a, b = FakeFirewall("0079510001", **options), FakeFirewall("0079510002")
    FakePair(a, b, mode)
    return panorama.add(a, b)


def test_standalone_push_from_panorama_without_firewall_internet(settings, store, panorama):
    fw = panorama.add(FakeFirewall("0079510001"))
    job = run(settings, store, fw.serial)
    assert job["status"] == "succeeded", job["result"]
    assert panorama.writes == [
        "download PanOS_3200-11.1.0",
        "upload PanOS_3200-11.1.0 0079510001",
        "upload PanOS_3200-11.1.6-h3 0079510001",
    ]
    assert fw.writes == ["install " + TARGET, "restart"]
    member = job["result"]["members"][fw.serial]
    assert member["software"]["files"][TARGET] == "PanOS_3200-11.1.6-h3"
    assert member["boot_verified"]["version"] == TARGET
    assert job["result"]["validated_version"] == TARGET and not job["lock_held"]
    artifacts = {a["kind"]: settings.backup_root / a["path"] for a in job["result"]["artifacts"]}
    assert artifacts["config"].read_bytes().startswith(b"<config")
    assert artifacts["tech_support"].read_bytes() == b"tech-support-archive"
    assert all(oct(p.stat().st_mode & 0o777) == "0o600" for p in artifacts.values())
    assert job["credential_summary"]["profiles_used"] == ["panorama-key"]
    client = TestClient(create_app(settings), headers={"Authorization": "Bearer " + settings.token})
    name = next(a["name"] for a in job["result"]["artifacts"] if a["kind"] == "tech_support")
    assert client.get(f"/api/v1/jobs/{job['id']}/artifacts/{name}").content == b"tech-support-archive"
    assert client.get(f"/api/v1/jobs/{job['id']}/artifacts/missing").status_code == 404


def test_firewall_without_update_information_relies_on_upload_jobs(settings, store, panorama):
    fw = panorama.add(FakeFirewall("0079510001"))
    fw.update_info = False
    job = run(settings, store, fw.serial, tech_support=False)
    assert job["status"] == "succeeded", job["result"]
    software = job["result"]["members"][fw.serial]["software"]
    assert software["verified_by"] == "panorama_upload" and software["uploaded"] == ["11.1.0", TARGET]
    assert fw.writes == ["install " + TARGET, "restart"]


def test_config_sync_disabled_pair_passes_but_out_of_sync_pair_is_blocked(settings, store, panorama):
    a, b = pair(panorama)
    a.sync_override = b.sync_override = "not synchronized"
    job = run(settings, store, a.serial, tech_support=False)
    assert job["status"] == "failed" and "not synchronized" in job["result"]["error"]
    assert a.writes == b.writes == []
    a.sync_enabled = b.sync_enabled = "no"
    job = run(settings, store, a.serial, tech_support=False)
    assert job["status"] == "succeeded", job["result"]
    assert job["result"]["ha"]["config_sync"] == "disabled"


def test_update_server_source_downloads_on_the_firewall(settings, store, panorama):
    fw = panorama.add(FakeFirewall("0079510001"))
    fw.internet = True
    job = run(settings, store, fw.serial, software_source="update_server", tech_support=False)
    assert job["status"] == "succeeded", job["result"]
    assert fw.writes == ["download 11.1.0", "download " + TARGET, "install " + TARGET, "restart"]
    assert panorama.writes == [] and [a["kind"] for a in job["result"]["artifacts"]] == ["config"]


@pytest.mark.parametrize(
    "change, options, error",
    [
        (lambda fw, p: setattr(fw, "version", "10.1.14"), {}, "outside allowed_source_versions"),
        (lambda fw, p: setattr(fw, "pending", True), {}, "uncommitted local changes"),
        (lambda fw, p: setattr(fw, "model", "PA-220"), {"approved_models": ["PA-3220"]}, "not approved"),
        (lambda fw, p: setattr(fw, "family", ""), {}, "set software_family"),
        (
            lambda fw, p: p.repository.clear(),
            {"panorama_download": False},
            "PanOS_3200-11.1.6-h3 is not in Panorama's software repository",
        ),
        (
            lambda fw, p: (p.repository.clear(), setattr(p, "internet", False)),
            {},
            "Panorama does not offer PanOS_3200-11.1.6-h3",
        ),
    ],
)
def test_failures_before_install_change_nothing(settings, store, panorama, change, options, error):
    fw = panorama.add(FakeFirewall("0079510001"))
    change(fw, panorama)
    job = run(settings, store, fw.serial, **options)
    assert job["status"] == "failed"
    assert error in job["result"]["error"]
    assert fw.writes == [] and not job["lock_held"]


def test_base_image_is_the_lowest_offered_release_and_optional(settings, store, panorama):
    # 12.x feature releases do not always ship X.Y.0; with no lower release the target installs directly.
    fw = panorama.add(FakeFirewall("0079510001"))
    panorama.offered = {"PanOS_3200-11.1.2", "PanOS_3200-11.1.4", "PanOS_3200-" + TARGET}
    job = run(settings, store, fw.serial, tech_support=False)
    assert job["status"] == "succeeded", job["result"]
    assert job["result"]["members"][fw.serial]["software"]["required"] == ["11.1.2", TARGET]
    fw2 = panorama.add(FakeFirewall("0079510003"))
    panorama.offered = {"PanOS_3200-" + TARGET}
    panorama.repository = {"PanOS_3200-" + TARGET: True}
    job = run(settings, store, fw2.serial, tech_support=False)
    assert job["status"] == "succeeded", job["result"]
    assert job["result"]["members"][fw2.serial]["software"]["required"] == [TARGET]
    # A release the source flags as Base wins over the lowest number.
    fw3 = panorama.add(FakeFirewall("0079510004"))
    panorama.offered = {"PanOS_3200-11.1.2", "PanOS_3200-11.1.4", "PanOS_3200-" + TARGET}
    panorama.base_files = {"PanOS_3200-11.1.4"}
    panorama.repository = {"PanOS_3200-" + TARGET: True}
    job = run(settings, store, fw3.serial, tech_support=False)
    assert job["result"]["members"][fw3.serial]["software"]["required"] == ["11.1.4", TARGET]


def test_family_override_selects_panorama_file(settings, store, panorama):
    fw = panorama.add(FakeFirewall("0079510001"))
    fw.family = "vm"
    panorama.repository = {"PanOS_vm-11.1.0": True, "PanOS_vm-" + TARGET: True}
    job = run(settings, store, fw.serial, software_family="vm", tech_support=False)
    assert job["status"] == "succeeded", job["result"]
    assert panorama.writes == ["upload PanOS_vm-11.1.0 0079510001", "upload PanOS_vm-11.1.6-h3 0079510001"]


def test_shared_repository_download_waits_for_the_running_job(settings, store, panorama):
    fw = panorama.add(FakeFirewall("0079510001"))
    panorama.busy = True
    job = run(settings, store, fw.serial, tech_support=False)
    assert job["status"] == "succeeded", job["result"]
    assert panorama.writes[0] == "download PanOS_3200-11.1.0"
    assert "upload PanOS_3200-11.1.0 0079510001" in panorama.writes


def test_upload_failure_stops_before_install(settings, store, panorama):
    fw = panorama.add(FakeFirewall("0079510001"))
    panorama.upload_result = "FAIL"
    job = run(settings, store, fw.serial, tech_support=False)
    assert job["status"] == "failed" and "upload of PanOS_3200-11.1.0" in job["result"]["error"]
    assert fw.writes == [] and fw.installed is None


def test_unrestored_bgp_opens_gate_and_accept_continues_without_replay(settings, store, panorama):
    fw = panorama.add(FakeFirewall("0079510001"))
    fw.bgp_after_upgrade = "Idle"
    job = run(settings, store, fw.serial, tech_support=False)
    assert job["status"] == "needs_review" and job["lock_held"]
    gate = job["validation_gates"][-1]
    assert gate["phase"] == "validate_traffic:0079510001"
    assert "0079510001: bgp_peers not restored: default|isp1" in gate["findings"]["critical"]
    writes = list(fw.writes)
    decide(store, job)
    job = work(settings, store)
    assert job["status"] == "completed_with_warnings", job["result"]
    assert job["result"]["manual_validations"][0]["phase"] == "validate_traffic:0079510001"
    assert fw.writes == writes and not job["lock_held"]


def test_active_passive_upgrades_standby_first_then_validates_the_failover(settings, store, panorama):
    a, b = pair(panorama, preemptive="yes")
    job = run(settings, store, a.serial)
    assert job["status"] == "succeeded", job["result"]
    assert a.version == b.version == TARGET
    assert b.writes == ["suspend", "install " + TARGET, "restart", "functional"]
    assert a.writes == [
        "preemptive-no",
        "commit",
        "suspend",
        "install " + TARGET,
        "restart",
        "functional",
        "preemptive-yes",
        "commit",
    ]
    order = [(s, w) for s, w in panorama.log if w in ("functional", "suspend")]
    assert order[:3] == [(b.serial, "suspend"), (b.serial, "functional"), (a.serial, "suspend")]
    assert job["result"]["upgrade_plan"] == [
        {"serial": b.serial, "handoff": False},
        {"serial": a.serial, "handoff": True},
    ]
    assert a.preemptive == "yes" and a.pair.state == {a.serial: "passive", b.serial: "active"}
    assert len(job["result"]["artifacts"]) == 4
    # The peer's own batch item later finds the whole pair upgraded and only validates.
    peer = run(settings, store, b.serial)
    assert peer["status"] == "succeeded" and peer["result"]["already_on_target"]
    assert b.writes == ["suspend", "install " + TARGET, "restart", "functional"]


@pytest.mark.parametrize("mode", ["Active-Passive", "Active-Active"])
def test_member_returning_to_service_after_reboot_is_validated_in_place(settings, store, panorama, mode):
    a, b = pair(panorama, mode=mode)
    a.pair.keep_suspended = False
    job = run(settings, store, a.serial, tech_support=False)
    assert job["status"] == "succeeded", job["result"]
    # No re-suspend and no functional command: the reboot already returned it to service.
    assert b.writes == ["suspend", "install " + TARGET, "restart"]
    assert (
        sum(e["step"] == "ha_returned_to_service_after_reboot" for e in store.events(job["id"], 0, 5000)) == 2
    )
    assert a.version == b.version == TARGET


@pytest.mark.parametrize("mode", ["Active-Passive", "Active-Active"])
def test_suspend_until_validated_suspends_a_returning_member_again(settings, store, panorama, mode):
    a, b = pair(panorama, mode=mode)
    a.pair.keep_suspended = False
    job = run(
        settings, store, a.serial, tech_support=False, ha_policy={"after_reboot": "suspend_until_validated"}
    )
    assert job["status"] == "succeeded", job["result"]
    assert b.writes == ["suspend", "install " + TARGET, "restart", "suspend", "functional"]
    assert sum(e["step"] == "ha_resuspended" for e in store.events(job["id"], 0, 5000)) == 2


def test_member_failing_validation_in_service_is_suspended_before_review(settings, store, panorama):
    a, b = pair(panorama)
    a.pair.keep_suspended = False
    original = b.handle

    def handle(cmd):
        if cmd == panos.CHASSIS_READY and b.version == TARGET:
            return "no"
        return original(cmd)

    b.handle = handle
    job = run(settings, store, a.serial, tech_support=False)
    assert job["status"] == "needs_review", job["result"]
    assert job["validation_gates"][-1]["phase"] == "validate_system:" + b.serial
    assert b.writes == ["suspend", "install " + TARGET, "restart", "suspend"]
    assert a.pair.state == {a.serial: "active", b.serial: "suspended"}
    b.handle = original
    decide(store, job, "retry")
    job = work(settings, store)
    assert job["status"] == "succeeded", job["result"]
    assert b.writes[-1] == "functional"


def test_failed_handoff_returns_traffic_to_the_original_active(settings, store, panorama):
    a, b = pair(panorama)
    b.bgp_after_upgrade = "Idle"
    job = run(settings, store, a.serial, tech_support=False)
    assert job["status"] == "needs_review", job["result"]
    assert job["validation_gates"][-1]["phase"] == "handoff:" + a.serial
    # The upgraded standby failed under traffic: the old active carries it again, untouched.
    assert a.pair.state == {a.serial: "active", b.serial: "suspended"}
    assert a.version == "10.2.9-h1" and "install " + TARGET not in a.writes
    b.bgp_after_upgrade = None
    decide(store, job, "retry")
    job = work(settings, store)
    assert job["status"] == "succeeded", job["result"]
    assert a.version == b.version == TARGET
    # Upgrade, failback suspend, then the retry returns it to service before handing off again.
    assert b.writes == ["suspend", "install " + TARGET, "restart", "functional", "suspend", "functional"]
    assert a.writes.count("suspend") == 2


def test_preemption_is_untouched_when_disabled_by_request(settings, store, panorama):
    a, b = pair(panorama, preemptive="yes")
    job = run(settings, store, a.serial, tech_support=False, ha_policy={"disable_preemption": False})
    assert job["status"] == "succeeded", job["result"]
    assert "preemption" not in job["result"] and a.preemptive == "yes"
    assert not any(w.startswith("preemptive-") or w == "commit" for w in a.writes + b.writes)
    plan = PanosUpgradeRequest(serial=a.serial, target_version=TARGET, allowed_source_versions=["10.2.9-h1"])
    assert "ha_disable_preemption_and_commit" in plan.plan()
    plan.ha_policy.disable_preemption = False
    assert "ha_disable_preemption_and_commit" not in plan.plan()


def test_active_active_upgrades_each_member_with_survivor_validation(settings, store, panorama):
    a, b = pair(panorama, mode="Active-Active")
    job = run(settings, store, a.serial, tech_support=False)
    assert job["status"] == "succeeded", job["result"]
    assert [p["serial"] for p in job["result"]["upgrade_plan"]] == [b.serial, a.serial]
    assert all(p["handoff"] for p in job["result"]["upgrade_plan"])
    assert a.writes == b.writes == ["suspend", "install " + TARGET, "restart", "functional"]
    assert a.pair.state == {a.serial: "active-primary", b.serial: "active-secondary"}
    assert set(job["result"]["post_validation"]) == {a.serial, b.serial}


def test_install_failure_returns_member_to_service_and_restores_preemption(settings, store, panorama):
    a, b = pair(panorama, preemptive="yes")
    b.install_result = "FAIL"
    job = run(settings, store, a.serial, tech_support=False)
    assert job["status"] == "failed", job["result"]
    assert "install of 11.1.6-h3 on 0079510002 failed" in job["result"]["error"]
    assert b.writes == ["suspend", "install " + TARGET, "functional"]
    assert a.writes == ["preemptive-no", "commit", "preemptive-yes", "commit"]
    assert a.pair.state == {a.serial: "active", b.serial: "passive"} and not job["lock_held"]


def test_unverified_reboot_requires_recovery(settings, store, panorama):
    fw = panorama.add(FakeFirewall("0079510001"))
    fw.boot_polls = 10**6
    job = run(settings, store, fw.serial, reboot_timeout=300, tech_support=False)
    assert job["status"] == "recovery_required"
    assert job["lock_held"]
    submit(store, fw.serial)
    assert store.claim("next") is None


def test_already_on_target_validates_without_writes(settings, store, panorama):
    fw = panorama.add(FakeFirewall("0079510001", version=TARGET))
    job = run(settings, store, fw.serial)
    assert job["status"] == "succeeded", job["result"]
    assert job["result"]["already_on_target"] and fw.writes == [] and panorama.writes == []


def test_stage_only_uploads_without_install(settings, store, panorama):
    a, b = pair(panorama, preemptive="yes")
    job = run(settings, store, a.serial, stage_only=True, tech_support=False)
    assert job["status"] == "succeeded", job["result"]
    assert sum(w.startswith("upload ") for w in panorama.writes) == 4
    assert a.writes == b.writes == [] and a.software[TARGET] and b.software[TARGET]


def test_cancel_during_download_stops_before_install(settings, store, panorama):
    fw = panorama.add(FakeFirewall("0079510001"))
    fw.internet, fw.download_polls = True, 5
    job = submit(store, fw.serial, software_source="update_server", tech_support=False)
    fw.on_download = lambda: store.cancel(job["id"])
    job = work(settings, store)
    assert job["status"] == "cancelled"
    assert fw.installed is None and not job["lock_held"]


def test_compare_gaps_thresholds_and_warning_mode():
    baseline = {
        "interfaces": {"ethernet1/1": "up", "ethernet1/2": "down"},
        "routes": ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"],
        "bgp_peers": {"default|isp": "established"},
        "ipsec_tunnels": {"t1": "active"},
        "sessions": 1000,
        "gaps": ["arp"],
    }
    current = {
        "interfaces": {"ethernet1/1": "down", "ethernet1/2": "up"},
        "routes": ["a", "b", "c", "d", "e", "f", "g", "h"],
        "bgp_peers": {"default|isp": "established"},
        "ipsec_tunnels": {},
        "sessions": 100,
        "gaps": ["arp"],
    }
    critical, findings, metrics = compare(baseline, current, PanosValidationPolicy(min_session_percent=50))
    assert "interfaces not restored: ethernet1/1" in critical
    assert "ipsec_tunnels not restored: t1" in critical
    assert any("route count 8" in c for c in critical) and any("sessions count" in c for c in critical)
    assert metrics["route_percent"] == 80
    critical, findings, _ = compare(
        baseline, current, PanosValidationPolicy(restore_required=False, min_route_percent=None)
    )
    assert critical == []
    assert {f["category"] for f in findings} >= {"interfaces", "ipsec_tunnels", "routes"}
    lost = {**current, "gaps": ["bgp_peers", "arp"]}
    assert (
        "bgp_peers could not be collected after the upgrade"
        in compare(baseline, lost, PanosValidationPolicy())[0]
    )


def test_uptime_parser():
    assert panos.uptime_seconds("12 days, 3:04:05") == ((12 * 24 + 3) * 60 + 4) * 60 + 5
    assert panos.uptime_seconds("0 days, 0:00:30") == 30
    assert panos.uptime_seconds("unknown") is None


def test_batch_api_queues_panos_waves(settings, store, panorama):
    client = TestClient(create_app(settings), headers={"Authorization": "Bearer " + settings.token})
    body = {
        "name": "Change456",
        "defaults": {"target_version": TARGET, "allowed_source_versions": ["10.2.9-h1"]},
        "overrides": {"0079510003": {"validation_policy": {"on_timeout": "fail"}}},
        "waves": [
            {"wave": 1, "upgrade_at_a_time": 2, "serials": ["0079510001", "0079510002"]},
            {"wave": 2, "upgrade_at_a_time": 20, "serials": ["0079510003"]},
        ],
    }
    response = client.post("/api/v1/panos/upgrade-batches", json=body, headers={"Idempotency-Key": "c456"})
    assert response.status_code == 202, response.text
    batch = response.json()
    assert batch["kind"] == "panos_upgrade" and batch["device_count"] == 3
    assert {j["kind"] for j in batch["jobs"]} == {"panos_upgrade"}
    assert {j["queue"] for j in batch["jobs"]} == {"upgrade"}
    again = client.post("/api/v1/panos/upgrade-batches", json=body, headers={"Idempotency-Key": "c456"})
    assert again.json()["id"] == batch["id"]
    claimed = [store.claim("w1"), store.claim("w2"), store.claim("w3")]
    assert sorted(j["device"] for j in claimed if j) == ["0079510001", "0079510002"]
    assert {j["lock_key"] for j in claimed if j} == {"panos:0079510001", "panos:0079510002"}
    item = store.get(next(j["id"] for j in batch["jobs"] if j["device"] == "0079510003"))
    assert item["request"]["validation_policy"]["on_timeout"] == "fail"
    plan = client.post("/api/v1/panos/plan", json={**body["defaults"], "serial": "0079510001"})
    assert plan.json()["steps"][-1] == "validate_final"
    assert "upload_to_firewall" in plan.json()["steps"]
    bad = client.post(
        "/api/v1/panos/jobs", json={**body["defaults"], "serial": "0079510001", "panorama": "other"}
    )
    assert bad.status_code == 422
    single = client.post(
        "/api/v1/panos/jobs", json={**body["defaults"], "serial": "0079510009", "queue": "priority"}
    )
    assert single.status_code == 202, single.text
    assert single.json()["queue"] == "priority"
    with pytest.raises(ValueError):
        PanosBatch.model_validate({**body, "overrides": {"0079519999": {}}})


def test_request_normalizes_download_versions():
    request = PanosUpgradeRequest(
        serial="0079510001",
        target_version=TARGET,
        allowed_source_versions=["10.2.9-h1"],
        download_versions=["10.2.0", "11.0.0", "10.2.0", TARGET],
    )
    assert request.download_versions == ["10.2.0", "11.0.0"]
    with pytest.raises(ValueError):
        PanosUpgradeRequest(serial="0079510001", target_version="11.1", allowed_source_versions=["10.2.9"])


def test_missing_target_or_rejected_key_fails_job_not_worker(settings, store, panorama):
    fw = panorama.add(FakeFirewall("0079510001"))
    job = run(settings, store, fw.serial, panorama="removed")
    assert job["status"] == "failed" and "not configured: removed" in job["result"]["error"]
    panorama.reject_probe = True
    job = run(settings, store, fw.serial)
    assert job["status"] == "failed"
    assert job["result"]["error"] == "Panorama rejected every eligible HTTP credential"
    assert fw.writes == []


F5 = "192.0.2.50"


def logged_f5(panorama):
    f5 = FakeDevice()
    original = f5.set_enabled

    def set_enabled(address, enabled):
        panorama.log.append(("f5", ("enable " if enabled else "disable ") + address))
        original(address, enabled)

    f5.set_enabled = set_enabled
    return f5


def drain_run(settings, store, serial, f5, drain=None, **options):
    submit(store, serial, tech_support=False, f5_drain={"device": F5, **(drain or {})}, **options)
    return work(settings, store, f5=f5)


def test_f5_drain_disables_before_install_and_restores_after_validation(settings, store, panorama):
    fw = panorama.add(FakeFirewall("0079510001"))
    f5 = logged_f5(panorama)
    job = drain_run(settings, store, fw.serial, f5)
    assert job["status"] == "succeeded", job["result"]
    log = [
        entry for entry in panorama.log if entry[0] == "f5" or entry[1] in ("install " + TARGET, "restart")
    ]
    assert log == [
        ("f5", "disable /Common/192.0.2.20"),
        (fw.serial, "install " + TARGET),
        (fw.serial, "restart"),
        ("f5", "enable /Common/192.0.2.20"),
    ]
    # Only addresses this job disabled are restored; an already-disabled address stays disabled.
    assert f5.addresses == {"/Common/192.0.2.20": True, "/Tenant/192.0.2.30": False}
    assert ("save /sys config", {"timeout": 180}) in f5.ssh.commands
    drain = job["result"]["f5_drain"]
    assert drain["initial_connections"] == 100 and drain["threshold"] == 0 and drain["restored"]
    steps = job["result"]["completed_steps"]
    assert (
        steps.index("validate_traffic:" + fw.serial)
        < steps.index("f5_restore")
        < steps.index("validate_restored")
    )
    events = store.events(job["id"], 0, 1000)
    reserved = next(e for e in events if e["step"] == "resources_reserved")["data"]["keys"]
    assert "device:" + F5 in reserved and "endpoint:" + F5 in reserved


def test_f5_drain_timeout_restores_and_stops_before_install(settings, store, panorama):
    fw = panorama.add(FakeFirewall("0079510001"))
    f5 = logged_f5(panorama)
    f5.counts = iter([100, 90, 90, 90, 90])
    job = drain_run(settings, store, fw.serial, f5, {"remaining_connections": 10, "timeout_seconds": 10})
    assert job["status"] == "failed" and "F5 drain timed out" in job["result"]["error"]
    assert f5.address_changes == [("/Common/192.0.2.20", False), ("/Common/192.0.2.20", True)]
    assert fw.writes == [] and not job["lock_held"]


def test_f5_drain_proceeds_on_timeout_when_allowed(settings, store, panorama):
    fw = panorama.add(FakeFirewall("0079510001"))
    f5 = logged_f5(panorama)
    f5.counts = iter([100, 90, 90, 90, 90])
    job = drain_run(
        settings,
        store,
        fw.serial,
        f5,
        {"reduction_percent": 50, "timeout_seconds": 10, "proceed_on_timeout": True},
    )
    assert job["status"] == "succeeded", job["result"]
    assert job["result"]["f5_drain"]["threshold"] == 50 and job["result"]["f5_drain"]["timed_out"]


def test_unvalidated_upgrade_keeps_the_f5_drained(settings, store, panorama):
    fw = panorama.add(FakeFirewall("0079510001"))
    fw.bgp_after_upgrade = "Idle"
    f5 = logged_f5(panorama)
    job = drain_run(settings, store, fw.serial, f5)
    assert job["status"] == "needs_review" and job["lock_held"]
    assert f5.addresses["/Common/192.0.2.20"] is False
    fw.bgp_after_upgrade = None
    decide(store, job, "retry")
    job = work(settings, store, f5=f5)
    assert job["status"] == "succeeded", job["result"]
    assert f5.addresses["/Common/192.0.2.20"] is True
    other = panorama.add(FakeFirewall("0079510003"))
    other.boot_polls = 10**6
    job = drain_run(settings, store, other.serial, logged_f5(panorama), reboot_timeout=300)
    assert job["status"] == "recovery_required" and job["result"]["f5_drain"]["pending_restore"]


def test_f5_drain_refuses_pairs_and_clustered_f5(settings, store, panorama):
    a, b = pair(panorama)
    job = drain_run(settings, store, a.serial, logged_f5(panorama))
    assert job["status"] == "failed" and "standalone firewalls" in job["result"]["error"]
    fw = panorama.add(FakeFirewall("0079510003"))
    f5 = logged_f5(panorama)
    f5.topology = lambda: {**FakeDevice.topology(f5), "cluster": "ha:f5"}
    job = drain_run(settings, store, fw.serial, f5)
    assert job["status"] == "failed" and "requires a standalone F5" in job["result"]["error"]
    assert f5.address_changes == [] and fw.writes == []


def test_batch_overrides_merge_into_shared_drain_defaults():
    batch = PanosBatch.model_validate(
        {
            "name": "Change789",
            "defaults": {
                "target_version": TARGET,
                "allowed_source_versions": ["10.2.9-h1"],
                "f5_drain": {"remaining_connections": 50, "timeout_seconds": 900},
            },
            "overrides": {
                "0079510001": {"f5_drain": {"device": "192.0.2.51"}},
                "0079510002": {"f5_drain": {"device": "192.0.2.52"}},
            },
            "waves": [{"wave": 1, "serials": ["0079510001", "0079510002"]}],
        }
    )
    drain = batch.request_for("0079510002").f5_drain
    assert (drain.device, drain.remaining_connections, drain.timeout_seconds) == ("192.0.2.52", 50, 900)
    with pytest.raises(ValueError):
        PanosBatch.model_validate(
            {**batch.model_dump(), "overrides": {"0079510001": {"f5_drain": {"device": "192.0.2.51"}}}}
        )


def executor_image(settings, store, content=b"panos image bytes", name="PanOS_3200-" + TARGET):
    Vault(store, settings.credential_key_file).put(
        "firewall-key",
        Credential(
            kind="http",
            scheme="header",
            header="X-PAN-KEY",
            token="firewall-secret",
            targets=["0079510001", "0079510002"],
        ),
    )
    (settings.image_root / name).write_bytes(content)
    return {"name": name, "sha256": hashlib.sha256(b"panos image bytes").hexdigest()}


def test_executor_pushes_from_its_image_cache_with_progress(settings, store, panorama):
    fw = panorama.add(FakeFirewall("0079510001"))
    image = executor_image(settings, store)
    job = run(settings, store, fw.serial, software_source="executor", images=[image], tech_support=False)
    assert job["status"] == "succeeded", job["result"]
    assert panorama.writes == []
    assert fw.writes == ["import PanOS_3200-" + TARGET, "install " + TARGET, "restart"]
    software = job["result"]["members"][fw.serial]["software"]
    assert software["source"] == "executor" and software["uploaded"] == [TARGET]
    uploads = [
        e["data"]
        for e in store.events(job["id"], 0, 5000)
        if e["step"] == "progress" and e["data"]["kind"] == "upload"
    ]
    assert uploads[-1]["percent"] == 100 and uploads[-1]["bytes"] == uploads[-1]["total_bytes"] == 17
    progress = job["result"]["progress"]
    assert progress["percent"] == 100 and progress["steps_completed"] == progress["steps_total"]
    assert {"reboot", "validation"} <= {
        e["data"]["kind"] for e in store.events(job["id"], 0, 5000) if e["step"] == "progress"
    }


def test_executor_import_504_is_confirmed_by_the_firewall_listing(settings, store, panorama):
    fw = panorama.add(FakeFirewall("0079510001"))
    fw.import_status = 504
    job = run(
        settings,
        store,
        fw.serial,
        software_source="executor",
        images=[executor_image(settings, store)],
        tech_support=False,
    )
    assert job["status"] == "succeeded", job["result"]
    assert any(e["step"] == "software_import_unconfirmed" for e in store.events(job["id"], 0, 5000))


@pytest.mark.parametrize(
    "corrupt_local, corrupt_remote, error",
    [
        (True, False, "executor image missing or SHA-256 mismatch"),
        (False, True, "reports a different SHA-256"),
    ],
)
def test_executor_rejects_checksum_mismatches(
    settings, store, panorama, corrupt_local, corrupt_remote, error
):
    fw = panorama.add(FakeFirewall("0079510001"))
    fw.corrupt = corrupt_remote
    image = executor_image(settings, store, content=b"tampered" if corrupt_local else b"panos image bytes")
    job = run(settings, store, fw.serial, software_source="executor", images=[image], tech_support=False)
    assert job["status"] == "failed" and error in job["result"]["error"]
    assert not any(w.startswith("install") for w in fw.writes) and not job["lock_held"]


def test_preload_stages_a_pair_without_backups_or_health_gates(settings, store, panorama):
    a, b = pair(panorama)
    a.pending = True
    a.sync_override = b.sync_override = "not synchronized"
    job = run(
        settings,
        store,
        a.serial,
        software_source="executor",
        images=[executor_image(settings, store)],
        stage_only=True,
    )
    assert job["status"] == "succeeded", job["result"]
    assert job["result"]["preloaded"] and "artifacts" not in job["result"]
    assert a.writes == ["import PanOS_3200-" + TARGET] and b.writes == ["import PanOS_3200-" + TARGET]
    assert any(e["step"] == "ha_preflight_warnings" for e in store.events(job["id"], 0, 5000))
    with pytest.raises(ValueError):
        PanosUpgradeRequest(
            serial=a.serial,
            target_version=TARGET,
            allowed_source_versions=["10.2.9-h1"],
            software_source="executor",
        )


def test_executor_generates_the_firewall_api_key_from_saved_credentials(settings, store, panorama):
    fw = panorama.add(FakeFirewall("0079510001"))
    image = executor_image(settings, store)
    vault = Vault(store, settings.credential_key_file)
    vault.put("firewall-key", Credential(kind="http", token="unused", enabled=False))
    vault.put(
        "firewall-login",
        Credential(
            kind="http", scheme="keygen", username="admin", password="lab-password", targets=[fw.serial]
        ),
    )
    job = run(settings, store, fw.serial, software_source="executor", images=[image], tech_support=False)
    assert job["status"] == "succeeded", job["result"]
    assert "firewall-login" in job["credential_summary"]["profiles_used"]
    assert "lab-password" not in json.dumps(job) and "firewall-secret" not in json.dumps(job)
    vault.put(
        "firewall-login",
        Credential(kind="http", scheme="keygen", username="admin", password="wrong", targets=[fw.serial]),
    )
    fw.software[TARGET], fw.version, fw.installed = False, "10.2.9-h1", None
    job = run(settings, store, fw.serial, software_source="executor", images=[image], tech_support=False)
    assert job["status"] == "failed" and "rejected every eligible" in job["result"]["error"]
