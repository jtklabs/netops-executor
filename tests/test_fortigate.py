import copy
import ftplib
import hashlib
import io

import pytest
from conftest import Clock
from fastapi.testclient import TestClient

from netops_executor.api import create_app
from netops_executor.config import Device, HTTPTarget
from netops_executor.fortigate_engine import FortigateRunner
from netops_executor.fortigate_models import FortigateBatch, FortigateUpgradeRequest
from netops_executor.fortinet import Fortigate, compare_configs, ha_status, partitions, status
from netops_executor.ftp_staging import OneShotFTP
from netops_executor.iosxe_models import IosxeConfigPolicy
from netops_executor.ssh import DeviceError

IMAGE = "FGT_600E-v7.4.5.F-build2702-FORTINET.out"
CONTENT = b"fortios firmware bytes" * 4096
CONFIG = """#config-version=FG600E-7.04-FW-build2662-240514:opmode=0:vdom=0:user=admin
#conf_file_ver=1234
#buildno=2662
#global_vdom=1
config system global
    set hostname "fw1"
    set admin-port 8443
end
config system admin
    edit "admin"
        set password ENC SH2abcdefgh
    next
end
config vpn certificate local
    edit "site"
        set certificate "-----BEGIN CERTIFICATE-----
MIIBszCCAVmgAwIBAgIUa
-----END CERTIFICATE-----"
    next
end
config firewall policy
    edit 1
        set name "allow-web"
        set action accept
    next
    edit 2
        set name "deny-all"
    next
end
"""
AFTER = (
    CONFIG.replace("build2662", "build2702")
    .replace("ENC SH2abcdefgh", "ENC SH2zyxwvut")
    .replace(
        '    set hostname "fw1"\n    set admin-port 8443\n',
        '    set admin-port 8443\n    set hostname "fw1"\n',
    )
)
TRAFFIC = {
    "interfaces": {"port1": "up", "port2": "up", "port3": "down"},
    "ipsec_tunnels": {"to-branch": "up"},
    "bgp_peers": {"VRF 0|10.0.0.2": "established"},
    "ospf_neighbors": {},
    "routes": 120,
    "sessions": 5000,
    "gaps": [],
}


class FakeFortigate:
    """The Fortigate client interface over a simulated FortiGate or FGCP cluster primary."""

    class SSH:
        class Selector:
            secrets = set()

        selector = Selector()

    def __init__(self, cluster=False):
        self.ssh = self.SSH()
        self.state = {"build": 2662, "version": "7.4.4", "uptime": 864000, "serial": "FG6H0E01"}
        self.cluster = cluster
        self.parts = [
            {
                "partition": 1,
                "image": "FG600E-7.04-FW-build2662",
                "build": 2662,
                "train": (7, 4),
                "active": True,
            },
            {
                "partition": 2,
                "image": "FG600E-7.04-FW-build2571",
                "build": 2571,
                "train": (7, 4),
                "active": False,
            },
        ]
        self.sync = {"FG6H0E01": "in-sync", "FG6H0E02": "in-sync"}
        self.running, self.after_config = CONFIG, AFTER
        self.traffic_state = copy.deepcopy(TRAFFIC)
        self.rebooting = 0
        self.next_reboot = None
        self.downloaded = None
        self.stage_lands = True
        self.after_sync = None
        self.calls = []
        self.console = "more"

    def check(self):
        if self.rebooting:
            self.rebooting -= 1
            if not self.rebooting:
                self.state.update(build=2702, version="7.4.5", uptime=100)
                self.running = self.after_config
                for p in self.parts:
                    p["active"] = p["build"] == 2702
                if self.after_sync:
                    self.sync.update(self.after_sync)
            raise DeviceError("SSH authentication or connection failed")

    def status(self):
        self.check()
        return {
            "model": "FortiGate-600E",
            "version": self.state["version"],
            "build": self.state["build"],
            "serial": self.state["serial"],
            "hostname": "fw1",
            "ha": "a-p" if self.cluster else "standalone",
            "vdoms": False,
            "uptime_seconds": self.state["uptime"],
        }

    def console_output(self):
        return self.console

    def restore_console(self, mode):
        self.calls.append("console " + mode)

    def ha(self):
        self.check()
        return {
            "healthy": all(v == "in-sync" for v in self.sync.values()),
            "members": {
                "FG6H0E01": {"name": "fw1", "role": "primary"},
                "FG6H0E02": {"name": "fw2", "role": "secondary"},
            },
            "sync": dict(self.sync),
        }

    def partitions(self):
        self.check()
        return copy.deepcopy(self.parts)

    def config(self):
        self.check()
        return self.running

    def pull(self, name, server, user, password, poll):
        host, port = server.split(":")
        ftp = ftplib.FTP()
        ftp.connect(host, int(port), timeout=10)
        ftp.login(user, password)
        buffer = io.BytesIO()
        ftp.retrbinary("RETR " + name, buffer.write)
        ftp.quit()
        poll()
        self.downloaded = buffer.getvalue()

    def stage(self, name, server, user, password, timeout, poll):
        self.calls.append("stage")
        self.pull(name, server, user, password, poll)
        if self.stage_lands:
            self.parts[1].update(image="FG600E-7.04-FW-build2702", build=2702)

    def restore(self, name, server, user, password, timeout, poll):
        self.calls.append("restore")
        self.pull(name, server, user, password, poll)
        self.parts[1].update(image="FG600E-7.04-FW-build2702", build=2702)
        self.rebooting = 2

    def set_next_reboot(self, which):
        self.calls.append("next " + which)
        self.next_reboot = which

    def reboot(self):
        self.calls.append("reboot")
        assert self.next_reboot == "secondary"
        self.rebooting = 2

    def traffic(self):
        self.check()
        return copy.deepcopy(self.traffic_state)

    def close(self):
        pass


class FakeFortiManager:
    def __init__(self):
        self.calls, self.polls, self.fail_retrieve = [], 0, False

    def device(self, adom, serial):
        self.calls.append("device " + serial)
        return {"name": "fw-cluster", "sn": serial}

    def preview(self, adom, device, version, build):
        self.calls.append("preview")
        return {"path": [f"{version}-{build}"]}

    def upgrade(self, adom, device, version, build):
        self.calls.append("upgrade")
        self.fgt.rebooting = 2
        return 77

    def task(self, task):
        self.polls += 1
        return {
            "percent": 100 if self.polls > 1 else 40,
            "state": "done" if self.polls > 1 else "running",
            "errors": 0,
        }

    def retrieve(self, adom, device):
        self.calls.append("retrieve")
        if self.fail_retrieve:
            raise DeviceError("FortiManager /dvm/cmd/reload/dev-list failed")

    def close(self):
        pass


@pytest.fixture
def staging(settings):
    settings.staging_address = "127.0.0.1"
    settings.staging_ports = range(42121, 42141)
    (settings.image_root / IMAGE).write_bytes(CONTENT)
    settings.http_targets["fmg"] = HTTPTarget(id="fmg", base_url="https://fmg.example.com")
    return {"name": IMAGE, "sha256": hashlib.sha256(CONTENT).hexdigest(), "version": "7.4.5", "build": 2702}


def run(settings, store, fgt, image, fmg=None, device="127.0.0.1", **options):
    request = FortigateUpgradeRequest(
        device=device, allowed_source_versions=["7.4.4"], image=image, **options
    )
    store.submit(request.model_dump(mode="json"), "device:" + device, kind="fortigate_upgrade")
    job = store.claim("w")
    clock = Clock()
    if fmg:
        fmg.fgt = fgt
    FortigateRunner(settings, store, job, "w", fgt=fgt, fmg=fmg, sleep=clock.sleep, clock=clock.clock).run()
    return store.get(job["id"])


def test_preload_stages_the_alternate_partition_over_one_time_ftp(settings, store, staging):
    fgt = FakeFortigate()
    job = run(settings, store, fgt, staging, stage_only=True)
    assert job["status"] == "succeeded", job["result"]
    assert fgt.downloaded == CONTENT and fgt.calls == ["stage", "console more"]
    assert job["result"]["staged"] == {"partition": "alternate", "build": 2702, "already": False}
    assert job["result"]["preloaded"] and not job["result"].get("mutations")
    events = [e["data"] for e in store.events(job["id"], 0, 1000) if e["step"] == "progress"]
    assert any(e["kind"] == "ftp_transfer" and e["percent"] == 100 for e in events)
    job = run(settings, store, fgt, staging, device="127.0.0.1", stage_only=True)
    assert "stage_skipped_verified" in [e["step"] for e in store.events(job["id"], 0, 100)]


def test_standalone_upgrade_boots_the_staged_partition_and_tolerates_rendering(settings, store, staging):
    fgt = FakeFortigate()
    job = run(settings, store, fgt, staging)
    assert job["status"] == "succeeded", job["result"]
    assert fgt.calls == ["stage", "next secondary", "reboot", "console more"]
    result = job["result"]
    assert result["boot_verified"]["build"] == 2702 and result["rollback"]["build"] == 2662
    assert result["config_comparison"]["equivalent"]
    assert {t["rule"] for t in result["config_comparison"]["tolerated"]} >= {
        "encrypted-secrets",
        "section-order",
    }


def test_cluster_upgrades_itself_from_the_primary(settings, store, staging):
    fgt = FakeFortigate(cluster=True)
    job = run(settings, store, fgt, staging)
    assert job["status"] == "succeeded", job["result"]
    assert fgt.calls == ["stage", "restore", "console more"] and fgt.next_reboot is None


def test_fortimanager_source_previews_and_runs_cluster_upgrades(settings, store, staging):
    fgt, fmg = FakeFortigate(cluster=True), FakeFortiManager()
    job = run(settings, store, fgt, staging, fmg=fmg, software_source="fortimanager", fortimanager="fmg")
    assert job["status"] == "succeeded", job["result"]
    assert fmg.calls == ["device FG6H0E01", "preview", "upgrade"] and "restore" not in fgt.calls
    assert job["result"]["fortimanager"]["task"] == 77
    tasks = [e["data"] for e in store.events(job["id"], 0, 1000) if e["step"] == "progress"]
    assert any(t["kind"] == "fortimanager_task" and t["percent"] == 40 for t in tasks)


def test_fortimanager_standalone_retrieves_and_warns_when_it_cannot(settings, store, staging):
    fgt, fmg = FakeFortigate(), FakeFortiManager()
    job = run(settings, store, fgt, staging, fmg=fmg, software_source="fortimanager", fortimanager="fmg")
    assert job["status"] == "succeeded" and fmg.calls[-1] == "retrieve" and "reboot" in fgt.calls
    fgt, fmg = FakeFortigate(), FakeFortiManager()
    fmg.fail_retrieve = True
    # Another unit, whose FTP connection comes from the address the staging server allows.
    job = run(
        settings,
        store,
        fgt,
        staging,
        fmg=fmg,
        device="192.0.2.70",
        staging_source_address="127.0.0.1",
        software_source="fortimanager",
        fortimanager="fmg",
    )
    assert job["status"] == "completed_with_warnings", job["result"]
    assert job["result"]["fortimanager"]["retrieve"].startswith("failed")


@pytest.mark.parametrize(
    "change, options, error",
    [
        (lambda f: setattr(f, "cluster", True) or f.state.update(serial="FG6H0E02"), {}, "cluster primary"),
        (
            lambda f: setattr(f, "cluster", True) or f.sync.update(FG6H0E02="out-of-sync"),
            {},
            "HA health is not OK",
        ),
        (lambda f: None, {"approved_models": ["FortiGate-100F"]}, "not approved"),
        (lambda f: f.state.update(version="7.2.8"), {}, "outside allowed_source_versions"),
        (lambda f: setattr(f, "stage_lands", False), {}, "does not hold build 2702"),
    ],
)
def test_failures_before_the_reboot_change_nothing(settings, store, staging, change, options, error):
    fgt = FakeFortigate()
    change(fgt)
    job = run(settings, store, fgt, staging, **options)
    assert job["status"] == "failed" and error in job["result"]["error"], job["result"]
    assert not {"reboot", "restore", "next secondary"} & set(fgt.calls) and not job["lock_held"]


def test_wrong_model_image_downgrade_and_missing_staging_address(settings, store, staging):
    other = {**staging, "name": "FGT_100F-v7.4.5.F-build2702-FORTINET.out"}
    job = run(settings, store, FakeFortigate(), other, stage_only=True)
    assert "is not a FortiGate-600E image" in job["result"]["error"]
    old = {**staging, "name": "FGT_600E-v7.4.3.F-build2573-FORTINET.out", "version": "7.4.3", "build": 2573}
    job = run(settings, store, FakeFortigate(), old, device="127.0.0.2", stage_only=True)
    assert "downgrades are not supported" in job["result"]["error"]
    settings.staging_address = None
    job = run(settings, store, FakeFortigate(), staging, device="127.0.0.3", stage_only=True)
    assert "NETOPS_STAGING_ADDRESS" in job["result"]["error"]


def test_cluster_that_does_not_resync_requires_recovery(settings, store, staging):
    fgt = FakeFortigate(cluster=True)
    fgt.after_sync = {"FG6H0E02": "out-of-sync"}
    job = run(settings, store, fgt, staging, cluster_timeout=600)
    assert job["status"] == "recovery_required" and "not verified before timeout" in job["result"]["error"]


def test_one_time_ftp_serves_one_file_to_one_address(tmp_path):
    image = tmp_path / IMAGE
    image.write_bytes(CONTENT)
    with OneShotFTP(image, "127.0.0.1", "127.0.0.1", range(42200, 42220), timeout=30) as server:
        host, port = server.address.split(":")
        ftp = ftplib.FTP()
        ftp.connect(host, int(port), timeout=10)
        with pytest.raises(ftplib.error_perm):
            ftp.login(server.user, "wrong")
        ftp.connect(host, int(port), timeout=10)
        ftp.login(server.user, server.password)
        assert ftp.size(IMAGE) == len(CONTENT)
        with pytest.raises(ftplib.error_perm):
            ftp.retrbinary("RETR other.out", lambda b: None)
        data = io.BytesIO()
        ftp.retrbinary("RETR " + IMAGE, data.write)
        assert data.getvalue() == CONTENT and server.completed.is_set() and server.sent == len(CONTENT)
        with pytest.raises(ftplib.error_perm):
            ftp.storbinary("STOR x.out", io.BytesIO(b"x"))
    with OneShotFTP(image, "192.0.2.99", "127.0.0.1", range(42200, 42220), timeout=30) as server:
        host, port = server.address.split(":")
        ftp = ftplib.FTP()
        with pytest.raises((EOFError, OSError, ftplib.Error)):
            ftp.connect(host, int(port), timeout=3)
            ftp.login(server.user, server.password)


class Shell:
    def __init__(self, outputs):
        self.outputs = outputs

    def execute(self, command, timeout=120, **kwargs):
        text = self.outputs[command]
        return {"stdout": text, "cli_error": False}


def test_client_parses_fortios_output():
    system = (
        "Version: FortiGate-600E v7.4.4,build2662,240514 (GA.F)\nSerial-Number: FG6H0E01\n"
        "Virtual domain configuration: disable\nCurrent HA mode: a-p, primary\nHostname: fw1\n"
    )
    ha = """HA Health Status: OK
Model: FortiGate-600E
Mode: HA A-P
Configuration Status:
    FG6H0E01(updated 2 seconds ago): in-sync
    FG6H0E02(updated 3 seconds ago): in-sync
Primary     : fw1             , FG6H0E01, HA cluster index = 0
Secondary   : fw2             , FG6H0E02, HA cluster index = 1
"""
    flash = """Partition  Image                                     TotalSize(KB)  Used(KB)  Use%  Active
1          FG600E-7.04-FW-build2662-240514          253871         112345    44%   Yes
2          FG600E-7.04-FW-build2702-240911          253871         109876    43%   No
3          ETDB-1.00000                              3368360        123456     4%   No
"""
    shell = Shell(
        {
            "get system status": system,
            "get system performance status": "CPU states: 1% user\nUptime: 10 days,  3 hours,  22 minutes\n",
            "get system ha status": ha,
            "diagnose sys flash list": flash,
            "get system interface physical": "== [onboard]\n\t==[port1]\n\t\tmode: static\n\t\tip: 10.0.0.1 255.255.255.0\n"
            "\t\tstatus: up\n\t\tspeed: 1000Mbps (Duplex: full)\n\t==[port2]\n\t\tmode: static\n\t\tstatus: down\n",
            "get vpn ipsec tunnel summary": "'to-branch' 203.0.113.10:0  selectors(total,up): 2/2  rx(pkt,err): 1/0  tx(pkt,err): 2/0\n"
            "'to-dc' 203.0.113.11:0  selectors(total,up): 1/0  rx(pkt,err): 0/0  tx(pkt,err): 0/0\n",
            "get router info bgp summary": "VRF 0 BGP router identifier 10.0.0.1, local AS number 65001\n"
            "Neighbor        V         AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd\n"
            "10.0.0.2        4      65002     123     125        5    0    0 01:02:03        12\n",
            "get router info ospf neighbor": "OSPF process 0, VRF 0:\nNeighbor ID     Pri   State           Dead Time   Address         Interface\n"
            "10.0.0.3          1   Full/DR         00:00:35    10.1.1.2        port2\n",
            "get router info routing-table all": "S*      0.0.0.0/0 [10/0] via 10.0.0.254, port1, [1/0]\n"
            "C       10.0.0.0/24 is directly connected, port1\nB       10.9.0.0/16 [20/0] via 10.0.0.2, port1, 01:02:03\n",
            "get system session status": "The total number of sessions for the current VDOM: 5000\n",
        }
    )
    fgt = Fortigate(None, None, None, None, None, ssh=shell)
    info = fgt.status()
    assert info["model"] == "FortiGate-600E" and info["version"] == "7.4.4" and info["build"] == 2662
    assert info["ha"] == "a-p" and info["uptime_seconds"] == 10 * 86400 + 3 * 3600 + 22 * 60
    cluster = fgt.ha()
    assert cluster["healthy"] and cluster["members"]["FG6H0E02"]["role"] == "secondary"
    assert cluster["sync"] == {"FG6H0E01": "in-sync", "FG6H0E02": "in-sync"}
    parts = fgt.partitions()
    assert [p["build"] for p in parts] == [2662, 2702] and parts[0]["active"] and parts[1]["train"] == (7, 4)
    traffic = fgt.traffic()
    assert traffic["interfaces"] == {"port1": "up", "port2": "down"}
    assert traffic["ipsec_tunnels"] == {"to-branch": "up", "to-dc": "down"}
    assert traffic["bgp_peers"] == {"default|10.0.0.2": "established"}
    assert traffic["ospf_neighbors"] == {"10.0.0.3|port2": "full"}
    assert traffic["routes"] == 3 and traffic["sessions"] == 5000 and traffic["gaps"] == []
    assert (
        status(system.replace("Current HA mode: a-p, primary", "Current HA mode: standalone"))["ha"]
        == "standalone"
    )
    with pytest.raises(DeviceError):
        ha_status("no ha here")
    with pytest.raises(DeviceError):
        partitions(flash.replace("Yes", "No"))


def test_fortios_config_comparison():
    policy = IosxeConfigPolicy()
    assert compare_configs(CONFIG, AFTER, policy)["equivalent"]
    swapped = AFTER.replace(
        '    edit 1\n        set name "allow-web"\n        set action accept\n    next\n', ""
    ).replace(
        "    next\nend\n",
        '    next\n    edit 1\n        set name "allow-web"\n        set action accept\n    next\nend\n',
        1,
    )
    assert not compare_configs(CONFIG, swapped, policy)["equivalent"]
    removed = compare_configs(CONFIG, AFTER.replace("    set admin-port 8443\n", ""), policy)
    assert removed["removed"] == ["config system global > set admin-port 8443"]
    cert = compare_configs(CONFIG, AFTER.replace("MIIBszCCAVmgAwIBAgIUa", "MIIBszCCAVmgAwIBAgIUb"), policy)
    assert cert["removed_count"] == 1 and "BEGIN CERTIFICATE" in cert["removed"][0]


def test_api_plans_queues_and_validates(settings, store, staging):
    settings.devices["eos1"] = Device(id="eos1", host="192.0.2.90", device_type="arista_eos")
    client = TestClient(create_app(settings), headers={"Authorization": "Bearer " + settings.token})
    defaults = {"allowed_source_versions": ["7.4.4"], "image": staging}
    body = {
        "name": "Change792",
        "defaults": {**defaults, "stage_only": True},
        "waves": [{"wave": 1, "devices": ["192.0.2.61", "192.0.2.62"]}],
    }
    batch = client.post("/api/v1/fortigate/upgrade-batches", json=body)
    assert batch.status_code == 202, batch.text
    assert batch.json()["kind"] == "fortigate_upgrade" and batch.json()["device_count"] == 2
    assert {j["queue"] for j in batch.json()["jobs"]} == {"upgrade"}
    single = client.post(
        "/api/v1/fortigate/jobs", json={**defaults, "device": "192.0.2.65", "queue": "priority"}
    )
    assert single.status_code == 202, single.text
    assert single.json()["queue"] == "priority"
    steps = client.post("/api/v1/fortigate/plan", json={**defaults, "device": "192.0.2.61"}).json()["steps"]
    assert steps[-1] == "validate_traffic" and "stage_alternate_partition_over_one_time_ftp" in steps
    assert client.post("/api/v1/fortigate/jobs", json={**defaults, "device": "eos1"}).status_code == 422
    bad = client.post(
        "/api/v1/fortigate/jobs",
        json={**defaults, "device": "192.0.2.63", "software_source": "fortimanager", "fortimanager": "nope"},
    )
    assert bad.status_code == 422
    with pytest.raises(ValueError, match="build"):
        FortigateUpgradeRequest(
            device="192.0.2.61", allowed_source_versions=["7.4.4"], image={**staging, "build": 2703}
        )
    settings.staging_address = None
    assert client.post("/api/v1/fortigate/jobs", json={**defaults, "device": "192.0.2.64"}).status_code == 422
    assert isinstance(FortigateBatch.model_validate(body).request_for("192.0.2.61"), FortigateUpgradeRequest)
