import copy
import hashlib
import json

import pytest
from conftest import Clock
from fastapi.testclient import TestClient

from netops_executor.api import create_app
from netops_executor.eos import Eos, flash_free, flash_size, image_name, normalized
from netops_executor.eos_engine import EosRunner, compare
from netops_executor.eos_models import EosBatch, EosUpgradeRequest, EosValidationPolicy
from netops_executor.execution_models import ValidationDecision
from netops_executor.ssh import DeviceError

TARGET, IMAGE = "4.32.2F", "EOS-4.32.2F.swi"
CONTENT = b"arista image bytes"
SHA512 = hashlib.sha512(CONTENT).hexdigest()

TRAFFIC = {
    "interfaces": {"Ethernet1": "connected", "Ethernet2": "connected", "Ethernet3": "notconnect"},
    "lldp": {"Ethernet1": "spine1|Ethernet7", "Ethernet2": "spine2|Ethernet7"},
    "bgp_peers": {"default|10.0.0.1": "established", "default|10.0.0.3": "established"},
    "ospf_neighbors": {},
    "port_channels": {"Port-Channel10|Ethernet49/1": "active", "Port-Channel10|Ethernet50/1": "active"},
    "routes": 120,
    "mac": 400,
    "arp": 60,
    "gaps": [],
}


class FakeSwitch:
    """The Eos client interface over a simulated switch."""

    def __init__(self, version="4.30.5M"):
        self.state = {"version": version, "boot": "EOS-4.30.5M.swi", "uptime": 864000}
        self.mlag_state = {
            "state": "active",
            "neg_status": "connected",
            "peer_link": "up",
            "local_interface": "up",
            "config_sanity": "consistent",
            "peer_address": "10.255.255.2",
        }
        self.config = "hostname leaf1\ninterface Ethernet1\n   description uplink\nend"
        self.dirty = False
        self.flash_files = {"EOS-4.30.5M.swi": b"old image"}
        self.free = 5_000_000_000
        self.traffic_state = copy.deepcopy(TRAFFIC)
        self.after_reboot = {}
        self.rebooting = 0
        self.boot_polls = 2
        self.cause = "Reload requested by the user."
        self.calls = []
        self.closed = 0

    def check(self):
        if self.rebooting:
            self.rebooting -= 1
            if not self.rebooting:
                self.state.update(version=TARGET, boot=IMAGE, uptime=40)
                self.traffic_state.update(copy.deepcopy(self.after_reboot))
            raise DeviceError("SSH authentication or connection failed")

    def version(self):
        self.check()
        return {
            "model": "DCS-7050SX3-48YC8",
            "version": self.state["version"],
            "serial": "JPE123",
            "mac": "00:1c:73:00:00:01",
            "uptime_seconds": self.state["uptime"],
            "boot_time": 1.0,
        }

    def boot_image(self):
        self.check()
        return self.state["boot"]

    def mlag(self):
        self.check()
        return dict(self.mlag_state)

    def unsaved(self):
        self.check()
        return self.dirty

    def running_config(self):
        self.check()
        return self.config

    def save(self):
        self.calls.append("write memory")
        self.dirty = False

    def flash(self, name):
        self.check()
        data = self.flash_files.get(name)
        return self.free, len(data) if data is not None else None

    def sha512(self, name):
        self.calls.append("verify " + name)
        return hashlib.sha512(self.flash_files[name]).hexdigest()

    def upload(self, local, name, progress):
        data = local.read_bytes()
        for done in (len(data) // 2, len(data)):
            progress(done, len(data))
        self.calls.append("upload " + name)
        self.flash_files[name] = data

    def install_reload(self, name, timeout):
        self.calls.append("install " + name)
        assert self.state["boot"] != name or self.state["version"] != TARGET
        self.rebooting = self.boot_polls
        raise DeviceError("network CLI session disconnected")

    def tech_support(self):
        return "show tech-support output"

    def reload_cause(self):
        return self.cause

    def traffic(self):
        self.check()
        return copy.deepcopy(self.traffic_state)

    def close(self):
        self.closed += 1


@pytest.fixture
def image_file(settings):
    (settings.image_root / IMAGE).write_bytes(CONTENT)
    return {"name": IMAGE, "sha256": hashlib.sha256(CONTENT).hexdigest()}


def submit(store, image, device="192.0.2.31", **options):
    request = EosUpgradeRequest(
        device=device, target_version=TARGET, allowed_source_versions=["4.30.5M"], image=image, **options
    )
    return store.submit(request.model_dump(mode="json"), "device:" + device, kind="eos_upgrade")


def work(settings, store, switch, peer=None):
    job = store.claim("w")
    clock = Clock()
    EosRunner(settings, store, job, "w", eos=switch, peer=peer, sleep=clock.sleep, clock=clock.clock).run()
    return store.get(job["id"])


def run(settings, store, switch, image, peer=None, **options):
    submit(store, image, **options)
    return work(settings, store, switch, peer)


def test_upgrade_copies_verifies_saves_installs_and_validates(settings, store, image_file):
    switch = FakeSwitch()
    switch.dirty = True
    job = run(settings, store, switch, image_file)
    assert job["status"] == "succeeded", job["result"]
    assert switch.calls == ["upload " + IMAGE, "verify " + IMAGE, "write memory", "install " + IMAGE]
    result = job["result"]
    assert result["software"] == {
        "image": IMAGE,
        "already_on_flash": False,
        "uploaded": True,
        "sha512_verified": True,
    }
    assert (
        result["boot_verified"]["version"] == TARGET and result["rollback"]["boot_image"] == "EOS-4.30.5M.swi"
    )
    assert {a["kind"] for a in result["artifacts"]} == {"config", "tech_support"}
    uploads = [e["data"] for e in store.events(job["id"], 0, 1000) if e["step"] == "progress"]
    assert any(u["kind"] == "upload" and u["percent"] == 100 for u in uploads)
    assert result["progress"]["percent"] == 100 and not job["lock_held"]


@pytest.mark.parametrize(
    "change, error",
    [
        (lambda s: s.mlag_state.update(state="inactive"), "MLAG state is inactive"),
        (lambda s: s.mlag_state.update(peer_link="down"), "MLAG peer link is down"),
        (lambda s: s.state.update(version="4.29.1F"), "outside allowed_source_versions"),
        (lambda s: setattr(s, "free", 1000), "insufficient flash space"),
        (lambda s: s.flash_files.update({IMAGE: b"tampered"}), "SHA-512 does not match"),
    ],
)
def test_failures_before_install_change_nothing(settings, store, image_file, change, error):
    switch = FakeSwitch()
    change(switch)
    job = run(settings, store, switch, image_file, tech_support=False)
    assert job["status"] == "failed" and error in job["result"]["error"]
    assert not any(c.startswith("install") for c in switch.calls) and not job["lock_held"]


def test_unhealthy_mlag_peer_blocks_and_peer_is_reserved(settings, store, image_file):
    switch, peer = FakeSwitch(), FakeSwitch()
    peer.mlag_state.update(neg_status="inactive")
    job = run(settings, store, switch, image_file, peer=peer, mlag_peer="192.0.2.32", tech_support=False)
    assert job["status"] == "failed" and "MLAG peer 192.0.2.32" in job["result"]["error"]
    reserved = next(e for e in store.events(job["id"], 0, 100) if e["step"] == "resources_reserved")["data"][
        "keys"
    ]
    assert "device:192.0.2.32" in reserved and "endpoint:192.0.2.32" in reserved


def test_configuration_change_after_baseline_stops_the_install(settings, store, image_file):
    switch = FakeSwitch()
    original = switch.save

    def save():
        original()
        switch.config += "\ninterface Ethernet9"

    switch.dirty, switch.save = True, save
    job = run(settings, store, switch, image_file, tech_support=False)
    assert job["status"] == "failed", job["result"]
    assert "configuration changed since precheck" in job["result"]["error"]
    assert not any(c.startswith("install") for c in switch.calls)


def test_unrestored_bgp_opens_gate_and_accept_continues_without_reinstall(settings, store, image_file):
    switch = FakeSwitch()
    switch.after_reboot = {"bgp_peers": {"default|10.0.0.1": "established", "default|10.0.0.3": "active"}}
    job = run(settings, store, switch, image_file, tech_support=False)
    assert job["status"] == "needs_review" and job["lock_held"]
    gate = job["validation_gates"][-1]
    assert gate["phase"] == "validate_traffic"
    assert "bgp_peers not restored: default|10.0.0.3" in gate["findings"]["critical"]
    store.decide(
        job["id"],
        ValidationDecision(
            gate_id=gate["id"],
            validation_revision=gate["revision"],
            operator="jason",
            reason="Peer is in maintenance",
        ),
    )
    job = work(settings, store, switch)
    assert job["status"] == "completed_with_warnings", job["result"]
    assert switch.calls.count("install " + IMAGE) == 1


def test_lost_reboot_requires_recovery(settings, store, image_file):
    switch = FakeSwitch()
    switch.boot_polls = 10**6
    job = run(settings, store, switch, image_file, tech_support=False, reboot_timeout=300)
    assert job["status"] == "recovery_required" and job["lock_held"]


def test_preload_copies_only_and_skips_mlag_and_backups(settings, store, image_file):
    switch = FakeSwitch()
    switch.mlag_state.update(state="inactive")
    job = run(settings, store, switch, image_file, stage_only=True)
    assert job["status"] == "succeeded", job["result"]
    assert switch.calls == ["upload " + IMAGE, "verify " + IMAGE]
    assert job["result"]["preloaded"] and "artifacts" not in job["result"]


def test_preloaded_image_is_verified_not_recopied_and_on_target_only_validates(settings, store, image_file):
    switch = FakeSwitch()
    switch.flash_files[IMAGE] = CONTENT
    job = run(settings, store, switch, image_file, tech_support=False)
    assert job["status"] == "succeeded", job["result"]
    assert "upload " + IMAGE not in switch.calls and job["result"]["software"]["already_on_flash"]
    calls = len(switch.calls)
    job = run(settings, store, switch, image_file)
    assert job["status"] == "succeeded" and job["result"]["already_on_target"]
    assert len(switch.calls) == calls


def test_target_running_with_wrong_boot_config_is_refused(settings, store, image_file):
    switch = FakeSwitch(version=TARGET)
    job = run(settings, store, switch, image_file)
    assert job["status"] == "failed" and "boot-config points at" in job["result"]["error"]


def test_compare_lldp_counts_and_warning_mode():
    current = copy.deepcopy(TRAFFIC)
    current.update(lldp={"Ethernet1": "spine1|Ethernet7"}, routes=100, mac=100)
    critical, findings, metrics = compare(TRAFFIC, current, EosValidationPolicy(min_mac_percent=50))
    assert "lldp not restored: Ethernet2" in critical
    assert any("mac count 100" in c for c in critical) and metrics["routes_percent"] == 83.3
    critical, findings, _ = compare(
        TRAFFIC, current, EosValidationPolicy(restore_required=False, min_route_percent=None)
    )
    assert critical == [] and findings[0]["category"] == "lldp"


class Shell:
    """NetworkSSH.execute replaced with canned EOS output."""

    def __init__(self, outputs):
        self.outputs, self.commands = outputs, []

    def execute(self, command, timeout=120, *, enable=False, mode="exec"):
        self.commands.append(command)
        output = self.outputs[command]
        text = output if isinstance(output, str) else json.dumps(output)
        return {"stdout": text, "cli_error": text.startswith("% "), "exit_code": None}

    def close(self):
        pass


def test_client_parses_eos_json_and_text():
    shell = Shell(
        {
            "show version | json": {
                "modelName": "DCS-7280SR-48C6",
                "version": "4.30.5M",
                "serialNumber": "JPE1",
                "systemMacAddress": "00:1c:73:aa:bb:cc",
                "uptime": 1234.5,
                "bootupTimestamp": 1700000000.0,
            },
            "show boot-config | json": {"softwareImage": "flash:/EOS-4.30.5M.swi", "consoleSpeed": 9600},
            "show mlag | json": {
                "state": "active",
                "negStatus": "connected",
                "peerLinkStatus": "up",
                "configSanity": "consistent",
            },
            "show interfaces status | json": {
                "interfaceStatuses": {"Ethernet1": {"linkStatus": "connected"}}
            },
            "show lldp neighbors | json": {
                "lldpNeighbors": [
                    {"port": "Ethernet1", "neighborDevice": "spine1", "neighborPort": "Ethernet7", "ttl": 120}
                ]
            },
            "show ip bgp summary vrf all | json": {
                "vrfs": {"default": {"peers": {"10.0.0.1": {"peerState": "Established"}}}}
            },
            "show ip ospf neighbor vrf all | json": {
                "vrfs": {
                    "default": {
                        "instList": {
                            "1": {
                                "ospfNeighborEntries": [
                                    {
                                        "routerId": "1.1.1.1",
                                        "interfaceName": "Ethernet2",
                                        "adjacencyState": "full",
                                    }
                                ]
                            }
                        }
                    }
                }
            },
            "show port-channel | json": {
                "portChannels": {
                    "Port-Channel10": {
                        "activePorts": {"Ethernet49/1": {}},
                        "inactivePorts": {"Ethernet50/1": {}},
                    }
                }
            },
            "show ip route vrf all summary | json": {
                "vrfs": {"default": {"totalRoutes": 25}, "mgmt": {"totalRoutes": 3}}
            },
            "show mac address-table | json": {"unicastTable": {"tableEntries": [{}, {}]}},
            "show ip arp vrf all | json": "% Invalid input",
            "show running-config diffs": "",
            "dir flash:": "Directory of flash:/\n\n       -rwx  1012345678  Oct 1 10:00  EOS-4.30.5M.swi\n\n3938504704 bytes total (2848504704 bytes free)\n",
            "verify /sha512 flash:EOS-4.30.5M.swi": "verify /sha512 (flash:EOS-4.30.5M.swi) = " + "ab" * 64,
            "write memory": "Copy completed successfully.",
            "show reload cause | json": {"resetCauses": [{"description": "Reload requested by the user."}]},
        }
    )
    eos = Eos(None, None, None, None, None, ssh=shell)
    assert eos.version()["uptime_seconds"] == 1234 and eos.boot_image() == "EOS-4.30.5M.swi"
    assert eos.mlag()["peer_link"] == "up" and eos.unsaved() is False
    assert eos.flash("EOS-4.30.5M.swi") == (2848504704, 1012345678)
    assert eos.flash("EOS-4.32.2F.swi")[1] is None
    assert eos.sha512("EOS-4.30.5M.swi") == "ab" * 64
    eos.save()
    assert "Reload requested" in eos.reload_cause()
    traffic = eos.traffic()
    assert traffic["port_channels"] == {
        "Port-Channel10|Ethernet49/1": "active",
        "Port-Channel10|Ethernet50/1": "inactive",
    }
    assert traffic["ospf_neighbors"] == {"default|1|1.1.1.1|Ethernet2": "full"}
    assert traffic["routes"] == 28 and traffic["mac"] == 2 and traffic["gaps"] == ["arp"]
    assert (
        image_name("flash:EOS.swi") == "EOS.swi"
        and normalized("! device: x\nhostname a\n!! keep") == "hostname a\n!! keep"
    )
    with pytest.raises(DeviceError):
        flash_free("no summary")
    assert flash_size("", "x.swi") is None


def test_batch_api_queues_eos_waves_and_validates_peers(settings, store):
    client = TestClient(create_app(settings), headers={"Authorization": "Bearer " + settings.token})
    image = {"name": IMAGE, "sha256": "0" * 64}
    body = {
        "name": "Change789",
        "defaults": {"target_version": TARGET, "allowed_source_versions": ["4.30.5M"], "image": image},
        "overrides": {"192.0.2.31": {"mlag_peer": "192.0.2.32"}},
        "waves": [
            {"wave": 1, "devices": ["192.0.2.31"]},
            {"wave": 2, "upgrade_at_a_time": 10, "devices": ["192.0.2.32", "192.0.2.33"]},
        ],
    }
    response = client.post("/api/v1/eos/upgrade-batches", json=body)
    assert response.status_code == 202, response.text
    batch = response.json()
    assert batch["kind"] == "eos_upgrade" and batch["device_count"] == 3
    assert [j["device"] for j in batch["jobs"] if j["wave"] == 1] == ["192.0.2.31"]
    assert (
        client.post("/api/v1/eos/plan", json={**body["defaults"], "device": "192.0.2.31"}).json()["steps"][-1]
        == "validate_traffic"
    )
    bad = client.post(
        "/api/v1/eos/jobs", json={**body["defaults"], "device": "192.0.2.31", "mlag_peer": "192.0.2.31"}
    )
    assert bad.status_code == 422
    with pytest.raises(ValueError):
        EosBatch.model_validate({**body, "overrides": {"192.0.2.99": {}}})
