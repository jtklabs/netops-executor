import copy
import hashlib

import pytest
from conftest import Clock
from fastapi.testclient import TestClient
from test_iosxe import TRAFFIC, Shell, session

from netops_executor.api import create_app
from netops_executor.config import Device
from netops_executor.ios import Ios, members
from netops_executor.ios_engine import IosRunner
from netops_executor.ios_models import IosBatch, IosUpgradeRequest, version_token
from netops_executor.iosxe_config import normalized
from netops_executor.ssh import DeviceError

SOURCE, TARGET = "15.2(7)E3", "15.2(7)E10"
TAR = "c2960x-universalk9-tar.152-7.E10.tar"
URL = "http://images.example.com/" + TAR
CONTENT = b"catalyst 2960x tar bytes" * 1000
OLD_BOOT = "flash:/c2960x-universalk9-mz.152-7.E3/c2960x-universalk9-mz.152-7.E3.bin"
NEW_BOOT = "flash:/c2960x-universalk9-mz.152-7.E10/c2960x-universalk9-mz.152-7.E10.bin"

BEFORE = """Building configuration...

Current configuration : 1800 bytes
!
version 15.2
no service pad
service timestamps debug datetime msec
hostname access1
!
boot-start-marker
boot-end-marker
!
ip domain-name example.com
ip scp server enable
!
spanning-tree mode rapid-pvst
!
interface GigabitEthernet1/0/1
 switchport access vlan 10
 switchport mode access
 spanning-tree portfast
!
interface GigabitEthernet1/0/52
 switchport mode trunk
!
end
"""
AFTER = BEFORE.replace("ip domain-name example.com", "ip domain name example.com").replace(
    " switchport access vlan 10\n switchport mode access\n",
    " switchport mode access\n switchport access vlan 10\n",
)


class FakeStack:
    """The Ios client interface over a simulated two-member 2960-X stack."""

    def __init__(self, version=SOURCE, model="WS-C2960X-48FPD-L", count=2):
        self.models = {str(n): model for n in range(1, count + 1)}
        self.state = {"version": version, "uptime": 864000}
        self.ready = {n: "Ready" for n in self.models}
        self.boot = [OLD_BOOT] * count
        self.running = self.startup = BEFORE
        self.after_config = AFTER
        self.files, self.directories = {}, set()
        self.free = {n: 80_000_000 for n in self.models}
        self.traffic_state = copy.deepcopy(TRAFFIC)
        self.rebooting = 0
        self.lost_member = None
        self.copy_fails = False
        self.archive_error = None
        self.archive_sets_boot = True
        self.calls = []

    def check(self):
        if self.rebooting:
            self.rebooting -= 1
            if not self.rebooting:
                self.state.update(version=TARGET, uptime=90)
                self.running = self.after_config
                if self.lost_member:
                    self.ready[self.lost_member] = "Removed"
            raise DeviceError("SSH authentication or connection failed")

    def version(self):
        self.check()
        rows = {
            n: {"model": m, "version": self.state["version"], "mode": None} for n, m in self.models.items()
        }
        return {
            "version": self.state["version"],
            "members": rows,
            "serials": ["FOC1", "FOC2"],
            "uptime_seconds": self.state["uptime"],
            "image": self.boot[0],
        }

    def stack(self):
        self.check()
        return {
            n: {"role": "Master" if n == "1" else "Member", "mac": "0011.2233.445" + n, "state": s}
            for n, s in self.ready.items()
        }

    def config(self, which):
        self.check()
        return self.running if which == "running-config" else self.startup

    def unsaved(self):
        return normalized(self.running) != normalized(self.startup)

    def save(self):
        self.calls.append("write memory")
        self.startup = self.running

    def flash(self, member, name, active=False):
        self.check()
        data = self.files.get(name) if active else None
        return self.free[member], len(data) if data is not None else None

    def has_directory(self, name):
        return name in self.directories

    def verify(self, name, algorithm):
        self.calls.append(f"verify {algorithm} {name}")
        return hashlib.new(algorithm, self.files[name]).hexdigest()

    def upload(self, local, name, progress):
        data = local.read_bytes()
        progress(len(data), len(data))
        self.calls.append("upload " + name)
        self.files[name] = data

    def device_copy(self, url, name, timeout, progress):
        self.calls.append("copy " + url)
        if self.copy_fails:
            self.files[name] = b"partial"
            raise DeviceError("switch copy of " + name + " failed")
        self.files[name] = CONTENT

    def delete(self, name):
        self.calls.append("delete " + name)
        self.files.pop(name)

    def boot_paths(self):
        self.check()
        return list(self.boot)

    def archive(self, source, timeout, progress):
        self.calls.append("archive " + source)
        progress("examining image...")
        if self.archive_error:
            raise DeviceError(self.archive_error)
        if self.archive_sets_boot:
            self.boot = [NEW_BOOT] * len(self.models)
        self.directories.add("c2960x-universalk9-mz.152-7.E10")
        return "All software images installed."

    def reload(self, timeout):
        self.calls.append("reload")
        self.rebooting = 2
        return "Reload requested"

    def tech_support(self):
        return "show tech-support output"

    def traffic(self):
        self.check()
        return copy.deepcopy(self.traffic_state)

    def install_summary(self):
        raise AssertionError("classic IOS has no install summary")

    def close(self):
        pass


@pytest.fixture
def tar(settings):
    (settings.image_root / TAR).write_bytes(CONTENT)
    return {"name": TAR, "sha256": hashlib.sha256(CONTENT).hexdigest()}


def run(settings, store, switch, image, device="192.0.2.51", **options):
    request = IosUpgradeRequest(
        device=device, target_version=TARGET, allowed_source_versions=[SOURCE], image=image, **options
    )
    store.submit(request.model_dump(mode="json"), "device:" + device, kind="ios_upgrade")
    job = store.claim("w")
    clock = Clock()
    IosRunner(settings, store, job, "w", ios=switch, sleep=clock.sleep, clock=clock.clock).run()
    return store.get(job["id"])


def test_upgrade_copies_over_http_archives_reloads_and_validates(settings, store, tar):
    switch = FakeStack()
    switch.startup = BEFORE.replace("hostname access1", "hostname old")
    job = run(settings, store, switch, {**tar, "device_url": URL})
    assert job["status"] == "succeeded", job["result"]
    assert switch.calls == [
        "copy " + URL,
        "verify md5 " + TAR,
        "write memory",
        "archive flash:" + TAR,
        "delete " + TAR,
        "reload",
        "write memory",
    ]
    result = job["result"]
    assert result["software"]["source"] == "flash" and result["install"]["boot"] == [NEW_BOOT, NEW_BOOT]
    assert result["rollback"] == {"version": SOURCE, "boot": [OLD_BOOT, OLD_BOOT]}
    assert result["config_comparison"]["equivalent"] and switch.startup == AFTER
    assert {a["kind"] for a in result["artifacts"]} == {"config", "tech_support"}
    assert result["artifacts"][0]["path"].startswith("ios/")
    events = [e["data"] for e in store.events(job["id"], 0, 1000) if e["step"] == "progress"]
    assert any(e["kind"] == "archive" and e["status"] == "examining image..." for e in events)


def test_failed_switch_copy_falls_back_to_scp(settings, store, tar):
    switch = FakeStack()
    switch.copy_fails = True
    job = run(settings, store, switch, {**tar, "device_url": URL}, tech_support=False)
    assert job["status"] == "succeeded", job["result"]
    assert switch.calls[:4] == ["copy " + URL, "delete " + TAR, "upload " + TAR, "verify md5 " + TAR]


def test_small_master_flash_archives_straight_from_the_url(settings, store, tar):
    switch = FakeStack()
    switch.free["1"] = len(CONTENT) + 3_000_000 + 10
    job = run(settings, store, switch, {**tar, "device_url": URL}, tech_support=False)
    assert job["status"] == "succeeded", job["result"]
    assert switch.calls[:2] == ["archive " + URL, "reload"]
    assert job["result"]["software"]["source"] == "device_url"
    switch = FakeStack()
    switch.free["1"] = len(CONTENT) + 3_000_000 + 10
    job = run(settings, store, switch, tar, device="192.0.2.52", tech_support=False)
    assert job["status"] == "failed" and "insufficient flash" in job["result"]["error"]


def test_preload_copies_and_verifies_the_tar_only(settings, store, tar):
    switch = FakeStack()
    job = run(settings, store, switch, tar, stage_only=True)
    assert job["status"] == "succeeded", job["result"]
    assert switch.calls == ["upload " + TAR, "verify md5 " + TAR] and job["result"]["preloaded"]
    switch = FakeStack()
    switch.free["1"] = len(CONTENT) + 3_000_000 + 10
    job = run(settings, store, switch, {**tar, "device_url": URL}, device="192.0.2.52", stage_only=True)
    assert job["status"] == "failed" and "insufficient flash" in job["result"]["error"]


@pytest.mark.parametrize(
    "change, error",
    [
        (lambda s: s.models.update({"2": "WS-C3650-48PD"}), "2960-X or 2960-XR"),
        (lambda s: s.state.update(version="15.2(4)E10"), "outside allowed_source_versions"),
        (lambda s: s.ready.update({"2": "Provisioned"}), "member 2 is Provisioned"),
        (lambda s: s.directories.add("c2960x-universalk9-mz.152-7.E10"), "already exists"),
        (lambda s: s.free.update({"2": 1000}), "insufficient flash"),
        (lambda s: setattr(s, "running", BEFORE.replace("ip scp server enable\n", "")), "ip scp server"),
    ],
)
def test_failures_before_archive_change_nothing(settings, store, tar, change, error):
    switch = FakeStack()
    change(switch)
    switch.startup = switch.running
    job = run(settings, store, switch, tar, tech_support=False)
    assert job["status"] == "failed" and error in job["result"]["error"], job["result"]
    assert not any(c.startswith(("archive", "reload")) for c in switch.calls) and not job["lock_held"]


def test_archive_failures_and_lost_members_require_recovery(settings, store, tar):
    switch = FakeStack()
    switch.archive_error = "archive download-sw reported a failure: ERROR: Not enough space"
    job = run(settings, store, switch, tar, tech_support=False)
    assert job["status"] == "recovery_required" and "Not enough space" in job["result"]["error"]
    assert "reload" not in switch.calls
    switch = FakeStack()
    switch.archive_sets_boot = False
    job = run(settings, store, switch, tar, device="192.0.2.52", tech_support=False)
    assert job["status"] == "recovery_required" and "boot path does not name" in job["result"]["error"]
    assert "reload" not in switch.calls
    switch = FakeStack()
    switch.lost_member = "2"
    job = run(settings, store, switch, tar, device="192.0.2.53", tech_support=False, reboot_timeout=300)
    assert job["status"] == "recovery_required" and "member 2 is Removed" in job["result"]["error"]


def test_models_and_wrong_family_image():
    assert version_token("15.2(7)E10") == "152-7.E10" and version_token("15.2(4)E10a") == "152-4.E10a"
    image = {"name": "c2960x-universalk9-tar.152-7.E3.tar", "sha256": "0" * 64}
    with pytest.raises(ValueError, match="target release"):
        IosUpgradeRequest(
            device="192.0.2.51", target_version=TARGET, allowed_source_versions=[SOURCE], image=image
        )
    with pytest.raises(ValueError):
        IosUpgradeRequest(
            device="192.0.2.51", target_version="17.12.6", allowed_source_versions=[SOURCE], image=image
        )


def test_wrong_family_image_is_refused(settings, store):
    image = {"name": "c2960s-universalk9-tar.152-7.E10.tar", "sha256": "0" * 64}
    job = run(settings, store, FakeStack(), image, tech_support=False)
    assert job["status"] == "failed" and "not a Catalyst 2960-X image" in job["result"]["error"]


def test_client_parses_classic_ios_and_dialogues():
    version = """Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E3, RELEASE SOFTWARE (fc2)
access1 uptime is 2 weeks, 3 days, 4 hours, 5 minutes
System image file is "flash:/c2960x-universalk9-mz.152-7.E3/c2960x-universalk9-mz.152-7.E3.bin"
1 Virtual Ethernet interface
52 Gigabit Ethernet interfaces
System serial number            : FOC1111X1AA

Switch Ports Model                     SW Version            SW Image
------ ----- -----                     ----------            ----------
*    1 52    WS-C2960X-48FPD-L         15.2(7)E3             C2960X-UNIVERSALK9-M
     2 52    WS-C2960X-48FPD-L         15.2(7)E3             C2960X-UNIVERSALK9-M

Switch 02
---------
System serial number            : FOC2222X2BB
"""
    listing = (
        "Directory of flash:/\n\n    2  drwx         512   Mar 1 1993 00:10:12 +00:00  c2960x-universalk9-mz.152-7.E3\n"
        "    5  -rwx    37580800   Mar 1 1993 00:20:12 +00:00  "
        + TAR
        + "\n\n122185728 bytes total (61267456 bytes free)\n"
    )
    shell = Shell(
        {
            "show version": version,
            "show switch": "Switch/Stack Mac Address : 0011.2233.4455\n"
            "                                           H/W   Current\n"
            "Switch#  Role   Mac Address     Priority Version  State\n"
            "----------------------------------------------------------\n"
            "*1       Master 0011.2233.4455     15     4       Ready\n"
            " 2       Member 0011.2233.4466     14     4       Ready\n",
            "dir flash:": listing,
            "dir flash2:": "Directory of flash2:/\n\n122185728 bytes total (80000000 bytes free)\n",
            "show boot": "Switch 1\n--------\nBOOT path-list      : "
            + OLD_BOOT
            + "\nConfig file         : flash:/config.text\n"
            "Switch 2\n--------\nBOOT path-list      : " + OLD_BOOT + "\n",
        }
    )
    ios = Ios(None, None, None, None, None, ssh=shell)
    info = ios.version()
    assert info["version"] == SOURCE and info["serials"] == ["FOC1111X1AA", "FOC2222X2BB"]
    assert info["members"]["2"] == {"model": "WS-C2960X-48FPD-L", "version": SOURCE, "mode": None}
    assert info["image"] == OLD_BOOT and info["uptime_seconds"] == 2 * 604800 + 3 * 86400 + 4 * 3600 + 300
    assert ios.stack()["1"]["role"] == "Master"
    assert ios.flash("1", TAR, active=True) == (61267456, 37580800)
    assert ios.flash("2", TAR) == (80000000, None)
    assert ios.has_directory("c2960x-universalk9-mz.152-7.E3") and not ios.has_directory(
        "c2960x-universalk9-mz.152-7.E10"
    )
    assert ios.boot_paths() == [OLD_BOOT, OLD_BOOT]
    with pytest.raises(DeviceError):
        members("Switch Ports Model\n*    1 52    WS-C2960X-48FPD-L\n")
    ssh = session(["reload\n", "Proceed with reload? [confirm]", "\n"])
    Ios(None, None, None, None, None, ssh=ssh).reload(60)
    assert ssh.driver.written == ["reload\n", "\n"]
    ssh = session(["reload\n", "System configuration has been modified. Save? [yes/no]: "])
    with pytest.raises(DeviceError, match="unrecognized prompt"):
        Ios(None, None, None, None, None, ssh=ssh).reload(60)
    ssh = session(
        [
            "archive download-sw /imageonly /safe flash:x.tar\nexamining image...\n%Error opening flash:x.tar (No such file)\nsw1#"
        ]
    )
    with pytest.raises(DeviceError, match="reported a failure"):
        Ios(None, None, None, None, None, ssh=ssh).archive("flash:x.tar", 60, lambda line: None)
    ssh = session(
        [
            "archive download-sw /imageonly /safe flash:x.tar\nexamining image...\nAll software images installed.\nsw1#"
        ]
    )
    assert "installed" in Ios(None, None, None, None, None, ssh=ssh).archive(
        "flash:x.tar", 60, lambda line: None
    )


def test_api_plans_queues_and_checks_device_type(settings, store):
    settings.devices["xe1"] = Device(id="xe1", host="192.0.2.90", device_type="arista_eos")
    client = TestClient(create_app(settings), headers={"Authorization": "Bearer " + settings.token})
    defaults = {
        "target_version": TARGET,
        "allowed_source_versions": [SOURCE],
        "image": {"name": TAR, "sha256": "0" * 64, "device_url": URL},
    }
    body = {
        "name": "Change791",
        "defaults": defaults,
        "waves": [{"wave": 1, "devices": ["192.0.2.51", "192.0.2.52"]}],
    }
    batch = client.post("/api/v1/ios/upgrade-batches", json=body)
    assert batch.status_code == 202, batch.text
    assert batch.json()["kind"] == "ios_upgrade" and batch.json()["device_count"] == 2
    steps = client.post("/api/v1/ios/plan", json={**defaults, "device": "192.0.2.51"}).json()["steps"]
    assert steps.index("archive_download_sw") < steps.index("reload")
    assert client.post("/api/v1/ios/jobs", json={**defaults, "device": "xe1"}).status_code == 422
    assert (
        client.post("/api/v1/ios/jobs", json={**defaults, "device": "192.0.2.53"}).json()["kind"]
        == "ios_upgrade"
    )
    assert isinstance(IosBatch.model_validate(body).request_for("192.0.2.51"), IosUpgradeRequest)
