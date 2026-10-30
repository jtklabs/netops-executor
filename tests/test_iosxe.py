import copy
import hashlib
import re
import stat

import pytest
from conftest import Clock
from fastapi.testclient import TestClient

from netops_executor.api import create_app
from netops_executor.config import Device
from netops_executor.execution_models import ValidationDecision
from netops_executor.iosxe import Iosxe, boot_ok, install_summary, listing, members, stack, uptime_seconds
from netops_executor.iosxe_config import compare, normalized
from netops_executor.iosxe_engine import IosxeRunner, masked
from netops_executor.iosxe_models import IosxeBatch, IosxeConfigPolicy, IosxeUpgradeRequest
from netops_executor.network_ssh import NetworkSSH
from netops_executor.ssh import DeviceError

SOURCE, TARGET = "17.09.05", "17.12.6"
IMAGE = "cat9k_iosxe.17.12.06.SPA.bin"
CONTENT = b"catalyst image bytes"

BEFORE = """Building configuration...

Current configuration : 2400 bytes
!
! Last configuration change at 01:00:00 UTC Mon Oct 1 2026
!
version 17.9
service timestamps debug datetime msec
service password-encryption
hostname sw1
!
boot-start-marker
boot system flash:packages.conf
boot-end-marker
!
ip domain-name example.com
no ip domain-lookup
ip scp server enable
!
access-list 10 permit 10.0.0.0 0.255.255.255
access-list 10 deny any
!
ip access-list extended MGMT
 permit tcp 10.0.0.0 0.255.255.255 any eq 22
 deny ip any any
!
class-map match-any system-cpp-police-data
  description Data
policy-map system-cpp-policy
!
snmp-server community s3cret RO
!
interface GigabitEthernet1/0/1
 description uplink
 switchport mode trunk
 channel-group 1 mode active
!
interface Vlan10
 ip address 10.1.1.1 255.255.255.0
!
banner motd ^C
Authorized access only
^C
!
end
"""
# The same configuration as a newer release renders it.
AFTER = """Building configuration...

Current configuration : 2900 bytes
!
version 17.12
hostname sw1
service password-encryption
service timestamps debug datetime msec
service call-home
!
boot-start-marker
boot system flash:packages.conf
boot-end-marker
!
ip domain name example.com
no ip domain lookup
ip scp server enable
!
ip access-list standard 10
 10 permit 10.0.0.0 0.255.255.255
 20 deny any
ip access-list extended MGMT
 10 permit tcp 10.0.0.0 0.255.255.255 any eq 22
 20 deny ip any any
!
class-map match-any system-cpp-police-data
  description Data and control
class-map match-any system-cpp-police-ios-routing
  description Routing control
policy-map system-cpp-policy
!
snmp-server community s3cret RO
!
interface Vlan10
 ip address 10.1.1.1 255.255.255.0
!
interface GigabitEthernet1/0/1
 switchport mode trunk
 description uplink
 channel-group 1 mode active
!
interface AppGigabitEthernet1/0/1
!
call-home
 contact-email-addr sch-smart-licensing@cisco.com
 profile "CiscoTAC-1"
  active
banner motd ^C
Authorized access only
^C
end
"""
TRAFFIC = {
    "interfaces": {"GigabitEthernet1/0/1": "up/up", "Vlan10": "up/up", "GigabitEthernet1/0/2": "down/down"},
    "cdp": {"Gi1/0/1": "core1|Te1/1/1"},
    "lldp": {},
    "port_channels": {"Po1|Gi1/0/1": "bundled", "Po1|Gi2/0/1": "bundled"},
    "bgp_peers": {},
    "ospf_neighbors": {"10.0.0.2|Vlan10": "full"},
    "hsrp": {"Vl10|10": "active"},
    "routes": 40,
    "mac": 300,
    "arp": 50,
    "access_sessions": 120,
    "gaps": [],
}


class FakeSwitch:
    """The Iosxe client interface over a simulated two-member C9300 stack."""

    def __init__(self, version=SOURCE, model="C9300-48P", count=2, mode="INSTALL"):
        self.models = {str(n): model for n in range(1, count + 1)}
        self.state = {"version": version, "mode": mode, "uptime": 864000}
        self.ready = {n: "Ready" for n in self.models}
        self.summary = {"committed": {n: version + ".0.1" for n in self.models}, "pending": False}
        self.summary.update(inactive=False, abort_timer=False)
        self.running = BEFORE
        self.startup = BEFORE
        self.after_config = AFTER
        self.files = {n: {} for n in self.models}
        self.free = 10_000_000_000
        self.traffic_state = copy.deepcopy(TRAFFIC)
        self.after_reboot = {}
        self.rebooting = 0
        self.boot_polls = 2
        self.lost_member = None
        self.install_output = None
        self.copy_fails = False
        self.calls = []

    def check(self):
        if self.rebooting:
            self.rebooting -= 1
            if not self.rebooting:
                self.state.update(version=TARGET, mode="INSTALL", uptime=120)
                self.summary.update(committed={n: "17.12.06.0.2" for n in self.models}, pending=False)
                self.running = self.after_config
                self.traffic_state.update(copy.deepcopy(self.after_reboot))
                if self.lost_member:
                    self.ready[self.lost_member] = "Initializing"
            raise DeviceError("SSH authentication or connection failed")

    def version(self):
        self.check()
        rows = {
            n: {"model": m, "version": self.state["version"], "mode": self.state["mode"]}
            for n, m in self.models.items()
        }
        return {
            "version": self.state["version"],
            "members": rows,
            "serials": ["FOC1", "FOC2"],
            "uptime_seconds": self.state["uptime"],
        }

    def stack(self):
        self.check()
        return {
            n: {"role": "Active" if n == "1" else "Standby", "mac": "0011.2233.445" + n, "state": s}
            for n, s in self.ready.items()
        }

    def install_summary(self):
        self.check()
        return copy.deepcopy(self.summary)

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
        data = self.files[member].get(name)
        return self.free, len(data) if data is not None else None

    def verify(self, name, algorithm):
        self.calls.append(f"verify {algorithm} {name}")
        return hashlib.new(algorithm, self.files["1"][name]).hexdigest()

    def upload(self, local, name, progress):
        data = local.read_bytes()
        for done in (len(data) // 2, len(data)):
            progress(done, len(data))
        self.calls.append("upload " + name)
        self.files["1"][name] = data

    def device_copy(self, url, name, timeout, progress):
        self.calls.append("copy " + url)
        if self.copy_fails:
            self.files["1"][name] = b"partial"
            raise DeviceError("switch copy of " + name + " failed")
        self.files["1"][name] = CONTENT

    def delete(self, name):
        self.calls.append("delete " + name)
        self.files["1"].pop(name)

    def remove_inactive(self, timeout, progress):
        self.calls.append("remove inactive")
        self.summary["inactive"] = False
        for files in self.files.values():
            files.clear()

    def configure_boot(self):
        self.calls.append("boot")
        self.running = self.running.replace(
            "boot-start-marker\n", "boot-start-marker\nboot system flash:packages.conf\n"
        )

    def install(self, name, timeout, progress):
        self.calls.append("install " + name)
        progress("install_add_activate_commit: Activating PACKAGE")
        if self.install_output:
            raise DeviceError(self.install_output)
        self.rebooting = self.boot_polls
        return "SUCCESS: install_add_activate_commit"

    def tech_support(self):
        return "show tech-support output"

    def traffic(self):
        self.check()
        return copy.deepcopy(self.traffic_state)

    def close(self):
        pass


@pytest.fixture
def image_file(settings):
    (settings.image_root / IMAGE).write_bytes(CONTENT)
    return {"name": IMAGE, "sha256": hashlib.sha256(CONTENT).hexdigest()}


def submit(store, image, device="192.0.2.41", **options):
    request = IosxeUpgradeRequest(
        device=device, target_version=TARGET, allowed_source_versions=["17.9.5"], image=image, **options
    )
    return store.submit(request.model_dump(mode="json"), "device:" + device, kind="iosxe_upgrade")


def work(settings, store, switch):
    job = store.claim("w")
    clock = Clock()
    IosxeRunner(settings, store, job, "w", ios=switch, sleep=clock.sleep, clock=clock.clock).run()
    return store.get(job["id"])


def run(settings, store, switch, image, **options):
    submit(store, image, **options)
    return work(settings, store, switch)


def test_upgrade_tolerates_release_rendering_and_saves_new_syntax(settings, store, image_file):
    switch = FakeSwitch()
    switch.startup = BEFORE.replace("hostname sw1\n", "hostname sw1-old\n")
    job = run(settings, store, switch, image_file)
    assert job["status"] == "succeeded", job["result"]
    assert switch.calls == [
        "upload " + IMAGE,
        "verify sha512 " + IMAGE,
        "write memory",
        "install " + IMAGE,
        "write memory",
    ]
    result = job["result"]
    comparison = result["config_comparison"]
    assert comparison["equivalent"] and not comparison["removed"]
    rules = {t["rule"] for t in comparison["tolerated"]}
    assert {"ip-domain-spelling", "acl-sequence-numbers", "smart-licensing-call-home"} <= rules
    assert {"control-plane-policy-classes", "app-hosting-interfaces", "section-order"} <= rules
    assert result["boot_verified"]["version"] == TARGET and result["rollback"] == {
        "version": SOURCE,
        "mode": "INSTALL",
    }
    assert result["post_save"] == {"saved": True} and switch.startup == AFTER
    assert {a["kind"] for a in result["artifacts"]} == {"config", "tech_support"}
    events = [e for e in store.events(job["id"], 0, 1000) if e["step"] == "progress"]
    assert any(e["data"]["kind"] == "upload" and e["data"]["percent"] == 100 for e in events)
    assert any(e["data"]["kind"] == "install" and "Activating" in e["data"]["status"] for e in events)
    assert result["progress"]["percent"] == 100 and not job["lock_held"]


def test_removed_lines_warn_with_masked_secrets_and_keep_startup(settings, store, image_file):
    switch = FakeSwitch()
    switch.after_config = AFTER.replace("snmp-server community s3cret RO\n", "").replace(
        " description uplink\n", ""
    )
    job = run(settings, store, switch, image_file, tech_support=False)
    assert job["status"] == "completed_with_warnings", job["result"]
    result = job["result"]
    finding = next(f for f in result["validation_differences"] if f["category"] == "config")
    assert finding["change"] == "removed"
    assert "snmp-server community <redacted> RO" in finding["objects"]
    assert "interface GigabitEthernet1/0/1 > description uplink" in finding["objects"]
    assert "s3cret" not in str(result)
    assert result["post_save"]["saved"] is False and switch.calls.count("write memory") == 0
    private = next(a for a in result["artifacts"] if a["kind"] == "config_differences")
    path = settings.backup_root / private["path"]
    assert "- snmp-server community s3cret RO" in path.read_text()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_removed_lines_marked_critical_open_a_gate_and_accept_continues(settings, store, image_file):
    switch = FakeSwitch()
    switch.after_config = AFTER.replace("ip scp server enable\n", "")
    job = run(settings, store, switch, image_file, tech_support=False, config_policy={"removed": "critical"})
    assert job["status"] == "needs_review" and job["lock_held"]
    gate = job["validation_gates"][-1]
    assert gate["phase"] == "validate_system"
    assert "1 configuration line(s) removed" in gate["findings"]["critical"][0]
    store.decide(
        job["id"],
        ValidationDecision(
            gate_id=gate["id"],
            validation_revision=gate["revision"],
            operator="jason",
            reason="Expected in 17.12",
        ),
    )
    job = work(settings, store, switch)
    assert job["status"] == "completed_with_warnings", job["result"]
    assert switch.calls.count("install " + IMAGE) == 1


@pytest.mark.parametrize(
    "change, options, error",
    [
        (lambda s: s.state.update(mode="BUNDLE"), {}, "BUNDLE mode"),
        (lambda s: s.state.update(version="17.06.01"), {}, "outside allowed_source_versions"),
        (lambda s: s.ready.update({"2": "Provisioned"}), {}, "member 2 is Provisioned"),
        (lambda s: s.summary.update(pending=True), {}, "uncommitted changes"),
        (lambda s: s.summary.update(committed={"1": SOURCE}), {}, "committed image cannot be confirmed"),
        (lambda s: s.models.update({"2": "C9200-48P"}), {}, "one supported family"),
        (lambda s: setattr(s, "free", 1000), {"remove_inactive": False}, "insufficient flash"),
        (lambda s: s.summary.update(inactive=True), {"remove_inactive": False}, "inactive install packages"),
        (lambda s: None, {"approved_models": ["C9300-24P"]}, "not approved"),
        (lambda s: setattr(s, "running", BEFORE.replace("ip scp server enable\n", "")), {}, "ip scp server"),
    ],
)
def test_failures_before_install_change_nothing(settings, store, image_file, change, options, error):
    switch = FakeSwitch()
    switch.startup = switch.running = BEFORE
    change(switch)
    switch.startup = switch.running
    job = run(settings, store, switch, image_file, tech_support=False, **options)
    assert job["status"] == "failed" and error in job["result"]["error"], job["result"]
    assert not any(c.startswith(("install", "boot")) for c in switch.calls) and not job["lock_held"]


def test_wrong_family_image_and_known_bad_paths_are_refused(settings, store, image_file):
    cat3k = {"name": "cat3k_caa-universalk9.17.12.06.SPA.bin", "sha256": image_file["sha256"]}
    job = run(settings, store, FakeSwitch(), cat3k, tech_support=False)
    assert "is not a C9300 install image" in job["result"]["error"]
    bug = {"name": "cisco9k_iosxe.17.18.03.SPA.bin", "sha256": image_file["sha256"]}
    request = IosxeUpgradeRequest(
        device="192.0.2.42", target_version="17.18.3", allowed_source_versions=["17.18.1"], image=bug
    )
    store.submit(request.model_dump(mode="json"), "device:192.0.2.42", kind="iosxe_upgrade")
    job = work(settings, store, FakeSwitch(version="17.18.01", model="C9350-48P"))
    assert "CSCwt90927" in job["result"]["error"]
    old = {"name": "cat3k_caa-universalk9.16.12.14.SPA.bin", "sha256": image_file["sha256"]}
    request = IosxeUpgradeRequest(
        device="192.0.2.43", target_version="16.12.14", allowed_source_versions=["16.6.4"], image=old
    )
    store.submit(request.model_dump(mode="json"), "device:192.0.2.43", kind="iosxe_upgrade")
    job = work(settings, store, FakeSwitch(version="16.06.04", model="WS-C3650-48PD"))
    assert "one-shot install floor" in job["result"]["error"]
    with pytest.raises(ValueError, match="filename release"):
        IosxeUpgradeRequest(
            device="192.0.2.41", target_version="17.12.5", allowed_source_versions=[SOURCE], image=image_file
        )


def test_remove_inactive_runs_before_the_copy(settings, store, image_file):
    switch = FakeSwitch()
    switch.summary["inactive"] = True
    switch.files["1"][IMAGE] = CONTENT  # Preloaded, but removal deletes unused .bin files.
    job = run(settings, store, switch, image_file, tech_support=False)
    assert job["status"] == "succeeded", job["result"]
    assert switch.calls[:3] == ["remove inactive", "upload " + IMAGE, "verify sha512 " + IMAGE]


def test_preload_copies_and_verifies_only(settings, store, image_file):
    switch = FakeSwitch(mode="BUNDLE")
    job = run(settings, store, switch, image_file, stage_only=True)
    assert job["status"] == "succeeded", job["result"]
    assert switch.calls == ["upload " + IMAGE, "verify sha512 " + IMAGE]
    assert job["result"]["preloaded"] and "artifacts" not in job["result"]


def test_device_copy_failure_removes_partial_file_and_pushes_over_scp(settings, store, image_file):
    switch = FakeSwitch()
    switch.copy_fails = True
    image = {**image_file, "device_url": "http://images.example.com/" + IMAGE}
    job = run(settings, store, switch, image, stage_only=True)
    assert job["status"] == "succeeded", job["result"]
    assert switch.calls[:3] == [
        "copy http://images.example.com/" + IMAGE,
        "delete " + IMAGE,
        "upload " + IMAGE,
    ]
    switch = FakeSwitch()
    job = run(
        settings,
        store,
        switch,
        {**image, "md5": hashlib.md5(CONTENT).hexdigest(), "verify": "md5"},
        stage_only=True,
    )
    assert switch.calls == ["copy http://images.example.com/" + IMAGE, "verify md5 " + IMAGE]


def test_boot_variable_is_set_to_packages_conf_before_install(settings, store, image_file):
    switch = FakeSwitch()
    switch.running = switch.startup = BEFORE.replace("boot system flash:packages.conf\n", "")
    job = run(settings, store, switch, image_file, tech_support=False)
    assert job["status"] == "succeeded", job["result"]
    assert switch.calls.index("boot") < switch.calls.index("install " + IMAGE)
    assert job["result"]["boot_changed"]


def test_configuration_change_after_baseline_stops_the_install(settings, store, image_file):
    switch = FakeSwitch()
    original = switch.verify

    def verify(name, algorithm):
        switch.running += "interface Vlan99\n"
        switch.startup = switch.running
        return original(name, algorithm)

    switch.verify = verify
    job = run(settings, store, switch, image_file, tech_support=False)
    assert job["status"] == "failed" and "configuration changed since precheck" in job["result"]["error"]


def test_installer_failure_and_missing_member_require_recovery(settings, store, image_file):
    switch = FakeSwitch()
    switch.install_output = "install add reported a failure: FAILED: install_add_activate_commit"
    job = run(settings, store, switch, image_file, tech_support=False)
    assert job["status"] == "recovery_required" and job["lock_held"]
    switch = FakeSwitch()
    switch.lost_member = "2"
    job = run(
        settings, store, switch, image_file, device="192.0.2.44", tech_support=False, reboot_timeout=300
    )
    assert job["status"] == "recovery_required"
    assert "member 2 is Initializing" in job["result"]["error"]


def test_unrestored_port_channel_member_fails_traffic_validation(settings, store, image_file):
    switch = FakeSwitch()
    switch.after_reboot = {
        "port_channels": {"Po1|Gi1/0/1": "bundled", "Po1|Gi2/0/1": "s"},
        "hsrp": {"Vl10|10": "standby"},
    }
    job = run(settings, store, switch, image_file, tech_support=False)
    assert job["status"] == "needs_review"
    gate = job["validation_gates"][-1]
    assert gate["phase"] == "validate_traffic"
    assert "port_channels not restored: Po1|Gi2/0/1" in gate["findings"]["critical"]
    assert {"category": "hsrp", "change": "state changed", "objects": ["Vl10|10"]} in gate["findings"][
        "differences"
    ]


def test_config_comparison_rules():
    assert compare(BEFORE, AFTER)["equivalent"]
    strict = compare(BEFORE, AFTER, IosxeConfigPolicy(builtin_rules=False))
    assert not strict["equivalent"] and "ip domain-name example.com" in strict["removed"]
    # Order still matters inside access lists and policy maps.
    swapped = AFTER.replace(
        " 10 permit tcp 10.0.0.0 0.255.255.255 any eq 22\n 20 deny ip any any\n",
        " 10 deny ip any any\n 20 permit tcp 10.0.0.0 0.255.255.255 any eq 22\n",
    )
    result = compare(BEFORE, swapped)
    assert not result["equivalent"]
    assert "ip access-list extended MGMT > deny ip any any" in result["added"] + result["removed"]
    site = AFTER.replace("snmp-server community s3cret RO", "snmp-server community s3cret ro")
    assert not compare(BEFORE, site)["equivalent"]
    policy = IosxeConfigPolicy(
        rewrite=[
            {"name": "community-case", "line": r"^(snmp-server community \S+) ro$", "replace": r"\1 RO"}
        ],
        ignore=[{"line": "^description ", "parent": "^interface "}],
    )
    result = compare(BEFORE, site.replace(" description uplink\n", ""), policy)
    assert result["equivalent"]
    assert {"community-case", "ignore:^description "} <= {t["rule"] for t in result["tolerated"]}
    # Numbered list lines split by other lines are still one list.
    split = BEFORE.replace("access-list 10 deny any\n", "logging buffered 64000\naccess-list 10 deny any\n")
    assert compare(BEFORE.replace("end\n", "logging buffered 64000\nend\n"), split)["equivalent"]
    with pytest.raises(ValueError):
        IosxeConfigPolicy(ignore=[{"line": "("}])
    certificate = (
        "hostname a\ncrypto pki certificate chain TP\n certificate self-signed 01 nvram:IOS-Self-Sig#1.cer\n"
    )
    assert normalized(certificate) == normalized(
        "hostname a\ncrypto pki certificate chain TP\n certificate self-signed 01\n  3082 0101\n  \tquit\n"
    )
    assert (
        masked("username admin privilege 15 secret 9 $9$abc")
        == "username admin privilege 15 secret 9 <redacted>"
    )


class Shell:
    def __init__(self, outputs):
        self.outputs = outputs

    def execute(self, command, timeout=120, **kwargs):
        text = self.outputs[command]
        return {"stdout": text, "cli_error": text.startswith("% Invalid"), "exit_code": None}

    def close(self):
        pass


def test_client_parses_ios_xe_tables():
    version = """Cisco IOS XE Software, Version 17.09.05
sw1 uptime is 1 week, 2 days, 3 hours, 4 minutes
System Serial Number               : FOC1111A1AA

Switch Ports Model              SW Version        SW Image              Mode
------ ----- -----              ----------        ----------            ----
*    1 65    C9300-48P          17.09.05          CAT9K_IOSXE           INSTALL
     2 65    C9300-48P          17.09.05          CAT9K_IOSXE           INSTALL

Switch 02
System Serial Number               : FOC2222B2BB
"""
    shell = Shell(
        {
            "show version": version,
            "show switch": "Switch/Stack Mac Address : 0011.2233.4455 - Local Mac Address\n"
            "                                             H/W   Current\n"
            "Switch#   Role    Mac Address     Priority Version  State\n"
            "-------------------------------------------------------------\n"
            "*1       Active   0011.2233.4455     15     V02     Ready\n"
            " 2       Standby  0011.2233.4466     14     V02     Ready\n",
            "show install summary": "[ Switch 1 2 ] Installed Package(s) Information:\n"
            "State (St): I - Inactive, U - Activated & Uncommitted,\n"
            "Type  St   Filename/Version\n"
            "IMG   C    17.09.05.0.6197\n"
            "IMG   I    17.06.04.0.5\n"
            "Auto abort timer: inactive\n",
            "dir flash-1:": "Directory of flash-1:/\n\n  1234  -rw-   1234567890  Oct 1 2026 10:00:00 +00:00  "
            + IMAGE
            + "\n\n11353194496 bytes total (8123456789 bytes free)\n",
            f"verify /sha512 flash:{IMAGE}": "......Done!\nverify /sha512 (flash:"
            + IMAGE
            + ") = "
            + "ab" * 64,
            "write memory": "Building configuration...\n[OK]",
            "show running-config": BEFORE,
            "show startup-config": BEFORE.replace(
                "Current configuration : 2400 bytes", "Using 2400 out of 2097152 bytes"
            ),
            "show ip interface brief": "Interface              IP-Address      OK? Method Status                Protocol\n"
            "Vlan10                 10.1.1.1        YES NVRAM  up                    up\n"
            "GigabitEthernet1/0/2   unassigned      YES unset  administratively down down\n",
            "show cdp neighbors detail": "-------------------------\nDevice ID: core1.example.com\n"
            "Interface: GigabitEthernet1/0/1,  Port ID (outgoing port): TenGigabitEthernet1/1/1\n",
            "show lldp neighbors detail": "------------------------------------------------\n"
            "Local Intf: Gi1/0/3\nChassis id: 0011.2233.4477\nPort id: Gi0/1\nSystem Name: ap1\n",
            "show etherchannel summary": "Number of channel-groups in use: 1\nGroup  Port-channel  Protocol    Ports\n"
            "------+-------------+-----------+-----------------------------------------------\n"
            "1      Po1(SU)         LACP        Gi1/0/1(P)  Gi2/0/1(P)\n"
            "                                 Gi1/0/2(s)\n",
            "show bgp all summary": "For address family: IPv4 Unicast\nBGP router identifier 10.255.0.1, local AS number 65001\n"
            "Neighbor        V           AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd\n"
            "10.0.0.1        4        65000    1234    1240       45    0    0 1w2d          120\n"
            "10.0.0.3        4        65000       0       0        1    0    0 never    Idle (Admin)\n",
            "show ip ospf neighbor": "Neighbor ID     Pri   State           Dead Time   Address         Interface\n"
            "10.0.0.2          1   FULL/DR         00:00:33    10.1.1.2        Vlan10\n"
            "10.0.0.4          0   FULL/  -        00:00:35    10.1.2.2        GigabitEthernet1/0/48\n",
            "show standby brief": "                     P indicates configured to preempt.\n"
            "Interface   Grp  Pri P State   Active          Standby         Virtual IP\n"
            "Vl10        10   110 P Active  local           10.1.1.3        10.1.1.254\n",
            "show ip route summary": "Route Source    Networks    Subnets     Replicates  Overhead    Memory (bytes)\nTotal           3           25          0           2000        8000\n",
            "show vrf": "  Name                             Default RD            Protocols   Interfaces\n"
            "  Mgmt-vrf                         <not set>             ipv4,ipv6   Gi0/0\n",
            "show ip route vrf Mgmt-vrf summary": "Total           1           2           0           100         400\n",
            "show mac address-table dynamic": "  10    0011.2233.4401    DYNAMIC     Gi1/0/3\n  10    0011.2233.4402    DYNAMIC     Gi1/0/4\n",
            "show ip arp summary": "12 IP ARP entries, with 0 of them incomplete\n",
            "show access-session": "% Invalid input detected at '^' marker.",
        }
    )
    ios = Iosxe(None, None, None, None, None, ssh=shell)
    info = ios.version()
    assert info["version"] == "17.09.05" and info["serials"] == ["FOC1111A1AA", "FOC2222B2BB"]
    assert info["members"]["2"] == {"model": "C9300-48P", "version": "17.09.05", "mode": "INSTALL"}
    assert info["uptime_seconds"] == 7 * 86400 + 2 * 86400 + 3 * 3600 + 4 * 60
    assert ios.stack()["1"]["role"] == "Active"
    summary = ios.install_summary()
    assert summary["committed"] == {"1": "17.09.05.0.6197", "2": "17.09.05.0.6197"} and summary["inactive"]
    assert not summary["pending"] and not summary["abort_timer"]
    assert ios.flash("1", IMAGE) == (8123456789, 1234567890) and ios.flash("1", "other.bin")[1] is None
    assert ios.verify(IMAGE, "sha512") == "ab" * 64
    assert ios.unsaved() is False and boot_ok(ios.config("running-config"))
    ios.save()
    traffic = ios.traffic()
    assert traffic["interfaces"] == {"Vlan10": "up/up", "GigabitEthernet1/0/2": "administratively down/down"}
    assert traffic["cdp"] == {"GigabitEthernet1/0/1": "core1.example.com|TenGigabitEthernet1/1/1"}
    assert traffic["lldp"] == {"Gi1/0/3": "ap1|Gi0/1"}
    assert traffic["port_channels"] == {
        "Po1|Gi1/0/1": "bundled",
        "Po1|Gi2/0/1": "bundled",
        "Po1|Gi1/0/2": "s",
    }
    assert traffic["bgp_peers"] == {
        "IPv4 Unicast|10.0.0.1": "established",
        "IPv4 Unicast|10.0.0.3": "idle (admin)",
    }
    assert traffic["ospf_neighbors"] == {"10.0.0.2|Vlan10": "full", "10.0.0.4|GigabitEthernet1/0/48": "full"}
    assert traffic["hsrp"] == {"Vl10|10": "active"} and traffic["routes"] == 31
    assert traffic["mac"] == 2 and traffic["arp"] == 12 and traffic["gaps"] == ["access_sessions"]
    with pytest.raises(DeviceError):
        members("Switch Ports Model\n*    1 65    C9300-48P          17.09.05          CAT9K_IOSXE\n")
    with pytest.raises(DeviceError):
        stack("nothing")
    with pytest.raises(DeviceError):
        listing("no free space", IMAGE)
    assert install_summary("IMG U 17.12.06.0.1\nAuto abort timer: active, time before rollback - 6:00:00")[
        "pending"
    ]
    assert uptime_seconds("no uptime") is None


class Channel:
    closed = False


class Transport:
    def __init__(self):
        self.active = True

    def is_active(self):
        return self.active


class Client:
    def __init__(self):
        self.transport = Transport()

    def get_transport(self):
        return self.transport


class Driver:
    RETURN = "\n"

    def __init__(self, chunks, client=None):
        self.chunks, self.written, self.client = list(chunks), [], client
        self.remote_conn = Channel()

    def enable(self):
        pass

    def exit_config_mode(self):
        pass

    def find_prompt(self):
        return "sw1#"

    def write_channel(self, value):
        self.written.append(value)

    def read_channel(self):
        if not self.chunks:
            self.client.transport.active = False
            return ""
        return self.chunks.pop(0)

    def disconnect(self):
        pass


class Redactor:
    def redact(self, text):
        return text


def session(chunks):
    ssh = object.__new__(NetworkSSH)
    ssh.client = Client()
    ssh.driver = Driver(chunks, ssh.client)
    ssh.guard, ssh.selector, ssh.operation_deadline, ssh.output_bytes = (lambda: None), Redactor(), None, 0
    ssh.close = lambda: None
    return ssh


def test_dialogue_answers_known_prompts_and_tolerates_the_reload():
    ssh = session(
        [
            "install add file flash:x.bin activate commit\ninstall_add_activate_commit: START\n",
            "This operation may require a reload of the system. Do you want to proceed? [y/n]",
            "\nReloading\n",
        ]
    )
    ios = Iosxe(None, None, None, None, None, ssh=ssh)
    lines = []
    assert "Reloading" in ios.install("x.bin", 60, lines.append)
    assert ssh.driver.written == ["install add file flash:x.bin activate commit\n", "y\n"]
    assert lines[-1] == "Reloading"
    ssh = session(
        [
            "copy http://x/a.bin flash:a.bin\n",
            "Destination filename [a.bin]? ",
            "\n!!!!\n1000 bytes copied in 2.0 secs\nsw1#",
        ]
    )
    Iosxe(None, None, None, None, None, ssh=ssh).device_copy("http://x/a.bin", "a.bin", 60, lambda line: None)
    assert ssh.driver.written[-1] == "\n"
    ssh = session(["install remove inactive\n", "Delete running config? [confirm]"])
    with pytest.raises(DeviceError, match="unrecognized prompt"):
        Iosxe(None, None, None, None, None, ssh=ssh).remove_inactive(60, lambda line: None)
    ssh = session(
        [
            "install add file flash:x.bin activate commit\nFAILED: install_add_activate_commit : bad image\nsw1#"
        ]
    )
    with pytest.raises(DeviceError, match="reported a failure"):
        Iosxe(None, None, None, None, None, ssh=ssh).install("x.bin", 60, lambda line: None)


def test_api_plans_queues_batches_and_compares(settings, store):
    settings.devices["eos1"] = Device(id="eos1", host="192.0.2.90", device_type="arista_eos")
    client = TestClient(create_app(settings), headers={"Authorization": "Bearer " + settings.token})
    image = {"name": IMAGE, "sha256": "0" * 64}
    defaults = {"target_version": TARGET, "allowed_source_versions": [SOURCE], "image": image}
    body = {
        "name": "Change790",
        "defaults": defaults,
        "overrides": {"192.0.2.41": {"peers": ["192.0.2.42"]}},
        "waves": [
            {"wave": 1, "devices": ["192.0.2.41"]},
            {"wave": 2, "upgrade_at_a_time": 10, "devices": ["192.0.2.42", "192.0.2.43"]},
        ],
    }
    response = client.post("/api/v1/iosxe/upgrade-batches", json=body)
    assert response.status_code == 202, response.text
    batch = response.json()
    assert batch["kind"] == "iosxe_upgrade" and batch["device_count"] == 3
    steps = client.post("/api/v1/iosxe/plan", json={**defaults, "device": "192.0.2.41"}).json()["steps"]
    assert steps[-1] == "write_memory_after_validation" and "install_add_activate_commit" in steps
    assert client.post("/api/v1/iosxe/jobs", json={**defaults, "device": "eos1"}).status_code == 422
    single = client.post("/api/v1/iosxe/jobs", json={**defaults, "device": "192.0.2.41", "queue": "priority"})
    assert (single.json()["kind"], single.json()["queue"]) == ("iosxe_upgrade", "priority")
    assert {j["queue"] for j in batch["jobs"]} == {"upgrade"}
    compared = client.post("/api/v1/iosxe/config-compare", json={"before": BEFORE, "after": AFTER}).json()
    assert compared["equivalent"] and compared["tolerated"]
    with pytest.raises(ValueError):
        IosxeBatch.model_validate({**body, "overrides": {"192.0.2.99": {}}})


def test_console_and_docs_work_behind_a_path_prefix(settings, store):
    settings.root_path = "/netops-executor"
    client = TestClient(create_app(settings))
    docs = client.get("/docs").text
    assert "/netops-executor/openapi.json" in docs
    for path in ("/", "/netops-executor/"):
        page = client.get(path)
        assert page.status_code == 200 and "Content-Security-Policy" in page.headers
        assert 'src="static/app.js"' in page.text and 'href="/' not in page.text
    for path in ("/static/app.js", "/netops-executor/static/app.js"):
        script = client.get(path)
        assert script.status_code == 200 and not re.search(r"fetch\(\"/", script.text)
    auth = {"Authorization": "Bearer " + settings.token}
    body = {
        "name": "Proxy",
        "defaults": {
            "target_version": TARGET,
            "allowed_source_versions": [SOURCE],
            "image": {"name": IMAGE, "sha256": "0" * 64},
        },
        "waves": [{"wave": 1, "devices": ["192.0.2.41"]}],
    }
    batch = client.post("/api/v1/iosxe/upgrade-batches", json=body, headers=auth).json()
    assert batch["status_url"].startswith("/netops-executor/api/v1/upgrade-batches/")
    assert client.get(batch["status_url"], headers=auth).status_code == 200
