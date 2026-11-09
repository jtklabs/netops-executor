from types import SimpleNamespace

import httpx
import pytest
from conftest import Clock, FakeDevice
from test_controls_credentials import vault_for
from test_engine import reboot_options

from netops_executor import f5_operations as ops
from netops_executor.config import Device, HTTPTarget
from netops_executor.credentials import Credential
from netops_executor.engine import Runner
from netops_executor.execution import ExecutionRunner
from netops_executor.execution_models import HTTPJob
from netops_executor.models import JobRequest
from netops_executor.ssh import DeviceError


class Pair:
    def __init__(self, factory=FakeDevice):
        self.a, self.b = factory(), factory()
        self.active = "a"
        self.sync = "in sync"
        self.outputs = {"a": {}, "b": {}}
        self.members = [
            {"name": "/Common/a", "host": "192.0.2.10"},
            {"name": "/Common/b", "host": "192.0.2.11"},
        ]
        for label, device in (("a", self.a), ("b", self.b)):
            device.topology = lambda label=label: {
                "self": "/Common/" + label,
                "members": self.members,
                "cluster": "ha:test",
                "role": "active" if self.active == label else "standby",
                "groups": ["/Common/pair"],
                "sync": self.sync,
                "auto_sync": False,
            }
            device.owners = lambda: {"/Common/traffic-group-1": "/Common/" + self.active}
            original = device.ssh.tmsh

            def tmsh(command, label=label, original=original, **kwargs):
                if command == "run /sys failover standby":
                    self.active = "b" if label == "a" else "a"
                if command.startswith("modify /auth user admin password "):
                    # Local user accounts are synchronized configuration (verified on BIG-IP 17.5).
                    self.sync = "changes pending"
                if command.startswith("run /cm config-sync "):
                    self.sync = "in sync"
                if command in self.outputs[label]:
                    original(command, **kwargs)
                    return self.outputs[label][command]
                return original(command, **kwargs)

            device.ssh.tmsh = tmsh


def run_pair(settings, store, pair, which, **options):
    request = JobRequest(
        device="lab" if which == "a" else "peer", **reboot_options(target_volume=None, drain=True, **options)
    )
    store.submit(request.model_dump(), "device:" + which)
    job = store.claim("worker" + which)
    clock = Clock()
    runner = Runner(settings, store, job, "worker" + which, getattr(pair, which), clock.sleep, clock.clock)
    runner.peer = getattr(pair, "b" if which == "a" else "a")
    runner.run()
    return store.get(job["id"])


def test_healthy_active_first_then_peer(settings, store):
    settings.devices["peer"] = Device(id="peer", host="192.0.2.11")
    pair = Pair()
    first = run_pair(settings, store, pair, "a")
    assert first["status"] == "succeeded", first
    assert pair.active == "b"
    assert pair.a.reboots == ["HD1.2"]
    assert not pair.a.address_changes and not pair.b.address_changes
    assert first["result"]["config_sync"].startswith("deferred")
    second = run_pair(settings, store, pair, "b")
    assert second["status"] == "succeeded", second
    assert pair.active == "a"
    assert pair.b.reboots == ["HD1.2"]
    assert second["result"]["config_sync"] == "in sync"


# Captured from the BIG-IP VE 17.5.1.10 lab pair after upgrading both members one at a time.
GROUPS_17_5 = """cm device-group datasync-device-a-dg { auto-sync enabled devices { a { } b { } } full-load-on-sync true }
cm device-group datasync-global-dg { devices { a { } b { } } full-load-on-sync true network-failover disabled }
cm device-group device_trust_group { auto-sync enabled devices { a { } b { } } network-failover disabled }
cm device-group gtm { devices { a { } } network-failover disabled }
cm device-group lab-ha { asm-sync enabled devices { a { } b { } } type sync-failover }
"""
CONFLICT_17_5 = """cm cmi-sync-status {
    color red
    details.0.details b: connected
    details.1.details datasync-global-dg (Changes Pending): There is a possible change conflict between a and b.
    details.2.details  - Recommended action: Synchronize b to group datasync-global-dg
    details.3.details lab-ha (Changes Pending): There is a possible change conflict between a and b.
    details.4.details  - Recommended action: Synchronize b to group lab-ha
    mode high-availability
    status Changes Pending
    summary There is a possible change conflict between a and b.
}
"""


def test_sync_targets_cover_failover_and_asm_groups_only():
    outputs = {
        "list /cm device-group all-properties": GROUPS_17_5,
        "show /cm sync-status field-fmt": CONFLICT_17_5,
    }
    device = SimpleNamespace(ssh=SimpleNamespace(tmsh=lambda c: outputs[c]))
    assert ops.sync_targets(device, ["/Common/a", "/Common/b"]) == {
        "datasync-global-dg": True,
        "lab-ha": True,
    }
    outputs["show /cm sync-status field-fmt"] = CONFLICT_17_5.replace(
        "There is a possible change conflict", "x"
    )
    assert ops.sync_targets(device, ["/Common/a", "/Common/b"]) == {
        "datasync-global-dg": False,
        "lab-ha": False,
    }


def test_change_conflict_after_both_upgrades_gets_full_push_from_active(settings, store):
    settings.devices["peer"] = Device(id="peer", host="192.0.2.11")
    pair = Pair()
    first = run_pair(settings, store, pair, "a")
    assert first["status"] == "succeeded", first
    # After b's upgrade and failback a is active again and both report a change conflict.
    pair.sync = "changes pending"
    pair.outputs["a"] = {
        "list /cm device-group all-properties": GROUPS_17_5,
        "show /cm sync-status field-fmt": CONFLICT_17_5,
    }
    second = run_pair(settings, store, pair, "b")
    assert second["status"] == "completed_with_warnings", second["result"]
    assert second["result"]["config_sync"] == "in sync"
    assert second["result"]["config_sync_forced"] == ["datasync-global-dg", "lab-ha"]
    syncs = [c for c, _ in pair.a.ssh.commands if c.startswith("run /cm config-sync")]
    assert syncs == [
        "run /cm config-sync force-full-load-push to-group datasync-global-dg",
        "run /cm config-sync force-full-load-push to-group lab-ha",
    ]
    assert not any(c.startswith("run /cm config-sync") for c, _ in pair.b.ssh.commands)


def rollback_pair(settings, store, pair, source):
    rollback = store.submit(
        {"device": "lab", "reboot_timeout": 900, "validation_timeout": 0},
        "device:a",
        kind="rollback",
        parent=source["id"],
    )
    job = store.claim("rollback")
    assert job["id"] == rollback["id"]
    clock = Clock()
    runner = Runner(settings, store, job, "rollback", pair.a, clock.sleep, clock.clock)
    runner.peer = pair.b
    runner.run()
    return store.get(rollback["id"])


def test_rollback_first_member_while_peer_runs_original(settings, store):
    settings.devices["peer"] = Device(id="peer", host="192.0.2.11")
    pair = Pair()
    first = run_pair(settings, store, pair, "a")
    assert first["status"] == "succeeded", first
    # The peer was never upgraded, so no validated peer upgrade exists; it runs the rollback target.
    rollback = rollback_pair(settings, store, pair, first)
    assert rollback["status"] == "succeeded", rollback["result"]
    assert pair.a.reboots == ["HD1.2", "HD1.1"]
    assert pair.a.active()["version"] == "16.1.5"


def test_mixed_version_rollback_refuses_peer_on_other_software(settings, store):
    settings.devices["peer"] = Device(id="peer", host="192.0.2.11")
    pair = Pair()
    first = run_pair(settings, store, pair, "a")
    pair.b.snap["active"]["version"] = "15.1.10"
    rollback = rollback_pair(settings, store, pair, first)
    assert rollback["status"] == "failed"
    assert "peer to run the rollback target" in rollback["result"]["error"]
    assert pair.a.reboots == ["HD1.2"]


def test_admin_password_reset_resynchronizes_pair_before_failover(settings, store):
    from test_admin_password import EXPECTED, AdminDevice, provision

    settings.devices["peer"] = Device(id="peer", host="192.0.2.11")
    provision(settings, store)
    pair = Pair(lambda: AdminDevice("old"))
    first = run_pair(settings, store, pair, "a", admin_password={})
    assert first["status"] == "succeeded", first["result"]
    assert pair.a.resets == [EXPECTED]
    commands = [c for c, _ in pair.a.ssh.commands]
    reset = next(i for i, c in enumerate(commands) if c.startswith("modify /auth user admin password"))
    sync = commands.index("run /cm config-sync to-group /Common/pair")
    assert reset < sync < commands.index("run /sys failover standby")
    before = first["result"]["admin_password"]["checks"][0]
    assert before["remediated"] and before["config_sync"] == "in sync"


@pytest.mark.parametrize("accepted", [False, True])
def test_manual_completion_counts_as_validated_peer_only_after_validation(store, accepted):
    from netops_executor.execution_models import ManualCompletion

    peer = store.submit({"device": "peer"}, "device:peer")
    store.claim("w")
    verified = {"volume": "HD1.2", "version": "17.1.2", "build": "0.0.5"}
    result = {"ha": {"cluster": "ha:x", "self": "/Common/b"}, "boot_verified": verified}
    store.record(peer["id"], "w", "reboot_completed", result={**result, "validation_accepted": accepted})
    store.finish(peer["id"], "w", "recovery_required")
    store.mark_done(peer["id"], ManualCompletion(operator="jason", reason="advance the wave"))
    store.resolve(peer["id"], {"worker_stopped": True, "device_inspected": True, "note": "inspected unit"})
    assert store.get(peer["id"])["status"] == "manually_completed"
    assert store.validated_peer("other", "ha:x", verified, "/Common/b") is accepted


def test_unhealthy_peer_blocks_before_backup(settings, store):
    pair = Pair()
    pair.b.snap["asm_ready"] = False
    first = run_pair(settings, store, pair, "a")
    assert first["status"] == "failed"
    assert not pair.a.ssh.commands and not pair.a.reboots


@pytest.mark.parametrize("names,status", [(["/Tenant/renamed"], "succeeded"), ([], "failed")])
def test_peer_waf_policies_compare_by_count(settings, store, names, status):
    settings.devices["peer"] = Device(id="peer", host="192.0.2.11")
    pair = Pair()
    pair.b.snap["waf_policy_names"] = names
    first = run_pair(settings, store, pair, "a")
    assert first["status"] == status, first["result"]
    if status == "failed":
        assert first["result"]["error"] == "peer WAF policy count differs"


def test_cluster_reservation_blocks_other_batch_and_generic_ssh(settings, store):
    a = store.submit({"device": "a"}, "a")
    store.claim("a")
    assert store.reserve(a["id"], "a", ["ha:pair", "endpoint:192.0.2.10", "endpoint:192.0.2.11"])
    b = store.submit({"device": "b"}, "b")
    store.claim("b")
    assert not store.reserve(b["id"], "b", ["ha:pair", "endpoint:192.0.2.11"])
    c = store.submit({"device": "b"}, "ssh:b", kind="ssh")
    store.claim("c")
    assert not store.reserve(c["id"], "c", ["endpoint:192.0.2.11"])
    store.finish(a["id"], "a", "recovery_required")
    assert not store.reserve(b["id"], "b", ["ha:pair"])


def test_topology_parser_and_traffic_owners():
    outputs = {
        "list /cm device all-properties": "cm device a { self-device true management-ip 192.0.2.10 } cm device b { self-device false management-ip 192.0.2.11 }",
        "list /cm device-group all-properties": "cm device-group pair { type sync-failover auto-sync disabled devices { a { } b { } } }",
        "show /cm failover-status field-fmt": "cm failover-status {\n status ACTIVE\n}",
        "show /cm sync-status field-fmt": 'cm sync-status {\n status "In Sync"\n}',
        "show /cm traffic-group field-fmt": "cm traffic-group-device traffic-group-1:a { device-name a failover-state active traffic-group traffic-group-1 } cm traffic-group-device traffic-group-1:b { device-name b failover-state standby traffic-group traffic-group-1 }",
    }
    device = SimpleNamespace(ssh=SimpleNamespace(tmsh=lambda c: outputs[c]))
    topo = ops.topology(device)
    assert topo["self"] == "/Common/a" and topo["cluster"].startswith("ha:")
    assert ops.owners(device) == {"/Common/traffic-group-1": "/Common/a"}
    outputs["show /cm traffic-group field-fmt"] = outputs["show /cm traffic-group field-fmt"].replace(
        "standby", "active"
    )
    with pytest.raises(DeviceError):
        ops.owners(device)


def test_traffic_owners_parse_17_5_rows():
    # Captured from a BIG-IP VE 17.5.1.10 lab pair.
    output = """cm traffic-group traffic-group-1:f5-lab01.home.arpa {
    active-reason -
    device-name f5-lab01.home.arpa
    failover-state standby
    next-active true
    previous-active false
    traffic-group traffic-group-1
}
cm traffic-group traffic-group-1:f5-lab02.home.arpa {
    active-reason peer-forced-standby
    device-name f5-lab02.home.arpa
    failover-state active
    next-active false
    previous-active false
    traffic-group traffic-group-1
}
cm traffic-group traffic-group-local-only:- {
    active-reason -
    device-name -
    failover-state -
    next-active -
    previous-active -
    traffic-group traffic-group-local-only
}
"""
    device = SimpleNamespace(ssh=SimpleNamespace(tmsh=lambda c: output))
    assert ops.owners(device) == {"/Common/traffic-group-1": "/Common/f5-lab02.home.arpa"}


def test_configuration_commands_match_17_5_syntax():
    commands = []

    def tmsh(command):
        commands.append(command)
        return ""

    ops.details(SimpleNamespace(ssh=SimpleNamespace(tmsh=tmsh)))
    assert "cd /; list /net route recursive all-properties" in commands
    assert "cd /; list /net trunk interfaces" in commands
    assert "cd /; list /ltm rule recursive app-service" in commands
    assert not any("one-line" in c or " gw" in c for c in commands)


def http_run(settings, store, monkeypatch, handler, probe="/probe", method="POST"):
    vault = vault_for(settings, store)
    for priority, profile in enumerate(("primary", "fallback")):
        vault.put(profile, Credential(kind="http", token=profile + "-secret", priority=priority))
    settings.http_targets["pan"] = HTTPTarget(id="pan", base_url="https://pan.example", auth_probe_path=probe)
    client = httpx.Client
    monkeypatch.setattr(
        "netops_executor.execution.httpx.Client",
        lambda **kwargs: client(transport=httpx.MockTransport(handler), **kwargs),
    )
    request = HTTPJob(
        target="pan",
        requests=[
            {
                "method": method,
                "path": "/command",
                "form": {"target": "firewall-serial", "cmd": "<show><system><info/></system></show>"},
            }
        ],
    )
    job = store.submit({**request.model_dump(), "device": "pan"}, "http:pan", kind="http")
    ExecutionRunner(settings, store, store.claim("http"), "http").run()
    return store.get(job["id"])


def test_http_fallback_probe_sends_write_once(settings, store, monkeypatch):
    requests = []

    def handler(request):
        requests.append((request.method, request.url.path, request.headers["authorization"]))
        if request.url.path == "/probe" and "primary" in request.headers["authorization"]:
            return httpx.Response(401)
        return httpx.Response(200, text="fallback-secret payload")

    job = http_run(settings, store, monkeypatch, handler)
    assert job["status"] == "succeeded", job
    assert [r[1] for r in requests] == ["/probe", "/probe", "/command"]
    assert job["credential_summary"]["profiles_used"] == ["fallback"]
    assert job["result"]["operations"][0]["body"] == "[REDACTED] payload"


def test_http_write_timeout_never_retries(settings, store, monkeypatch):
    requests = []

    def handler(request):
        requests.append(request.url.path)
        if request.url.path == "/command":
            raise httpx.ReadTimeout("ambiguous outcome")
        return httpx.Response(200)

    job = http_run(settings, store, monkeypatch, handler)
    assert job["status"] == "recovery_required"
    assert requests == ["/probe", "/command"]
    assert job["lock_held"]


def test_http_permission_rejection_does_not_try_other_credentials(settings, store, monkeypatch):
    requests = []

    def handler(request):
        requests.append(request.url.path)
        return httpx.Response(403)

    job = http_run(settings, store, monkeypatch, handler)
    assert job["status"] == "failed"
    assert requests == ["/probe"]


def test_http_requires_probe_even_for_get(settings, store, monkeypatch):
    requests = []
    job = http_run(
        settings, store, monkeypatch, lambda request: requests.append(request), probe=None, method="GET"
    )
    assert job["status"] == "failed" and requests == []
