import json

import pytest
from conftest import Clock, FakeDevice

from netops_executor.engine import Runner
from netops_executor.models import JobRequest
from netops_executor.ssh import DeviceError


def execute(settings, store, payload, device=None):
    request = JobRequest(device="lab", **payload)
    store.submit(request.model_dump(), "device:lab")
    job = store.claim("worker")
    fake = device or FakeDevice()
    clock = Clock()
    Runner(settings, store, job, "worker", fake, clock.sleep, clock.clock).run()
    return store.get(job["id"]), fake


def reboot_options(**kwargs):
    return {
        "reboot": True,
        "target_volume": "HD1.2",
        "allowed_source_versions": ["16.1.5"],
        "expected_version": "17.1.2",
        "expected_build": "0.0.5",
        "ucs_unencrypted": True,
        **kwargs,
    }


def test_full_upgrade_and_recorded_rollback(settings, store, image):
    fake = FakeDevice()
    fake.v["HD1.2"]["version"] = "15.1.0"
    j, fake = execute(settings, store, reboot_options(install=True, images=[image], drain_percent=90), fake)
    assert j["status"] == "succeeded", j["result"]
    assert fake.installs == [("BIGIP.iso", "HD1.2", False)]
    assert fake.reboots == ["HD1.2"]
    assert fake.address_changes == [("/Common/192.0.2.20", False), ("/Common/192.0.2.20", True)]
    assert not fake.addresses["/Tenant/192.0.2.30"]
    assert j["result"]["drain"]["threshold"] == 10
    assert j["result"]["rollback"]["volume"] == "HD1.1"
    assert j["result"]["backup"]["encrypted"] is False
    assert j["result"]["post_validation"]["virtual_ips"]["total"] == 2
    rollback = store.submit(
        {"device": "lab", "reboot_timeout": 60, "validation_timeout": 0},
        "device:lab",
        kind="rollback",
        parent=j["id"],
    )
    job = store.claim("other")
    clock = Clock()
    Runner(settings, store, job, "other", fake, clock.sleep, clock.clock).run()
    assert store.get(rollback["id"])["status"] == "succeeded"
    assert fake.reboots == ["HD1.2", "HD1.1"]


def test_no_reboot_install(settings, store, image):
    j, fake = execute(
        settings,
        store,
        {
            "install": True,
            "images": [image],
            "target_volume": "HD1.2",
            "allowed_source_versions": ["16.1.5"],
            "ucs_unencrypted": True,
        },
    )
    assert j["status"] == "succeeded"
    assert not fake.reboots
    assert not fake.address_changes
    assert j["result"]["post_validation"]["active"]["volume"] == "HD1.1"


def test_disallowed_version_changes_nothing(settings, store):
    j, fake = execute(settings, store, reboot_options(allowed_source_versions=["15.1.0"]))
    assert j["status"] == "failed"
    assert not fake.ssh.commands and not fake.reboots


def test_active_volume_rejected(settings, store):
    j, fake = execute(settings, store, reboot_options(target_volume="HD1.1"))
    assert j["status"] == "failed"
    assert not fake.ssh.commands


def test_missing_encryption_secret_blocks_mutations(settings, store, monkeypatch):
    monkeypatch.delenv("F5_UCS_PASSPHRASE", raising=False)
    j, fake = execute(settings, store, {"create_ucs": True})
    assert j["status"] == "failed"
    assert not fake.ssh.commands


def test_secret_not_persisted(settings, store, monkeypatch):
    secret = 'sensitive "value" \\ with symbols'
    monkeypatch.setenv("F5_UCS_PASSPHRASE", secret)
    j, fake = execute(settings, store, {"create_ucs": True})
    assert j["status"] == "succeeded"
    command, kwargs = next(x for x in fake.ssh.commands if "save /sys ucs" in x[0])
    assert kwargs["secret"] is True
    assert "passphrase" in command
    assert secret not in json.dumps(j) + json.dumps(store.events(j["id"]))


@pytest.mark.parametrize("force,expected_reboots", [(False, []), (True, ["HD1.2"])])
def test_drain_timeout_restores_addresses(settings, store, force, expected_reboots):
    fake = FakeDevice()
    fake.counts = iter([100, 100, 100])
    j, fake = execute(
        settings, store, reboot_options(drain=True, drain_timeout=0, reboot_on_drain_timeout=force), fake
    )
    assert fake.reboots == expected_reboots
    assert fake.address_changes == [("/Common/192.0.2.20", False), ("/Common/192.0.2.20", True)]
    assert j["result"]["drain"]["timed_out"]
    assert j["status"] == ("succeeded" if force else "recovery_required")


def test_auto_sync_rejected_before_backup(settings, store):
    fake = FakeDevice()
    fake.auto_sync = True
    j, fake = execute(settings, store, reboot_options(drain=True), fake)
    assert j["status"] == "failed"
    assert not fake.ssh.commands and not fake.address_changes


def test_zero_baseline_and_percent(settings, store):
    fake = FakeDevice()
    fake.counts = iter([0, 0])
    j, _ = execute(settings, store, reboot_options(drain_percent=100), fake)
    assert j["status"] == "succeeded"
    assert j["result"]["drain"]["threshold"] == 0


def test_partial_drain_error_restores_inflight_address(settings, store):
    fake = FakeDevice()
    original = fake.set_enabled

    def failing(address, enabled):
        original(address, enabled)
        if not enabled:
            raise DeviceError("transport lost")

    fake.set_enabled = failing
    j, _ = execute(settings, store, reboot_options(drain=True), fake)
    assert j["status"] == "recovery_required"
    assert fake.addresses["/Common/192.0.2.20"]
    assert not fake.reboots
    assert j["result"]["drain"]["changed_addresses"] == ["/Common/192.0.2.20"]


def test_unverified_reboot_retains_lock_and_drain_recovery(settings, store):
    fake = FakeDevice()
    fake.new_boot = False
    j, _ = execute(settings, store, reboot_options(drain=True, reboot_timeout=60), fake)
    assert j["status"] == "recovery_required"
    assert not fake.addresses["/Common/192.0.2.20"]
    store.submit({"device": "lab"}, "device:lab")
    assert store.claim("next") is None


def test_post_validation_detects_individual_regression(settings, store):
    fake = FakeDevice()
    original = fake.reboot

    def reboot(volume):
        original(volume)
        fake.snap["pools"]["objects"]["/Common/up"]["up"] = False
        fake.snap["pools"]["objects"]["/Common/disabled"]["up"] = True

    fake.reboot = reboot
    j, _ = execute(settings, store, reboot_options(validation_timeout=0), fake)
    assert j["status"] == "completed_with_warnings"
    assert any(i["category"] == "pools" for i in j["result"]["validation_differences"])


def test_wrong_image_digest_prevents_install(settings, store, image):
    image["sha256"] = "0" * 64
    j, fake = execute(
        settings,
        store,
        {
            "install": True,
            "images": [image],
            "target_volume": "HD1.2",
            "allowed_source_versions": ["16.1.5"],
            "ucs_unencrypted": True,
        },
    )
    assert not fake.installs
    assert "SHA-256" in j["result"]["error"]


def test_rollback_rejects_changed_device(settings, store):
    j, fake = execute(settings, store, reboot_options())
    fake.snap["active"]["version"] = "19.0.0"
    r = store.submit(
        {"device": "lab", "reboot_timeout": 60, "validation_timeout": 0},
        "device:lab",
        kind="rollback",
        parent=j["id"],
    )
    job = store.claim("rollback")
    clock = Clock()
    Runner(settings, store, job, "rollback", fake, clock.sleep, clock.clock).run()
    assert store.get(r["id"])["status"] == "failed"
    assert fake.reboots == ["HD1.2"]


def test_post_boot_validation_waits_for_services(settings, store):
    fake = FakeDevice()
    original = fake.snapshot
    attempts = []

    def snapshot_after_boot():
        if fake.reboots and not attempts:
            attempts.append(True)
            raise DeviceError("ASM is starting")
        return original()

    fake.snapshot = snapshot_after_boot
    job, _ = execute(settings, store, reboot_options(validation_timeout=30), fake)
    assert job["status"] == "succeeded"
    assert any(e["step"] == "post_validation_waiting_for_device" for e in store.events(job["id"]))


def test_transferred_image_waits_for_catalog(settings, store, image):
    fake = FakeDevice()
    attempts = []

    def verify_image(spec):
        attempts.append(spec.name)
        if len(attempts) == 1:
            raise DeviceError("image catalog still scanning")

    fake.verify_image = verify_image
    job, _ = execute(settings, store, {"transfer": True, "images": [image]}, fake)
    assert job["status"] == "succeeded"
    assert len(attempts) == 2
