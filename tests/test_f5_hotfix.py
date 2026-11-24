"""F5 engineering hotfixes: installed on the running release from its base image on the device."""

import hashlib

import pytest
from conftest import FakeDevice
from test_engine import execute

from netops_executor.device import BigIP
from netops_executor.engine import Runner
from netops_executor.models import JobRequest

HOTFIX = "Hotfix-BIGIP-17.1.1.3.0.12.5-ENG.iso"
BASE = {"name": "BIGIP-17.1.1.3-0.0.5.iso", "version": "17.1.1.3", "build": "0.0.5"}


@pytest.fixture
def hotfix(settings):
    content = b"fixture engineering hotfix; not vendor software"
    (settings.image_root / HOTFIX).write_bytes(content)
    return {
        "name": HOTFIX,
        "sha256": hashlib.sha256(content).hexdigest(),
        "version": "17.1.1.3",
        "build": "0.12.5",
        "kind": "hotfix",
    }


class Patched(FakeDevice):
    """Running 17.1.1.3 build 0.0.5, with that release's base image in /shared/images."""

    def __init__(self, base=True):
        super().__init__()
        for volume in (self.snap["active"], self.v["HD1.1"]):
            volume.update(version="17.1.1.3", build="0.0.5")
        self.base = dict(BASE) if base else None

    def base_image(self, version):
        return self.base if self.base and version == self.base["version"] else None


def request(hotfix, **options):
    return {"install": True, "reboot": True, "images": [hotfix], "ucs_unencrypted": True, **options}


def test_engineering_hotfix_installs_on_the_running_release(settings, store, hotfix):
    job, fake = execute(settings, store, request(hotfix), Patched())
    assert job["status"] == "succeeded", job["result"]
    # The hotfix alone goes onto the spare volume; BIG-IP builds it from the base image there.
    assert fake.installs == [(HOTFIX, "HD1.2", False)]
    assert fake.reboots == ["HD1.2"]
    assert job["result"]["base_images"] == [BASE]
    assert job["request"]["allowed_source_versions"] == ["17.1.1.3"]
    assert (fake.snap["active"]["version"], fake.snap["active"]["build"]) == ("17.1.1.3", "0.12.5")
    assert job["result"]["rollback"]["build"] == "0.0.5"


def test_a_missing_base_image_is_refused_before_anything_changes(settings, store, hotfix):
    job, fake = execute(settings, store, request(hotfix), Patched(base=False))
    assert job["status"] == "failed"
    assert "17.1.1.3 base image" in job["result"]["error"]
    assert fake.installs == [] and fake.reboots == [] and not job["result"].get("mutations")


def test_a_device_already_on_the_hotfix_is_left_alone(settings, store, hotfix):
    fake = Patched()
    for volume in (fake.snap["active"], fake.v["HD1.1"]):
        volume["build"] = "0.12.5"
    job, fake = execute(settings, store, request(hotfix), fake)
    assert job["status"] == "succeeded"
    assert job["result"]["already_running"] == {"volume": "HD1.1", "version": "17.1.1.3", "build": "0.12.5"}
    assert fake.installs == [] and fake.reboots == [] and not job["result"].get("mutations")


def test_hotfix_only_defaults_to_its_own_release(hotfix):
    request = JobRequest(device="lab", install=True, images=[hotfix])
    assert request.hotfix_only and request.allowed_source_versions == ["17.1.1.3"]
    explicit = JobRequest(device="lab", install=True, images=[hotfix], allowed_source_versions=["17.1.1"])
    assert explicit.allowed_source_versions == ["17.1.1"]
    base = {**hotfix, "name": BASE["name"], "kind": "image", "build": "0.0.5"}
    with pytest.raises(ValueError, match="allowed_source_versions"):
        JobRequest(device="lab", install=True, images=[base, hotfix])


def test_a_staged_hotfix_reports_a_missing_base_image(settings, store, hotfix):
    job, _ = execute(settings, store, {"stage_only": True, "images": [hotfix]}, Patched(base=False))
    assert job["status"] == "failed" and "base image" in job["result"]["error"]


class Catalog:
    def __init__(self):
        self.commands = []

    def tmsh(self, command, **kwargs):
        self.commands.append(command)
        if command == "list /sys software image":
            return (
                "sys software image BIGIP-17.1.1.3-0.0.5.iso {\n    build 0.0.5\n    verified yes\n"
                "    version 17.1.1.3\n}\nsys software image BIGIP-16.1.5-0.0.3.iso {\n    build 0.0.3\n"
                "    verified yes\n    version 16.1.5\n}\n"
            )
        if command == "list /sys software hotfix":
            return "sys software hotfix " + HOTFIX + " {\n    version 17.1.1.3\n}\n"
        return ""


def test_device_finds_the_verified_base_image_of_a_release():
    device = object.__new__(BigIP)
    device.ssh = Catalog()
    assert device.base_image("17.1.1.3") == BASE
    assert device.base_image("17.5.0") is None


def test_image_cleanup_keeps_the_base_image_a_hotfix_needs(hotfix):
    runner = object.__new__(Runner)
    runner.ssh = Catalog()
    runner.result = {"base_images": [BASE]}
    runner.checkpoint = lambda: None
    runner.intent = lambda *a, **k: None
    runner.cleanup_images(JobRequest(device="lab", install=True, images=[hotfix]))
    deleted = [c for c in runner.ssh.commands if c.startswith("delete")]
    assert deleted == ["delete /sys software image BIGIP-16.1.5-0.0.3.iso"]
