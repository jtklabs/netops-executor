import copy
import hashlib
import os

import pytest
from conftest import Clock
from fastapi.testclient import TestClient

from netops_executor.api import create_app
from netops_executor.config import Device
from netops_executor.execution_models import ValidationDecision
from netops_executor.opengear import Opengear, parse_version, version_key
from netops_executor.opengear_engine import OpengearRunner
from netops_executor.opengear_models import OpengearBatch, OpengearUpgradeRequest
from netops_executor.ssh import DeviceError
from netops_executor.store import LostOwnership

TARGET = "5.3.3"
IMAGE = "im72xx-5.3.3.flash"
CONTENT = b"fixture firmware, not a vendor image"
SHA = hashlib.sha256(CONTENT).hexdigest()
BOOT = "84683d82-a4e0-4ecb-991f-abbfe9944482"


class Console:
    def __init__(self):
        self.info = {"model": "IM7248-2-DAC", "version": "5.3.1", "mac": "00:13:c6:12:34:56", "boot_id": BOOT}
        self.state = {"config_sha256": "ab" * 32, "interfaces": {"eth0": "up", "eth1": "up"}}
        self.calls, self.files = [], {}
        self.after = {}
        self.reboot_polls = 2
        self.polls = 0
        self.free = 10**9
        self.flash_code = None
        self.change_boot = True
        self.change_version = True
        self.on_install = lambda: None
        self.on_upload = lambda: None

    def preflight(self):
        self.calls.append("preflight")

    def version(self):
        if self.polls:
            self.polls -= 1
            if not self.polls:
                if self.change_boot:
                    self.info["boot_id"] = "9d476273-d79c-4889-889f-e0b325ab66af"
                if self.change_version:
                    self.info["version"] = TARGET
                self.state.update(copy.deepcopy(self.after))
            raise DeviceError("rebooting")
        return dict(self.info)

    def snapshot(self):
        return copy.deepcopy(self.state)

    def prepare(self, base):
        return base + "/netops-executor"

    def free_bytes(self, base):
        return self.free

    def staged(self, path):
        return path in self.files

    def sha256(self, path):
        return hashlib.sha256(self.files[path]).hexdigest()

    def upload(self, local, path, timeout, progress, job_id):
        self.calls.append("upload")
        self.files[path] = local.read_bytes()
        progress(len(CONTENT), len(CONTENT))
        self.on_upload()

    def backup(self, remote, local, timeout, progress):
        self.calls.append("backup")
        with os.fdopen(os.open(local, os.O_CREAT | os.O_WRONLY, 0o600), "wb") as stream:
            stream.write(b"private configuration backup")
        progress(1, 1)

    def install_reload(self, path, timeout):
        self.calls.append("flash")
        self.on_install()
        if self.flash_code is not None:
            return self.flash_code
        self.polls = self.reboot_polls
        raise DeviceError("connection closed during flash")

    def close(self):
        pass


@pytest.fixture
def image_file(settings):
    (settings.image_root / IMAGE).write_bytes(CONTENT)
    return {"name": IMAGE, "sha256": SHA}


def payload(image, **options):
    return OpengearUpgradeRequest(
        device="192.0.2.72", target_version=TARGET, allowed_source_versions=["5.3.1"], image=image, **options
    ).model_dump(mode="json")


def work(settings, store, console):
    job = store.claim("w")
    clock = Clock()
    OpengearRunner(settings, store, job, "w", client=console, sleep=clock.sleep, clock=clock.clock).run()
    return store.get(job["id"])


def run(settings, store, console, image, **options):
    store.submit(payload(image, **options), "device:192.0.2.72", kind="opengear_upgrade")
    return work(settings, store, console)


def test_full_upgrade_private_backup_new_boot_and_progress(settings, store, image_file):
    console = Console()
    job = run(settings, store, console, image_file)
    assert job["status"] == "succeeded", job["result"]
    result = job["result"]
    assert console.calls == ["preflight", "backup", "upload", "preflight", "flash"]
    backup = settings.backup_root / result["backup"]["path"]
    assert backup.stat().st_mode & 0o777 == 0o600
    assert hashlib.sha256(backup.read_bytes()).hexdigest() == result["backup"]["sha256"]
    assert result["backup"]["format"] == "opengear-opg"
    assert result["boot_verified"]["version"] == TARGET
    assert result["rollback"] == {"supported": False, "source_version": "5.3.1"}
    assert result["progress"]["percent"] == 100 and not job["lock_held"]
    assert result["software"]["sha256_verified"] and result["validation_accepted"]


def test_preload_reused_by_later_upgrade_and_already_target_is_noop(settings, store, image_file):
    console = Console()
    job = run(settings, store, console, image_file, stage_only=True)
    assert job["status"] == "succeeded" and job["result"]["preloaded"]
    assert console.calls == ["preflight", "upload"]
    job = run(settings, store, console, image_file)
    assert job["status"] == "succeeded" and job["result"]["software"]["reused"]
    assert console.calls.count("upload") == 1 and console.calls.count("flash") == 1
    job = run(settings, store, console, image_file)
    assert job["status"] == "succeeded" and job["result"]["already_on_target"]
    assert console.calls.count("flash") == 1 and console.calls.count("backup") == 1


@pytest.mark.parametrize(
    "change,error",
    [
        (lambda s: setattr(s, "free", 0), "insufficient staging space"),
        (lambda s: s.info.update(version="5.2.2"), "outside allowed_source_versions"),
        (lambda s: s.files.update({"/tmp/netops-executor/" + SHA + ".flash": b"changed"}), "SHA-256"),
    ],
)
def test_precheck_failures_never_flash(settings, store, image_file, change, error):
    console = Console()
    change(console)
    job = run(settings, store, console, image_file)
    assert job["status"] == "failed" and error in job["result"]["error"]
    assert "flash" not in console.calls and not job["lock_held"]


@pytest.mark.parametrize("source,target", [("4.13.2", "5.3.3"), ("5.3.3", "5.3.1")])
def test_bridge_release_and_downgrade_rejected(settings, store, image_file, source, target):
    console = Console()
    console.info["version"] = source
    request = payload(image_file)
    request.update(allowed_source_versions=[source], target_version=target)
    store.submit(request, "device:192.0.2.72", kind="opengear_upgrade")
    job = work(settings, store, console)
    assert job["status"] == "failed" and "flash" not in console.calls
    assert "4.13.3" in job["result"]["error"] or "downgrade" in job["result"]["error"]


def test_local_image_checksum_and_model_allowlist(settings, store, image_file):
    console = Console()
    job = run(settings, store, console, image_file, approved_models=["IM7208-2-DAC"])
    assert job["status"] == "failed" and "model" in job["result"]["error"]
    (settings.image_root / IMAGE).write_bytes(b"bad")
    job = run(settings, store, console, image_file)
    assert job["status"] == "failed" and "SHA-256" in job["result"]["error"]
    assert "flash" not in console.calls


@pytest.mark.parametrize("change", ["config", "image", "boot"])
def test_changed_precheck_state_blocks_flash(settings, store, image_file, change):
    console = Console()

    def after():
        if change == "config":
            console.state["config_sha256"] = "cd" * 32
        elif change == "boot":
            console.info["boot_id"] = "changed"
        else:
            console.files["/tmp/netops-executor/" + SHA + ".flash"] = b"bad"

    console.on_upload = after
    job = run(settings, store, console, image_file)
    assert job["status"] == "failed" and "flash" not in console.calls


def test_minor_post_differences_warn_and_finish(settings, store, image_file):
    console = Console()
    console.after = {"config_sha256": "cd" * 32, "interfaces": {"eth0": "up", "eth1": "down"}}
    job = run(settings, store, console, image_file)
    assert job["status"] == "completed_with_warnings" and not job["lock_held"]
    assert {f["category"] for f in job["result"]["validation_differences"]} == {"config", "interfaces"}


@pytest.mark.parametrize("action", ["accept", "retry"])
def test_review_continuation_never_reflashes(settings, store, image_file, action):
    console = Console()
    console.after = {"interfaces": {"eth0": "up", "eth1": "down"}}
    job = run(
        settings,
        store,
        console,
        image_file,
        validation_timeout=0,
        validation_policy={"restore_interfaces": True, "settling_seconds": 0},
    )
    assert job["status"] == "needs_review" and job["lock_held"]
    gate = job["validation_gates"][-1]
    store.decide(
        job["id"],
        ValidationDecision(
            gate_id=gate["id"],
            validation_revision=gate["revision"],
            operator="jason",
            reason="checked console",
            action=action,
        ),
    )
    if action == "retry":
        console.state["interfaces"]["eth1"] = "up"
    job = work(settings, store, console)
    assert job["status"] in ("succeeded", "completed_with_warnings"), job["result"]
    assert console.calls.count("flash") == 1


@pytest.mark.parametrize("failure", ["no_boot", "wrong_version", "offline", "rejected", "different_device"])
def test_uncertain_flash_holds_lock_for_recovery(settings, store, image_file, failure):
    console = Console()
    if failure == "no_boot":
        console.change_boot = False
    elif failure == "wrong_version":
        console.change_version = False
    elif failure == "offline":
        console.reboot_polls = 10**6
    elif failure == "rejected":
        console.flash_code = 24
    else:
        console.on_install = lambda: console.info.update(mac="00:13:c6:99:99:99")
    job = run(settings, store, console, image_file, reboot_timeout=60)
    assert job["status"] == "recovery_required" and job["lock_held"], job["result"]
    assert console.calls.count("flash") == 1


def test_cancel_before_and_after_flash(settings, store, image_file):
    console = Console()
    created = store.submit(payload(image_file), "device:192.0.2.72", kind="opengear_upgrade")
    console.on_upload = lambda: store.cancel(created["id"])
    job = work(settings, store, console)
    assert job["status"] == "cancelled" and "flash" not in console.calls
    console.on_upload = lambda: None
    created = store.submit(payload(image_file), "device:192.0.2.72", kind="opengear_upgrade")
    console.on_install = lambda: store.cancel(created["id"])
    job = work(settings, store, console)
    assert job["status"] == "recovery_required" and job["result"]["boot_verified"]
    assert console.calls.count("flash") == 1


def test_lost_ownership_is_not_swallowed_as_flash_disconnect(settings, store, image_file):
    console = Console()

    def lost():
        raise LostOwnership()

    console.on_install = lost
    job = run(settings, store, console, image_file)
    assert job["result"]["install"]["status"] == "started"
    assert console.calls.count("flash") == 1
    assert "boot_verified" not in job["result"]


@pytest.mark.parametrize(
    "version,issue,model",
    [
        ("OpenGear/IM7208-2-DAC-LR version 4.1.0", "", "IM7208-2-DAC-LR"),
        ("5.3.1\n", "Opengear IM7248-2-DAC", "IM7248-2-DAC"),
        ("Opengear/IM7216-L version 4.13.3u1", "", "IM7216-L"),
    ],
)
def test_version_parser(version, issue, model):
    assert parse_version(version, issue)["model"] == model
    assert version_key("4.13.3u1") > version_key("4.13.3")


@pytest.mark.parametrize(
    "version",
    [
        "OpenGear/CM7148 version 5.3.1",
        "Opengear/OM2248 version 24.1.1",
        "5.3.1",
        "IM7248 version unknown",
        "OpenGear/IM7248 version 5.3.3-custom",
        "OpenGear/IM72480 version 5.3.3",
    ],
)
def test_unidentified_or_wrong_family_is_rejected(version):
    with pytest.raises(DeviceError):
        parse_version(version)


class Shell:
    def __init__(self, outputs):
        self.outputs, self.commands = outputs, []

    def execute(self, command, timeout=120):
        self.commands.append(command)
        value = self.outputs[command]
        return value if isinstance(value, dict) else {"stdout": value, "exit_code": 0}

    def close(self):
        pass


def test_adapter_reads_identity_and_keeps_netflash_checks_enabled():
    shell = Shell(
        {
            "cat /etc/version": "OpenGear/IM7208-2-DAC version 5.3.1",
            "cat /sys/class/net/eth0/address": "00:13:c6:12:34:56",
            "cat /proc/sys/kernel/random/boot_id": BOOT,
            "netflash /tmp/approved.flash": {"stdout": "", "exit_code": 24},
            "id -u": "1000",
        }
    )
    device = Opengear(None, None, None, None, None, ssh=shell)
    assert device.version()["boot_id"] == BOOT
    assert device.install_reload("/tmp/approved.flash", 60) == 24
    assert shell.commands[-1] == "netflash /tmp/approved.flash"
    with pytest.raises(DeviceError, match="root shell"):
        device.preflight()


def test_backup_adapter_verifies_bytes_and_keeps_private_permissions(tmp_path):
    content = b"private backup data"
    sha = hashlib.sha256(content).hexdigest()
    commands = []
    device = Opengear(None, None, None, None, None, ssh=Shell({}))

    def text(command, timeout=120):
        commands.append(command)
        return sha + "  /tmp/config.opg" if command.startswith("sha256sum") else ""

    device.text = text

    def transfer(local, remote, timeout, progress, download=False):
        assert download and local.stat().st_mode & 0o777 == 0o600
        local.write_bytes(content)

    device.transfer = transfer
    path = tmp_path / "backup.opg"
    device.backup("/tmp/config.opg", path, 60, lambda *_: None)
    assert path.read_bytes() == content and path.stat().st_mode & 0o777 == 0o600
    assert any("config -e /tmp/config.opg" in c for c in commands)
    device.sha256 = lambda _: "0" * 64
    with pytest.raises(DeviceError, match="SHA-256 mismatch"):
        device.backup("/tmp/config.opg", tmp_path / "bad.opg", 60, lambda *_: None)
    assert not (tmp_path / "bad.opg").exists() and not list(tmp_path.glob("*.partial"))


def test_api_auth_plan_jobs_idempotency_and_schema(settings, store, image_file):
    client = TestClient(create_app(settings))
    body = payload(image_file)
    assert client.post("/api/v1/opengear/jobs", json=body).status_code == 401
    client.headers["Authorization"] = "Bearer " + settings.token
    plan = client.post("/api/v1/opengear/plan", json=body)
    assert plan.status_code == 200 and "netflash_and_reboot" in plan.json()["steps"]
    headers = {"Idempotency-Key": "opengear-once"}
    first = client.post("/api/v1/opengear/jobs", json=body, headers=headers)
    again = client.post("/api/v1/opengear/jobs", json=body, headers=headers)
    assert first.status_code == 202 and first.json()["id"] == again.json()["id"]
    assert first.json()["kind"] == "opengear_upgrade" and first.json()["queue"] == "upgrade"
    assert client.get("/api/v1/jobs/" + first.json()["id"]).status_code == 200
    schema = client.get("/openapi.json").json()
    assert "OpengearUpgradeRequest" in schema["components"]["schemas"]
    settings.devices["wrong"] = Device(id="wrong", host="192.0.2.9", device_type="f5")
    assert client.post("/api/v1/opengear/jobs", json={**body, "device": "wrong"}).status_code == 422


def test_batch_waves_queue_window_and_dispatch(settings, store, image_file, monkeypatch):
    from netops_executor import worker

    client = TestClient(create_app(settings), headers={"Authorization": "Bearer " + settings.token})
    defaults = payload(image_file)
    defaults.pop("device")
    body = {
        "name": "consoles",
        "defaults": defaults,
        "queue": "priority",
        "start_at": "2020-01-01T00:00:00Z",
        "waves": [{"wave": 1, "devices": ["192.0.2.72"]}, {"wave": 2, "devices": ["192.0.2.73"]}],
    }
    response = client.post("/api/v1/opengear/upgrade-batches", json=body)
    assert response.status_code == 202, response.text
    batch = response.json()
    assert batch["kind"] == "opengear_upgrade" and {j["queue"] for j in batch["jobs"]} == {"priority"}
    job = store.claim("w")
    assert job["device"] == "192.0.2.72" and store.claim("w2") is None
    assert job["request"]["start_at"] == "2020-01-01T00:00:00Z"
    called = []

    class Runner:
        def __init__(self, *args):
            called.append(args[2]["id"])

        def run(self):
            store.finish(job["id"], "w", "succeeded")

    monkeypatch.setattr(worker, "OpengearRunner", Runner)
    worker.process(settings, store, job, "w")
    assert called == [job["id"]] and store.claim("w2")["device"] == "192.0.2.73"
    assert client.get("/api/v1/upgrade-batches/" + batch["id"]).status_code == 200
    with pytest.raises(ValueError):
        OpengearBatch.model_validate({**body, "overrides": {"unknown": {}}})


@pytest.mark.parametrize(
    "override",
    [
        {"staging_directory": "/tmp/../etc"},
        {"staging_directory": "/tmp;id"},
        {"staging_directory": "/"},
        {"backup_directory": "../../etc"},
        {"target_version": "5.3.3; reboot"},
        {"image": {"name": "om.raucb", "sha256": SHA}},
        {"reboot": False},
    ],
)
def test_request_rejects_unsafe_or_unsupported_options(image_file, override):
    with pytest.raises(ValueError):
        OpengearUpgradeRequest.model_validate({**payload(image_file), **override})
