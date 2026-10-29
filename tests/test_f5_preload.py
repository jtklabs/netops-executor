import pytest
from conftest import Clock, FakeDevice
from fastapi.testclient import TestClient

from netops_executor.api import create_app
from netops_executor.engine import Runner
from netops_executor.models import JobRequest
from netops_executor.ssh import DeviceError


def run(settings, store, payload, device=None, key="device:lab"):
    request = JobRequest(device="lab", **payload)
    store.submit(request.model_dump(), key)
    job = store.claim("worker")
    fake = device or FakeDevice()
    clock = Clock()
    Runner(settings, store, job, "worker", fake, clock.sleep, clock.clock).run()
    return store.get(job["id"]), fake


def steps(store, job):
    return [e["step"] for e in store.events(job["id"], 0, 1000)]


def test_preload_uploads_and_verifies_without_touching_the_running_system(settings, store, image):
    fake = FakeDevice()
    fake.snapshot = lambda: pytest.fail("a preload must not take a traffic snapshot")
    fake.topology = lambda: pytest.fail("a preload must not reserve the HA pair")
    put = fake.ssh.put

    def upload(local, remote):
        put(local, remote)
        size = len(fake.ssh.remote[remote])
        fake.ssh.progress(size // 2, size)
        fake.ssh.progress(size, size)

    fake.ssh.put = upload
    job, _ = run(settings, store, {"stage_only": True, "images": [image]}, fake)
    assert job["status"] == "succeeded", job["result"]
    result = job["result"]
    assert result["preloaded"] == ["BIGIP.iso"] and result["source"]["version"] == "16.1.5"
    assert result["plan"] == ["preload_checks", "transfer", "verify_images"]
    assert "/shared/images/BIGIP.iso" in fake.ssh.remote and not result.get("mutations")
    assert (
        result["transfer_progress"]["percent"] == 100 and result["transfer_progress"]["image"] == "BIGIP.iso"
    )
    events = steps(store, job)
    assert "transfer_completed" in events and "image_verified" in events and "transfer_progress" in events
    assert not any(c.startswith(("save", "tmsh save", "cpcfg")) for c, _ in fake.ssh.commands)
    keys = next(
        e["data"]["keys"] for e in store.events(job["id"], 0, 100) if e["step"] == "resources_reserved"
    )
    assert keys == ["device:lab", "endpoint:192.0.2.10"]


def test_preloaded_image_is_reused_without_an_executor_copy(settings, store, image):
    fake = FakeDevice()
    job, fake = run(settings, store, {"stage_only": True, "images": [image]}, fake)
    assert job["status"] == "succeeded"
    # Without the executor's copy, the device copy is verified in place.
    (settings.image_root / "BIGIP.iso").unlink()
    job, _ = run(settings, store, {"stage_only": True, "images": [image]}, fake)
    assert job["status"] == "succeeded", job["result"]
    assert "transfer_skipped_verified" in steps(store, job)
    fake.v["HD1.2"]["version"] = "16.0.0"
    job, _ = run(
        settings,
        store,
        {
            "install": True,
            "target_volume": "HD1.2",
            "allowed_source_versions": ["16.1.5"],
            "ucs_unencrypted": True,
            "images": [image],
        },
        fake,
    )
    assert job["status"] == "succeeded", job["result"]
    assert "transfer_skipped_verified" in steps(store, job) and fake.installs


def test_failed_upload_removes_the_partial_file_and_fails_cleanly(settings, store, image):
    fake = FakeDevice()

    def put(local, remote):
        fake.ssh.remote[remote] = b"truncated"

    fake.ssh.put = put
    job, _ = run(settings, store, {"stage_only": True, "images": [image]}, fake)
    assert job["status"] == "failed" and "SHA-256 mismatch" in job["result"]["error"]
    assert any(c.startswith("rm -f -- ") and ".partial" in c for c, _ in fake.ssh.commands)
    assert not job["lock_held"]


@pytest.mark.parametrize(
    "options, error",
    [
        ({"allowed_source_versions": ["15.1.10"]}, "outside allowed_source_versions"),
        ({"approved_models": ["BIG-IP i5800"]}, "hardware model is not approved"),
    ],
)
def test_preload_gates_on_release_and_model_when_given(settings, store, image, options, error):
    fake = FakeDevice()
    fake.platform = lambda: ["BIG-IP Virtual Edition", "Z100"]
    job, _ = run(settings, store, {"stage_only": True, "images": [image], **options}, fake)
    assert job["status"] == "failed" and error in job["result"]["error"]
    assert not fake.ssh.remote


def test_insufficient_space_fails_before_upload(settings, store, image):
    fake = FakeDevice()
    fake.free_bytes = lambda: 10
    job, _ = run(settings, store, {"stage_only": True, "images": [image]}, fake)
    assert job["status"] == "failed" and "insufficient image filesystem space" in job["result"]["error"]
    assert not fake.ssh.remote


def test_stage_only_rejects_disruptive_options(image):
    for extra in (
        {"install": True, "allowed_source_versions": ["16.1.5"]},
        {"create_ucs": True},
        {"images_on_device": True},
    ):
        with pytest.raises(ValueError, match="stage_only"):
            JobRequest(device="lab", stage_only=True, images=[image], **extra)
    with pytest.raises(ValueError, match="requires images"):
        JobRequest(device="lab", stage_only=True)
    assert JobRequest(device="lab", stage_only=True, images=[image]).transfer


def test_preload_batch_through_the_api(settings, store, image):
    client = TestClient(create_app(settings), headers={"Authorization": "Bearer " + settings.token})
    body = {
        "name": "Preload-F5",
        "defaults": {"stage_only": True, "images": [image]},
        "waves": [{"wave": 1, "upgrade_at_a_time": 20, "ips": ["192.0.2.10", "192.0.2.11"]}],
    }
    response = client.post("/api/v1/upgrade-batches", json=body)
    assert response.status_code == 202, response.text
    assert response.json()["device_count"] == 2
    plan = client.post("/api/v1/plan", json={"device": "lab", "stage_only": True, "images": [image]}).json()
    assert plan["steps"] == ["preload_checks", "transfer", "verify_images"]


def test_catalog_that_never_verifies_fails_the_preload(settings, store, image):
    fake = FakeDevice()

    def verify_image(spec):
        raise DeviceError("device image metadata/signature verification does not match manifest")

    fake.verify_image = verify_image
    job, _ = run(settings, store, {"stage_only": True, "images": [image]}, fake)
    assert job["status"] == "failed" and "signature verification" in job["result"]["error"]
