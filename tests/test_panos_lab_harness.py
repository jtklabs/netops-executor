import re
from urllib.parse import parse_qs

import httpx
from conftest import Clock
from lab import panos_direct
from test_panos import TARGET, FakeFirewall, FakePair


class DirectTransport:
    """Each fake firewall answers its own XML API, as real lab firewalls do."""

    def __init__(self, firewalls):
        self.firewalls = firewalls

    def __call__(self, request):
        fw = self.firewalls[request.url.host]
        if request.method == "GET":
            return httpx.Response(200, text='<response status="success"><result/></response>')
        if request.url.params.get("type") == "import":
            filename = re.search(rb'filename="([^"]+)"', request.content).group(1).decode()
            fw.write("import " + filename)
            fw.software[filename.split("-", 1)[1]] = True
            return httpx.Response(200, text='<response status="success"><msg>uploaded</msg></response>')
        body = fw.handle_form({k: v[0] for k, v in parse_qs(request.content.decode()).items()})
        if body is None:
            return httpx.Response(
                200, text='<response status="error"><msg><line>failed</line></msg></response>'
            )
        if isinstance(body, bytes):
            return httpx.Response(200, content=body, headers={"content-type": "application/octet-stream"})
        return httpx.Response(200, text=f'<response status="success"><result>{body}</result></response>')


def harness(tmp_path, monkeypatch, *args):
    a, b = FakeFirewall("0079510001", preemptive="yes"), FakeFirewall("0079510002")
    a.family = b.family = "vm"
    a.mgmt_ip, b.mgmt_ip = "10.0.0.1", "10.0.0.2"
    FakePair(a, b)
    client = httpx.Client
    monkeypatch.setattr(
        "netops_executor.panos.httpx.Client",
        lambda **kwargs: client(
            transport=httpx.MockTransport(DirectTransport({"10.0.0.1": a, "10.0.0.2": b})), **kwargs
        ),
    )
    keys = []
    for address in ("10.0.0.1", "10.0.0.2"):
        key = tmp_path / (address + ".key")
        key.write_text("lab-key\n")
        keys += ["--firewall", f"{address}={key}"]
    clock = Clock()
    report = panos_direct.main(
        [*args, *keys, "--workdir", str(tmp_path / "run"), "--validation-timeout", "60"],
        clock.sleep,
        clock.clock,
    )
    return report, a, b


def test_discover_reads_both_firewalls_without_writes(tmp_path, monkeypatch):
    report, a, b = harness(tmp_path, monkeypatch, "discover")
    assert {d["serial"]: d["ha_peer"] for d in report["devices"]} == {a.serial: b.serial, b.serial: a.serial}
    assert report["firewalls"][a.serial]["ha_state"]["local"] == "active"
    assert a.writes == b.writes == []


def test_ha_cycle_runs_standby_first_failover_and_restores_preemption(tmp_path, monkeypatch):
    report, a, b = harness(
        tmp_path, monkeypatch, "ha-cycle", "--allow-writes", "--no-tech-support", "--commit-check"
    )
    assert report["status"] == "succeeded", report
    assert report["commit_check"][b.serial] == {"preemptive": "no", "commit": "OK", "details": "Commit OK"}
    assert b.writes == ["preemptive-no", "commit", "suspend", "functional"]
    assert a.writes == [
        "preemptive-yes",
        "commit",
        "preemptive-no",
        "commit",
        "suspend",
        "functional",
        "preemptive-yes",
        "commit",
    ]
    assert report["survivor_state"] == "active"


def test_upgrade_imports_local_images_in_place_of_panorama_push(tmp_path, monkeypatch):
    images = tmp_path / "images"
    images.mkdir()
    for version in ("11.1.0", TARGET):
        (images / ("PanOS_vm-" + version)).write_bytes(b"image")
    report, a, b = harness(
        tmp_path,
        monkeypatch,
        "upgrade",
        "--allow-writes",
        "--images",
        str(images),
        "--target",
        TARGET,
        "--allowed-source",
        "10.2.9-h1",
    )
    assert report["status"] == "succeeded", report
    assert a.version == b.version == TARGET
    assert b.writes[:2] == ["import PanOS_vm-11.1.0", "import PanOS_vm-" + TARGET]


def test_preload_through_the_executor_upload_path(tmp_path, monkeypatch):
    images = tmp_path / "images"
    images.mkdir()
    (images / ("PanOS_vm-" + TARGET)).write_bytes(b"image")
    report, a, b = harness(
        tmp_path,
        monkeypatch,
        "preload",
        "--allow-writes",
        "--source",
        "executor",
        "--images",
        str(images),
        "--target",
        TARGET,
        "--allowed-source",
        "10.2.9-h1",
    )
    assert report["status"] == "succeeded", report
    assert a.writes == b.writes == ["import PanOS_vm-" + TARGET]
    assert {s["source"] for s in report["software"].values()} == {"executor"}
