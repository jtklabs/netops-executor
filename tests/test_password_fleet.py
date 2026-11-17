"""Panorama-wide rotation: templates committed on Panorama only, then each firewall-local copy."""

import copy
import json
import xml.etree.ElementTree as ET
from urllib.parse import parse_qs

import httpx
import pytest
from passlib.hash import sha256_crypt
from test_password_panos import api_setup

from netops_executor.credentials import Credential
from netops_executor.password_fleet import PanoramaRotationRunner, push_targets, scopes
from netops_executor.password_panos import account

PASSWORD = "Fleet-Rotation-Password-1!"
USER = "automation"


def user(parent, phash="old"):
    users = parent.find("mgt-config/users")
    if users is None:
        users = ET.SubElement(ET.SubElement(parent, "mgt-config"), "users")
    entry = ET.SubElement(users, "entry", name=USER)
    ET.SubElement(entry, "phash").text = sha256_crypt.hash(phash)
    ET.SubElement(ET.SubElement(ET.SubElement(entry, "permissions"), "role-based"), "superuser").text = "yes"
    return entry


def panorama_config():
    config = ET.fromstring(
        "<config><mgt-config><users/></mgt-config><devices><entry name='localhost.localdomain'>"
        "<template><entry name='T1'><config/></entry><entry name='T2'><config/></entry>"
        "<entry name='T3'><config/></entry></template>"
        "<template-stack>"
        "<entry name='S1'><templates><member>T1</member></templates>"
        "<devices><entry name='000000000001'/><entry name='000000000002'/></devices></entry>"
        "<entry name='S2'><templates><member>T2</member></templates>"
        "<devices><entry name='000000000003'/></devices></entry>"
        "</template-stack></entry></devices></config>"
    )
    templates = config.find("devices/entry/template")
    user(templates.find("entry[@name='T1']/config"))
    # T3 defines the account for external authentication only: never rotated.
    external = user(templates.find("entry[@name='T3']/config"))
    external.remove(external.find("phash"))
    ET.SubElement(external, "authentication-profile").text = "tacacs"
    return config


def firewall_config(local=True):
    config = ET.fromstring("<config><mgt-config><users/></mgt-config><shared/></config>")
    if local:
        user(config)
    return config


class Node:
    def __init__(self, config, behaviour=None):
        self.running, self.candidate = config, copy.deepcopy(config)
        self.behaviour, self.commits, self.locks, self.removed = behaviour, 0, {}, []


class Simulated:
    def __init__(self):
        self.panorama = Node(panorama_config())
        self.firewalls = {
            "000000000001": Node(firewall_config()),  # rotates
            "000000000002": Node(firewall_config(local=False)),  # template only: untouched
            "000000000003": Node(firewall_config(), "deny_set"),  # role may not edit admins
            "000000000004": Node(firewall_config(), "refuse_commit"),  # role may not commit
            "000000000005": Node(firewall_config(), "pending"),  # someone else's changes
        }
        self.firewalls["000000000005"].candidate.find("shared").append(ET.Element("address"))
        self.calls = []

    @staticmethod
    def reply(body=None, status="success", code=None):
        root = ET.Element("response", status=status, **({"code": code} if code else {}))
        root.append(body if body is not None else ET.Element("result"))
        return httpx.Response(200, text=ET.tostring(root, encoding="unicode"))

    def handle(self, req):
        if req.method == "GET":
            return self.reply()
        form = {k: v[0] for k, v in parse_qs(req.content.decode()).items()}
        self.calls.append(form)
        serial = form.get("target")
        node = self.firewalls[serial] if serial else self.panorama
        body = ET.Element("result")
        if form["type"] == "config":
            xpath = form["xpath"].removeprefix("/config").lstrip("/")
            if form["action"] in ("get", "show"):
                source = node.running if form["action"] == "show" else node.candidate
                found = source if not xpath else source.find(xpath)
                if found is not None:
                    body.append(copy.deepcopy(found))
            else:
                if node.behaviour == "deny_set":
                    return self.reply(
                        ET.fromstring("<msg>Unauthorized request</msg>"), status="error", code="403"
                    )
                element = ET.fromstring(form["element"])
                if serial:
                    target = account(node.candidate, USER)
                    target.find("phash").text = element.findtext("phash")
                else:
                    node.candidate.find(xpath).find("phash").text = element.text
        elif form["type"] == "commit":
            if node.behaviour == "refuse_commit":
                return self.reply(
                    ET.fromstring("<msg>admin is not authorized to commit</msg>"), status="error", code="403"
                )
            node.running, node.commits = copy.deepcopy(node.candidate), node.commits + 1
            ET.SubElement(body, "job").text = "9"
        else:
            cmd = ET.fromstring(form["cmd"])
            if cmd.find("devices") is not None:
                devices = ET.SubElement(body, "devices")
                for number, (s, fw) in enumerate(self.firewalls.items(), 1):
                    entry = ET.SubElement(devices, "entry", name=s)
                    for k, v in (
                        ("serial", s),
                        ("connected", "yes"),
                        ("hostname", "fw" + str(number)),
                        ("ip-address", "192.0.2." + str(number)),
                    ):
                        ET.SubElement(entry, k).text = v
                offline = ET.SubElement(devices, "entry", name="000000000009")
                ET.SubElement(offline, "connected").text = "no"
            elif cmd.tag == "check":
                body.text = "no"
            elif cmd.find("system") is not None:
                ET.SubElement(ET.SubElement(body, "system"), "serial").text = serial
            elif cmd.find("password-hash") is not None:
                ET.SubElement(body, "phash").text = sha256_crypt.hash(cmd.findtext("password-hash/password"))
            elif cmd.find("jobs") is not None:
                job = ET.SubElement(body, "job")
                for k, v in (("id", "9"), ("status", "FIN"), ("result", "OK")):
                    ET.SubElement(job, k).text = v
            elif cmd.tag == "load":
                node.candidate = copy.deepcopy(node.running)
            elif cmd.tag == "show" and cmd.find("config") is not None:
                pass  # no pushed template
            else:
                for kind in ("config", "commit"):
                    if cmd.find(kind + "-lock/remove") is not None:
                        node.removed.append(kind)
                    elif cmd.find(kind + "-lock/add") is not None:
                        node.locks[kind] = cmd.findtext(kind + "-lock/add/comment")
                    elif cmd.find(kind + "-locks") is not None:
                        ET.SubElement(ET.SubElement(body, kind + "-locks"), "comment").text = node.locks.get(
                            kind
                        )
        return self.reply(body)


@pytest.fixture
def fleet(settings, store, monkeypatch):
    vault, api = api_setup(settings, store)
    vault.put("panorama-key", Credential(kind="http", scheme="header", header="X-PAN-KEY", token="k"))
    simulated = Simulated()
    original = httpx.Client
    monkeypatch.setattr(
        "netops_executor.panos.httpx.Client",
        lambda **kwargs: original(transport=httpx.MockTransport(simulated.handle), **kwargs),
    )
    return api, simulated


def run(settings, store, api, **options):
    body = {"panorama": "panorama", "username": USER, "password": PASSWORD, "allow_preview": True, **options}
    response = api.post("/api/v1/password-rotation/panorama/jobs", json=body)
    assert response.status_code == 202, response.text
    PanoramaRotationRunner(settings, store, store.claim("worker"), "worker").run()
    return store.get(response.json()["id"])


def phash(config, path):
    return config.find(
        (path + "/" if path else "") + "mgt-config/users/entry[@name='" + USER + "']/phash"
    ).text


def test_templates_commit_on_panorama_and_local_firewalls_rotate_one_by_one(settings, store, fleet):
    api, sim = fleet
    job = run(settings, store, api)
    result = job["result"]
    assert job["status"] == "completed_with_warnings", result

    # Templates: T1 rotated and committed on Panorama only; T3 (external auth) skipped.
    assert {t["name"]: t["status"] for t in result["templates"]} == {"T1": "committed", "T3": "skipped"}
    t1 = "devices/entry/template/entry[@name='T1']/config"
    assert sha256_crypt.verify(PASSWORD, phash(sim.panorama.running, t1))
    assert sim.panorama.commits == 1 and sorted(sim.panorama.removed) == ["commit", "config"]
    assert result["push_required"] == ["000000000001", "000000000002"]
    assert not any(c.get("type") == "op" and "push" in c.get("cmd", "") for c in sim.calls)

    firewalls = result["firewalls"]
    assert firewalls["000000000001"]["status"] == "rotated"
    assert firewalls["000000000001"]["confirmed"] == ["candidate_hash", "commit", "running_hash"]
    assert sha256_crypt.verify(PASSWORD, phash(sim.firewalls["000000000001"].running, ""))
    assert "000000000002" not in firewalls  # template-only firewalls are reached by the push
    assert firewalls["000000000003"]["status"] == "not_accepted"
    assert "permission denied" in firewalls["000000000003"]["reason"]
    assert firewalls["000000000004"]["status"] == "not_accepted"
    assert "reverted" in firewalls["000000000004"]["reason"]
    assert firewalls["000000000005"]["status"] == "skipped"
    assert "pending configuration changes" in firewalls["000000000005"]["reason"]
    for serial in ("000000000003", "000000000004"):
        fw = sim.firewalls[serial]
        assert sha256_crypt.verify("old", phash(fw.running, "")) and fw.commits == 0
        assert ET.tostring(fw.candidate) == ET.tostring(fw.running)
    assert result["mutations"] == ["panorama_templates", "firewall:000000000001"]
    assert result["summary"] == {"rotated": 1, "not_accepted": 2, "skipped": 2, "committed": 1}
    assert PASSWORD not in json.dumps(job) and "$5$" not in json.dumps(job)


def test_dirty_panorama_refuses_before_any_change(settings, store, fleet):
    api, sim = fleet
    sim.panorama.candidate.find("mgt-config/users").append(ET.Element("entry", name="someone"))
    job = run(settings, store, api)
    assert job["status"] == "failed" and "uncommitted changes" in job["result"]["error"]
    assert not job["result"].get("mutations") and sim.panorama.commits == 0
    assert all(fw.commits == 0 for fw in sim.firewalls.values())


def test_firewalls_only_and_serial_filter(settings, store, fleet):
    api, sim = fleet
    job = run(settings, store, api, templates=False, serials=["000000000001", "000000000002", "000000000077"])
    firewalls = job["result"]["firewalls"]
    assert firewalls["000000000001"]["status"] == "rotated"
    assert firewalls["000000000002"] == {
        "hostname": "fw2",
        "address": "192.0.2.2",
        "status": "skipped",
        "reason": "no local account",
    }
    assert firewalls["000000000077"]["reason"] == "not managed by this Panorama"
    assert sim.panorama.commits == 0 and "templates" not in job["result"]


def test_a_firewall_left_mid_change_is_never_replayed(settings, store, fleet):
    api, sim = fleet
    job = run(settings, store, api, templates=False, serials=["000000000001"])
    runner = PanoramaRotationRunner(settings, store, {**job, "result": copy.deepcopy(job["result"])}, "w")
    runner.result["firewalls"]["000000000001"]["status"] = "changing"
    runner.request = None
    with pytest.raises(Exception, match="mid-change"):
        runner.rotate_firewalls()


def test_request_requires_preview_and_a_scope(fleet):
    api, _ = fleet
    base = {"panorama": "panorama", "username": USER, "password": PASSWORD}
    assert api.post("/api/v1/password-rotation/panorama/plan", json=base).status_code == 422
    both_off = {**base, "allow_preview": True, "templates": False, "firewalls": False}
    assert api.post("/api/v1/password-rotation/panorama/plan", json=both_off).status_code == 422
    plan = api.post("/api/v1/password-rotation/panorama/plan", json={**base, "allow_preview": True})
    assert plan.status_code == 200 and plan.json()["lock_key"] == "panorama:panorama"
    assert "password" not in plan.json()["request"]


def test_scope_helpers_find_templates_stacks_and_push_targets():
    config = panorama_config()
    found = scopes(config, USER)
    assert [(s["name"], s["local_password"]) for s in found] == [("T1", True), ("T3", False)]
    assert push_targets(config, [{"kind": "template", "name": "T2"}]) == ["000000000003"]
