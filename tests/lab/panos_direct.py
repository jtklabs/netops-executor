"""Run the real PAN-OS upgrade runner against lab firewalls without a Panorama.

Requests that production sends through Panorama with target=<serial> go straight to that
firewall's XML API, unchanged. Only Panorama's own commands are emulated: the device list
comes from each firewall's system info and HA state, and the software repository is a
local directory of PanOS_<family>-<version> files imported with type=import&category=software.
This exercises every firewall command and parser the product sends; Panorama's device
list fields, batch software commands and target relay remain unverified.

Not collected by pytest. Read-only modes need no flag. Modes that change a firewall need
--allow-writes; take Hyper-V checkpoints of both firewalls first.

    python tests/lab/panos_direct.py \\
        --firewall 10.50.10.168=~/.config/netops-lab/pan-10.50.10.168.key \\
        --firewall 10.50.10.169=~/.config/netops-lab/pan-10.50.10.169.key discover

Modes: discover, readiness, backup (read-only); ha-cycle, reboot-suspended, upgrade, preload,
f5-drain (writes). f5-drain runs the PAN job's F5 precheck, drain and restore against --f5 over
SSH (host keys pinned on first use); --f5-allow-clustered lets a lab HA F5 continue past the
production refusal so the real disable, restore, save and read-back run.
With --source executor the product's own direct upload (type=import) runs instead of the
emulated Panorama push, from --images.
"""

import argparse
import json
import os
import sys
import time
import types
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from netops_executor import panos
from netops_executor.config import Device, HTTPTarget, Settings
from netops_executor.credentials import Credential, Vault, initialize_key
from netops_executor.panos import Firewall, Panorama, PanosError, text
from netops_executor.panos_engine import PanosRunner, carries
from netops_executor.panos_models import PanosUpgradeRequest
from netops_executor.ssh import digest
from netops_executor.store import NeedsReview, Store

WRITES = ("ha-cycle", "reboot-suspended", "upgrade", "preload", "f5-drain")


def field(cmd, name):
    return cmd.split("<" + name + ">")[1].split("<")[0]


class DirectPanorama(Panorama):
    """Stands in for Panorama: proxied requests go to each firewall's own API."""

    def __init__(self, clients, images):
        self.clients, self.images = clients, images
        self.selector = next(iter(clients.values())).selector
        self.jobs = {}
        self.import_wait = 1200

    def request(self, form, **kwargs):
        if form.get("target"):
            proxied = {k: v for k, v in form.items() if k != "target"}
            result = self.clients[form["target"]].request(proxied, **kwargs)
            if isinstance(result, ET.Element):
                # Unlicensed lab VMs report serial "unknown"; Panorama-managed firewalls always have one.
                for node in result.iter("serial"):
                    if (node.text or "").strip() == "unknown":
                        node.text = form["target"]
            return result
        return self.emulate(form["cmd"])

    def address(self, serial):
        return urlsplit(self.clients[serial].target.base_url).hostname

    def emulate(self, cmd):
        result = ET.Element("result")
        if cmd == panos.DEVICES:
            devices = ET.SubElement(result, "devices")
            for serial, client in self.clients.items():
                entry = ET.SubElement(devices, "entry", name=serial)
                ET.SubElement(entry, "serial").text = serial
                try:
                    system = client.op(panos.SYSTEM_INFO).find("system")
                    ha = Firewall(self, serial).ha_state()
                except PanosError:
                    ET.SubElement(entry, "connected").text = "no"
                    continue
                ET.SubElement(entry, "connected").text = "yes"
                for key in ("model", "sw-version", "family", "hostname"):
                    ET.SubElement(entry, key).text = text(system, key)
                ET.SubElement(entry, "ip-address").text = self.address(serial)
                # Panorama reports ha/peer/serial; here the peer is the firewall at the peer mgmt IP.
                peer = next((s for s in self.clients if self.address(s) == ha["peer_mgmt_ip"]), None)
                if ha["enabled"] and peer:
                    node = ET.SubElement(entry, "ha")
                    ET.SubElement(node, "state").text = ha["local"]
                    ET.SubElement(ET.SubElement(node, "peer"), "serial").text = peer
            return result
        if cmd in (panos.REPOSITORY_INFO, panos.REPOSITORY_CHECK):
            versions = ET.SubElement(ET.SubElement(result, "sw-updates"), "versions")
            for path in sorted(self.images.glob("PanOS_*")):
                entry = ET.SubElement(versions, "entry")
                ET.SubElement(entry, "version").text = path.name.split("-", 1)[1]
                ET.SubElement(entry, "filename").text = path.name
                ET.SubElement(entry, "downloaded").text = "yes"
            return result
        if cmd.startswith("<request><batch><software><download>"):
            raise PanosError("direct lab mode has no Panorama update server; add the file to --images")
        if cmd.startswith("<request><batch><software><upload>"):
            return self.upload(field(cmd, "file"), field(cmd, "devices"))
        if cmd == panos.JOBS:
            for job_id in self.jobs:
                result.append(self.job_element(job_id))
            return result
        if cmd.startswith("<show><jobs><id>"):
            result.append(self.job_element(int(field(cmd, "id"))))
            return result
        raise PanosError("unsupported Panorama command in direct lab mode: " + cmd[:80])

    def upload(self, filename, serial):
        path = self.images / filename
        if not path.is_file():
            raise PanosError(filename + " is not in " + str(self.images))
        client = self.clients[serial]
        auth = client.connect()
        try:
            with path.open("rb") as stream:
                response = client.client.post(
                    "/api/",
                    params={"type": "import", "category": "software"},
                    files={"file": (filename, stream)},
                    timeout=3600,
                    **auth,
                )
            try:
                root = ET.fromstring(response.content)
                ok, details = root.get("status") == "success", panos.message(root)
            except ET.ParseError:
                ok, details = False, "HTTP " + str(response.status_code)
        except httpx.HTTPError as exc:
            ok, details = False, type(exc).__name__
        if not ok:
            # The web front end can answer 504 on a large import while the firewall keeps working.
            version = filename.split("-", 1)[1]
            deadline = time.monotonic() + self.import_wait
            while time.monotonic() < deadline:
                time.sleep(20)
                try:
                    if Firewall(self, serial).software().get(version, {}).get("downloaded"):
                        ok, details = True, details + "; image listed after the error"
                        break
                except PanosError:
                    pass
        self.jobs[len(self.jobs) + 1] = {
            "type": "SWUpload",
            "result": "OK" if ok else "FAIL",
            "details": details,
        }
        result = ET.Element("result")
        ET.SubElement(result, "job").text = str(len(self.jobs))
        return result

    def job_element(self, job_id):
        job = self.jobs[job_id]
        node = ET.Element("job")
        for key, value in (
            ("id", job_id),
            ("type", job["type"]),
            ("status", "FIN"),
            ("result", job["result"]),
        ):
            ET.SubElement(node, key).text = str(value)
        ET.SubElement(ET.SubElement(node, "details"), "line").text = job["details"]
        return node

    def close(self):
        for client in self.clients.values():
            client.close()


def build(args):
    work = Path(args.workdir).expanduser().resolve()
    work.mkdir(parents=True, exist_ok=True, mode=0o700)
    work.chmod(0o700)
    for folder in ("data", "images", "backups"):
        (work / folder).mkdir(parents=True, exist_ok=True, mode=0o700)
    settings = Settings(
        "lab-" + "x" * 40, work / "data", work / "images", work / "backups", work / "known_hosts", {}
    )
    settings.credential_key_file = work / "vault.key"
    if not settings.credential_key_file.exists():
        initialize_key(settings.credential_key_file)
    store = Store(work / "data" / "jobs.sqlite3")
    vault = Vault(store, settings.credential_key_file)
    if getattr(args, "f5", None):
        # Legacy key_file inventory: the product loads the operator's existing SSH key in place.
        key = str(Path(args.f5_key).expanduser())
        settings.devices[args.f5] = Device(id=args.f5, host=args.f5, username="root", key_file=key)
        settings.ssh_host_keys = "pin"
    for spec in args.firewall or []:
        address, _, key_file = spec.partition("=")
        target = "fw-" + address
        settings.http_targets[target] = HTTPTarget(
            id=target,
            base_url="https://" + address,
            auth_probe_path="/api/",
            auth_probe_params={"type": "version"},
            # Lab firewalls are self-signed: exercise the product's pin-on-first-use path.
            tls="pin",
            # ADDRESS alone uses the saved login "login-ADDRESS" (scheme keygen) from credential-put.
            credential_profiles=[target if key_file else "login-" + address],
        )
        if not key_file:
            continue
        token = Path(key_file).expanduser().read_text().strip()
        if not token:
            raise SystemExit("empty API key file: " + key_file)
        vault.put(
            target,
            Credential(
                kind="http", scheme="header", header="X-PAN-KEY", token=token, targets=[target, address]
            ),
        )
    return settings, store


def direct(settings, store, images, guard=lambda: None, audit=lambda _: None):
    clients = {}
    for target in settings.http_targets:
        client = Panorama(settings, store, target, None, guard, audit)
        serial = text(client.op(panos.SYSTEM_INFO).find("system"), "serial")
        if serial in ("", "unknown"):
            address = urlsplit(client.target.base_url).hostname
            serial = "LAB" + "".join(f"{int(octet):03d}" for octet in address.split("."))
        clients[serial] = client
    return DirectPanorama(clients, images)


def discover(panorama):
    report = {"devices": [], "firewalls": {}}
    report["devices"] = [panorama.device(serial) for serial in panorama.clients]
    for serial in panorama.clients:
        fw = Firewall(panorama, serial)
        item = report["firewalls"][serial] = {}
        for name, read in (
            ("system_info", fw.system_info),
            ("ha_state", fw.ha_state),
            ("chassis_ready", fw.chassis_ready),
            ("pending_changes", fw.pending_changes),
            ("jobs", lambda: fw.jobs()[-5:]),
            ("software", fw.software),
            ("interfaces", fw.interfaces),
            ("routes", lambda: len(fw.routes())),
            ("bgp_peers", fw.bgp_peers),
            ("ipsec_tunnels", fw.tunnels),
            ("sessions", fw.session_count),
            ("arp", fw.arp_count),
        ):
            try:
                item[name] = read()
            except PanosError as exc:
                item[name] = {"error": str(exc)}
    return report


def run_job(args, settings, store, images, sleep, clock):
    probe = direct(settings, store, images)
    serial = next(iter(probe.clients))
    current = Firewall(probe, serial).system_info()["sw_version"]
    probe.close()
    options = {
        "serial": serial,
        "panorama": "lab-direct",
        "target_version": args.target or current,
        "allowed_source_versions": args.allowed_source or [current],
        "tech_support": args.tech_support,
        "validation_timeout": args.validation_timeout,
        "software_source": args.source,
        "stage_only": args.mode == "preload",
    }
    if args.mode == "f5-drain":
        options["f5_drain"] = {"device": args.f5, "addresses": args.f5_address or [], "timeout_seconds": 120}
    if args.source == "executor":
        # The executor uploads from its own image root.
        settings.image_root = images.resolve()
        options["images"] = [{"name": p.name, "sha256": digest(p)} for p in sorted(images.glob("PanOS_*"))]
    if args.family:
        options["software_family"] = args.family
    request = PanosUpgradeRequest.model_validate(options)
    store.submit(request.model_dump(mode="json"), "panos:" + serial, kind="panos_upgrade")
    worker = "lab-harness"
    job = store.claim(worker)
    runner = PanosRunner(settings, store, job, worker, sleep=sleep, clock=clock)
    runner.panorama = direct(settings, store, images, runner.guard, runner.audit)
    if args.mode in ("upgrade", "preload"):
        runner.run()
        return store.get(job["id"])
    status = "succeeded"
    try:
        runner.setup()
        runner.reserve()
        runner.prevalidate()
        if args.mode == "backup":
            for member in runner.members:
                runner.backup(member)
        if args.mode == "f5-drain":
            # Only the F5 is exercised; the lab PAN pair just provides the job context.
            runner.result["ha"] = {**runner.result["ha"], "enabled": False}
            try:
                runner.f5_precheck()
                runner.result["f5_production_precheck"] = "passed"
            except PanosError as exc:
                runner.result["f5_production_precheck"] = str(exc)
                if not args.f5_allow_clustered:
                    raise
                f5 = runner.f5()
                f5.check_drain()
                states = runner.f5_selected(f5.address_states())
                runner.result["f5_drain"] = {
                    "device": args.f5,
                    "address_states": states,
                    "to_disable": sorted(a for a, enabled in states.items() if enabled),
                    "changed_addresses": [],
                    "pending_restore": [],
                    "restored": False,
                }
            runner.f5_drain()
            runner.result["f5_states_while_drained"] = runner.f5_selected(runner.f5().address_states())
            runner.f5_restore()
        if args.mode in ("ha-cycle", "reboot-suspended"):
            if not runner.ha["enabled"]:
                raise PanosError("HA is not enabled on " + serial)
            standby = next(
                s for s in runner.members if runner.member(s)["role"] in ("passive", "active-secondary")
            )
            active = runner.peer_of(standby)
            if args.commit_check:
                # Same-value set and commit: proves the HA election xpath and commit job path without
                # changing behavior when preemption is already off.
                checks = runner.result["commit_check"] = {}
                for member in runner.members:
                    value = runner.member(member)["preemptive"]
                    fw = runner.fw(member)
                    fw.set_config(panos.HA_ELECTION, "<preemptive>" + value + "</preemptive>")
                    commit = runner.wait_job(fw.commit(), 900, "commit", False, fw)
                    checks[member] = {
                        "preemptive": value,
                        "commit": commit["result"],
                        "details": commit["details"][:300],
                    }
                    if commit["result"] != "OK":
                        raise PanosError("commit check failed on " + member)
            runner.preemption("no")
            runner.suspend(standby)
            runner.validate("lab_standby_suspended", lambda: runner.pair_sample(suspended={standby}))
            if args.mode == "reboot-suspended":
                # Same-version restart: verifies a new boot and whether suspension survives it.
                runner.reboot(standby)
                runner.result["suspended_after_reboot"] = runner.fw(standby).ha_state()["local"]
                runner.settle()
                runner.validate("lab_standby_system", lambda: runner.system_sample(standby))
                runner.validate("lab_standby_rebooted", lambda: runner.pair_sample(suspended={standby}))
            runner.make_functional(standby)
            runner.validate("lab_standby_functional", runner.pair_sample)
            if args.mode == "ha-cycle":
                runner.handoff(active)
                survivor = runner.fw(standby).ha_state()
                runner.result["survivor_state"] = survivor["local"]
                assert carries(survivor["local"])
                runner.make_functional(active)
                runner.validate("lab_active_functional", runner.pair_sample)
            runner.preemption(None)
            runner.validate("lab_final", runner.pair_sample)
    except NeedsReview:
        status = "needs_review"
    except Exception as exc:
        runner.result["error"] = str(exc) if isinstance(exc, PanosError) else repr(exc)
        status = "failed"
        try:
            runner.restore_service()
        except Exception as restore:
            runner.result["restore_error"] = repr(restore)
    finally:
        try:
            runner.event("lab_" + args.mode + "_" + status)
            store.finish(job["id"], worker, status)
        except Exception:
            pass
        runner.panorama.close()
    return store.get(job["id"])


def summary(job):
    result = job["result"]
    return {
        "status": job["status"],
        "error": result.get("error"),
        "issues": result.get("validation_issues"),
        "differences": result.get("validation_differences"),
        "ha": result.get("ha"),
        "members": {
            s: {k: m.get(k) for k in ("role", "preemptive", "source", "suspended", "boot_verified")}
            for s, m in result.get("members", {}).items()
        },
        "preemption": result.get("preemption"),
        "upgrade_plan": result.get("upgrade_plan"),
        "artifacts": result.get("artifacts"),
        "gaps": {
            k: v.get("gaps")
            for k, v in result.get("pre_validation", {}).get("traffic", {}).items()
            if isinstance(v, dict)
        },
        "suspended_after_reboot": result.get("suspended_after_reboot"),
        "survivor_state": result.get("survivor_state"),
        "commit_check": result.get("commit_check"),
        "f5_production_precheck": result.get("f5_production_precheck"),
        "f5_drain": result.get("f5_drain"),
        "f5_states_while_drained": result.get("f5_states_while_drained"),
        "progress": result.get("progress"),
        "software": {s: m.get("software") for s, m in result.get("members", {}).items()},
        "gates": [{"phase": g["phase"], "findings": g["findings"]} for g in job["validation_gates"]],
    }


def main(argv=None, sleep=time.sleep, clock=time.monotonic):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("mode", choices=["discover", "readiness", "backup", "credential-put", *WRITES])
    p.add_argument("name", nargs="?", help="credential-put: profile name; reads credential JSON from stdin")
    p.add_argument(
        "--firewall", action="append", help="ADDRESS=API_KEY_FILE, or ADDRESS to use the saved login-ADDRESS"
    )
    p.add_argument(
        "--workdir", default="~/.config/netops-lab/run", help="Private job store, vault and backups"
    )
    p.add_argument("--images", default=None, help="Directory of PanOS_<family>-<version> files")
    p.add_argument("--target")
    p.add_argument("--allowed-source", action="append")
    p.add_argument("--family")
    p.add_argument("--source", choices=["panorama", "executor"], default="panorama")
    p.add_argument("--f5", help="F5 management IP for f5-drain")
    p.add_argument(
        "--f5-key", default="~/.ssh/id_rsa", help="Existing SSH private key file for root on the F5"
    )
    p.add_argument(
        "--f5-address", action="append", help="Virtual address to drain, such as /Common/10.1.1.10"
    )
    p.add_argument(
        "--f5-allow-clustered", action="store_true", help="Lab only: continue past the clustered-F5 refusal"
    )
    p.add_argument("--tech-support", action=argparse.BooleanOptionalAction, default=True)
    p.add_argument("--validation-timeout", type=int, default=900)
    p.add_argument(
        "--insecure",
        action="store_true",
        help="Skip TLS checks entirely instead of pinning first-use certificates",
    )
    p.add_argument("--allow-writes", action="store_true")
    p.add_argument(
        "--commit-check",
        action="store_true",
        help="ha-cycle: set each member's current preemptive value and commit, to exercise the config/commit path",
    )
    args = p.parse_args(argv)
    os.umask(0o077)
    if args.mode in WRITES and not args.allow_writes:
        raise SystemExit(args.mode + " changes firewalls; pass --allow-writes after taking checkpoints")
    if args.insecure:
        real = httpx.Client

        def client(**kwargs):
            return real(**{**kwargs, "verify": False})

        panos.httpx = types.SimpleNamespace(Client=client, HTTPError=httpx.HTTPError)
    settings, store = build(args)
    if args.mode == "credential-put":
        # Secrets arrive on stdin and are stored encrypted; only metadata is printed.
        stored = Vault(store, settings.credential_key_file).put(
            args.name, Credential.model_validate_json(sys.stdin.read())
        )
        print(json.dumps({k: stored[k] for k in ("id", "kind", "revision")}))
        return stored
    if not args.firewall:
        raise SystemExit("--firewall is required")
    images = Path(args.images).expanduser() if args.images else settings.image_root
    if args.mode == "discover":
        panorama = direct(settings, store, images)
        try:
            report = discover(panorama)
        finally:
            panorama.close()
    else:
        job = run_job(args, settings, store, images, sleep, clock)
        out = Path(args.workdir).expanduser() / ("result-" + args.mode + ".json")
        out.write_text(json.dumps(job, indent=2, default=str))
        report = summary(job)
    json.dump(report, sys.stdout, indent=2, default=str)
    print()
    return report


if __name__ == "__main__":
    main()
