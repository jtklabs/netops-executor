import copy
import hashlib
from pathlib import Path

import pytest

from netops_executor.config import Device, Settings
from netops_executor.store import Store


@pytest.fixture
def settings(tmp_path):
    for folder in ("data", "images", "backups"):
        (tmp_path / folder).mkdir()
    return Settings(
        "test-token-" + "x" * 40,
        tmp_path / "data",
        tmp_path / "images",
        tmp_path / "backups",
        tmp_path / "known_hosts",
        {"lab": Device(id="lab", host="192.0.2.10")},
    )


@pytest.fixture
def store(settings):
    return Store(settings.data_dir / "jobs.sqlite3")


@pytest.fixture
def image(settings):
    content = b"fixture image; not vendor software"
    (settings.image_root / "BIGIP.iso").write_bytes(content)
    return {
        "name": "BIGIP.iso",
        "sha256": hashlib.sha256(content).hexdigest(),
        "version": "17.1.2",
        "build": "0.0.5",
        "kind": "image",
    }


def snapshot(volume="HD1.1", version="16.1.5", build="0.0.3", boot="old-boot"):
    stats = {
        "up": 1,
        "total": 2,
        "objects": {
            "/Common/up": {"up": True, "availability": "available", "enabled": "enabled", "connections": 100},
            "/Common/disabled": {
                "up": False,
                "availability": "available",
                "enabled": "disabled",
                "connections": 0,
            },
        },
    }
    return {
        "active": {
            "volume": volume,
            "version": version,
            "build": build,
            "basebuild": build,
            "status": "complete",
            "active": True,
        },
        "boot_id": boot,
        "waf_policies": 1,
        "waf_policy_names": ["/Tenant/policy"],
        "asm_provision": "nominal",
        **{key: copy.deepcopy(stats) for key in ("virtual_servers", "pools", "nodes", "virtual_ips")},
    }


class FakeSSH:
    def __init__(self):
        self.commands = []
        self.remote = {}

    def tmsh(self, command, **kwargs):
        self.commands.append((command, kwargs))
        return ""

    def shell(self, command, **kwargs):
        self.commands.append((command, kwargs))
        if command.startswith("mv --"):
            _, _, source, dest = command.split()
            self.remote[dest] = self.remote[source]
        return ""

    def put(self, local, remote):
        self.remote[remote] = Path(local).read_bytes()

    def get(self, remote, local):
        Path(local).write_bytes(b"fixture backup")

    def remote_digest(self, remote):
        return hashlib.sha256(self.remote[remote]).hexdigest()

    def close(self):
        pass


class FakeDevice:
    def __init__(self):
        self.ssh = FakeSSH()
        self.snap = snapshot()
        self.v = {
            "HD1.1": self.snap["active"].copy(),
            "HD1.2": {
                "volume": "HD1.2",
                "version": "17.1.2",
                "build": "0.0.5",
                "basebuild": "0.0.5",
                "status": "complete",
                "active": False,
            },
        }
        self.addresses = {"/Common/192.0.2.20": True, "/Tenant/192.0.2.30": False}
        self.address_changes = []
        self.counts = iter([100, 10, 0])
        self.last_count = 0
        self.reboots = []
        self.installs = []
        self.new_boot = True
        self.auto_sync = False

    def topology(self):
        return {
            "self": "/Common/lab",
            "cluster": None,
            "members": [{"name": "/Common/lab", "host": "192.0.2.10"}],
            "role": "active",
            "groups": [],
            "auto_sync": self.auto_sync,
            "sync": "standalone",
        }

    def free_bytes(self):
        return 100 * 1024**3

    def start_copy(self, source, target, job):
        self.ssh.commands.append(("cpcfg " + source + " " + target, {}))
        return "/var/tmp/netops-executor-" + job

    def copy_status(self, directory):
        return True

    def snapshot(self):
        return copy.deepcopy(self.snap)

    def active(self):
        return self.snap["active"].copy()

    def boot_id(self):
        return self.snap["boot_id"]

    def volumes(self):
        return copy.deepcopy(self.v)

    def verify_image(self, image):
        pass

    def install(self, image, volume, create):
        self.installs.append((image.name, volume, create))
        self.v[volume] = {
            "volume": volume,
            "version": image.version,
            "build": image.build,
            "basebuild": image.build,
            "status": "complete",
            "active": False,
        }

    def reboot(self, volume):
        self.reboots.append(volume)
        if self.new_boot:
            self.v[self.snap["active"]["volume"]]["active"] = False
            self.v[volume]["active"] = True
            self.snap["active"] = self.v[volume].copy()
            self.snap["boot_id"] += "-new"

    def address_states(self):
        return self.addresses.copy()

    def set_enabled(self, address, enabled):
        self.address_changes.append((address, enabled))
        self.addresses[address] = enabled

    def connections(self):
        self.last_count = next(self.counts, self.last_count)
        return self.last_count

    def check_drain(self):
        if self.auto_sync:
            from netops_executor.ssh import DeviceError

            raise DeviceError("automatic config sync enabled")


class Clock:
    now = 0

    def clock(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds
