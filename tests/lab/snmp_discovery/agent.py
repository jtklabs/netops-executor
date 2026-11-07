"""Serve every lab walk on its own address from one container.

Runs inside the agent container. The container's own address is the stack's;
each other device's address is added to eth0, which makes this container
answer ARP for it on the lab bridge. Each device is a separate snmpd from the
snmp-inventory emulator, bound to its address on UDP 161.

STACK_WALK picks which 9300 walk the stack address serves, so lab.py can fail
the stack over by recreating this container.
"""

import json
import os
import signal
import subprocess
import sys

sys.path.insert(0, "/emulator")

from emulator import EmulatedDevice  # noqa: E402

WALKS = "/walks"


def main() -> int:
    with open(os.path.join(WALKS, "fleet.json")) as handle:
        fleet = json.load(handle)
    stack_walk = os.environ.get("STACK_WALK", "c9300-stack")
    own = subprocess.run(["hostname", "-i"], capture_output=True, text=True, check=True).stdout.split()
    devices = []
    for name, address in fleet.items():
        if address not in own:
            subprocess.run(["ip", "addr", "add", f"{address}/24", "dev", "eth0"], check=True)
        walk = stack_walk if name == "c9300-stack" else name
        device = EmulatedDevice(os.path.join(WALKS, f"{walk}.walk"), port=161, listen=address)
        device.start()
        devices.append(device)
        print(f"{name:24s} {address} ({walk})", flush=True)
    print(f"{len(devices)} devices up", flush=True)
    signal.sigwait({signal.SIGTERM, signal.SIGINT})
    for device in devices:
        device.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
