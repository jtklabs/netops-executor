"""Explicit platform selection; commands remain native device syntax."""

from typing import Literal

DeviceType = Literal["linux", "f5", "cisco_ios", "cisco_nxos", "arista_eos", "fortinet"]
NETWORK_TYPES = {"cisco_ios", "cisco_nxos", "arista_eos", "fortinet"}


def validate_commands(request, device_type):
    if device_type not in NETWORK_TYPES:
        if request.enable or any(c.mode != "exec" for c in request.commands):
            raise ValueError("enable and config mode require a network CLI device_type")
    elif any("\n" in c.command or "\r" in c.command for c in request.commands):
        raise ValueError("network CLI requires one line per command; use multiple command entries")
