#!/usr/bin/env python3
"""net-snmp `pass_persist` backend that replays a recorded walk.

snmpd handles the SNMPv3 protocol — engine discovery, USM authentication,
privacy — and asks this program for values. So the scanner under test talks to
a genuine SNMP agent over a real socket with real crypto; only the numbers come
from a file.

The protocol snmpd speaks on stdin is line based:

    PING            -> PONG
    get\\n<oid>      -> <oid>\\n<type>\\n<value>   or NONE
    getnext\\n<oid>  -> <oid>\\n<type>\\n<value>   or NONE
    set\\n<oid>...   -> not-writable

Values that a real agent would return as binary octet strings — MAC addresses,
mostly — are written back as raw bytes so snmpd prints them as `Hex-STRING`,
exactly as a real device does. That matters because the scanner has to parse
Hex-STRING correctly, and an emulator that only ever produced printable strings
would never exercise that path.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from walkfile import Varbind, load_walk  # noqa: E402


def oid_key(oid: str) -> tuple[int, ...]:
    """Numeric sort key. Lexicographic string order is wrong for OIDs — it puts
    .10 before .2 — and getnext ordering has to match what a real agent does."""
    return tuple(int(part) for part in oid.strip(".").split(".") if part.isdigit())


class Responder:
    def __init__(self, varbinds: list[Varbind]):
        self.varbinds = sorted(varbinds, key=lambda v: oid_key(v.oid))
        self.keys = [oid_key(v.oid) for v in self.varbinds]
        self.by_oid = {v.oid: v for v in self.varbinds}

    def get(self, oid: str) -> Varbind | None:
        return self.by_oid.get(oid.strip().lstrip("."))

    def getnext(self, oid: str) -> Varbind | None:
        target = oid_key(oid)
        # Linear scan is fine: fixtures are thousands of rows at most, and this
        # runs once per varbind in a walk.
        for key, varbind in zip(self.keys, self.varbinds):
            if key > target:
                return varbind
        return None


def write_response(out, varbind: Varbind | None) -> None:
    if varbind is None:
        out.write(b"NONE\n")
        out.flush()
        return
    out.write(f".{varbind.oid}\n{varbind.pass_type()}\n".encode())
    out.write(varbind.pass_value_bytes())
    out.write(b"\n")
    out.flush()


def main() -> int:
    if len(sys.argv) < 2:
        sys.stderr.write("usage: responder.py <walkfile> [root-oid]\n")
        return 2
    varbinds = load_walk(sys.argv[1])
    if len(sys.argv) > 2:
        # Serve only the registered subtree. The emulator registers this
        # program twice — at .1.3.6.1 and at .1.0.8802, because LLDP-MIB's
        # IEEE root lies outside 1.3.6.1 — and a getnext that runs off the end
        # of one subtree must answer NONE rather than an OID from the other
        # registration's territory.
        prefix = sys.argv[2].strip().lstrip(".")
        varbinds = [v for v in varbinds if v.oid == prefix or v.oid.startswith(prefix + ".")]
    responder = Responder(varbinds)

    stdin = sys.stdin
    out = sys.stdout.buffer
    while True:
        line = stdin.readline()
        if not line:
            return 0
        command = line.strip().lower()
        if command == "ping":
            out.write(b"PONG\n")
            out.flush()
        elif command in ("get", "getnext"):
            oid_line = stdin.readline()
            if not oid_line:
                return 0
            oid = oid_line.strip()
            found = responder.get(oid) if command == "get" else responder.getnext(oid)
            write_response(out, found)
        elif command == "set":
            stdin.readline()  # oid
            stdin.readline()  # type and value
            out.write(b"not-writable\n")
            out.flush()
        # Anything else is ignored; snmpd only sends the commands above.


if __name__ == "__main__":
    sys.exit(main())
