"""Read and write the recorded-walk format used by fixtures and the emulator.

The format is literally what `snmpwalk -On -Oe -Ot` prints:

    .1.3.6.1.2.1.1.1.0 = STRING: "Arista Networks EOS version 4.29.2F"
    .1.3.6.1.2.1.2.2.1.6.1 = Hex-STRING: 00 1C 73 AA BB CC
    .1.3.6.1.2.1.2.2.1.3.1 = INTEGER: 6

Using the tool's own output as the fixture format means `record_walk.py` can
capture a real device with no transformation, a fixture stays readable and
diffable in review, and the file the emulator serves is the same artefact the
parser tests read.

This parser is deliberately separate from the scanner's own parser in
snmpinv/snmp.py. They read the same text, and if the emulator reused the
parser under test then a parsing bug could cancel itself out — the emulator
would misread the fixture in exactly the way the scanner misreads the wire, and
the test would still pass.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# `.1.3.6.1.2.1.1.1.0 = STRING: value`
_LINE = re.compile(r"^(\.?[\d.]+)\s+=\s+(?:([A-Za-z0-9-]+):\s?)?(.*)$")
_HEX_BYTE = re.compile(r"^[0-9A-Fa-f]{2}$")

# net-snmp's printed type -> the type name pass_persist expects back.
PASS_TYPES = {
    "STRING": "string",
    "Hex-STRING": "octet",
    "INTEGER": "integer",
    "Gauge32": "gauge",
    "Counter32": "counter",
    "Counter64": "counter64",
    "Timeticks": "timeticks",
    "IpAddress": "ipaddress",
    "OID": "objectid",
    "Network Address": "ipaddress",
    "BITS": "string",
}


@dataclass
class Varbind:
    oid: str  # numeric, no leading dot
    type: str  # net-snmp's printed type name
    value: str  # as printed, minus quotes; Hex-STRING kept as "00 1C 73"

    def pass_type(self) -> str:
        return PASS_TYPES.get(self.type, "string")

    def pass_value_bytes(self) -> bytes:
        """Render the value the way pass_persist wants it.

        Hex-STRINGs go back as type "octet", whose value is space-separated
        hex TEXT — snmpd.conf(5)'s own words: 'octets are sent as ASCII,
        space-separated hex strings, e.g. "00 3f dd 00 c6 be"'. snmpd builds
        a real OCTET STRING from it, so the client still sees Hex-STRING for
        binary values, exactly as from a real device. They must NOT go back
        as raw bytes on this line-based protocol: a value byte of 0x0A reads
        as end-of-line and desyncs the whole stream (every 10.x.y.z address
        starts with one), and a 0x00 truncates the line — which is how CDP
        rows silently vanished from the emulated wire until an assertion
        counted them.

        Embedded newlines in TEXT values are flattened to spaces. That is a
        hard limit of the protocol for the string type: the value is one
        line, and a second line would be read as the next command. Real
        devices *do* return multi-line strings — Cisco's sysDescr is a
        four-line paragraph — so the emulator cannot cover that case and the
        recorded-walk tests carry it instead
        (test_parsing.py::test_multiline_value_is_joined). The fixture keeps
        the real multi-line text; only what goes over this wire is flattened.
        """
        if self.type == "Hex-STRING":
            parts = [p for p in self.value.replace(":", " ").split() if _HEX_BYTE.match(p)]
            return " ".join(p.lower() for p in parts).encode()
        if self.type == "Timeticks":
            match = re.match(r"\((\d+)\)", self.value)
            if match:
                return match.group(1).encode()
        if self.type == "OID":
            return ("." + self.value.lstrip(".")).encode()
        flattened = self.value.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
        return flattened.encode("utf-8", "replace")


def parse_walk(text: str) -> list[Varbind]:
    """Parse recorded walk text, joining values that span multiple lines."""
    varbinds: list[Varbind] = []
    oid = value_type = None
    value_lines: list[str] = []

    def flush():
        if oid is not None:
            varbinds.append(Varbind(oid, value_type or "STRING", _unquote("\n".join(value_lines))))

    for line in text.splitlines():
        if not line.strip():
            continue
        if line.lstrip().startswith("#"):
            continue
        match = _LINE.match(line)
        if match:
            flush()
            oid = match.group(1).lstrip(".")
            value_type = match.group(2)
            value_lines = [match.group(3)]
        elif oid is not None:
            # Continuation of a multi-line value — Cisco's sysDescr is a
            # paragraph, and truncating it loses the software version.
            value_lines.append(line)
    flush()
    return varbinds


def _unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        return value[1:-1]
    return value


def load_walk(path: str) -> list[Varbind]:
    with open(path, encoding="utf-8") as handle:
        return parse_walk(handle.read())


def format_walk(varbinds: list[Varbind]) -> str:
    lines = []
    for varbind in varbinds:
        value = varbind.value
        if varbind.type == "STRING":
            value = f'"{value}"'
        lines.append(f".{varbind.oid} = {varbind.type}: {value}")
    return "\n".join(lines) + "\n"
