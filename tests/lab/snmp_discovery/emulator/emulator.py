"""Run a real snmpd that impersonates a network device from a recorded walk.

This is how the scanner gets tested without any network hardware. snmpd does
the SNMPv3 work — engine ID discovery, SHA/AES USM, the wire format — and a
`pass_persist` backend answers every OID from a fixture file. From the
scanner's point of view there is no difference between this and a switch.

What it does and does not prove:

    proves      credential handling, the snmp.conf/SNMPCONFPATH mechanism,
                multi-credential fallback, GETBULK vs GETNEXT, walking, output
                parsing including Hex-STRING and multi-line values, and every
                layer above that up to the NetBox writes
    proves not  that any particular real device populates any particular MIB —
                only a real device can tell you that, and the fixtures encode
                what real devices of each family are documented to return

Each emulated device gets its own UDP port on the loopback interface, so a
whole fleet can run at once and the scanner can be pointed at 127.0.0.1 with
different ports, or at distinct 127.0.0.x addresses.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time

DEFAULT_USER = "netops"
DEFAULT_AUTH_PROTOCOL = "SHA-256"
DEFAULT_AUTH_PASS = "labauthpass123"
DEFAULT_PRIV_PROTOCOL = "AES"
DEFAULT_PRIV_PASS = "labprivpass123"

_RESPONDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "responder.py")

# snmpd's own MIB modules have to be switched off, or the emulated device
# answers with this Linux box's facts instead of the fixture's.
#
# `pass_persist -p 1` is not enough on its own. net-snmp dispatches to the
# *most specific* registration, and a built-in registered at .1.3.6.1.2.1.1 is
# more specific than our pass_persist at .1.3.6.1, so priority never gets
# consulted. Priority only breaks ties between registrations at the same depth.
#
# The names below are net-snmp's internal module names, taken from
# `snmpd -Dmib_init` on net-snmp 5.9.4 rather than guessed — note that the
# init list matches the trailing component, so "mibII/system_mib" does not
# work but "system_mib" does. The SNMPv3 machinery (snmpEngine, usmUser,
# usmStats, usmConf, vacm_*) and pass_persist itself are deliberately kept.
SNMPD_EXCLUDED_MODULES = (
    # MIB-II — everything the fixtures actually serve
    "system_mib",
    "sysORTable",
    "interface",
    "ifTable",
    "ifXTable",
    "ip",
    "ip_scalars",
    "ipAddressTable",
    "ipAddressPrefixTable",
    "ipCidrRouteTable",
    "ipDefaultRouterTable",
    "ipIfStatsTable",
    "ipSystemStatsTable",
    "inetCidrRouteTable",
    "inetNetToMediaTable",
    "ipv6",
    "ipv6ScopeZoneIndexTable",
    "var_route",
    "at",
    "icmp",
    "snmp_mib",
    "tcp",
    "tcpTable",
    "tcpConnectionTable",
    "tcpListenerTable",
    "udp",
    "udpTable",
    "udpEndpointTable",
    "dot3StatsTable",
    # Host Resources and the UCD extensions — not part of any fixture, and
    # they make a plain walk of the emulated device enormous.
    "hr_device",
    "hr_disk",
    "hr_network",
    "hr_other",
    "hr_partition",
    "hr_print",
    "hr_proc",
    "hr_system",
    "hrh_filesys",
    "hrh_storage",
    "hrSWInstalledTable",
    "hrSWRunTable",
    "hrSWRunPerfTable",
    "swinst",
    "swrun",
    "cpu",
    "cpu_linux",
    "hw_fsys",
    "hw_mem",
    "hw_sensors",
    "disk_hw",
    "diskio",
    "loadave",
    "memory",
    "vmstat",
    "proc",
    "versioninfo",
    "logmatch",
    "errormib",
    "file",
    "extend",
    "mta_sendmail",
    "lmsensorsMib",
    "dlmod",
    "proxy",
    "smux",
)


class EmulatorError(RuntimeError):
    pass


class EmulatedDevice:
    """One snmpd instance serving one fixture.

    Use as a context manager:

        with EmulatedDevice("fixtures/cisco-c9300-stack.walk", port=11161) as device:
            ...scan device.address / device.port...
    """

    def __init__(
        self,
        walk_path: str,
        port: int,
        listen: str = "127.0.0.1",
        user: str = DEFAULT_USER,
        auth_protocol: str = DEFAULT_AUTH_PROTOCOL,
        auth_pass: str = DEFAULT_AUTH_PASS,
        priv_protocol: str = DEFAULT_PRIV_PROTOCOL,
        priv_pass: str = DEFAULT_PRIV_PASS,
        extra_users: list[dict] | None = None,
    ):
        self.walk_path = os.path.abspath(walk_path)
        if not os.path.exists(self.walk_path):
            raise EmulatorError(f"fixture not found: {self.walk_path}")
        self.port = port
        self.listen = listen
        self.user = user
        self.auth_protocol = auth_protocol
        self.auth_pass = auth_pass
        self.priv_protocol = priv_protocol
        self.priv_pass = priv_pass
        self.extra_users = extra_users or []
        self._dir: str | None = None
        self._proc: subprocess.Popen | None = None
        self._log_path: str | None = None
        self._log_handle = None

    @property
    def address(self) -> str:
        return f"{self.listen}:{self.port}"

    def config_text(self) -> str:
        lines = [
            f"agentaddress udp:{self.listen}:{self.port}",
            # Serve the entire tree from the fixture. Priority 1 beats snmpd's
            # own built-in MIB modules (which default to 127), so the emulated
            # device's system group is the fixture's, not this Linux box's.
            f"pass_persist -p 1 .1.3.6.1 {_python()} {_RESPONDER} {self.walk_path} .1.3.6.1",
            # LLDP-MIB is an IEEE MIB rooted at 1.0.8802 — outside 1.3.6.1
            # entirely — so it needs its own registration or the emulated
            # device answers noSuchObject for every LLDP OID and a neighbor
            # fixture silently tests nothing. Each responder is told its root
            # so a getnext running off the end of one subtree answers NONE
            # instead of leaking an OID from the other registration.
            f"pass_persist -p 1 .1.0.8802 {_python()} {_RESPONDER} {self.walk_path} .1.0.8802",
        ]
        for user in [self._primary_user()] + self.extra_users:
            lines.append(_create_user_line(user))
            lines.append(f"rouser {user['name']} {_level(user)}")
        return "\n".join(lines) + "\n"

    def _primary_user(self) -> dict:
        return {
            "name": self.user,
            "auth_protocol": self.auth_protocol,
            "auth_pass": self.auth_pass,
            "priv_protocol": self.priv_protocol,
            "priv_pass": self.priv_pass,
        }

    def __enter__(self) -> EmulatedDevice:
        self.start()
        return self

    def __exit__(self, *exc_info) -> None:
        self.stop()

    def start(self) -> None:
        snmpd = shutil.which("snmpd")
        if snmpd is None:
            raise EmulatorError("snmpd not found — install net-snmp (apt install snmpd)")
        self._dir = tempfile.mkdtemp(prefix="snmpinv-emu-")
        conf_path = os.path.join(self._dir, "snmpd.conf")
        with open(conf_path, "w") as handle:
            handle.write(self.config_text())

        env = dict(os.environ)
        # Keep snmpd's persistent state (engine ID and boot counter) inside the
        # temp dir. Without this it writes to /var/lib/snmp, which needs root
        # and would make separate emulated devices share one engine ID.
        env["SNMP_PERSISTENT_DIR"] = self._dir

        self._log_path = os.path.join(self._dir, "snmpd.log")
        self._log_handle = open(self._log_path, "w")
        self._proc = subprocess.Popen(
            [
                snmpd,
                "-f",  # foreground, so we own the process
                "-Lo",  # log to stdout rather than syslog
                "-C",
                "-c",
                conf_path,  # this config only, ignore system config
                "-r",  # do not require root
                # snmpd(8): "-I [-]INITLIST" — the leading '-' negates the
                # WHOLE list, so it is written once, not once per name.
                # Prefixing each name individually silently matches nothing
                # after the first.
                "-I",
                "-" + ",".join(SNMPD_EXCLUDED_MODULES),
            ],
            env=env,
            stdout=self._log_handle,
            stderr=subprocess.STDOUT,
        )
        self._wait_until_listening()

    def _wait_until_listening(self, timeout: float = 20.0) -> None:
        """Wait until the agent answers with fixture data, not merely until the
        socket is bound.

        snmpd binds its UDP socket before the `pass_persist` backend is up —
        net-snmp starts that child lazily, on the first request that needs it.
        In that window the agent is reachable and answers every OID with
        noSuchObject, so a scan started too early returns an empty walk rather
        than an error. Checking for a real value is the only readiness signal
        that means anything.
        """
        snmpget = shutil.which("snmpget")
        if snmpget is None:
            raise EmulatorError("snmpget not found — install net-snmp")
        argv = [
            snmpget,
            "-v3",
            "-l",
            _level(self._primary_user()),
            "-u",
            self.user,
            "-a",
            self.auth_protocol,
            "-A",
            self.auth_pass,
            "-x",
            self.priv_protocol,
            "-X",
            self.priv_pass,
            "-On",
            "-t",
            "1",
            "-r",
            "0",
            self.address,
            "1.3.6.1.2.1.1.2.0",
        ]
        # Passphrases on the command line are fine here and only here: this is
        # the emulator's own lab credential, not a device credential, and the
        # scanner under test still goes through SNMPCONFPATH.
        deadline = time.time() + timeout
        last = ""
        while time.time() < deadline:
            if self._proc is not None and self._proc.poll() is not None:
                raise EmulatorError(f"snmpd exited immediately:\n{self.logs()[-2000:]}")
            try:
                proc = subprocess.run(argv, capture_output=True, text=True, timeout=5)
            except subprocess.TimeoutExpired:
                time.sleep(0.2)
                continue
            last = (proc.stdout or "") + (proc.stderr or "")
            if "1.3.6.1.2.1.1.2.0" in last and "No Such" not in last and "= " in last:
                return
            time.sleep(0.2)
        raise EmulatorError(
            f"snmpd on {self.address} never served fixture data.\n"
            f"last response: {last.strip()[:300]}\n"
            f"snmpd log:\n{self.logs()[-2000:]}"
        )

    def logs(self) -> str:
        """snmpd's own output — the first thing to read when a scan comes back empty."""
        if not self._log_path or not os.path.exists(self._log_path):
            return ""
        if self._log_handle is not None:
            self._log_handle.flush()
        with open(self._log_path, errors="replace") as handle:
            return handle.read()

    def stop(self) -> None:
        if self._proc is not None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
            self._proc = None
        if self._log_handle is not None:
            self._log_handle.close()
            self._log_handle = None
        if self._dir:
            shutil.rmtree(self._dir, ignore_errors=True)
            self._dir = None
            self._log_path = None


def _python() -> str:
    import sys

    return sys.executable or "python3"


def _level(user: dict) -> str:
    if user.get("auth_pass") and user.get("priv_pass"):
        return "authPriv"
    if user.get("auth_pass"):
        return "authNoPriv"
    return "noAuthNoPriv"


def _create_user_line(user: dict) -> str:
    """Build a createUser directive.

    net-snmp quotes passphrases so they may contain spaces, and the protocol
    names here are the ones snmpd accepts (SHA-256, AES-128 and so on) rather
    than the shorthand the client tools take.
    """
    parts = [f"createUser {user['name']}"]
    if user.get("auth_pass"):
        parts.append(f'{user.get("auth_protocol", DEFAULT_AUTH_PROTOCOL)} "{user["auth_pass"]}"')
    if user.get("priv_pass"):
        parts.append(f'{user.get("priv_protocol", DEFAULT_PRIV_PROTOCOL)} "{user["priv_pass"]}"')
    return " ".join(parts)
