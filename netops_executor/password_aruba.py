"""ArubaOS 8 Mobility Controller and Mobility Conductor local administrator rotation (preview).

Built from the HPE Aruba Networking AOS 8 CLI reference (`mgmt-user`, `show mgmt-user`,
`show configuration`, `write memory`) and user guides (configuration hierarchy), without a
lab device:

- A local administrator is `mgmt-user <username> <role>`; the command prompts for the password
  and a re-typed copy, answered through NetworkSSH.dialogue (never on the command line). The
  node configuration stores `mgmt-user <username> <role> <encrypted>`: a new encrypted value
  is the proof that the device accepted the password. Rotation sends the role the account
  already has; a creation sends the requested role (default root).
- Configuration node: a login starts at /mm/mynode on a Mobility Conductor (configuration of
  that conductor only, editable only there and not synced to the standby), which is also where a
  stand-alone controller and a managed device keep their own local configuration. Every read
  and write uses that node; `cd` is never sent. An administrator that `show mgmt-user` lists but
  /mm/mynode does not define is inherited from a parent node (/mm is shared with the standby
  conductor; a conductor pushes /md to managed devices) and is refused instead of being shadowed
  by a node-local copy.
- AOS 8 keeps changes pending until `write memory` commits (and pushes) them. Preflight refuses
  any pending change (`show configuration unsaved-nodes` and `show configuration pending
  /mm/mynode`); before `write memory` the only pending change may be this account's line, and
  the committed node configuration must then hold it (`show configuration committed
  /mm/mynode` is the persisted configuration). A change that shows up committed with nothing
  pending is accepted the same way, and `write memory` still saves it.
- Administrators without a local mgmt-user entry (TACACS/RADIUS logins) are missing; a
  certificate or SSH-key administrator without a password entry is refused.

Assumed without a lab device: the output layouts (a dashed column table with USER and ROLE
headers; configuration lines for pending/committed views; one node path per unsaved node, none
when everything is saved); that the pending line carries the new encrypted value; that a plain
entry has exactly those four words (node-scoped or SHA2 entries are refused, not rewritten).
NetworkSSH must accept the `^` unsaved-changes marker the prompt gains after the change and
loses after `write memory` (`(host) ^[mynode] (config) #`).
"""

import re

from .network_ssh import CLI_ERROR, NetworkSSH
from .password_devices import (
    ERROR,
    PERMISSION,
    ChangeNotAccepted,
    not_accepted,
    refusal,
    verify_login,
)
from .password_models import AccountCreation
from .ssh import DeviceError

NODE = "/mm/mynode"
# `mgmt-user` subcommands that are not administrator entries.
KEYWORDS = {"localauth", "localauth-disable", "ssh-pubkey", "webui-cacert", "audit-period"}
PASSWORD_PROMPT = re.compile(r"(?i)password\s*:\s*$")
# AOS error text beyond the shared patterns: management password policy and validation errors.
REFUSED = re.compile(
    r"(?im)^\s*%|^\s*error\b|non-compliant|validation failed|internal error|do(?: not|n't) match"
)


def refused(output):
    """Error text in the short output of a change command."""
    return any(p.search(output) for p in (CLI_ERROR, ERROR, PERMISSION, REFUSED))


def failed(output):
    """An error instead of a show command's output. Only the first line is checked for refusal
    wording: configuration text can contain names such as an ACL called deny-unauthorized."""
    first = next((line.strip() for line in output.splitlines() if line.strip()), "")
    return bool(CLI_ERROR.search(output) or first.startswith("%") or PERMISSION.search(first))


def lines(output):
    """Configuration lines of a `show configuration` view, without blanks and `!` separators."""
    return [line.rstrip() for line in output.splitlines() if line.strip() not in ("", "!")]


def entry(line):
    """The words of a password administrator entry, or None for any other line."""
    words = [word.strip('"') for word in line.split()]
    if len(words) >= 2 and words[0] == "mgmt-user" and words[1] not in KEYWORDS:
        return words
    return None


def account(config, username):
    entries = [words for line in config if (words := entry(line)) and words[1] == username]
    if len(entries) > 1:
        raise DeviceError("ArubaOS configuration has duplicate entries for the administrator")
    if entries and len(entries[0]) != 4:
        raise DeviceError("ArubaOS administrator has options this job does not preserve (node scope or hash)")
    return entries[0] if entries else None


def outside(config, username):
    return [line for line in config if not ((words := entry(line)) and words[1] == username)]


def certificate_only(config, username):
    for words in (line.split() for line in config):
        if words[:1] == ["mgmt-user"] and words[1:2] in (["ssh-pubkey"], ["webui-cacert"]):
            if username in (word.strip('"') for word in words[2:]):
                return True
    return False


def user_table(output):
    """USER -> ROLE from the `show mgmt-user` table; columns are sliced at the dashed rule."""
    rows = output.splitlines()
    for index, header in enumerate(rows[:-1]):
        rule = rows[index + 1]
        if not ({"USER", "ROLE"} <= set(header.split()) and re.fullmatch(r"\s*-+(?:\s+-+)*\s*", rule)):
            continue
        starts = [m.start() for m in re.finditer(r"-+", rule)]

        def cells(line):
            return [line[a:b].strip() for a, b in zip(starts, starts[1:] + [len(line)])]

        names = cells(header)
        if "USER" not in names or "ROLE" not in names:
            break
        users = {}
        for line in rows[index + 2 :]:
            if not line.strip():
                break
            row = dict(zip(names, cells(line)))
            user, role = row.get("USER", ""), row.get("ROLE", "")
            if not user or not role or " " in user or user in users:
                raise DeviceError("ArubaOS management user table is unreadable")
            users[user] = role
        return users
    raise DeviceError("ArubaOS management user table is unreadable")


class ArubaAccounts:
    def __init__(self, settings, store, device, request, password, guard, audit, ssh=None):
        self.settings, self.device, self.request = settings, device, request
        self.password, self.guard = password, guard
        self.ssh = ssh or NetworkSSH(
            settings, device, guard, request.credential_profiles, audit, device_type=request.device_type
        )
        self.ssh.selector.secrets.add(password)
        self.creation = request.new_account or AccountCreation.administrator("aruba_os")
        self.baseline = self.before = self.staged = self.staged_state = None
        self.report, self.reservations = {}, []

    def show(self, command):
        result = self.ssh.execute(command, timeout=self.request.command_timeout)
        if result["cli_error"] or failed(result["stdout"]):
            raise refusal(result["stdout"], "ArubaOS command rejected; device output omitted")
        return result["stdout"]

    def state(self):
        """The user table, this node's committed configuration and every pending change."""
        unsaved = [line.strip() for line in self.show("show configuration unsaved-nodes").splitlines()]
        unsaved = [node for node in unsaved if node]
        if any(not re.fullmatch(r"/[\w./:-]*", node) for node in unsaved):
            raise DeviceError("ArubaOS unsaved configuration nodes are unreadable")
        return {
            "users": user_table(self.show("show mgmt-user")),
            "committed": lines(self.show("show configuration committed " + NODE)),
            "pending": lines(self.show("show configuration pending " + NODE)),
            "unsaved": unsaved,
        }

    def preflight(self):
        user = self.request.username
        if user in KEYWORDS:
            raise DeviceError("username is an ArubaOS mgmt-user keyword")
        state = self.state()
        if state["pending"] or state["unsaved"]:
            # write memory would also commit (and push) someone else's pending change.
            raise DeviceError("ArubaOS has uncommitted configuration changes; commit or purge them first")
        self.before = account(state["committed"], user)
        listed = state["users"].get(user)
        if self.before is None:
            if listed is not None:
                raise DeviceError(
                    "ArubaOS administrator is inherited from a parent configuration node (/mm or the "
                    "conductor); rotate it where it is defined"
                )
            if certificate_only(state["committed"], user):
                raise DeviceError("ArubaOS administrator uses certificate or SSH-key authentication only")
            if not self.request.create_if_missing:
                raise DeviceError("local account is missing and create_if_missing is false")
        elif listed != self.before[2]:
            raise DeviceError("ArubaOS management user table and configuration disagree")
        self.baseline = state
        self.report["config_node"] = NODE
        return self.before is not None

    def apply(self):
        if self.state() != self.baseline:
            raise DeviceError("account changed since precheck; submit a new job")
        role = self.before[2] if self.before else self.creation.role
        try:
            output, _ = self.ssh.dialogue(
                "mgmt-user " + self.request.username + " " + role,
                [(PASSWORD_PROMPT, self.password)],
                self.request.command_timeout,
                mode="config",
                max_replies=2,
            )
            if refused(output):
                raise refusal(output, "ArubaOS rejected the administrator change")
        except DeviceError as exc:
            # A fresh session that proves nothing was staged ends the job without recovery.
            if self.unchanged():
                raise not_accepted(exc) from None
            raise
        self.confirm(role)

    def unchanged(self):
        self.ssh.close()
        try:
            return self.state() == self.baseline
        except DeviceError:
            return False

    def confirm(self, role):
        user, state = self.request.username, self.state()
        if state == self.baseline:
            # Nothing staged and nothing applied: a role-limited login can be acknowledged and ignored.
            raise ChangeNotAccepted(
                "ArubaOS acknowledged the change but the administrator "
                + ("password did not change" if self.before else "was not created")
                + "; check the login's role or TACACS authorization (permission); the account is unchanged"
            )
        if outside(state["pending"], user) or set(state["unsaved"]) - {NODE}:
            raise DeviceError("ArubaOS has pending changes besides this account; inspect before recovery")
        pending = account(state["pending"], user)
        if pending is not None:
            staged, changed = pending, state["committed"] != self.baseline["committed"]
        else:
            # A platform that applies the change at once shows it committed instead of pending.
            staged = account(state["committed"], user)
            changed = outside(state["committed"], user) != outside(self.baseline["committed"], user)
        if staged is None or changed:
            raise DeviceError("ArubaOS configuration changed unexpectedly; inspect before recovery")
        if staged[2] != role:
            raise DeviceError("ArubaOS administrator role changed unexpectedly; inspect before recovery")
        if self.before is not None and staged[3] == self.before[3]:
            raise DeviceError(
                "ArubaOS staged the administrator without a new password; inspect before recovery"
            )
        self.staged, self.staged_state = staged, state
        self.report.setdefault("confirmed", []).append("change_staged")

    def save(self):
        user = self.request.username
        # write memory commits every pending change: re-check that only this account is pending.
        if self.state() != self.staged_state:
            raise DeviceError("ArubaOS configuration changed before write memory; inspect before recovery")
        result = self.ssh.execute("write memory", timeout=self.request.command_timeout)
        if result["cli_error"] or refused(result["stdout"]):
            raise DeviceError("ArubaOS write memory was refused; the change may still be pending")
        state = self.state()
        if (
            state["pending"]
            or state["unsaved"]
            or account(state["committed"], user) != self.staged
            or outside(state["committed"], user) != outside(self.baseline["committed"], user)
            or state["users"].get(user) != self.staged[2]
        ):
            raise DeviceError("ArubaOS committed configuration does not match the staged account")
        self.report.setdefault("confirmed", []).append("saved")

    def verify(self):
        if self.request.verification != "ssh_login":
            raise DeviceError("ArubaOS rotation is verified only by SSH login")
        verify_login(self.settings, self.device, self.request.username, self.password, self.guard)
        self.report.setdefault("confirmed", []).append("login")

    def close(self):
        self.ssh.close()
