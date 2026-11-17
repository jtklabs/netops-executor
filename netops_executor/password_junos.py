"""Juniper Junos local login rotation through a private candidate configuration.

Vendor behaviour relied on (Junos CLI User Guide: "Overview of the configure command",
"Commit the Configuration"; User Access guide: "User Accounts", login classes):
- `configure private` gives this session its own candidate. Junos refuses it while the shared
  candidate holds uncommitted changes or another session is in `configure exclusive`, a private
  commit carries only this session's changes (never another user's uncommitted work), and
  uncommitted private changes are discarded when the session leaves configuration mode or ends.
  A private commit also fails if the shared candidate changed meanwhile. (`configure exclusive`
  was not chosen: it edits and locks the shared candidate, and leaving it rolls back other users'
  uncommitted private changes.)
- A refused or silently dropped statement, or a failed `commit check`, is discarded (`rollback 0`,
  leave configuration mode) and becomes ChangeNotAccepted once the committed account re-reads
  unchanged. Nothing reaches the active configuration before `save()` commits.
- The password is sent as a locally generated sha512_crypt hash (`$6$`, 5000 rounds) in
  `set system login user <u> authentication encrypted-password "<hash>"`; a new account also
  gets `set system login user <u> class <role>` and Junos assigns its `uid` at commit. Device
  password-format rules (`system login password`) apply to plain-text input only.
- `show | compare` in the private session must show only this user's stanza before
  `commit check` and `commit comment "..."`; `show configuration system login user <u> |
  display set` then confirms the committed account.
- Encrypted passwords are readable only with the login class `secret` permission (otherwise
  masked as SECRET-DATA); rotation is refused in preflight when the stored hash is unreadable.

Assumptions not verified on a lab device (the platform ships as preview):
- Refusal wording: denied statements print "error: ..." (for example "error: permission
  denied"), "syntax error" or "unknown command"; a refused `configure private` prints "error:"
  and returns to the operational prompt. Any such output is treated as a refusal, and a
  statement that is silently dropped is caught by re-reading the candidate.
- `display set` prints one quoted hash per account without `## SECRET-DATA` comments. Accounts
  defined only through configuration groups (apply-groups) look missing and are not supported.
- `show | compare` lists a new user as one `+ user <u> { ... }` block under `[edit system login]`
  and other changes under `[edit system login user <u> ...]` headers.
- Netmiko's juniper_junos driver enters configuration mode with a plain (shared) `configure`, so
  the private session is opened on the driver directly and every later configuration command
  checks that this same session is still open.
"""

import re

from passlib.hash import sha512_crypt

from .network_ssh import CLI_ERROR, NetworkSSH
from .password_devices import ChangeNotAccepted, PasswordRejected, crypt_matches, verify_login
from .password_models import AccountCreation
from .ssh import DeviceError
from .store import CancelRequested, LostOwnership

# Device output is redacted of every selector secret, so the generated hash reads back as this.
REDACTED = "[REDACTED]"
COMMIT_COMMENT = "netops-executor password rotation"
PREDEFINED_CLASSES = ("operator", "read-only", "super-user", "unauthorized")
# What Netmiko reads after `configure private`: the configuration prompt, or a refusal followed by
# the operational prompt again (so a refusal does not wait for a read timeout).
PRIVATE_PROMPT = r"(?s:Entering configuration mode.*\].*#\s*$|(?:error:|unknown command).*>\s*$)"
REFUSED = re.compile(
    r"(?im)^\s*(?:error:|syntax error|unknown command|invalid (?:value|command)|"
    r".*\b(?:permission denied|access denied|not authori[sz]ed))"
)
# Refusal text that names the login's privileges (the wording password_devices uses as well).
DENIED = re.compile(
    r"(?i)permission denied|access denied|not authori[sz]ed|unauthori[sz]ed|authori[sz]ation (?:failed|denied)"
    r"|insufficient (?:privilege|permission|access|rights)"
)
# Context lines Junos prints before a prompt: [edit], {master:0}, or both on one line.
CONTEXT = re.compile(r"^(?:\{(?:master|backup|primary|secondary|line)[^}]*\})?(?:\[edit(?: [^\]]*)?\])?$")
HASH = re.compile(r"\$[0-9a-z]+\$[^\s\"]+")

DENIED_REASON = (
    "Junos refused the change for this login's class (permission denied); "
    "nothing was committed and the account is unchanged"
)
REFUSED_REASON = "Junos refused the account change; nothing was committed and the account is unchanged"
IGNORED_REASON = (
    "Junos did not stage the account change (absent from show | compare); this login's class may "
    "lack permission; nothing was committed and the account is unchanged"
)
CHECK_REASON = (
    "Junos commit check rejected the account change; nothing was committed and the account is unchanged"
)
OPEN_REASON = (
    "Junos refused a private configuration session (uncommitted shared changes, an exclusive lock "
    "or no configure permission); nothing was written and the account is unchanged"
)


def body(output, echoed=False):
    """Non-empty output lines without the echoed command, the prompt and trailing context."""
    lines = output.splitlines()
    if echoed:
        lines = lines[1:-1]
    lines = [line.rstrip() for line in lines]
    while lines and (not lines[-1].strip() or CONTEXT.match(lines[-1].strip())):
        lines.pop()
    return [line for line in lines if line.strip()]


def account(lines, username):
    """The user's `display set` statements, or None when the user is not configured."""
    record = []
    for line in lines:
        if line.split()[:5] != ["set", "system", "login", "user", username]:
            raise DeviceError("unrecognized Junos login configuration")
        record.append(line.strip())
    return record or None


def password_line(username):
    return "set system login user " + username + " authentication encrypted-password "


def stored_hash(record, username):
    prefix = password_line(username)
    values = [line[len(prefix) :].strip().strip('"') for line in record or [] if line.startswith(prefix)]
    if len(values) > 1:
        raise DeviceError("Junos account has more than one encrypted password")
    return values[0] if values else None


def access(record, username):
    """Every statement except the password hash: class, uid, keys and other settings."""
    return sorted(line for line in record or [] if not line.startswith(password_line(username)))


def only_account(diff, username):
    """True when every `show | compare` entry belongs to this user's stanza."""
    own, header, depth, added = ("system", "login", "user", username), None, 0, False
    for line in diff:
        match = re.fullmatch(r"\[edit(?: (.*))?\]", line.strip())
        if match:
            if depth:
                return False
            header = tuple((match[1] or "").split())
            continue
        if header is None:
            return False
        if header[:4] == own:
            continue
        if header != ("system", "login") or not line.startswith("+"):
            return False
        # A new user is one added block directly under [edit system login].
        text = line[1:].strip()
        if not depth:
            if added or text != "user " + username + " {":
                return False
            added = True
        depth += text.count("{") - text.count("}")
        if depth < 0:
            return False
    return not depth


class JunosAccounts:
    def __init__(self, settings, store, device, request, password, guard, audit, ssh=None):
        self.settings, self.device, self.request = settings, device, request
        self.user, self.password, self.guard = request.username, password, guard
        self.ssh = ssh or NetworkSSH(
            settings, device, guard, request.credential_profiles, audit, device_type=request.device_type
        )
        self.ssh.selector.secrets.add(password)
        self.creation = request.new_account or AccountCreation.administrator("juniper_junos")
        self.before = self.staged = self.hashed = None
        # The Netmiko driver while this adapter's private configuration session is open.
        self.session = None
        self.report, self.reservations = {}, []

    def show(self, command):
        """Operational read. Netmiko leaves configuration mode first, which discards an
        uncommitted private candidate."""
        self.session = None
        result = self.ssh.execute(command, timeout=self.request.command_timeout)
        if result["cli_error"] or REFUSED.search(result["stdout"]):
            raise DeviceError("Junos read command rejected; output omitted")
        return body(result["stdout"])

    def committed(self):
        return account(
            self.show("show configuration system login user " + self.user + " | display set"), self.user
        )

    def open(self):
        """Enter `configure private` on a fresh operational prompt; False if Junos refuses it."""
        driver = self.ssh.connect()
        try:
            driver.config_mode(config_command="configure private", pattern=PRIVATE_PROMPT)
        except (CancelRequested, LostOwnership):
            self.ssh.close()
            raise
        except Exception:
            # Nothing was written. Ending the session also ends any half-open configuration mode.
            self.ssh.close()
            return False
        self.session = driver
        return True

    def config(self, command, timeout=None):
        """One command in this adapter's private session. NetworkSSH would enter the shared
        candidate if this session had ended, so a lost session stops here (without reconnecting)."""
        if self.session is None or getattr(self.ssh, "driver", None) is not self.session:
            self.session = None
            raise DeviceError("Junos private configuration session was lost; nothing further was sent")
        output, _ = self.ssh.dialogue(
            command, [], timeout or self.request.command_timeout, mode="config", max_replies=0
        )
        return body(output, echoed=True)

    def candidate(self):
        return account(self.config("show system login user " + self.user + " | display set"), self.user)

    def discard(self):
        try:
            self.config("rollback 0")
        except DeviceError:
            # NetworkSSH closed the session: Junos discards an uncommitted private candidate then.
            pass
        self.session = None

    def reject(self, reason):
        """Discard the private candidate, prove the committed account is unchanged, and refuse."""
        self.discard()
        if self.committed() != self.before:
            raise DeviceError(
                "Junos account differs from precheck after a refused change; inspect before recovery"
            )
        raise ChangeNotAccepted(reason)

    def matches(self, record, committed=False):
        """The record holds the generated hash and the expected access statements."""
        if record is None or stored_hash(record, self.user) != REDACTED:
            return False
        statements = access(record, self.user)
        if self.before is not None:
            return statements == access(self.before, self.user)
        if committed:
            # Junos assigns a uid to a new user when it commits.
            statements = [s for s in statements if not re.fullmatch(r"set system login user \S+ uid \d+", s)]
        return statements == ["set system login user " + self.user + " class " + self.creation.role]

    def preflight(self):
        if self.user == "root":
            raise DeviceError(
                "Junos root is configured under system root-authentication; it is not rotated here"
            )
        # A private session is refused while the shared candidate holds uncommitted changes or is
        # locked exclusively: such changes would block the commit or be committed with it.
        if not self.open():
            raise DeviceError(
                "Junos private configuration could not be opened (uncommitted shared changes, an exclusive "
                "lock or no configure permission); resolve it before rotation"
            )
        if self.config("show | compare"):
            raise DeviceError("Junos private candidate is not clean; resolve pending changes before rotation")
        self.before = self.committed()
        if self.before is None:
            if not self.request.create_if_missing:
                raise DeviceError("local account is missing and create_if_missing is false")
            role = self.creation.role
            if role not in PREDEFINED_CLASSES and not self.show(
                "show configuration system login class " + role + " | display set"
            ):
                raise DeviceError("Junos login class for the new account does not exist")
            return False
        value = stored_hash(self.before, self.user)
        if value is None:
            raise DeviceError(
                "Junos account has no local password (remote, template or key-only user); "
                "it cannot be rotated as a local account"
            )
        if not HASH.fullmatch(value):
            raise DeviceError(
                "Junos stored password hash is not readable; the login class needs the secret permission"
            )
        return True

    def apply(self):
        self.hashed = sha512_crypt.using(rounds=5000).hash(self.password)
        self.ssh.selector.secrets.add(self.hashed)
        if not self.open():
            raise ChangeNotAccepted(OPEN_REASON)
        if self.config("show | compare"):
            self.discard()
            raise DeviceError(
                "Junos private candidate was not clean; nothing was written, inspect before recovery"
            )
        # A new private candidate is a copy of the committed configuration.
        if self.candidate() != self.before:
            self.discard()
            raise DeviceError("account changed since precheck; submit a new job")
        prefix = "set system login user " + self.user
        commands = [prefix + " class " + self.creation.role] if self.before is None else []
        commands.append(prefix + ' authentication encrypted-password "' + self.hashed + '"')
        for command in commands:
            output = "\n".join(self.config(command))
            if REFUSED.search(output) or CLI_ERROR.search(output):
                self.reject(DENIED_REASON if DENIED.search(output) else REFUSED_REASON)
        self.staged = self.candidate()
        diff = self.config("show | compare")
        if not diff and self.staged == self.before:
            self.reject(IGNORED_REASON)
        if not diff or not only_account(diff, self.user) or not self.matches(self.staged):
            self.discard()
            raise DeviceError(
                "Junos staged change is not exactly the requested account change; it was discarded, "
                "inspect before recovery"
            )
        check = "\n".join(self.config("commit check", self.request.commit_timeout))
        if REFUSED.search(check) or "configuration check succeeds" not in check:
            self.reject(CHECK_REASON)
        self.report.setdefault("confirmed", []).append("change_staged")

    def save(self):
        if self.staged is None or self.session is None:
            raise DeviceError(
                "Junos private candidate from the change step is not open; nothing was committed, "
                "inspect before recovery"
            )
        diff = self.config("show | compare")
        if self.candidate() != self.staged or not diff or not only_account(diff, self.user):
            self.discard()
            raise DeviceError(
                "Junos private candidate changed before commit; it was discarded, inspect before recovery"
            )
        output = "\n".join(
            self.config('commit comment "' + COMMIT_COMMENT + '"', self.request.commit_timeout)
        )
        complete = "commit complete" in output
        if not complete and REFUSED.search(output):
            # A refused commit leaves the private candidate uncommitted: discard it and prove it.
            self.reject(
                "Junos refused the commit; the staged change was discarded and the account is unchanged"
            )
        if not complete or REFUSED.search(output):
            raise DeviceError("Junos commit was not confirmed; inspect before recovery")
        self.report.setdefault("confirmed", []).append("committed")
        if not self.matches(self.committed(), committed=True):
            raise DeviceError(
                "Junos committed account does not match the staged change; inspect before recovery"
            )
        self.report["confirmed"].append("running_matches")

    def verify(self):
        if self.request.verification == "ssh_login":
            verify_login(self.settings, self.device, self.user, self.password, self.guard)
            return
        value = stored_hash(self.committed(), self.user)
        if value is None:
            raise DeviceError("Junos account has no readable password hash; use SSH login verification")
        if value == REDACTED and self.hashed:
            # Redaction replaced exactly the hash this adapter generated from the password.
            value = self.hashed
        if not crypt_matches(self.password, value):
            raise PasswordRejected("Junos committed password hash does not match the requested password")

    def close(self):
        self.ssh.close()
