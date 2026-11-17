"""Check Point Gaia local administrator rotation in clish.

Vendor behaviour relied on (Gaia Administration Guide R81 to R82: "Configuration Locks",
"Managing User Accounts in Gaia Clish", "Configuring Roles in Gaia Clish", password policy):
- `lock database override` (the same as `set config-lock on override`) takes the configuration
  lock from any other session; without it clish answers "CLINFR0519 Configuration lock
  present". `unlock database` releases it, and so does ending the SSH session.
- clish changes apply to the running configuration at once; `save config` persists the whole
  running configuration and `show config-state` prints `saved` or `unsaved`. Rotation does not
  start while unsaved changes exist, because `save config` would persist them too, and holds the
  lock from before the write until after the save.
- `set user <u> password-hash <hash>` sets a password from a crypt hash. R81 and later hash local
  passwords with SHA-512 (`set password-controls password-hash-type`), so a locally generated
  sha512_crypt hash (`$6$`, 5000 rounds) is sent and the password never appears on a command line.
  Password-policy checks (complexity, history) are not evaluated for a hash.
- New administrators: `add user <u> uid <uid> homedir /home/<u>`, the password hash,
  `set user <u> shell /etc/cli.sh` and `add rba user <u> roles <role>`. UID 0 makes an account
  equal to the built-in admin (its roles cannot be changed), so a new account takes the lowest
  free UID from 103 (the documented non-administrator range is 103-65533) and the clish shell,
  never bash: expert access stays a deliberate operator decision, whatever existing admins use.

Assumptions not verified on a lab device (the platform ships as preview):
- `show configuration user` prints only `add user ...`/`set user ...` lines, including
  `set user <u> password-hash <hash>` (`*` when the account has no password), and
  `show configuration rba` prints `add rba user <u> roles <role>[,<role>]` and `add rba role ...`.
- Successful configuration commands print nothing; refusals print a CLINFR code (for example
  CLINFR0519 for the lock) or "Permission denied"/"not authorized". A write that prints nothing
  but leaves the hash unchanged is caught by re-reading the account.
- Netmiko's checkpoint_gaia driver must land in clish; an expert (bash) login is refused. Its
  enable() enters expert mode, and NetworkSSH.dialogue() always enables, so this adapter only uses
  exec-mode commands and never an interactive password prompt.
- Cluster members and cloning groups are not coordinated: each member is its own job.
"""

import re

from passlib.hash import sha512_crypt

from .network_ssh import NetworkSSH
from .password_devices import ChangeNotAccepted, PasswordRejected, crypt_matches, verify_login
from .password_models import AccountCreation
from .ssh import DeviceError

# Device output is redacted of every selector secret, so the generated hash reads back as this.
REDACTED = "[REDACTED]"
SHELL = "/etc/cli.sh"
FIRST_UID, LAST_UID = 103, 65533
BUILTIN_ROLES = ("adminRole", "monitorRole")
REFUSED = re.compile(
    r"(?im)^\s*(?:CLI[A-Z]{3}\d{3,4}\b|.*\b(?:permission denied|not authori[sz]ed|access denied|"
    r"invalid command|incomplete command|command not found|failed|error)\b)"
)
# Refusal text that names the login's privileges (the wording password_devices uses as well).
DENIED = re.compile(
    r"(?i)permission denied|access denied|not authori[sz]ed|unauthori[sz]ed|authori[sz]ation (?:failed|denied)"
    r"|insufficient (?:privilege|permission|access|rights)"
)
LOCKED = re.compile(r"(?i)CLINFR0519|configuration lock present")
EXPERT = re.compile(r"(?i)command not found|\[Expert@|^-?bash:", re.M)
# The lock owner notice clish may print for a session without the lock; it is not data.
NOTICE = re.compile(r"(?i)lock database override|config(?:uration)?[ -]lock is")
HASH = re.compile(r"\$[0-9a-z]+\$\S+")

DENIED_REASON = (
    "Check Point Gaia refused the change for this login's role (permission denied or not authorized); "
    "the account is unchanged"
)
LOCKED_REASON = (
    "Check Point Gaia refused the change: this session does not hold the configuration lock "
    "(another session took it, or this role cannot take it); the account is unchanged"
)
REFUSED_REASON = "Check Point Gaia refused the account change; the account is unchanged"
IGNORED_REASON = (
    "Check Point Gaia did not apply the change (the stored hash is unchanged); this login's role may "
    "lack the user management feature; the account is unchanged"
)


def refusal(output):
    if DENIED.search(output):
        return DENIED_REASON
    if LOCKED.search(output):
        return LOCKED_REASON
    return REFUSED_REASON


def option(lines, key):
    """The value after `key` in clish statements, for example `uid` or `shell`."""
    values = []
    for line in lines:
        words = line.split()
        values += [words[i + 1] for i, word in enumerate(words[:-1]) if word == key]
    return values


def stored_hash(record):
    values = option(record["user"], "password-hash") if record else []
    if len(values) > 1:
        raise DeviceError("Gaia account has more than one password hash")
    return values[0].strip("'\"") if values else None


def access(record):
    """Every user and role statement except the password hash."""
    lines = [line for line in record["user"] if "password-hash" not in line.split()]
    return sorted(lines + record["rba"])


class CheckpointAccounts:
    def __init__(self, settings, store, device, request, password, guard, audit, ssh=None):
        self.settings, self.device, self.request = settings, device, request
        self.user, self.password, self.guard = request.username, password, guard
        self.ssh = ssh or NetworkSSH(
            settings, device, guard, request.credential_profiles, audit, device_type=request.device_type
        )
        self.ssh.selector.secrets.add(password)
        self.creation = request.new_account or AccountCreation.administrator("checkpoint_gaia")
        self.before = self.after = self.hashed = self.uid = None
        self.uids, self.roles, self.locked = set(), set(), False
        self.report, self.reservations = {}, []

    def run(self, command):
        """One clish command (exec mode only: enabling would enter expert mode).
        Returns the output and whether it reads as a refusal."""
        result = self.ssh.execute(command, timeout=self.request.command_timeout)
        output = result["stdout"]
        return output, bool(result["cli_error"] or REFUSED.search(output))

    def read(self, command):
        output = self.ssh.execute(command, timeout=self.request.command_timeout)["stdout"]
        if EXPERT.search(output):
            raise DeviceError("Gaia login opened an expert (bash) shell; rotation requires a clish login")
        lines = [line.strip() for line in output.splitlines() if line.strip() and not NOTICE.search(line)]
        # Configuration statements are data (a real name may say "error"); anything else is judged.
        if any(line.split()[0] not in ("add", "set") and REFUSED.search(line) for line in lines):
            raise DeviceError("Gaia read command rejected; output omitted")
        return lines

    def state(self):
        states = [line for line in self.read("show config-state") if line in ("saved", "unsaved")]
        if len(states) != 1:
            raise DeviceError("Gaia configuration state is unavailable")
        return states[0]

    def account(self):
        """This user's clish statements, or None. Also records used UIDs and defined roles."""
        users = {}
        for line in self.read("show configuration user"):
            words = line.split()
            if len(words) < 3 or words[0] not in ("add", "set") or words[1] != "user":
                raise DeviceError("unrecognized Gaia user configuration")
            users.setdefault(words[2], []).append(line)
        rba = self.read("show configuration rba")
        self.uids = {int(uid) for lines in users.values() for uid in option(lines, "uid") if uid.isdigit()}
        self.roles = {line.split()[3] for line in rba if line.split()[:3] == ["add", "rba", "role"]}
        if self.user not in users:
            return None
        return {
            "user": users[self.user],
            "rba": [line for line in rba if line.split()[1:4] == ["rba", "user", self.user]],
        }

    def unlock(self):
        """Release the configuration lock; ending the session releases it as well."""
        if not self.locked:
            return
        self.locked = False
        try:
            refused = self.run("unlock database")[1]
        except DeviceError:
            refused = True
        if refused:
            self.ssh.close()

    def reject(self, reason):
        self.unlock()
        raise ChangeNotAccepted(reason)

    def matches(self, record):
        """The record holds the generated hash and the expected access statements."""
        if record is None or stored_hash(record) != REDACTED:
            return False
        if self.before is not None:
            return access(record) == access(self.before)
        add = [line for line in record["user"] if line.split()[:2] == ["add", "user"]]
        roles = [set(value.split(",")) for value in option(record["rba"], "roles")]
        return (
            option(add, "uid") == [str(self.uid)]
            and option(add, "homedir") == ["/home/" + self.user]
            and option(record["user"], "shell") == [SHELL]
            and roles == [{self.creation.role}]
        )

    def preflight(self):
        # Also proves the login is in clish: an expert shell has no `show config-state`.
        if self.state() != "saved":
            raise DeviceError(
                "Gaia has unsaved configuration changes that save config would persist; "
                "resolve them before rotation"
            )
        self.before = self.account()
        if self.before is None:
            if not self.request.create_if_missing:
                raise DeviceError("local account is missing and create_if_missing is false")
            if self.creation.role not in BUILTIN_ROLES and self.creation.role not in self.roles:
                raise DeviceError("Gaia role for the new account does not exist")
            return False
        value = stored_hash(self.before)
        if value is None or not HASH.fullmatch(value):
            raise DeviceError(
                "Gaia account has no usable local password (disabled or remote-only); "
                "it cannot be rotated as a local account"
            )
        return True

    def apply(self):
        self.hashed = sha512_crypt.using(rounds=5000).hash(self.password)
        self.ssh.selector.secrets.add(self.hashed)
        self.locked = True
        output, refused = self.run("lock database override")
        if refused:
            self.reject(refusal(output))
        if self.state() != "saved":
            self.reject(
                "Gaia has unsaved configuration changes from another session; nothing was written "
                "and the account is unchanged"
            )
        if self.account() != self.before:
            self.unlock()
            raise DeviceError("account changed since precheck; submit a new job")
        user, commands = self.user, []
        if self.before is None:
            self.uid = next((uid for uid in range(FIRST_UID, LAST_UID + 1) if uid not in self.uids), None)
            if self.uid is None:
                self.reject("Gaia has no free user ID for a new account; nothing was written")
            commands.append("add user " + user + " uid " + str(self.uid) + " homedir /home/" + user)
        commands.append("set user " + user + " password-hash " + self.hashed)
        if self.before is None:
            commands += [
                "set user " + user + " shell " + SHELL,
                "add rba user " + user + " roles " + self.creation.role,
            ]
        reason = None
        for command in commands:
            output, refused = self.run(command)
            if refused:
                reason = refusal(output)
                break
        self.after = self.account()
        if self.after == self.before:
            self.reject(reason or IGNORED_REASON)
        if reason or not self.matches(self.after):
            raise DeviceError(
                "Gaia account is only partly changed or differs from the request; inspect before recovery"
            )
        self.report.setdefault("confirmed", []).append("running_matches")

    def save(self):
        if self.after is None or not self.locked:
            raise DeviceError(
                "Gaia change step did not complete in this session; nothing was saved, "
                "inspect before recovery"
            )
        if self.run("save config")[1]:
            raise DeviceError(
                "Gaia save config was refused; the change is in the running configuration only, "
                "inspect before recovery"
            )
        # `saved` means the saved configuration equals the running one, which holds the new hash.
        if self.state() != "saved" or self.account() != self.after:
            raise DeviceError(
                "Gaia saved configuration does not hold the new password hash; inspect before recovery"
            )
        self.report.setdefault("confirmed", []).append("saved")
        self.unlock()

    def verify(self):
        if self.request.verification == "ssh_login":
            verify_login(self.settings, self.device, self.user, self.password, self.guard)
            return
        value = stored_hash(self.account())
        if value is None:
            raise DeviceError("Gaia account has no readable password hash; use SSH login verification")
        if value == REDACTED and self.hashed:
            # Redaction replaced exactly the hash this adapter generated from the password.
            value = self.hashed
        if not crypt_matches(self.password, value):
            raise PasswordRejected("Gaia stored password hash does not match the requested password")

    def close(self):
        self.ssh.close()
