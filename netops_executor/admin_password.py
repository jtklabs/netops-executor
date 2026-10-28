"""Compare the expected local admin password without an authentication attempt.

Only a boolean leaves the hash verifier. Never retain raw device output, password
hashes, or plaintext passwords in the job database, events, or exception messages.
"""

import re

from passlib.hash import sha256_crypt, sha512_crypt

from .device import blocks, field
from .ssh import DeviceError


class PasswordCheckUnavailable(DeviceError):
    pass


def matches_admin_password(ssh, password):
    try:
        output = ssh.tmsh("list /auth user admin encrypted-password", timeout=30)
        users = blocks(output, "auth user")
        if len(users) != 1 or next(iter(users)) not in ("admin", "/Common/admin"):
            raise ValueError()
        encoded = field(next(iter(users.values())), "encrypted-password")
        if encoded == "none":
            return False
        match = re.fullmatch(
            r"\$(5|6)\$(?:rounds=([1-9][0-9]{3,6})\$)?[./0-9A-Za-z]{1,16}\$([./0-9A-Za-z]+)",
            encoded or "",
        )
        if not match or len(match[3]) != (43 if match[1] == "5" else 86):
            raise ValueError()
        # Bound computation for device-returned hashes, including forged rounds.
        if int(match[2] or 5000) > 1000000:
            raise ValueError()
        verifier = sha256_crypt if match[1] == "5" else sha512_crypt
        return verifier.verify(password, encoded)
    except (ValueError, TypeError, DeviceError):
        raise PasswordCheckUnavailable(
            "local admin password could not be checked; verify account visibility and supported SHA-crypt format"
        ) from None


def reset_admin_password(ssh, password):
    if not password or len(password.encode()) > 1024 or any(c in password for c in "\r\n\x00"):
        raise DeviceError("invalid expected admin password")
    # This goes to tmsh's stdin, not a shell argument or a process command line.
    quoted = password.replace("\\", "\\\\").replace('"', '\\"')
    ssh.tmsh('modify /auth user admin password "' + quoted + '"', timeout=30, secret=True)
