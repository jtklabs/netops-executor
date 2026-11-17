"""Infoblox NIOS Grid Manager local administrator rotation over WAPI (preview).

Relies on the WAPI `adminuser` object (WAPI 2.x reference): searchable by `name`; readable
`_ref`, `name`, `admin_groups` (one group), `auth_type` (LOCAL, REMOTE, SAML, SAML_LOCAL),
`disable` and `comment`; `password` is write-only. `GET <base>/adminuser?name=<u>&_return_fields=...`
reads it, `PUT <base>/<_ref>` with `{"password": ...}` changes only the password and
`POST <base>/adminuser` with `{name, password, admin_groups}` creates a local (LOCAL) user.
The WAPI base (`/wapi/v2.12`) comes from the target's `auth_probe_path` (`/wapi/v2.12/grid`).
The session uses the target's basic-auth profile against the Grid Master.

Acceptance: WAPI never returns a password, so a write is accepted when WAPI acknowledges it
and the re-read record is otherwise identical (or, for a creation, local, enabled and in the
requested group); the new password is proven by the api_login verification. A refused write
(4xx) is reported as not accepted only after a re-read shows the record exactly as before; the
password cannot be re-read, so that relies on WAPI applying a request as one transaction.
NIOS has no candidate configuration or save step, and `adminuser` does not support scheduled
or approval-workflow changes, so `save` re-reads the record.

api_login: one `GET <base>/grid` with HTTP Basic authentication as the rotated user, on a new
connection (an `ibapauth` cookie from the API session must not answer for it). 2xx proves the
password; 401 is a rejection. A 403 carrying a WAPI error body is taken as proof too: NIOS
checks the password before authorization, so the user authenticated but lacks API permission.
REMOTE and SAML-only users have no local password and are refused; SAML_LOCAL users keep a local
password that WAPI accepts and are rotated. Assumed without a lab device: WAPI versions that
expose `auth_type` (older grids reject the read, which fails safe), the error statuses above,
that the grid's authentication policy tries the local database for local users, and that the
rotated user's admin group allows API access (otherwise NIOS answers 401 and the job is
reviewed). The API session's own account cannot be rotated: its saved password would go stale.
"""

import base64
import re

from .password_devices import ChangeNotAccepted, PasswordRejected
from .password_http import ApiSession, ApiUnavailable
from .password_models import AccountCreation
from .ssh import DeviceError

BASE = re.compile(r"(/wapi/v[0-9]+(?:\.[0-9]+)*)(?:/|$)")
FIELDS = ("name", "admin_groups", "auth_type", "disable", "comment")
LOCAL_AUTH = ("LOCAL", "SAML_LOCAL")
REF = re.compile(r"adminuser/[A-Za-z0-9_+=/:%.-]+")
PERMISSION_TEXT = re.compile(r"(?i)permission|not authori[sz]ed|unauthori[sz]ed|denied|forbidden|superuser")
PERMISSION = (
    "Infoblox refused the change for the API login's admin group (permission denied); "
    "the admin user is unchanged"
)
REJECTED = (
    "Infoblox rejected the admin user change (for example its password policy); the admin user is unchanged"
)


def check_password(password):
    # The verification login sends the password in HTTP Basic authentication, whose character
    # encoding NIOS does not document; printable ASCII is unambiguous.
    if not password or any(not " " <= c <= "~" for c in password):
        raise ValueError("Infoblox passwords must contain only printable ASCII characters")


class InfobloxAccounts:
    def __init__(self, settings, store, device, request, password, guard, audit, ssh=None, session=None):
        self.request, self.password = request, password
        if session is None and request.http_target not in settings.http_targets:
            raise DeviceError("the Infoblox HTTP target is not configured")
        self.session = session or ApiSession(
            settings,
            store,
            request.http_target,
            request.http_credential_profiles,
            guard,
            audit,
            timeout=request.command_timeout,
        )
        self.session.selector.secrets.add(password)
        match = BASE.match(self.session.target.auth_probe_path or "")
        if not match:
            raise DeviceError(
                "the Infoblox HTTP target's auth_probe_path must be a WAPI path such as /wapi/v2.12/grid"
            )
        self.base = match[1]
        self.creation = request.new_account
        self.before = self.after = None
        # Serialize with generic HTTP jobs and other rotations on the same API.
        self.reservations = ["http:" + self.session.target.id]
        self.report = {}

    def confirmed(self, fact):
        self.report.setdefault("confirmed", []).append(fact)

    def read(self):
        user = self.request.username
        status, body = self.session.request(
            "GET", self.base + "/adminuser", params={"name": user, "_return_fields": ",".join(FIELDS)}
        )
        if status in (401, 403):
            raise DeviceError("the Infoblox API login cannot read admin users (permission denied)")
        if status != 200 or not isinstance(body, list) or any(not isinstance(item, dict) for item in body):
            raise DeviceError("Infoblox admin user list is unavailable")
        if any(item.get("name") != user for item in body):
            raise DeviceError("Infoblox did not apply the admin user name search")
        if len(body) > 1:
            raise DeviceError("duplicate Infoblox admin user")
        if not body:
            return None
        record = {key: body[0].get(key) for key in ("_ref", *FIELDS)}
        if (
            not isinstance(record["_ref"], str)
            or not REF.fullmatch(record["_ref"])
            or ".." in record["_ref"]
            or not isinstance(record["admin_groups"], list)
            or not isinstance(record["auth_type"], str)
            or not isinstance(record["disable"], bool)
        ):
            raise DeviceError("Infoblox admin user record is unreadable")
        return record

    def preflight(self):
        try:
            check_password(self.password)
        except ValueError:
            raise DeviceError("Infoblox passwords must contain only printable ASCII characters") from None
        login = self.session.connect().get("auth")
        if login and str(login[0]).casefold() == self.request.username.casefold():
            raise DeviceError(
                "the Infoblox API login cannot rotate its own password; use another HTTP credential profile"
            )
        self.before = self.read()
        if self.before is None:
            if not self.request.create_if_missing:
                raise DeviceError("Infoblox admin user is missing and create_if_missing is false")
            self.creation = self.creation or AccountCreation.administrator("infoblox")
            if len(self.creation.groups or []) != 1:
                raise DeviceError("an Infoblox admin user belongs to exactly one admin group")
        elif self.before["auth_type"] not in LOCAL_AUTH:
            raise DeviceError(
                "Infoblox admin user uses remote or SAML-only authentication; it has no local password"
            )
        elif self.before["disable"]:
            raise DeviceError("Infoblox admin user is disabled; enable it deliberately before rotation")
        return self.before is not None

    def apply(self):
        user = self.request.username
        if self.read() != self.before:
            raise DeviceError("Infoblox admin user changed since precheck; submit a new job")
        if self.before is None:
            method, path = "POST", self.base + "/adminuser"
            body = {"name": user, "password": self.password, "admin_groups": list(self.creation.groups)}
        else:
            method, path, body = "PUT", self.base + "/" + self.before["_ref"], {"password": self.password}
        try:
            status, answer = self.session.request(method, path, json=body)
        except ApiUnavailable:
            raise DeviceError(
                "Infoblox admin user write had no definite answer; inspect the account before recovery"
            ) from None
        after = self.read()
        if 400 <= status < 500:
            if after != self.before:
                raise DeviceError(
                    "Infoblox refused the change but the admin user differs from the precheck; "
                    "inspect it before recovery"
                )
            # The error text can echo the request: it is only matched, after redaction, never kept.
            text = (
                " ".join(str(answer.get(k, "")) for k in ("Error", "code", "text"))
                if isinstance(answer, dict)
                else ""
            )
            refused = status in (401, 403) or PERMISSION_TEXT.search(self.session.selector.redact(text))
            raise ChangeNotAccepted(PERMISSION if refused else REJECTED)
        if not 200 <= status < 300:
            raise DeviceError("Infoblox answered the admin user write with an error; inspect before recovery")
        if self.before is None:
            if after is None:
                raise ChangeNotAccepted(
                    "Infoblox acknowledged the creation but the admin user is still missing; nothing changed"
                )
            if (
                after["admin_groups"] != list(self.creation.groups)
                or after["auth_type"] != "LOCAL"
                or after["disable"]
            ):
                raise DeviceError("Infoblox created the admin user with unexpected settings; inspect it")
        elif after != self.before:
            raise DeviceError("Infoblox admin user settings changed unexpectedly; inspect before recovery")
        self.after = after
        self.confirmed("change_applied")
        self.confirmed("groups_applied" if self.before is None else "access_unchanged")

    def save(self):
        # NIOS stores the change as soon as WAPI acknowledges it; confirm the record holds.
        if self.after is None or self.read() != self.after:
            raise DeviceError("Infoblox admin user changed after the write; inspect before recovery")
        self.confirmed("persisted")

    def verify(self):
        user = self.request.username
        self.session.selector.secrets.add(base64.b64encode((user + ":" + self.password).encode()).decode())
        # A fresh connection without the API session's cookie or credentials.
        self.session.close()
        try:
            status, body = self.session.request(
                "GET", self.base + "/grid", options={"auth": (user, self.password)}
            )
        except ApiUnavailable:
            raise DeviceError(
                "Infoblox login verification had no answer; the new password is unverified"
            ) from None
        finally:
            self.session.close()
        if 200 <= status < 300:
            self.confirmed("login")
            return
        if status == 401:
            raise PasswordRejected("Infoblox rejected a WAPI login with the new password; no automatic retry")
        if status == 403 and isinstance(body, dict) and ("Error" in body or "code" in body):
            # Authenticated, then refused: the password is proven although the user lacks API access.
            self.confirmed("login_without_api_permission")
            return
        raise DeviceError("Infoblox WAPI login verification failed; the new password is unverified")

    def close(self):
        self.session.close()
