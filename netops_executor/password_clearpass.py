"""Aruba ClearPass Policy Manager local administrator rotation over the REST API (preview).

Relies on the ClearPass 6.x REST API (API Explorer at /api-docs, AdminUser resource):
`GET /api/admin-user?filter={"user_id": ...}` lists records as
`{"_embedded": {"items": [...]}}` with `id`, `user_id`, `name`, `enabled` and `privilege_level`
(never the password); `PATCH /api/admin-user/{id}` with `{"password": ...}` changes one field;
`POST /api/admin-user` creates `{user_id, name, password, enabled, privilege_level}`. The session
is the target's oauth2 (client credentials) profile; the API client's operator profile decides
what it may change, and ClearPass answers 403 when that profile lacks the permission.

Acceptance: ClearPass never returns a password, so a write is accepted when the API acknowledges
it and the record's other settings (id, user_id, name, enabled, privilege_level) are unchanged
(or carry the requested privilege level for a new account); the new password itself is proven
by the api_login verification. A refused write (4xx) is reported as not accepted only after a
re-read shows the record exactly as before; the password cannot be re-read, so that relies on
ClearPass rejecting a request before applying any of it. Admin users are written to the
configuration database at once: there is no candidate or save step, so `save` re-reads the
record. Point the target at the cluster publisher, where configuration is written.

api_login: Policy Manager admin users have no API login of their own. The closest API route is
the OAuth2 password grant at `/api/oauth`, which needs an API client whose grant type is
"Username and password credentials" (a client has exactly one grant type, so the session's
client-credentials client cannot be reused). Its client ID and secret are read from the HTTP
credential profile named `<http_target>-password-grant` (scheme oauth2; restrict its targets to
that name so the session never tries it). The password grant authenticates operator logins
through the [Guest Operator Logins] service, which by default does not use the Admin User
Repository: it must be configured to authenticate admin users (and map them to an operator
profile), otherwise a correct password is reported as rejected and the job goes to review.
Assumed without a lab device: field names and error statuses above, `invalid_grant` for a wrong
password (RFC 6749 section 5.2), and that the issued token is simply left to expire.
"""

import json

from .credentials import Vault
from .password_devices import ChangeNotAccepted, PasswordRejected
from .password_http import ApiSession, ApiUnavailable
from .password_models import AccountCreation
from .ssh import DeviceError
from .store import Conflict

USERS = "/api/admin-user"
LOGIN_PROFILE = "{target}-password-grant"
# Settings a password change must leave alone; the record has no readable password field.
ACCESS = ("id", "user_id", "name", "enabled", "privilege_level")
PERMISSION = (
    "ClearPass refused the change for the API client's operator profile (permission denied); "
    "the admin user is unchanged"
)
UNAUTHORIZED = (
    "ClearPass rejected the API session's authorization for the change; the admin user is unchanged"
)
REJECTED = (
    "ClearPass rejected the admin user change (for example its password policy); the admin user is unchanged"
)


class ClearpassAccounts:
    def __init__(self, settings, store, device, request, password, guard, audit, ssh=None, session=None):
        self.settings, self.store, self.request, self.password = settings, store, request, password
        if session is None and request.http_target not in settings.http_targets:
            raise DeviceError("the ClearPass HTTP target is not configured")
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
        self.role = request.new_account.role if request.new_account else None
        self.before = self.after = self.login = None
        # Serialize with generic HTTP jobs and other rotations on the same API.
        self.reservations = ["http:" + self.session.target.id]
        self.report = {}

    def confirmed(self, fact):
        self.report.setdefault("confirmed", []).append(fact)

    def login_client(self):
        name = LOGIN_PROFILE.format(target=self.session.target.id)
        try:
            found = Vault(self.store, self.settings.credential_key_file).candidates(
                "http", [name], (self.session.target.id, name)
            )
        except Conflict:
            found = []
        if len(found) != 1 or found[0].get("scheme") != "oauth2":
            raise DeviceError(
                "ClearPass api_login requires an enabled oauth2 HTTP credential profile named "
                "<http_target>-password-grant for an API client with the password grant"
            )
        client = found[0]
        self.session.selector.secrets.add(client["password"])
        return client["username"], client["password"], client.get("token_path") or "/api/oauth"

    def read(self):
        user = self.request.username
        status, body = self.session.request(
            "GET", USERS, params={"filter": json.dumps({"user_id": user}), "limit": "25"}
        )
        if status in (401, 403):
            raise DeviceError("the ClearPass API client cannot read admin users (permission denied)")
        items = (
            (body.get("_embedded") or {}).get("items") if status == 200 and isinstance(body, dict) else None
        )
        if not isinstance(items, list) or any(
            not isinstance(item, dict) or not isinstance(item.get("user_id"), str) for item in items
        ):
            raise DeviceError("ClearPass admin user list is unavailable")
        if any(item["user_id"].casefold() != user.casefold() for item in items):
            raise DeviceError("ClearPass did not apply the admin user filter")
        if any(item["user_id"] != user for item in items):
            raise DeviceError("a ClearPass admin user ID differs only in letter case")
        if len(items) > 1:
            raise DeviceError("duplicate ClearPass admin user")
        if not items:
            return None
        record = {key: items[0].get(key) for key in ACCESS}
        if (
            not isinstance(record["id"], int)
            or isinstance(record["id"], bool)
            or not isinstance(record["enabled"], bool)
            or not isinstance(record["privilege_level"], str)
        ):
            raise DeviceError("ClearPass admin user record is unreadable")
        return record

    def preflight(self):
        # Without a usable verification client the new password could never be proven.
        self.login = self.login_client()
        self.before = self.read()
        if self.before is None:
            if not self.request.create_if_missing:
                raise DeviceError("ClearPass admin user is missing and create_if_missing is false")
            self.role = self.role or AccountCreation.administrator("clearpass").role
        elif not self.before["enabled"]:
            raise DeviceError("ClearPass admin user is disabled; enable it deliberately before rotation")
        return self.before is not None

    def apply(self):
        user = self.request.username
        if self.read() != self.before:
            raise DeviceError("ClearPass admin user changed since precheck; submit a new job")
        if self.before is None:
            method, path = "POST", USERS
            body = {
                "user_id": user,
                "name": user,
                "password": self.password,
                "enabled": True,
                "privilege_level": self.role,
            }
        else:
            method, path, body = "PATCH", USERS + "/" + str(self.before["id"]), {"password": self.password}
        try:
            status, _ = self.session.request(method, path, json=body)
        except ApiUnavailable:
            raise DeviceError(
                "ClearPass admin user write had no definite answer; inspect the account before recovery"
            ) from None
        after = self.read()
        if 400 <= status < 500:
            if after != self.before:
                raise DeviceError(
                    "ClearPass refused the change but the admin user differs from the precheck; "
                    "inspect it before recovery"
                )
            raise ChangeNotAccepted(
                PERMISSION if status == 403 else UNAUTHORIZED if status == 401 else REJECTED
            )
        if not 200 <= status < 300:
            raise DeviceError(
                "ClearPass answered the admin user write with an error; inspect before recovery"
            )
        if self.before is None:
            if after is None:
                raise ChangeNotAccepted(
                    "ClearPass acknowledged the creation but the admin user is still missing; nothing changed"
                )
            if after["privilege_level"] != self.role or not after["enabled"] or after["name"] != user:
                raise DeviceError("ClearPass created the admin user with unexpected settings; inspect it")
        elif after != self.before:
            raise DeviceError("ClearPass admin user settings changed unexpectedly; inspect before recovery")
        self.after = after
        self.confirmed("change_applied")
        self.confirmed("role_applied" if self.before is None else "access_unchanged")

    def save(self):
        # Admin users are stored as soon as the API acknowledges them; confirm the record holds.
        if self.after is None or self.read() != self.after:
            raise DeviceError("ClearPass admin user changed after the write; inspect before recovery")
        self.confirmed("persisted")

    def verify(self):
        client_id, secret, token_path = self.login or self.login_client()
        # A fresh connection: nothing from the API client's session takes part in the login.
        self.session.close()
        try:
            status, body = self.session.request(
                "POST",
                token_path,
                json={
                    "grant_type": "password",
                    "username": self.request.username,
                    "password": self.password,
                    "client_id": client_id,
                    "client_secret": secret,
                },
                options={},
            )
        except ApiUnavailable:
            raise DeviceError(
                "ClearPass login verification had no answer; the new password is unverified"
            ) from None
        finally:
            self.session.close()
        body = body if isinstance(body, dict) else {}
        token, error = body.get("access_token"), body.get("error")
        if 200 <= status < 300 and isinstance(token, str) and token:
            self.session.selector.secrets.add(token)
            self.confirmed("login")
            return
        if error == "invalid_grant" or (status == 401 and error is None):
            raise PasswordRejected(
                "ClearPass rejected a password-grant login with the new password; no automatic retry"
            )
        raise DeviceError(
            "ClearPass password-grant login did not complete; check the verification API client and "
            "that operator logins authenticate admin users"
        )

    def close(self):
        self.session.close()
