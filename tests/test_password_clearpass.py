import json

import httpx
import pytest
from test_controls_credentials import vault_for

from netops_executor.config import HTTPTarget
from netops_executor.credentials import Credential, Vault
from netops_executor.password_clearpass import ClearpassAccounts
from netops_executor.password_devices import ChangeNotAccepted, PasswordRejected
from netops_executor.password_engine import adapter
from netops_executor.password_models import PasswordRotationOptions
from netops_executor.ssh import DeviceError

PASSWORD = "Desired-Password-123!"
OLD = "Old-Password-456!"


class ClearPass:
    """A simulated ClearPass REST API: OAuth, admin users and the password grant."""

    def __init__(self, existing=True):
        self.users = {}
        self.passwords = {}
        self.calls = []
        self.write = "ok"
        self.login = "ok"
        if existing:
            self.add("automation", "Network Administrator")
        self.add("admin", "Super Administrator")

    def add(self, user_id, privilege, enabled=True):
        self.users[user_id] = {
            "id": 3000 + len(self.users),
            "user_id": user_id,
            "name": user_id,
            "enabled": enabled,
            "privilege_level": privilege,
            "_links": {"self": {"href": "https://clearpass.test/api/admin-user/" + user_id}},
        }
        self.passwords[user_id] = OLD

    def remove(self, user_id):
        del self.users[user_id], self.passwords[user_id]

    def handle(self, request):
        body = json.loads(request.content) if request.content else None
        path = request.url.path
        self.calls.append((request.method, path, body))
        if path == "/api/oauth":
            if body["grant_type"] == "client_credentials":
                if (body["client_id"], body["client_secret"]) == ("netops", "client-secret"):
                    return httpx.Response(200, json={"access_token": "session-token", "expires_in": 28800})
                return httpx.Response(400, json={"error": "invalid_client"})
            if (body["client_id"], body["client_secret"]) != ("verifier", "verifier-secret"):
                return httpx.Response(400, json={"error": "invalid_client"})
            if self.passwords.get(body["username"]) == body["password"] and self.login == "ok":
                return httpx.Response(200, json={"access_token": "user-token", "expires_in": 28800})
            return httpx.Response(400, json={"error": "invalid_grant", "error_description": body["password"]})
        if request.headers.get("Authorization") != "Bearer session-token":
            return httpx.Response(401, json={"title": "Unauthorized"})
        if path == "/api/oauth/me":
            return httpx.Response(200, json={"name": "netops"})
        if request.method == "GET" and path == "/api/admin-user":
            wanted = json.loads(request.url.params["filter"])["user_id"]
            # Assumed case-insensitive, as user IDs are.
            items = [u for u in self.users.values() if u["user_id"].casefold() == wanted.casefold()]
            return httpx.Response(200, json={"_embedded": {"items": items}, "_links": {}})
        if self.write == "forbidden":
            return httpx.Response(403, json={"title": "Forbidden", "detail": "Access denied"})
        if self.write == "policy":
            # Error details can echo the request.
            return httpx.Response(422, json={"title": "Unprocessable", "detail": "weak: " + body["password"]})
        if self.write == "error":
            return httpx.Response(500, json={"detail": body["password"]})
        if self.write == "timeout":
            raise httpx.ReadTimeout("no answer", request=request)
        if request.method == "POST" and path == "/api/admin-user":
            if self.write != "noop":
                self.add(body["user_id"], body["privilege_level"], body["enabled"])
                self.passwords[body["user_id"]] = body["password"]
            return httpx.Response(201, json={"id": 1, "user_id": body["user_id"]})
        if request.method == "PATCH" and path.startswith("/api/admin-user/"):
            user = next(u for u in self.users.values() if str(u["id"]) == path.rsplit("/", 1)[1])
            if self.write == "ok":
                self.passwords[user["user_id"]] = body["password"]
            if self.write == "privilege":
                self.passwords[user["user_id"]] = body["password"]
                user["privilege_level"] = "Super Administrator"
            return httpx.Response(200, json={k: v for k, v in user.items()})
        return httpx.Response(404, json={"title": "Not Found"})


@pytest.fixture
def api(settings, store, monkeypatch):
    vault = vault_for(settings, store)
    vault.put(
        "clearpass-api",
        Credential(kind="http", scheme="oauth2", username="netops", password="client-secret"),
    )
    # The verification client is never tried as the session's own credential.
    vault.put(
        "clearpass-password-grant",
        Credential(
            kind="http",
            scheme="oauth2",
            username="verifier",
            password="verifier-secret",
            targets=["clearpass-password-grant"],
        ),
    )
    settings.http_targets["clearpass"] = HTTPTarget(
        id="clearpass", base_url="https://clearpass.test", auth_probe_path="/api/oauth/me"
    )
    server = ClearPass()
    original = httpx.Client
    monkeypatch.setattr(
        "netops_executor.password_http.httpx.Client",
        lambda **kwargs: original(transport=httpx.MockTransport(lambda r: server.handle(r)), **kwargs),
    )
    return server


def request(**kwargs):
    r = PasswordRotationOptions.model_validate(
        {
            "device": "clearpass",
            "device_type": "clearpass",
            "username": "automation",
            "http_target": "clearpass",
            "allow_preview": True,
            **kwargs,
        }
    )
    r.for_platform(r.device_type)
    return r


def accounts(settings, store, **kwargs):
    return ClearpassAccounts(settings, store, None, request(**kwargs), PASSWORD, lambda: None, None)


def writes(server):
    return [(m, p, b) for m, p, b in server.calls if m in ("POST", "PATCH") and p != "/api/oauth"]


def secret_free(*values):
    text = json.dumps([str(v) for v in values])
    return PASSWORD not in text and "verifier-secret" not in text and "session-token" not in text


def test_engine_resolves_the_clearpass_adapter():
    assert adapter("clearpass") is ClearpassAccounts
    assert request().verification == "api_login"


def test_update_keeps_privileges_and_proves_the_password_by_login(settings, store, api):
    device = accounts(settings, store)
    assert device.preflight() is True
    assert device.reservations == ["http:clearpass"]
    device.apply()
    device.save()
    device.verify()
    device.close()
    assert writes(api) == [("PATCH", "/api/admin-user/3000", {"password": PASSWORD})]
    assert api.users["automation"]["privilege_level"] == "Network Administrator"
    assert api.passwords["automation"] == PASSWORD
    grant = [b for m, p, b in api.calls if p == "/api/oauth" and b["grant_type"] == "password"]
    assert grant == [
        {
            "grant_type": "password",
            "username": "automation",
            "password": PASSWORD,
            "client_id": "verifier",
            "client_secret": "verifier-secret",
        }
    ]
    assert device.report["confirmed"] == ["change_applied", "access_unchanged", "persisted", "login"]
    assert secret_free(device.report)


@pytest.mark.parametrize("role", [None, "Netops-Operators"])
def test_creation_uses_requested_or_default_privilege_level(settings, store, api, role):
    api.remove("automation")
    options = {"new_account": {"role": role}} if role else {}
    device = accounts(settings, store, **options)
    assert device.preflight() is False
    device.apply()
    device.save()
    device.verify()
    expected = role or "Super Administrator"
    assert writes(api) == [
        (
            "POST",
            "/api/admin-user",
            {
                "user_id": "automation",
                "name": "automation",
                "password": PASSWORD,
                "enabled": True,
                "privilege_level": expected,
            },
        )
    ]
    assert api.users["automation"]["privilege_level"] == expected
    assert device.report["confirmed"][:2] == ["change_applied", "role_applied"]


def test_missing_account_without_creation_is_refused_read_only(settings, store, api):
    api.remove("automation")
    device = accounts(settings, store, create_if_missing=False)
    with pytest.raises(DeviceError, match="missing and create_if_missing is false"):
        device.preflight()
    assert writes(api) == []


@pytest.mark.parametrize(
    "setup, message",
    [
        (lambda s: s.users["automation"].update(enabled=False), "disabled"),
        (lambda s: s.add("Automation", "Super Administrator"), "letter case"),
    ],
)
def test_preflight_refuses_accounts_it_cannot_rotate_safely(settings, store, api, setup, message):
    setup(api)
    with pytest.raises(DeviceError, match=message):
        accounts(settings, store).preflight()
    assert writes(api) == []


def test_preflight_requires_the_verification_client_before_any_change(settings, store, api):
    with store.connect() as db:
        db.execute("DELETE FROM credentials WHERE id='clearpass-password-grant'")
    assert [c["id"] for c in Vault(store, settings.credential_key_file).list()] == ["clearpass-api"]
    with pytest.raises(DeviceError, match="password-grant"):
        accounts(settings, store).preflight()
    assert api.calls == []


@pytest.mark.parametrize("existing", [True, False])
@pytest.mark.parametrize(
    "mode, wording",
    [("forbidden", "operator profile \\(permission denied\\)"), ("policy", "password policy")],
)
def test_refused_write_is_not_accepted_when_the_record_is_unchanged(
    settings, store, api, existing, mode, wording
):
    if not existing:
        api.remove("automation")
    device = accounts(settings, store)
    device.preflight()
    api.write = mode
    with pytest.raises(ChangeNotAccepted, match=wording) as caught:
        device.apply()
    assert ("automation" in api.users) is existing
    assert api.passwords.get("automation") == (OLD if existing else None)
    assert secret_free(caught.value, device.report)
    assert "confirmed" not in device.report


def test_acknowledged_creation_that_left_no_account_is_not_accepted(settings, store, api):
    api.remove("automation")
    device = accounts(settings, store)
    device.preflight()
    api.write = "noop"
    with pytest.raises(ChangeNotAccepted, match="still missing"):
        device.apply()


def test_silently_ignored_password_is_caught_by_login_verification(settings, store, api):
    # ClearPass cannot show a password, so an ignored PATCH only surfaces at verification.
    device = accounts(settings, store)
    device.preflight()
    api.write = "noop"
    device.apply()
    device.save()
    with pytest.raises(PasswordRejected) as caught:
        device.verify()
    assert secret_free(caught.value, device.report)
    assert sum(b["grant_type"] == "password" for m, p, b in api.calls if p == "/api/oauth") == 1


@pytest.mark.parametrize("mode", ["privilege", "error", "timeout", "refused_but_changed"])
def test_partial_or_unknown_outcome_requires_recovery(settings, store, api, mode):
    device = accounts(settings, store)
    device.preflight()
    if mode == "refused_but_changed":
        api.write = "forbidden"
        original = api.handle

        def handle(request):
            response = original(request)
            if request.method == "PATCH":
                api.users["automation"]["enabled"] = False
            return response

        api.handle = handle
    else:
        api.write = mode
    with pytest.raises(DeviceError) as caught:
        device.apply()
    assert not isinstance(caught.value, ChangeNotAccepted)
    assert secret_free(caught.value)


def test_change_since_precheck_is_refused_before_writing(settings, store, api):
    device = accounts(settings, store)
    device.preflight()
    api.users["automation"]["privilege_level"] = "Super Administrator"
    with pytest.raises(DeviceError, match="changed since precheck"):
        device.apply()
    assert writes(api) == []


def test_save_confirms_the_record_still_holds(settings, store, api):
    device = accounts(settings, store)
    device.preflight()
    device.apply()
    api.users["automation"]["enabled"] = False
    with pytest.raises(DeviceError, match="changed after the write"):
        device.save()


@pytest.mark.parametrize(
    "login, error",
    [("ok", None), ("rejected", PasswordRejected), ("client", DeviceError)],
)
def test_verification_after_resume_uses_one_password_grant(settings, store, api, login, error):
    api.passwords["automation"] = PASSWORD if login != "rejected" else OLD
    if login == "client":
        # A misconfigured verification client proves nothing about the password.
        Vault(store, settings.credential_key_file).put(
            "clearpass-password-grant",
            Credential(
                kind="http",
                scheme="oauth2",
                username="verifier",
                password="wrong-secret",
                targets=["clearpass-password-grant"],
            ),
        )
    # A review continuation builds a new adapter and runs only verify.
    device = accounts(settings, store)
    if error is None:
        device.verify()
        assert device.report["confirmed"] == ["login"]
    else:
        with pytest.raises(error) as caught:
            device.verify()
        assert type(caught.value) is error
        assert secret_free(caught.value, device.report)
    assert writes(api) == []
    assert [b["grant_type"] for m, p, b in api.calls if p == "/api/oauth"] == ["password"]
    # The verification never authenticates as the API client.
    assert not any(p == "/api/oauth/me" for m, p, b in api.calls)
