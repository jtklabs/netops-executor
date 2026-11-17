import base64
import json

import httpx
import pytest
from test_controls_credentials import vault_for

from netops_executor.config import HTTPTarget
from netops_executor.credentials import Credential
from netops_executor.password_devices import ChangeNotAccepted, PasswordRejected
from netops_executor.password_engine import adapter
from netops_executor.password_infoblox import InfobloxAccounts, check_password
from netops_executor.password_models import PasswordRotationOptions
from netops_executor.ssh import DeviceError

# "Denied" also checks that an error echoing the password is not read as a permission refusal.
PASSWORD = "Denied-Password-123!"
OLD = "Old-Password-456!"
WAPI = "/wapi/v2.12"


class Grid:
    """A simulated Grid Master WAPI with basic auth and an ibapauth session cookie."""

    def __init__(self):
        self.users, self.passwords, self.calls = {}, {"netops-api": "api-secret"}, []
        self.write = self.login = "ok"
        self.add("automation", ["dns-admins"])
        self.add("admin", ["admin-group"])

    def add(self, name, groups, auth_type="LOCAL", disable=False):
        ref = "adminuser/" + base64.urlsafe_b64encode(b".admin$" + name.encode()).decode().rstrip("=")
        self.users[name] = {
            "_ref": ref + ":" + name,
            "name": name,
            "admin_groups": groups,
            "auth_type": auth_type,
            "disable": disable,
            "comment": "managed",
        }
        self.passwords[name] = OLD

    def remove(self, name):
        del self.users[name], self.passwords[name]

    def authenticate(self, request):
        # The API session's cookie answers before credentials, as an ibapauth session would.
        if "ibapauth=api-session" in request.headers.get("cookie", ""):
            return "netops-api"
        scheme, _, value = request.headers.get("authorization", "").partition(" ")
        if scheme == "Basic":
            user, _, password = base64.b64decode(value).decode().partition(":")
            if self.passwords.get(user) == password:
                return user
        return None

    def handle(self, request):
        body = json.loads(request.content) if request.content else None
        path, user = request.url.path, self.authenticate(request)
        self.calls.append((request.method, path, body, user))
        if user is None:
            return httpx.Response(401, text="<html>Authorization Required</html>")
        cookies = {"set-cookie": "ibapauth=api-session; Path=/"} if user == "netops-api" else {}
        if path == WAPI + "/grid":
            if user != "netops-api" and self.login == "no_api":
                error = {"Error": "AdmConProtoError: API access is not allowed", "code": "Client.Ibap.Proto"}
                return httpx.Response(403, json=error)
            if user != "netops-api" and self.login == "proxy":
                return httpx.Response(403, text="<html>Forbidden</html>")
            return httpx.Response(200, json=[{"_ref": "grid/b25lLmNsdXN0ZXIkMA:Infoblox"}], headers=cookies)
        if request.method == "GET" and path == WAPI + "/adminuser":
            fields = request.url.params["_return_fields"].split(",")
            assert fields == ["name", "admin_groups", "auth_type", "disable", "comment"]
            found = [u for u in self.users.values() if u["name"] == request.url.params["name"]]
            return httpx.Response(200, json=found, headers=cookies)
        if self.write == "forbidden":
            return httpx.Response(
                403, json={"Error": "AdmConProtoError: forbidden", "code": "Client.Ibap.Proto"}
            )
        if self.write == "denied":
            error = {
                "Error": "AdmConDataError: None (IBDataConflictError: IB.Data.Conflict:Write permission denied)",
                "code": "Client.Ibap.Data.Conflict",
                "text": "Write permission denied",
            }
            return httpx.Response(400, json=error)
        if self.write == "policy":
            # WAPI error text can echo the request.
            error = {"Error": "AdmConDataError", "text": "Password " + body["password"] + " too weak"}
            return httpx.Response(400, json=error)
        if self.write == "error":
            return httpx.Response(500, json={"Error": "internal", "text": body["password"]})
        if self.write == "timeout":
            raise httpx.ReadTimeout("no answer", request=request)
        if request.method == "POST" and path == WAPI + "/adminuser":
            if self.write != "noop":
                self.add(body["name"], body["admin_groups"])
                self.passwords[body["name"]] = body["password"]
            return httpx.Response(201, json="adminuser/new:" + body["name"])
        target = next((u for u in self.users.values() if WAPI + "/" + u["_ref"] == path), None)
        if request.method == "PUT" and target:
            if self.write in ("ok", "groups"):
                self.passwords[target["name"]] = body["password"]
            if self.write == "groups":
                target["admin_groups"] = ["admin-group"]
            return httpx.Response(200, json=target["_ref"])
        return httpx.Response(
            404, json={"Error": "AdmConDataNotFoundError", "code": "Client.Ibap.Data.NotFound"}
        )


@pytest.fixture
def grid(settings, store, monkeypatch):
    vault_for(settings, store).put(
        "infoblox-api", Credential(kind="http", scheme="basic", username="netops-api", password="api-secret")
    )
    settings.http_targets["infoblox"] = HTTPTarget(
        id="infoblox", base_url="https://infoblox.test", auth_probe_path=WAPI + "/grid"
    )
    server = Grid()
    original = httpx.Client
    monkeypatch.setattr(
        "netops_executor.password_http.httpx.Client",
        lambda **kwargs: original(transport=httpx.MockTransport(lambda r: server.handle(r)), **kwargs),
    )
    return server


def request(**kwargs):
    r = PasswordRotationOptions.model_validate(
        {
            "device": "infoblox",
            "device_type": "infoblox",
            "username": "automation",
            "http_target": "infoblox",
            "allow_preview": True,
            **kwargs,
        }
    )
    r.for_platform(r.device_type)
    return r


def accounts(settings, store, password=PASSWORD, **kwargs):
    return InfobloxAccounts(settings, store, None, request(**kwargs), password, lambda: None, None)


def writes(grid):
    return [(m, p, b) for m, p, b, _ in grid.calls if m in ("POST", "PUT")]


def secret_free(*values):
    text = json.dumps([str(v) for v in values])
    return PASSWORD not in text and "api-secret" not in text


def test_engine_resolves_the_infoblox_adapter_and_password_syntax():
    assert adapter("infoblox") is InfobloxAccounts
    assert request().verification == "api_login"
    check_password(PASSWORD + " ~!@#$%^&*()'\"\\:")
    for bad in ("pässword", "tab\there", ""):
        with pytest.raises(ValueError, match="printable ASCII"):
            check_password(bad)


@pytest.mark.parametrize(
    "probe, base",
    [
        ("/wapi/v2.12/grid", "/wapi/v2.12"),
        ("/wapi/v2.12", "/wapi/v2.12"),
        ("/wapi/v2.9.5/grid", "/wapi/v2.9.5"),
    ],
)
def test_wapi_base_comes_from_the_probe_path(settings, store, grid, probe, base):
    settings.http_targets["infoblox"] = HTTPTarget(
        id="infoblox", base_url="https://infoblox.test", auth_probe_path=probe
    )
    assert accounts(settings, store).base == base


@pytest.mark.parametrize("probe", ["/api/grid", "/wapi/grid", "/wapiv2.12/grid", "/wapi/v2.12x/grid"])
def test_non_wapi_probe_path_is_refused(settings, store, grid, probe):
    settings.http_targets["infoblox"] = HTTPTarget(
        id="infoblox", base_url="https://infoblox.test", auth_probe_path=probe
    )
    with pytest.raises(DeviceError, match="WAPI path"):
        accounts(settings, store)


def test_update_changes_only_the_password_and_proves_it_by_login(settings, store, grid):
    device = accounts(settings, store)
    assert device.preflight() is True
    assert device.reservations == ["http:infoblox"]
    device.apply()
    device.save()
    device.verify()
    device.close()
    ref = grid.users["automation"]["_ref"]
    assert writes(grid) == [("PUT", WAPI + "/" + ref, {"password": PASSWORD})]
    assert grid.users["automation"]["admin_groups"] == ["dns-admins"]
    assert grid.passwords["automation"] == PASSWORD
    # The session's cookie is reused by the API login, never by the verification login.
    assert any(user == "netops-api" for m, p, b, user in grid.calls[1:])
    assert grid.calls[-1] == ("GET", WAPI + "/grid", None, "automation")
    assert device.report["confirmed"] == ["change_applied", "access_unchanged", "persisted", "login"]
    assert secret_free(device.report)


@pytest.mark.parametrize("groups", [None, ["dns-admins"]])
def test_creation_uses_requested_or_default_group(settings, store, grid, groups):
    grid.remove("automation")
    device = accounts(settings, store, **({"new_account": {"groups": groups}} if groups else {}))
    assert device.preflight() is False
    device.apply()
    device.save()
    device.verify()
    expected = groups or ["admin-group"]
    assert writes(grid) == [
        ("POST", WAPI + "/adminuser", {"name": "automation", "password": PASSWORD, "admin_groups": expected})
    ]
    assert grid.users["automation"]["admin_groups"] == expected
    assert device.report["confirmed"][:2] == ["change_applied", "groups_applied"]


def test_missing_account_without_creation_is_refused_read_only(settings, store, grid):
    grid.remove("automation")
    with pytest.raises(DeviceError, match="missing and create_if_missing is false"):
        accounts(settings, store, create_if_missing=False).preflight()
    assert writes(grid) == []


@pytest.mark.parametrize(
    "setup, username, options, message",
    [
        (lambda g: g.users["automation"].update(auth_type="REMOTE"), "automation", {}, "remote or SAML-only"),
        (lambda g: g.users["automation"].update(auth_type="SAML"), "automation", {}, "remote or SAML-only"),
        (lambda g: g.users["automation"].update(disable=True), "automation", {}, "disabled"),
        (lambda g: None, "netops-api", {}, "its own password"),
        (
            lambda g: g.remove("automation"),
            "automation",
            {"new_account": {"groups": ["a", "b"]}},
            "one admin",
        ),
    ],
)
def test_preflight_refuses_accounts_it_cannot_rotate(
    settings, store, grid, setup, username, options, message
):
    setup(grid)
    with pytest.raises(DeviceError, match=message):
        accounts(settings, store, username=username, **options).preflight()
    assert writes(grid) == []


def test_saml_local_users_keep_a_local_password_and_are_rotated(settings, store, grid):
    grid.users["automation"]["auth_type"] = "SAML_LOCAL"
    device = accounts(settings, store)
    device.preflight()
    device.apply()
    assert grid.passwords["automation"] == PASSWORD


@pytest.mark.parametrize("existing", [True, False])
@pytest.mark.parametrize(
    "mode, wording",
    [
        ("forbidden", "admin group \\(permission denied\\)"),
        ("denied", "admin group \\(permission denied\\)"),
        ("policy", "password policy"),
    ],
)
def test_refused_write_is_not_accepted_when_the_record_is_unchanged(
    settings, store, grid, existing, mode, wording
):
    if not existing:
        grid.remove("automation")
    device = accounts(settings, store)
    device.preflight()
    grid.write = mode
    with pytest.raises(ChangeNotAccepted, match=wording) as caught:
        device.apply()
    assert grid.passwords.get("automation") == (OLD if existing else None)
    assert secret_free(caught.value, device.report)
    assert "confirmed" not in device.report


def test_acknowledged_creation_that_left_no_account_is_not_accepted(settings, store, grid):
    grid.remove("automation")
    device = accounts(settings, store)
    device.preflight()
    grid.write = "noop"
    with pytest.raises(ChangeNotAccepted, match="still missing"):
        device.apply()


def test_silently_ignored_password_is_caught_by_a_cookie_free_login(settings, store, grid):
    device = accounts(settings, store)
    device.preflight()
    grid.write = "noop"
    device.apply()
    device.save()
    # The API session holds an ibapauth cookie that would answer for any request.
    with pytest.raises(PasswordRejected) as caught:
        device.verify()
    assert secret_free(caught.value, device.report)
    assert sum(p == WAPI + "/grid" and user is None for m, p, b, user in grid.calls) == 1


@pytest.mark.parametrize("mode", ["groups", "error", "timeout", "refused_but_changed"])
def test_partial_or_unknown_outcome_requires_recovery(settings, store, grid, mode):
    device = accounts(settings, store)
    device.preflight()
    if mode == "refused_but_changed":
        grid.write = "forbidden"
        original = grid.handle

        def handle(request):
            if request.method == "PUT":
                grid.users["automation"]["comment"] = "changed by someone else"
            return original(request)

        grid.handle = handle
    else:
        grid.write = mode
    with pytest.raises(DeviceError) as caught:
        device.apply()
    assert not isinstance(caught.value, ChangeNotAccepted)
    assert secret_free(caught.value)


def test_change_since_precheck_is_refused_before_writing(settings, store, grid):
    device = accounts(settings, store)
    device.preflight()
    grid.users["automation"]["admin_groups"] = ["admin-group"]
    with pytest.raises(DeviceError, match="changed since precheck"):
        device.apply()
    assert writes(grid) == []


def test_save_confirms_the_record_still_holds(settings, store, grid):
    device = accounts(settings, store)
    device.preflight()
    device.apply()
    grid.users["automation"]["disable"] = True
    with pytest.raises(DeviceError, match="changed after the write"):
        device.save()


@pytest.mark.parametrize(
    "login, error, fact",
    [
        ("ok", None, "login"),
        ("no_api", None, "login_without_api_permission"),
        ("rejected", PasswordRejected, None),
        ("proxy", DeviceError, None),
    ],
)
def test_verification_after_resume_is_one_basic_auth_login(settings, store, grid, login, error, fact):
    grid.passwords["automation"] = OLD if login == "rejected" else PASSWORD
    grid.login = login
    # A review continuation builds a new adapter and runs only verify.
    device = accounts(settings, store)
    if error is None:
        device.verify()
        assert device.report["confirmed"] == [fact]
    else:
        with pytest.raises(error) as caught:
            device.verify()
        assert type(caught.value) is error
        assert secret_free(caught.value, device.report)
    assert [(m, p) for m, p, b, user in grid.calls] == [("GET", WAPI + "/grid")]
    assert writes(grid) == []
