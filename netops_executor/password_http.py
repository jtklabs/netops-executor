"""Authenticated HTTPS sessions for API-managed administrator accounts (ClearPass, Infoblox).

The session authenticates once with a saved HTTP credential profile (tried in order, with a
read-only probe), keeps the token in memory only, and redacts every known secret from
anything it returns. Callers turn responses into fixed messages: device bodies can echo a
submitted password.
"""

import ssl
import time

import httpx

from .credentials import AuthenticationRejected, Selector, Vault
from .execution import credential_options, probe
from .pins import PinnedContext, tls_key
from .ssh import DeviceError
from .store import Conflict

LIMIT = 4 * 1024 * 1024


class ApiError(DeviceError):
    """The API answered with an error status. `status` is the HTTP code; the body is withheld."""

    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


class ApiUnavailable(DeviceError):
    """No usable answer: the request may or may not have reached the server."""


class ApiSession:
    def __init__(self, settings, store, target, profiles, guard, audit, timeout=60):
        self.target = settings.http_targets[target] if isinstance(target, str) else target
        if not self.target.auth_probe_path:
            raise DeviceError("the HTTP target requires a read-only authentication probe")
        self.store, self.guard, self.timeout = store, guard, timeout
        self.selector = Selector(
            Vault(store, settings.credential_key_file),
            "http",
            self.target.id,
            profiles if profiles is not None else self.target.credential_profiles,
            audit,
        )
        self.client = self.options = None

    def verify(self):
        if self.target.tls == "pin":
            return PinnedContext(self.store, tls_key(self.target.base_url))
        if self.target.ca_file:
            return ssl.create_default_context(cafile=self.target.ca_file)
        return True

    def open_client(self):
        return httpx.Client(
            base_url=self.target.base_url, verify=self.verify(), follow_redirects=False, trust_env=False
        )

    def connect(self):
        if self.client is None:
            self.client = self.open_client()
        if self.options is None:

            def authenticate(c):
                options = credential_options(self.selector, c, self.client)
                probe(self.client, self.target, options, 30, self.guard)
                return options

            try:
                self.options = self.selector.run(authenticate)
            except httpx.HTTPError as exc:
                raise ApiUnavailable("API authentication probe failed (" + type(exc).__name__ + ")") from None
            except AuthenticationRejected:
                raise DeviceError("the API rejected every eligible HTTP credential") from None
            except (Conflict, ValueError) as exc:
                raise DeviceError("API authentication failed: " + str(exc)) from None
        return self.options

    def request(self, method, path, *, json=None, params=None, options=None, timeout=None):
        """One request; returns (status, parsed JSON or None). Never retried.

        With `options` the request uses those headers/auth instead of the session's own login
        (a verification login as the rotated account).
        """
        self.guard()
        if options is None:
            options = self.connect()
        elif self.client is None:
            self.client = self.open_client()
        timeout = timeout or self.timeout
        try:
            with self.client.stream(
                method, path, json=json, params=params, timeout=timeout, **options
            ) as response:
                content, deadline = bytearray(), time.monotonic() + timeout
                for chunk in response.iter_bytes():
                    self.guard()
                    content.extend(chunk)
                    if len(content) > LIMIT or time.monotonic() > deadline:
                        raise ApiUnavailable("API response exceeded size or duration limit")
                status = response.status_code
        except httpx.HTTPError as exc:
            raise ApiUnavailable("API request failed (" + type(exc).__name__ + ")") from None
        try:
            body = httpx.Response(status, content=bytes(content)).json() if content.strip() else None
        except ValueError:
            body = None
        return status, body

    def close(self):
        if self.client is not None:
            self.client.close()
        self.client = self.options = None
