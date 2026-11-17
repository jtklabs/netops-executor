"""Durable local password rotation. Ambiguous account writes are never retried."""

import importlib
import time

from .credentials import Vault
from .password_devices import AccountDevice, ChangeNotAccepted, PasswordRejected, check_password_syntax
from .password_models import API_PLATFORMS, PasswordRotationOptions
from .password_panos import PanosAccountDevice
from .ssh import DeviceError
from .stepped import StepRunner


class RotationFailure(RuntimeError):
    """A safe terminal error that validation must not sample again."""


# Platform modules share one interface: __init__(settings, store, device, request, password, guard,
# audit), preflight() -> account existed, apply(), save(), verify(), close(), and optional
# `report` (public facts such as `confirmed`) and `reservations` (extra resource keys).
ADAPTERS = {
    "juniper_junos": ("password_junos", "JunosAccounts"),
    "aruba_os": ("password_aruba", "ArubaAccounts"),
    "checkpoint_gaia": ("password_checkpoint", "CheckpointAccounts"),
    "clearpass": ("password_clearpass", "ClearpassAccounts"),
    "infoblox": ("password_infoblox", "InfobloxAccounts"),
}


def adapter(platform):
    module, name = ADAPTERS[platform]
    return getattr(importlib.import_module("." + module, __package__), name)


class PasswordRotationRunner(StepRunner):
    device_errors = (DeviceError,)
    error = RotationFailure

    def __init__(self, settings, store, job, worker, client=None, sleep=time.sleep, clock=time.monotonic):
        super().__init__(settings, store, job, worker, sleep, clock)
        self.client = client

    def prevalidate(self):
        exists = self.client.preflight()
        # Resources found on the device: a firewall serial, or an F5 HA peer and pair.
        keys = list(getattr(self.client, "reservations", []))
        if self.request.device_type == "paloalto_panos":
            keys.append("panos:" + self.client.serial)
        if keys:
            if not self.store.reserve(self.job["id"], self.worker, keys):
                self.store.defer(self.job["id"], self.worker)
            self.result["reservations"] = sorted(set(keys))
        if self.request.device_type == "paloalto_panos":
            self.result["serial"] = self.client.serial
        self.result.update(getattr(self.client, "report", {}))
        self.result.update(account_existed=exists, action="updated" if exists else "created")
        self.event("account_prevalidated", account_existed=exists)

    def change(self):
        self.checkpoint()
        if "account_change" in self.result.get("mutations", []):
            raise DeviceError("account mutation was already attempted; inspect it before recovery")
        self.intent("account_change")
        try:
            self.client.apply()
        except ChangeNotAccepted as exc:
            self.not_accepted(exc)
        self.result["change_accepted"] = True
        self.result.update(getattr(self.client, "report", {}))
        self.event("account_changed")

    def not_accepted(self, exc):
        # The device refused the change and the account is unchanged: nothing to recover.
        self.result["mutations"].remove("account_change")
        self.result["change_accepted"] = False
        self.result.update(getattr(self.client, "report", {}))
        self.event("account_change_not_accepted")
        raise RotationFailure(str(exc)) from None

    def save(self):
        # Once a change starts, finish saving before acknowledging cancellation.
        self.guard()
        try:
            self.client.save()
        except ChangeNotAccepted as exc:
            # A refused commit whose staged change was reverted (Palo Alto).
            self.not_accepted(exc)
        self.result.update(getattr(self.client, "report", {}))
        self.result["saved"] = True

    def sample(self):
        try:
            self.client.verify()
        except PasswordRejected as exc:
            # A rejected login or a definite hash mismatch: review it instead of sampling again.
            if self.request.validation_policy.on_timeout == "fail":
                raise RotationFailure(str(exc)) from None
            self.store.open_gate(
                self.job["id"],
                self.worker,
                "verify_account",
                {"critical": [str(exc)]},
                self.result,
            )
        self.result.update(getattr(self.client, "report", {}))
        self.result["verified"] = True
        return [], []

    def upgrade(self):
        r = self.request = PasswordRotationOptions.model_validate(self.job["request"])
        if r.device_type in API_PLATFORMS:
            # ClearPass and Infoblox: the HTTP target is the device; its lock key names it.
            device = None
            r.for_platform(r.device_type)
            keys = [self.job["lock_key"]]
        else:
            device = self.settings.device(r.device)
            r.device_type = r.device_type or device.device_type
            r.for_platform(r.device_type)
            keys = [self.job["lock_key"], "endpoint:" + device.host]
        if r.serial:
            keys.append("panos:" + r.serial)
        elif self.result.get("serial"):
            keys.append("panos:" + self.result["serial"])
        # A continuation keeps every resource the first attempt reserved.
        keys += self.result.get("reservations", [])
        if not self.store.reserve(self.job["id"], self.worker, keys):
            if self.result.get("mutations"):
                raise DeviceError("reservation changed during password rotation")
            self.store.defer(self.job["id"], self.worker)
        self.checkpoint()
        password = Vault(self.store, self.settings.credential_key_file).job_password(self.job["id"])
        check_password_syntax(r.device_type, password)
        if self.client is None:
            if r.device_type == "paloalto_panos":
                self.client = PanosAccountDevice(
                    self.settings, self.store, device, r, password, self.guard, self.audit
                )
            elif r.device_type in ADAPTERS:
                self.client = adapter(r.device_type)(
                    self.settings, self.store, device, r, password, self.guard, self.audit
                )
            else:
                self.client = AccountDevice(self.settings, device, r, password, self.guard, self.audit)
        self.result.update(username=r.username, device_type=r.device_type, verification=r.verification)
        self.result.setdefault("verified", False)
        self.result.setdefault("progress", {})["steps_total"] = 4
        self.decision = self.store.apply_decision(self.job["id"], self.worker)
        self.step("prevalidate", self.prevalidate)
        self.step("change_account", self.change)
        self.step("save_account", self.save)
        self.step("verify_account", lambda: self.validate("verify_account", self.sample))
        self.result["validation_accepted"] = True

    def unsafe(self):
        return bool(self.result.get("mutations"))

    def close(self):
        if self.client:
            self.client.close()
