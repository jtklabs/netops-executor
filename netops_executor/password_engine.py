"""Durable local password rotation. Ambiguous account writes are never retried."""

import time

from .credentials import Vault
from .password_devices import AccountDevice, PasswordRejected, check_password_syntax
from .password_models import PasswordRotationOptions
from .password_panos import PanosAccountDevice
from .ssh import DeviceError
from .stepped import StepRunner


class RotationFailure(RuntimeError):
    """A safe terminal error that validation must not sample again."""


class PasswordRotationRunner(StepRunner):
    device_errors = (DeviceError,)
    error = RotationFailure

    def __init__(self, settings, store, job, worker, client=None, sleep=time.sleep, clock=time.monotonic):
        super().__init__(settings, store, job, worker, sleep, clock)
        self.client = client

    def prevalidate(self):
        exists = self.client.preflight()
        if self.request.device_type == "paloalto_panos":
            serial = self.client.serial
            if not self.store.reserve(self.job["id"], self.worker, ["panos:" + serial]):
                self.store.defer(self.job["id"], self.worker)
            self.result["serial"] = serial
        self.result.update(account_existed=exists, action="updated" if exists else "created")
        self.event("account_prevalidated", account_existed=exists)

    def change(self):
        self.checkpoint()
        if "account_change" in self.result.get("mutations", []):
            raise DeviceError("account mutation was already attempted; inspect it before recovery")
        self.intent("account_change")
        self.client.apply()
        self.event("account_changed")

    def save(self):
        # Once a change starts, finish saving before acknowledging cancellation.
        self.guard()
        self.client.save()
        self.result["saved"] = True

    def sample(self):
        try:
            self.client.verify()
        except PasswordRejected as exc:
            if self.request.validation_policy.on_timeout == "fail":
                raise RotationFailure(str(exc)) from None
            self.store.open_gate(
                self.job["id"],
                self.worker,
                "verify_account",
                {"critical": ["new-account SSH authentication rejected; no automatic retry"]},
                self.result,
            )
        self.result["verified"] = True
        return [], []

    def upgrade(self):
        r = self.request = PasswordRotationOptions.model_validate(self.job["request"])
        device = self.settings.device(r.device)
        r.device_type = r.device_type or device.device_type
        r.for_platform(r.device_type)
        keys = [self.job["lock_key"], "endpoint:" + device.host]
        if r.serial:
            keys.append("panos:" + r.serial)
        elif self.result.get("serial"):
            keys.append("panos:" + self.result["serial"])
        if not self.store.reserve(self.job["id"], self.worker, keys):
            if self.result.get("mutations"):
                raise DeviceError("reservation changed during password rotation")
            self.store.defer(self.job["id"], self.worker)
        self.checkpoint()
        password = Vault(self.store, self.settings.credential_key_file).job_password(self.job["id"])
        check_password_syntax(r.device_type, password)
        if self.client is None:
            self.client = (
                PanosAccountDevice(self.settings, self.store, device, r, password, self.guard, self.audit)
                if r.device_type == "paloalto_panos"
                else AccountDevice(self.settings, device, r, password, self.guard, self.audit)
            )
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
