"""Resumable named steps, progress reporting and bounded validation shared by upgrade runners.

A step runs once; review gates pause a job and a decision resumes it after the completed
steps. Every disruptive write is recorded before it is sent and never replayed.
"""

import os
import time
from datetime import datetime, timezone

from .ssh import DeviceError, digest
from .store import CancelRequested, Deferred, LostOwnership, NeedsReview


class StepRunner:
    # A sample raising one of these counts as an unavailable device, not a crash.
    device_errors = ()
    # Raised when validation times out with on_timeout "fail".
    error = RuntimeError

    def __init__(self, settings, store, job, worker, sleep=time.sleep, clock=time.monotonic):
        self.settings, self.store, self.job, self.worker = settings, store, job, worker
        self.sleep, self.clock = sleep, clock
        self.result = job["result"]
        self.phase = "connect"
        self.request = self.decision = None
        self.last_report = float("-inf")

    def guard(self):
        self.store.guard(self.job["id"], self.worker)

    def checkpoint(self):
        self.store.checkpoint(self.job["id"], self.worker)

    def audit(self, data):
        self.store.credential_event(self.job["id"], self.worker, {**data, "phase": self.phase})

    def event(self, step, **data):
        self.phase = step
        self.store.record(self.job["id"], self.worker, step, data, self.result)

    def intent(self, step, **data):
        # Persist BEFORE issuing a disruptive write. An interrupted operation is never replayed.
        self.result.setdefault("mutations", []).append(step)
        self.event(step + "_started", **data)

    def wait(self, seconds):
        self.guard()
        self.sleep(seconds)
        self.guard()

    def step(self, key, action):
        """Run each named step once; a review continuation resumes after the completed ones."""
        done = self.result.setdefault("completed_steps", [])
        if key in done:
            return
        progress = self.result.setdefault("progress", {})
        progress.update(step=key, operation=None)
        action()
        done.append(key)
        total = progress.get("steps_total")
        progress.update(
            steps_completed=len(done),
            percent=round(100 * len(done) / total) if total else None,
            operation=None,
        )
        self.event("step_completed", name=key)

    def report(self, kind, serial=None, percent=None, force=False, **detail):
        """Expose the current operation in result.progress for pollers.

        Saved at most every five seconds, or when the operation or its whole percent changes.
        """
        progress = self.result.setdefault("progress", {})
        previous = progress.get("operation") or {}
        operation = {
            "kind": kind,
            "serial": serial,
            "percent": None if percent is None else round(percent, 1),
        }
        progress["operation"] = {**operation, **detail}
        progress["updated_at"] = datetime.now(timezone.utc).isoformat()
        changed = (previous.get("kind"), previous.get("serial")) != (kind, serial) or (
            percent is not None and int(percent) != int(previous.get("percent") or -1)
        )
        if force or changed or self.clock() - self.last_report >= 5:
            self.last_report = self.clock()
            self.store.record(self.job["id"], self.worker, "progress", progress["operation"], self.result)

    def take(self, phase):
        """Consume the operator decision for the gate this phase opened, if any."""
        if not self.decision or self.decision["phase"] != phase:
            return None
        decision, self.decision = self.decision, None
        action = decision["decision"]["action"]
        if action == "accept":
            self.result.setdefault("manual_validations", []).append({**decision["decision"], "phase": phase})
            self.event("manual_validation_applied", gate_id=decision["id"], phase=phase)
        return action

    def validate(self, phase, sample, failback=None):
        if self.take(phase) == "accept":
            return
        policy, timeout = self.request.validation_policy, self.request.validation_timeout
        deadline = self.clock() + timeout
        passes = 0
        while True:
            self.checkpoint()
            try:
                critical, findings = sample()
            except self.device_errors as exc:
                critical, findings = ["device unavailable: " + str(exc)], []
            review = bool(findings) and policy.noncritical_differences == "require_review"
            self.result.setdefault("validation_findings", {})[phase] = findings
            self.result["validation_differences"] = [
                f for items in self.result["validation_findings"].values() for f in items
            ]
            self.result["validation_issues"] = critical
            passes = passes + 1 if not critical and not review else 0
            required = policy.consecutive_passes if timeout else 1
            self.report(
                "validation",
                phase=phase,
                consecutive_passes=passes,
                required_passes=required,
                critical=len(critical),
                differences=len(findings),
            )
            self.event(
                phase + "_sample",
                critical=critical,
                difference_count=len(findings),
                consecutive_passes=passes,
            )
            if passes >= required:
                return
            if self.clock() >= deadline:
                if failback:
                    failback()
                if policy.on_timeout == "fail":
                    raise self.error(phase + " timed out; findings recorded")
                self.store.open_gate(
                    self.job["id"],
                    self.worker,
                    phase,
                    {"critical": critical, "differences": findings},
                    self.result,
                )
            self.wait(min(policy.sample_interval_seconds, max(0, deadline - self.clock())))

    def settle(self):
        remaining = self.request.validation_policy.settling_seconds
        while remaining > 0:
            self.report("settle", remaining_seconds=remaining)
            self.checkpoint()
            self.wait(min(15, remaining))
            remaining -= min(15, remaining)

    def write_private(self, path, data):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())

    def artifact(self, serial, kind, path, backup_format=None):
        """Record a saved pre-change file; the first configuration also answers GET /backup."""
        item = {
            "name": path.name,
            "serial": serial,
            "kind": kind,
            "path": str(path.relative_to(self.settings.backup_root.resolve())),
            "sha256": digest(path),
            "bytes": path.stat().st_size,
        }
        self.result.setdefault("artifacts", []).append(item)
        if kind == "config" and "backup" not in self.result:
            self.result["backup"] = {**item, "format": backup_format}
        self.event(kind + "_backup_completed", serial=serial, bytes=item["bytes"])

    # Runner hooks: what a failure leaves behind, what to put back, and connections to close.
    def unsafe(self):
        return False

    def restore_service(self):
        pass

    def close(self):
        pass

    def run(self):
        try:
            self.upgrade()
            self.result["completed"] = True
            self.event("completed")
            # Different devices use different profiles; a warning means one target fell back
            # from one profile to another.
            profiles = {}
            for usage in self.store.get(self.job["id"])["credential_usage"]:
                if usage["outcome"] == "authenticated":
                    profiles.setdefault(usage["target"], set()).add(usage["profile"])
            warnings = bool(
                self.result.get("validation_differences")
                or self.result.get("manual_validations")
                or any(len(used) > 1 for used in profiles.values())
            )
            self.store.finish(
                self.job["id"], self.worker, "completed_with_warnings" if warnings else "succeeded"
            )
        except (LostOwnership, Deferred, NeedsReview):
            pass
        except CancelRequested:
            try:
                self.restore_service()
                self.result["cancelled_at"] = self.phase
                self.event("cancel_acknowledged")
                self.store.finish(
                    self.job["id"], self.worker, "recovery_required" if self.unsafe() else "cancelled"
                )
            except LostOwnership:
                pass
            except Exception:
                self.store.finish(self.job["id"], self.worker, "recovery_required")
        except Exception as exc:
            known = isinstance(exc, (self.error, DeviceError, *self.device_errors))
            message = str(exc) if known else "operation failed (" + type(exc).__name__ + ")"
            self.result["error"] = message
            try:
                try:
                    self.restore_service()
                except LostOwnership:
                    raise
                except Exception:
                    self.result["restore_failed"] = True
                self.event("failed", message=message)
                self.store.finish(
                    self.job["id"], self.worker, "recovery_required" if self.unsafe() else "failed"
                )
            except LostOwnership:
                pass
        finally:
            self.close()
