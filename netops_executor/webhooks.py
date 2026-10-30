"""Signed completion callbacks: POST each finished job to the central application, with retries.

Delivery is at least once. The payload is built when it is sent, so it carries the job's current
record even when an earlier attempt failed; receivers deduplicate by the delivery ID.
"""

import hashlib
import hmac
import json
import time
import uuid
from urllib.parse import urlsplit, urlunsplit

import httpx

from . import __version__

MAX_BACKOFF = 600


class Rejected(Exception):
    pass


def sign(secret, timestamp, body):
    return "sha256=" + hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()


def redacted(url):
    """The configured URL without its query string, which may carry a receiver token."""
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


class WebhookSender:
    def __init__(self, settings, store, client=None):
        self.settings, self.store = settings, store
        self.client = client or httpx.Client(
            timeout=10,
            follow_redirects=False,
            verify=str(settings.webhook_ca_file) if settings.webhook_ca_file else True,
        )
        # While the receiver is failing, wait out the backoff instead of trying every queued delivery.
        self.paused_until = 0

    def payload(self, delivery):
        job = self.store.get(delivery["job"])
        body = {
            "event": "job.needs_review" if delivery["status"] == "needs_review" else "job.finished",
            "delivery_id": delivery["id"],
            "status": delivery["status"],
            "executor_version": __version__,
            "job": job,
        }
        if job["kind"] == "snmp_walk":
            # Same shape as GET /api/v1/snmp/walks/{id}/results; continue from next_cursor if has_more.
            body["snmp_results"] = self.store.snmp_results(job["id"], 0, self.settings.webhook_max_rows)
        return body

    def post(self, event, delivery_id, body, now):
        content = json.dumps(body, separators=(",", ":")).encode()
        timestamp = str(int(now))
        headers = {
            "Authorization": "Bearer " + self.settings.webhook_token,
            "Content-Type": "application/json",
            "User-Agent": "netops-executor/" + __version__,
            "X-NetOps-Event": event,
            "X-NetOps-Delivery": delivery_id,
            "X-NetOps-Timestamp": timestamp,
        }
        if self.settings.webhook_secret:
            headers["X-NetOps-Signature"] = sign(self.settings.webhook_secret, timestamp, content)
        response = self.client.post(self.settings.webhook_url, content=content, headers=headers)
        if not response.is_success:
            raise Rejected(f"HTTP {response.status_code}")
        return response.status_code

    def deliver_due(self, now=None, limit=50):
        now = time.time() if now is None else now
        if now < self.paused_until:
            return 0
        sent = 0
        for due in self.store.webhook_due(now, limit):
            delivery = self.store.webhook_attempt(due["id"], now)
            delay = min(MAX_BACKOFF, 5 * 2 ** (delivery["attempts"] - 1))
            try:
                body = self.payload(delivery)
            except Exception as exc:
                # A payload that cannot be built is this delivery's problem, not the receiver's.
                self.store.webhook_failed(delivery["id"], "payload: " + type(exc).__name__, now + delay)
                continue
            try:
                self.post(body["event"], delivery["id"], body, now)
            except (httpx.HTTPError, Rejected) as exc:
                # Exception text can include the URL and its query token; keep only the cause.
                error = str(exc) if isinstance(exc, Rejected) else type(exc).__name__
                self.store.webhook_failed(delivery["id"], error, now + delay)
                self.paused_until = now + delay
                break
            self.store.webhook_delivered(delivery["id"], time.time())
            sent += 1
        return sent

    def ping(self):
        delivery_id = uuid.uuid4().hex
        body = {"event": "ping", "delivery_id": delivery_id, "executor_version": __version__}
        return self.post("ping", delivery_id, body, time.time())

    def run(self, stop):
        while not stop.is_set():
            try:
                sent = self.deliver_due()
            except Exception:
                # A database or payload error must not end delivery for the life of the API.
                sent = 0
            stop.wait(0 if sent else 2)
