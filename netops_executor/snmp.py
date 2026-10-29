"""Bounded SNMP v3 GETBULK/GETNEXT walks and GETs; no SSH or inventory dependency."""

import asyncio
import base64
import json
import os

from pysnmp.hlapi.v3arch import asyncio as snmp
from pysnmp.proto import rfc1902, rfc1905

from .credentials import AuthenticationRejected, Selector, Vault
from .snmp_models import SnmpWalkRequest
from .store import CancelRequested, LostOwnership

MAX_RESULT_BYTES = 16 * 1024 * 1024
# Exact-instance GETs per request; a tooBig response splits the batch.
GET_BATCH = 10
TOO_BIG = 1
AUTH_ERRORS = ("UnknownUserName", "WrongDigest", "DecryptionError", "UnsupportedSecurityLevel")
MISSING = (rfc1905.NoSuchObject, rfc1905.NoSuchInstance, rfc1905.EndOfMibView)


class WalkError(Exception):
    pass


def auth_protocols():
    return {
        "SHA": snmp.usmHMACSHAAuthProtocol,
        "SHA224": snmp.usmHMAC128SHA224AuthProtocol,
        "SHA256": snmp.usmHMAC192SHA256AuthProtocol,
        "SHA384": snmp.usmHMAC256SHA384AuthProtocol,
        "SHA512": snmp.usmHMAC384SHA512AuthProtocol,
    }


def credentials(profile):
    def secret(name):
        value = os.environ.get(name or "", "")
        if len(value.encode()) < 8:
            raise WalkError("SNMP profile credential is missing or shorter than 8 bytes")
        return value

    auth = profile.security_level != "noAuthNoPriv"
    private = profile.security_level == "authPriv"
    return snmp.UsmUserData(
        profile.username,
        authKey=secret(profile.auth_password_env) if auth else None,
        privKey=secret(profile.priv_password_env) if private else None,
        authProtocol=auth_protocols()[profile.auth_protocol] if auth else snmp.usmNoAuthProtocol,
        privProtocol=snmp.usmAesCfb128Protocol if private else snmp.usmNoPrivProtocol,
    )


def serialize(root, oid, value):
    encoding = "text"
    if isinstance(value, rfc1902.IpAddress):
        rendered = value.prettyPrint()
    elif isinstance(value, rfc1902.OctetString):
        # Preserve octets exactly, including non-UTF8 values and embedded NULs.
        rendered = base64.b64encode(value.asOctets()).decode("ascii")
        encoding = "base64"
    else:
        rendered = value.prettyPrint()
    return {
        "root_oid": root,
        "oid": str(oid),
        "type": type(value).__name__,
        "value": rendered,
        "encoding": encoding,
    }


async def request(kind, engine, auth, target, context, oids, repetitions=0):
    """One GET, GETNEXT or GETBULK exchange: (indication, status, index, (oid, value) pairs)."""
    context = snmp.ContextData(contextName=context)
    varbinds = [snmp.ObjectType(snmp.ObjectIdentity(oid)) for oid in oids]
    if kind == "bulk":
        return await snmp.bulk_cmd(engine, auth, target, context, 0, repetitions, *varbinds, lookupMib=False)
    call = snmp.next_cmd if kind == "next" else snmp.get_cmd
    return await call(engine, auth, target, context, *varbinds, lookupMib=False)


class SnmpRunner:
    def __init__(self, settings, store, job, worker):
        self.settings, self.store, self.job, self.worker = settings, store, job, worker
        self.request = SnmpWalkRequest.model_validate(job["request"])
        names = self.request.credential_profiles or ([self.request.profile] if self.request.profile else None)
        self.selector = Selector(
            Vault(store, settings.credential_key_file),
            "snmp",
            str(self.request.device_ip),
            names,
            lambda data: store.credential_event(job["id"], worker, data),
        )
        # GETBULK size is learned per agent: a reduction or GETNEXT fallback applies to later roots too.
        self.repetitions = 0 if self.request.walk_mode == "next" else self.request.max_repetitions
        self.responded = False
        self.requests = 0
        self.result = {
            "rows": 0,
            "bytes": 0,
            "walk": {
                "mode": self.request.walk_mode,
                "method": "next" if self.repetitions == 0 else "bulk",
                "max_repetitions": self.repetitions or None,
                "requests": 0,
                "fallbacks": [],
            },
            "gets": [{"oid": oid, "status": "pending", "rows": 0} for oid in self.request.get_oids],
            "oids": [{"oid": oid, "status": "pending", "rows": 0} for oid in self.request.oids],
        }

    def items(self):
        return self.result["gets"] + self.result["oids"]

    def record(self, step):
        self.result["walk"]["requests"] = self.requests
        self.store.record(self.job["id"], self.worker, step, result=self.result)

    def run(self):
        try:
            self.record("snmp_started")
            asyncio.run(self.walk())
            success = all(r["status"] in ("succeeded", "missing") for r in self.items())
            self.record("snmp_finished")
            self.store.finish(self.job["id"], self.worker, "succeeded" if success else "failed")
        except LostOwnership:
            return
        except CancelRequested:
            self.result["error"] = "cancelled; partial results retained"
            for item in self.items():
                if item["status"] in ("pending", "running"):
                    item["status"] = "cancelled"
            self.record("snmp_cancelled")
            self.store.finish(self.job["id"], self.worker, "cancelled")
        except Exception:
            # Library exceptions can contain credential material; never persist their text.
            self.result["error"] = "SNMP worker failed; check server profile configuration"
            for item in self.items():
                if item["status"] in ("pending", "running"):
                    item["status"] = "failed"
            try:
                self.record("snmp_failed")
                self.store.finish(self.job["id"], self.worker, "failed")
            except LostOwnership:
                pass

    async def walk(self):
        engine = snmp.SnmpEngine()
        try:
            async with asyncio.timeout(self.request.job_timeout):
                use_vault = bool(self.request.credential_profiles) or any(
                    c["kind"] == "snmp" for c in self.selector.vault.list()
                )
                if (
                    self.request.profile in self.settings.snmp_profiles
                    and not self.request.credential_profiles
                ):
                    use_vault = False
                profile = (
                    None if use_vault else self.settings.snmp_profiles[self.request.profile or "default"]
                )
                auth = None if use_vault else credentials(profile)
                transport = (
                    snmp.Udp6TransportTarget
                    if self.request.device_ip.version == 6
                    else snmp.UdpTransportTarget
                )
                target = await transport.create(
                    (str(self.request.device_ip), self.request.port),
                    timeout=self.request.timeout,
                    retries=self.request.retries,
                )

                async def authenticated(operation):
                    # Credential fallback is allowed only until this operation has produced data.
                    if not use_vault:
                        return await operation(auth, profile.context_name)

                    async def attempt(c):
                        auth_data = snmp.UsmUserData(
                            c["username"],
                            authKey=c.get("auth_password"),
                            privKey=c.get("priv_password"),
                            authProtocol=auth_protocols()[c["auth_protocol"]]
                            if c["security_level"] != "noAuthNoPriv"
                            else snmp.usmNoAuthProtocol,
                            privProtocol=snmp.usmAesCfb128Protocol
                            if c["security_level"] == "authPriv"
                            else snmp.usmNoPrivProtocol,
                        )
                        self.current_credential = c
                        await operation(auth_data, c["context_name"])

                    await self.selector.run_async(attempt)

                for start in range(0, len(self.result["gets"]), GET_BATCH):
                    batch = self.result["gets"][start : start + GET_BATCH]
                    self.store.checkpoint(self.job["id"], self.worker)
                    for item in batch:
                        item["status"] = "running"
                    self.record("snmp_get_started")
                    try:
                        await authenticated(
                            lambda a, ctx, batch=batch: self.get_items(engine, a, target, ctx, batch)
                        )
                    except (WalkError, AuthenticationRejected) as exc:
                        for item in batch:
                            if item["status"] == "running":
                                item.update(status="failed", error=str(exc))
                    self.record("snmp_get_finished")
                    if self.result.get("truncated"):
                        break
                for item in self.result["oids"]:
                    if self.result.get("truncated"):
                        break
                    self.store.checkpoint(self.job["id"], self.worker)
                    item["status"] = "running"
                    self.record("snmp_oid_started")
                    try:
                        await authenticated(
                            lambda a, ctx, item=item: self.walk_oid(engine, a, target, ctx, item)
                        )
                        item["status"] = "succeeded"
                    except (WalkError, AuthenticationRejected) as exc:
                        item.update(status="failed", error=str(exc))
                    self.record("snmp_oid_finished")
        except TimeoutError:
            self.result["error"] = "job timeout exceeded"
        finally:
            engine.close_dispatcher()
        for item in self.items():
            if item["status"] in ("pending", "running"):
                item.update(
                    status="failed" if item["status"] == "running" else "skipped",
                    error=self.result.get("error", "job result limit reached"),
                )

    def audit_credential(self, items):
        # Record the vault profile once an operation's first data is committed.
        c = getattr(self, "current_credential", None)
        if c is None or any(item.get("credential_profile") for item in items):
            return
        for item in items:
            item["credential_profile"] = c["id"]
        self.store.credential_event(
            self.job["id"],
            self.worker,
            {
                "profile": c["id"],
                "revision": c["revision"],
                "transport": "snmp",
                "target": str(self.request.device_ip),
                "outcome": "authenticated",
            },
        )

    async def send(self, engine, auth, target, context, kind, oids):
        if self.request.request_interval and self.requests:
            await asyncio.sleep(self.request.request_interval)
        self.requests += 1
        self.store.checkpoint(self.job["id"], self.worker)
        return await request(kind, engine, auth, target, context, oids, self.repetitions)

    def check(self, indication, status, index, produced):
        """None for a usable response, else (reason, error message). Credential rejection raises."""
        if indication:
            name = type(indication).__name__
            if name in AUTH_ERRORS and not produced:
                raise AuthenticationRejected("SNMP v3 credentials rejected")
            # Class names describe timeout/auth/transport failures without exposing secrets.
            message = "SNMP engine error: " + name
            if name == "RequestTimedOut":
                return "timeout", message
            if name in ("ReportPduReceived", "UnknownPDUHandler"):
                # A Report PDU (such as snmpUnknownPDUHandlers): the agent answered but rejected the request type.
                self.responded = True
                return "unsupported", message
            raise WalkError(message)
        self.responded = True
        if status:
            message = f"SNMP PDU error {int(status)} at binding {int(index)}"
            return ("tooBig" if int(status) == TOO_BIG else "error"), message
        return None

    def degrade(self, reason, oid):
        """Lower GETBULK repetitions, then fall back to GETNEXT. Returns False when nothing gentler is left."""
        mode, current = self.request.walk_mode, self.repetitions
        if current == 0:
            return False
        if reason in ("unsupported", "error") or (reason == "timeout" and not self.responded):
            # A rejected GETBULK, or silence from the first request (a dead agent or one that
            # drops GETBULK): spend one GETNEXT attempt rather than a full halving sequence.
            if mode == "bulk":
                return False
            new = 0
        elif current > 1:
            new = max(1, current // 2)
        elif mode == "auto":
            new = 0
        else:
            return False
        self.repetitions = new
        walk = self.result["walk"]
        walk.update(method="bulk" if new else "next", max_repetitions=new or None)
        walk["fallbacks"].append({"reason": reason, "oid": oid, "max_repetitions": new or None})
        self.record("snmp_walk_degraded")
        return True

    def store_rows(self, rows, item):
        """Commit the rows that fit the job limits, then fail with partial data retained."""
        accepted, size = [], 0
        for row in rows:
            row_size = len(json.dumps(row).encode())
            if (
                self.result["rows"] + len(accepted) >= self.request.max_rows
                or self.result["bytes"] + size + row_size > MAX_RESULT_BYTES
            ):
                self.result["truncated"] = True
                break
            accepted.append(row)
            size += row_size
        if accepted:
            self.result["rows"] += len(accepted)
            self.result["bytes"] += size
            item["rows"] += len(accepted)
            self.store.append_snmp_rows(self.job["id"], self.worker, accepted, self.result)
            self.audit_credential([item])
        if self.result.get("truncated"):
            raise WalkError("job result limit reached")

    async def walk_oid(self, engine, auth, target, context, item):
        root = item["oid"]
        prefix = rfc1902.ObjectName(root)
        current = prefix
        while True:
            kind = "bulk" if self.repetitions else "next"
            indication, status, index, bindings = await self.send(
                engine, auth, target, context, kind, [current]
            )
            failure = self.check(indication, status, index, item["rows"])
            if failure:
                reason, message = failure
                if kind == "bulk" and self.degrade(reason, root):
                    continue
                raise WalkError(message)
            if not bindings:
                raise WalkError("SNMP agent returned an empty response")
            rows, finished = [], False
            for oid, value in bindings:
                # GETBULK can run past the subtree in the same response; stop at the boundary.
                if isinstance(value, rfc1905.EndOfMibView) or not prefix.isPrefixOf(oid):
                    finished = True
                    break
                if oid <= current:
                    raise WalkError("SNMP agent returned a non-increasing OID")
                rows.append(serialize(root, oid, value))
                current = oid
            if rows:
                self.store_rows(rows, item)
            if finished:
                break
        if item["rows"] == 0:
            # Like net-snmp snmpwalk: an empty subtree may be a scalar instance such as sysName.0.
            try:
                ((oid, value),) = await self.get(engine, auth, target, context, [root], produced=0)
            except WalkError as exc:
                # The empty walk result stands; only the scalar probe failed.
                item["scalar_probe_error"] = str(exc)
                return
            if value is not None:
                item["scalar"] = True
                self.store_rows([serialize(root, oid, value)], item)

    async def get(self, engine, auth, target, context, oids, produced):
        indication, status, index, bindings = await self.send(engine, auth, target, context, "get", oids)
        failure = self.check(indication, status, index, produced)
        if failure:
            reason, message = failure
            # A large or lost response splits the batch; a silent agent is not retried piecemeal.
            if len(oids) > 1 and (reason == "tooBig" or (reason == "timeout" and self.responded)):
                half = len(oids) // 2
                first = await self.get(engine, auth, target, context, oids[:half], produced)
                return first + await self.get(engine, auth, target, context, oids[half:], produced)
            raise WalkError(message)
        if len(bindings) != len(oids) or any(str(oid) != wanted for (oid, _), wanted in zip(bindings, oids)):
            raise WalkError("SNMP agent returned a mismatched GET response")
        return [(oid, None if isinstance(value, MISSING) else value) for oid, value in bindings]

    async def get_items(self, engine, auth, target, context, batch):
        values = await self.get(engine, auth, target, context, [item["oid"] for item in batch], produced=0)
        for item, (oid, value) in zip(batch, values):
            item["rows"] = 0
            if value is None:
                item["status"] = "missing"
            else:
                self.store_rows([serialize(item["oid"], oid, value)], item)
                item["status"] = "succeeded"
