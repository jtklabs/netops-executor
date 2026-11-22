"""Bounded SNMP v3 reads and optional NetBox discovery."""

import asyncio
import base64
import json
import os
import re
from datetime import datetime, timezone

import httpx
from paramiko import SSHException
from pysnmp.hlapi.v3arch import asyncio as snmp
from pysnmp.proto import rfc1902, rfc1905

from .credentials import AuthenticationRejected, CredentialUnanswered, Selector, Vault
from .discovery_overrides import apply_manual_fallback, apply_rules, load_rules
from .f5_operations import license_details
from .inventory_enrichment import attempts_for, collect_enrichment, discovery_target
from .netbox_discovery import SyncError, sync_device, sync_licenses
from .netbox_operations import preferred_image, report_failed_poll, report_observation, sync_observed_licenses
from .snmp_address import collect_polled_address
from .snmp_identity import ENTITY_CLASS, collect_identity, text
from .snmp_models import SnmpWalkRequest
from .snmp_neighbors import collect_neighbors
from .snmp_stack import StackInventoryError, collect_stack
from .snmp_wireless import AccessPointInventoryError, collect_access_points
from .ssh import SSH, DeviceError
from .store import CancelRequested, Conflict, LostOwnership

MAX_RESULT_BYTES = 16 * 1024 * 1024
# Exact-instance GETs per request; a tooBig response splits the batch.
GET_BATCH = 10
TOO_BIG = 1
AUTH_ERRORS = ("UnknownUserName", "WrongDigest", "DecryptionError", "UnsupportedSecurityLevel")
TIMED_OUT = "SNMP engine error: RequestTimedOut"
NO_ANSWER = "no SNMP response with any eligible credential (request timed out)"
MISSING = (rfc1905.NoSuchObject, rfc1905.NoSuchInstance, rfc1905.EndOfMibView)


class WalkError(Exception):
    pass


def auth_protocols():
    return {
        "MD5": snmp.usmHMACMD5AuthProtocol,
        "SHA": snmp.usmHMACSHAAuthProtocol,
        "SHA224": snmp.usmHMAC128SHA224AuthProtocol,
        "SHA256": snmp.usmHMAC192SHA256AuthProtocol,
        "SHA384": snmp.usmHMAC256SHA384AuthProtocol,
        "SHA512": snmp.usmHMAC384SHA512AuthProtocol,
    }


def priv_protocols():
    return {
        "DES": snmp.usmDESPrivProtocol,
        "3DES": snmp.usm3DESEDEPrivProtocol,
        "AES": snmp.usmAesCfb128Protocol,
        # Standard (Blumenthal) key extension, as net-snmp's AES-192/AES-256.
        "AES192": snmp.usmAesBlumenthalCfb192Protocol,
        "AES256": snmp.usmAesBlumenthalCfb256Protocol,
        # Reeder key extension: Cisco's AES-192/256 (net-snmp's AES-192-C/AES-256-C).
        "AES192C": snmp.usmAesCfb192Protocol,
        "AES256C": snmp.usmAesCfb256Protocol,
    }


def usm(c):
    """pysnmp authentication data for a credential: a community for v1/v2c, a USM user for v3."""
    version = c.get("version") or "3"
    if version in ("1", "2c"):
        return snmp.CommunityData(c["community"], mpModel=0 if version == "1" else 1)
    level = c.get("security_level") or "authPriv"
    auth, private = level != "noAuthNoPriv", level == "authPriv"
    return snmp.UsmUserData(
        c["username"],
        authKey=c.get("auth_password") if auth else None,
        privKey=c.get("priv_password") if private else None,
        authProtocol=auth_protocols()[c.get("auth_protocol") or "SHA256"] if auth else snmp.usmNoAuthProtocol,
        privProtocol=priv_protocols()[c.get("priv_protocol") or "AES"] if private else snmp.usmNoPrivProtocol,
    )


def masked(secret):
    """Enough of a secret to recognise it: the first three characters, or one for a secret
    shorter than eight (a short community would otherwise show most of itself), then a fixed
    run of stars so the length is not shown either."""
    if not secret:
        return None
    return secret[: 3 if len(secret) >= 8 else 1] + "*****"


def credential_summary(number, c):
    """A request credential for the job result: every setting, secrets masked."""
    fields = ("version", "community", "username", "security_level", "auth_protocol", "auth_password")
    fields += ("priv_protocol", "priv_password", "context_name")
    secrets = ("community", "auth_password", "priv_password")
    summary = {"id": "request:" + str(number)}
    for key in fields:
        value = c.get(key)
        if value not in (None, ""):
            summary[key] = masked(value) if key in secrets else value
    return summary


def file_candidate(profile):
    """A configured snmp-profiles.json entry (secrets from the environment) as a credential."""

    def secret(name):
        value = os.environ.get(name or "", "")
        if len(value.encode()) < 8:
            raise WalkError("SNMP profile credential is missing or shorter than 8 bytes")
        return value

    auth = profile.security_level != "noAuthNoPriv"
    private = profile.security_level == "authPriv"
    return {
        "id": "file:" + profile.id,
        "revision": 0,
        "transient": True,
        "version": "3",
        "username": profile.username,
        "security_level": profile.security_level,
        "auth_protocol": profile.auth_protocol,
        "auth_password": secret(profile.auth_password_env) if auth else None,
        "priv_protocol": "AES",
        "priv_password": secret(profile.priv_password_env) if private else None,
        "context_name": profile.context_name,
    }


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
        self.v1 = False
        # Every eligible credential went unanswered: later operations fail without trying again.
        self.silent = False
        self.requests = 0
        self._f5_license = None
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
            success = not self.result.get("error") and self.reads_succeeded()
            status = "succeeded" if success else "failed"
            if self.request.site:
                if not success and self.request.manual_fallback.model_dump(exclude_none=True):
                    self.seed_manual_inventory()
                if "discovery" in self.result and (
                    success or self.request.manual_fallback.model_dump(exclude_none=True)
                ):
                    synchronized = self.sync_inventory()
                    status = synchronized if success else "failed"
                if not success and not self.result.get("discovery", {}).get("collection_report"):
                    self.result["collection_report"] = report_failed_poll(
                        self.settings,
                        self.job["id"],
                        self.request.poller_instance,
                        str(self.request.device_ip),
                        lambda: self.store.checkpoint(self.job["id"], self.worker),
                    )
            self.record("snmp_finished")
            self.store.finish(self.job["id"], self.worker, status)
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

    def request_credentials(self):
        """Credentials sent with the request, decrypted from the job's secret, as candidates."""
        if not self.request.credential_count:
            return []
        try:
            values = json.loads(
                Vault(self.store, self.settings.credential_key_file).job_password(self.job["id"])
            )
        except (Conflict, ValueError):
            raise WalkError("request SNMP credentials are unavailable; submit the job again") from None
        if not isinstance(values, list) or len(values) != self.request.credential_count:
            raise WalkError("request SNMP credentials are unavailable; submit the job again")
        # Which credentials were sent, for the job's output; credential_usage uses the same IDs.
        self.result["request_credentials"] = [
            credential_summary(number, value) for number, value in enumerate(values, 1)
        ]
        self.record("snmp_request_credentials")
        return [
            {**value, "id": "request:" + str(number), "revision": 0, "transient": True}
            for number, value in enumerate(values, 1)
        ]

    async def walk(self):
        engine = snmp.SnmpEngine()
        try:
            async with asyncio.timeout(self.request.job_timeout):
                # Request credentials first, then (unless use_profiles is false) the configured
                # file profile or the saved profiles, as before.
                extra = self.request_credentials()
                use_vault = self.request.use_profiles and (
                    bool(self.request.credential_profiles)
                    or any(c["kind"] == "snmp" for c in self.selector.vault.list())
                )
                if (
                    self.request.profile in self.settings.snmp_profiles
                    and not self.request.credential_profiles
                ):
                    use_vault = False
                if self.request.use_profiles and not use_vault:
                    name = self.request.profile or "default"
                    if name in self.settings.snmp_profiles or not extra:
                        extra.append(file_candidate(self.settings.snmp_profiles[name]))
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
                    if self.silent:
                        raise WalkError(NO_ANSWER)

                    async def attempt(c):
                        auth_data = usm(c)
                        # SNMPv1 has no GETBULK.
                        self.v1 = c.get("version") == "1"
                        self.current_credential = c
                        walk = self.result["walk"]
                        state = (
                            self.repetitions,
                            walk["method"],
                            walk["max_repetitions"],
                            len(walk["fallbacks"]),
                        )
                        try:
                            await operation(auth_data, c.get("context_name") or "")
                        except WalkError as exc:
                            if self.responded or str(exc) != TIMED_OUT:
                                raise
                            # Silence before the agent has ever answered: an SNMPv3 agent drops
                            # requests from a user it does not know or its access list refuses,
                            # so try the next credential. Undo the GETBULK fallback that silence
                            # caused: it says nothing about the agent's GETBULK support.
                            self.repetitions, walk["method"], walk["max_repetitions"], kept = state
                            del walk["fallbacks"][kept:]
                            raise CredentialUnanswered() from None

                    try:
                        await self.selector.run_async(attempt, extra=extra, vault=use_vault)
                    except CredentialUnanswered:
                        self.silent = True
                        raise WalkError(NO_ANSWER) from None

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
                if self.request.site and self.reads_succeeded():
                    try:
                        await authenticated(lambda a, ctx: self.read_inventory(engine, a, target, ctx))
                    except (WalkError, AuthenticationRejected) as exc:
                        self.result["error"] = str(exc)
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

    def reads_succeeded(self):
        return all(item["status"] in ("succeeded", "missing") for item in self.items())

    async def read_inventory(self, engine, auth, target, context):
        inventory = {}

        async def get(oids):
            if not oids:
                return {}
            values = await self.get(engine, auth, target, context, oids, produced=bool(inventory))
            if any(value is not None for _, value in values):
                self.audit_credential([inventory])
            return {str(oid): text(value) for oid, value in values}

        async def walk_column(root, *, bulk, limit):
            current = prefix = rfc1902.ObjectName(root)
            remaining = limit
            while True:
                kind = "bulk" if bulk and self.repetitions and not self.v1 else "next"
                indication, status, index, bindings = await self.send(
                    engine, auth, target, context, kind, [current]
                )
                failure = self.check(indication, status, index, produced=bool(inventory))
                if failure:
                    if kind == "bulk" and self.degrade(failure[0], root):
                        continue
                    raise WalkError(failure[1])
                if not bindings:
                    raise WalkError("SNMP agent returned an empty inventory response")
                for oid, value in bindings:
                    if value is None or isinstance(value, MISSING) or not prefix.isPrefixOf(oid):
                        return
                    if oid <= current or not remaining:
                        raise WalkError("SNMP inventory column is invalid or exceeds its row limit")
                    self.audit_credential([inventory])
                    yield str(oid).removeprefix(root + "."), text(value)
                    current = oid
                    remaining -= 1

        async def first_value(root, expected=None):
            # ENTITY-MIB chassis rows normally appear early even in large inventories.
            try:
                async for index, value in walk_column(root, bulk=expected is not None, limit=256):
                    if expected is None:
                        return value
                    if value == expected:
                        return index
            except WalkError:
                pass
            return ""

        async def chassis_index():
            return await first_value(ENTITY_CLASS, expected="3")

        system_values = {}
        facts = await collect_identity(get, chassis_index, first_value, system_values)
        if facts["manufacturer"] == "Cisco":
            try:
                members = await collect_stack(get, walk_column)
            except StackInventoryError as error:
                facts["stack_inventory"] = {"status": "failed", "error": str(error)}
            except WalkError:
                facts["stack_inventory"] = {"status": "failed", "error": "Cisco stack inventory read failed"}
            else:
                if members:
                    active = next(member for member in members if member["role"] == "active")
                    facts["stack_members"] = members
                    facts["model"] = active["model"]
                    facts["serial"] = active["serial"]
                    facts["software_version"] = active["software_version"] or facts["software_version"]
        if facts["manufacturer"] == "HPE" and facts["platform"] == "ArubaOS":
            # Mobility controllers list the APs they terminate; ClearPass and CX switches do not.
            try:
                facts["access_points"] = await collect_access_points(walk_column)
            except AccessPointInventoryError as error:
                facts["access_point_inventory"] = {"status": "failed", "error": str(error)}
            except WalkError:
                facts["access_point_inventory"] = {
                    "status": "failed",
                    "error": "Aruba access point table read failed",
                }

        self.result["discovery"] = {
            **facts,
            "site": self.request.site,
            "poller_instance": self.request.poller_instance,
            "address": str(self.request.device_ip),
            "polled": self.responded,
        }
        try:
            rules, digest = load_rules(self.settings.discovery_overrides_file)
        except ValueError:
            facts["identity_rules_config"] = {
                "status": "failed",
                "reason": "Invalid discovery overrides file; validate it before the next scan",
            }
            rules, digest = [], None
        await apply_rules(
            facts,
            system_values,
            str(self.request.device_ip),
            get,
            walk_column,
            [*rules, *self.request.identity_rules],
        )
        if digest:
            facts["identity_rules_sha256"] = digest
        apply_manual_fallback(facts, self.request.manual_fallback)
        facts["polled"] = True
        if self.request.collect_neighbors:
            try:
                facts["neighbors"] = await collect_neighbors(
                    walk_column, cisco=facts["manufacturer"] == "Cisco"
                )
                facts["neighbor_inventory"] = {"status": "success"}
            except WalkError:
                facts["neighbor_inventory"] = {
                    "status": "failed",
                    "reason": "Neighbor tables unavailable or exceeded limit",
                }
        else:
            facts["neighbor_inventory"] = {"status": "skipped", "reason": "Neighbor collection disabled"}

        address_queries = []

        async def get_address(oids):
            try:
                values = await get(oids)
            except WalkError as error:
                address_queries.append({"oids": oids, "error": str(error)})
                # One unsupported optional object can reject an otherwise usable batch.
                # Read each object independently before discarding its companion values.
                values = {}
                if len(oids) > 1:
                    for oid in oids:
                        values.update(await get_address([oid]))
                return values
            address_queries.append({"oids": oids, "values": values})
            return values

        collected_at = datetime.now(timezone.utc).isoformat()
        management_ip = await collect_polled_address(get_address, self.request.device_ip)
        if management_ip is None and self.request.device_ip.version == 4:
            management_ip = {
                "interface": "discovery-management",
                "address": f"{self.request.device_ip}/32",
                "dhcp": False,
                "prefix_source": "host",
                "interface_source": "placeholder",
            }
        address_lookup = {
            "status": "succeeded" if management_ip else "warning",
            "context_name": context,
            "queries": address_queries,
        }
        if management_ip is None:
            address_lookup["reason"] = (
                "SNMP could not resolve the polled IP to a usable interface address. "
                "Check the address tables, SNMP view, and VRF context shown in the queries."
            )
        elif management_ip.get("interface_source") == "placeholder":
            address_lookup.update(
                status="warning",
                prefix_source="host",
                reason=(
                    "SNMP did not identify the interface. Reuse an existing NetBox assignment or create "
                    "a discovery-management interface of type Other for the polled IPv4 /32."
                ),
            )
        elif management_ip.get("prefix_source") == "host":
            address_lookup.update(
                prefix_source="host",
                reason="SNMP confirmed the interface but omitted the subnet; using an IPv4 /32 host address.",
            )
        self.result["discovery"] = {
            **facts,
            "collected_at": collected_at,
            "address": str(self.request.device_ip),
            "site": self.request.site,
            "poller_instance": self.request.poller_instance,
            "management_ip": management_ip,
            "management_ip_lookup": address_lookup,
        }

    def seed_manual_inventory(self):
        # Keep poll failure truthful while allowing a complete manual identity to seed inventory.
        facts = {
            key: "" for key in ("name", "manufacturer", "model", "platform", "serial", "software_version")
        }
        facts.update(self.result.get("discovery", {}))
        apply_manual_fallback(facts, self.request.manual_fallback)
        facts.update(
            polled=False,
            collected_at=datetime.now(timezone.utc).isoformat(),
            address=str(self.request.device_ip),
            site=self.request.site,
            poller_instance=self.request.poller_instance,
        )
        facts["management_ip"] = {
            "interface": "discovery-management",
            "address": f"{self.request.device_ip}/{32 if self.request.device_ip.version == 4 else 128}",
            "dhcp": False,
            "prefix_source": "host",
            "interface_source": "placeholder",
        }
        facts["poll_status"] = "failed"
        if (
            facts.get("manufacturer") == "F5"
            and facts.get("serial")
            and re.search(r"\bBIG-IP\s+(?:Virtual Edition|VE)\b", facts.get("model", ""), re.I)
        ):
            # A partial poll read the VE's chassis serial, not its license serial: it may fill an
            # empty NetBox serial but never replace one.
            facts["serial_source"] = "snmp"
        self.result["discovery"] = facts

    def sync_inventory(self):
        discovery = self.result["discovery"]

        def checkpoint():
            self.store.checkpoint(self.job["id"], self.worker)

        if discovery["manufacturer"] == "F5" and discovery.get("polled", True):
            serial, discovery["license_lookup"] = self.read_f5_license_serial(checkpoint)
            virtual_edition = re.search(r"\bBIG-IP\s+(?:Virtual Edition|VE)\b", discovery["model"], re.I)
            if serial and virtual_edition:
                discovery.update(serial=serial, serial_source="license")
                if "field_sources" in discovery:
                    # Observed over SSH: never treat it as a manual or NetBox-kept value.
                    discovery["field_sources"]["serial"] = "observed"
            elif virtual_edition and discovery["serial"]:
                # Without SSH, keep the chassis serial SNMP reported. It never replaces a
                # serial NetBox already holds (see netbox_discovery.sync_inventory).
                discovery["serial_source"] = "snmp"

        missing = [
            field
            for field in ("name", "manufacturer", "model", "serial", "software_version")
            if not discovery[field]
        ]
        discovery["missing"] = missing

        try:
            if any(field in missing for field in ("name", "manufacturer", "model")):
                raise SyncError("SNMP did not report enough identity to create a device")
            action, device_id = sync_device(
                self.settings,
                discovery["site"],
                discovery["poller_instance"],
                discovery["address"],
                discovery,
                checkpoint,
            )
        except SyncError as error:
            discovery["netbox"] = {"status": "failed", "error": str(error)}
        except httpx.HTTPStatusError as error:
            discovery["netbox"] = {
                "status": "failed",
                "error": f"NetBox returned HTTP {error.response.status_code} for {error.request.method} {error.request.url.path}",
            }
        except (httpx.RequestError, OSError, ValueError, TypeError, KeyError):
            discovery["netbox"] = {
                "status": "failed",
                "error": "Could not read or write the configured NetBox API",
            }
        else:
            discovery["netbox"] = {"status": action, "device_id": device_id}
            if self._f5_license is not None:
                discovery["license_inventory"] = sync_licenses(
                    self.settings, device_id, discovery["poller_instance"], self._f5_license, checkpoint
                )
            enrichment = {
                "components": {
                    name: {"status": "skipped", "reason": "SSH enrichment disabled"}
                    for name in ("ha", "readiness", "licenses")
                }
            }
            if self.request.enrich_ssh and discovery.get("polled", True):
                enrichment = collect_enrichment(
                    self.settings,
                    self.store,
                    discovery["address"],
                    discovery,
                    self.job["id"],
                    checkpoint,
                    lambda data: self.store.credential_event(self.job["id"], self.worker, data),
                    backup=self.request.backup_config,
                    target_image=preferred_image(self.settings, device_id, checkpoint),
                )
                if enrichment.get("licenses"):
                    discovery["license_inventory"] = sync_observed_licenses(
                        self.settings,
                        device_id,
                        discovery["poller_instance"],
                        discovery["manufacturer"],
                        enrichment["licenses"],
                        checkpoint,
                    )
            if self._f5_license is not None:
                enrichment["license_products"] = [
                    item[:200] for item in self._f5_license["installed_modules"]
                ][:100]
                if self._f5_license.get("reported_expiration"):
                    enrichment["license_expiration"] = self._f5_license["reported_expiration"]
            discovery["collection_report"] = report_observation(
                self.settings, self.job["id"], device_id, discovery, enrichment, checkpoint
            )
            discovery["enrichment"] = {k: v for k, v in enrichment.items() if k != "licenses"}
            optional_failure = (
                discovery["collection_report"]["status"] in {"failed", "unavailable"}
                or any(
                    row["status"] in {"failed", "partial"}
                    for row in enrichment.get("components", {}).values()
                )
                or any(
                    discovery.get(field, {}).get("status") in {"failed", "warning"}
                    for field in (
                        "software_inventory",
                        "stack_inventory",
                        "access_point_inventory",
                        "license_lookup",
                        "license_inventory",
                        "management_ip_sync",
                    )
                )
            )
            # Blank SNMP readings, filled from manual data or kept from NetBox, are reported.
            manual = [
                key
                for key, source in discovery.get("field_sources", {}).items()
                if source in {"manual", "netbox-existing"}
            ]
            discovery["manual_fields"] = manual
            rule_failure = discovery.get("identity_rules_config", {}).get("status") == "failed" or any(
                row["status"] in {"failed", "missing"} for row in discovery.get("identity_rules", [])
            )
            return (
                "completed_with_warnings"
                if missing or optional_failure or manual or rule_failure
                else "succeeded"
            )
        return "failed"

    def read_f5_license_serial(self, checkpoint):
        """Return the VE license serial or a failure with redacted diagnostics."""
        address = str(self.request.device_ip)
        self._f5_license = None
        if not self.request.enrich_ssh:
            return "", {"status": "skipped", "reason": "SSH enrichment disabled for this job"}
        try:
            target = discovery_target(self.settings, self.store, address, "f5")
        except DeviceError as error:
            return "", {"status": "skipped", "reason": str(error)}
        except Conflict:
            return "", {
                "status": "failed",
                "reason": "SSH credential store is unavailable; check NETOPS_CREDENTIAL_KEY_FILE",
            }
        if target is None:
            return "", {
                "status": "skipped",
                "reason": "no SSH credential profile is enabled for discovery or lists this IP",
            }
        inventory = bool(self.settings.inventory_at(address))
        ssh = SSH(
            self.settings,
            target,
            guard=checkpoint,
            audit=lambda data: self.store.credential_event(self.job["id"], self.worker, data),
            max_attempts=attempts_for(self.settings, address),
        )
        lookup = {"device": target.id, "source": "inventory" if inventory else "discovery"}
        try:
            self._f5_license = license_details(ssh)
            serial = self._f5_license["serial"]
            if shell_type := getattr(ssh, "f5_shell_type", None):
                lookup["shell"] = shell_type
            return serial, {**lookup, "status": "succeeded"}
        except DeviceError as error:
            failure = {**lookup, "status": "failed", "reason": str(error)}
            if error.diagnostics is not None:
                failure["diagnostics"] = error.diagnostics
            return "", failure
        except (OSError, EOFError, SSHException):
            return "", {**lookup, "status": "failed", "reason": "SSH connection failed"}
        finally:
            ssh.close()

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
            kind = "bulk" if self.repetitions and not self.v1 else "next"
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
