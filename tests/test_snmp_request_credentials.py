"""SNMP credentials sent with a request: v1, v2c and v3, tried before any profile, never stored."""

import asyncio
import json
import socket

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.entity import config, engine
from pysnmp.entity.rfc3413 import cmdrsp, context
from pysnmp.proto.errind import RequestTimedOut
from test_controls_credentials import vault_for
from test_snmp import ROOT, FakeAgent, rows

from netops_executor.api import create_app
from netops_executor.credentials import Credential, Vault
from netops_executor.snmp import SnmpRunner
from netops_executor.snmp_models import SnmpCredential, SnmpProfile, SnmpWalkRequest
from netops_executor.worker import process

COMMUNITY = "request-community-7731"
AUTH, PRIV = "request-auth-passphrase", "request-priv-passphrase"
V3 = {
    "version": "3",
    "username": "request-user",
    "auth_protocol": "SHA512",
    "auth_password": AUTH,
    "priv_protocol": "AES256C",
    "priv_password": PRIV,
}


@pytest.fixture
def api(settings, store):
    vault = vault_for(settings, store)
    vault.put(
        "saved",
        Credential(kind="snmp", username="saved-user", auth_password=AUTH, priv_password=PRIV, priority=1),
    )
    settings.snmp_profiles = {}
    return TestClient(create_app(settings), headers={"Authorization": "Bearer " + settings.token})


def submit(api, **body):
    response = api.post("/api/v1/snmp/walks", json={"device_ip": "192.0.2.40", "oids": [ROOT], **body})
    assert response.status_code == 202, response.text
    return response.json()


class Agent(FakeAgent):
    """Answers only the identities it knows: communities (v1/v2c) or USM user names (v3)."""

    def __init__(self, monkeypatch, known):
        super().__init__(monkeypatch, rows(ROOT, 3))
        self.known, self.seen = known, []

    async def request(self, kind, engine, auth, target, context, oids, repetitions=0):
        identity = str(getattr(auth, "communityName", None) or auth.userName)
        model = getattr(auth, "message_processing_model", 3)
        self.seen.append((identity, model, kind))
        if identity not in self.known:
            self.calls.append((kind, None, []))
            return RequestTimedOut(), 0, 0, ()
        return await super().request(kind, engine, auth, target, context, oids, repetitions)


def run(settings, store):
    process(settings, store, store.claim("w"), "w")


def test_request_credentials_are_validated_by_version():
    assert SnmpCredential.model_validate({"version": "v2", "community": "c"}).version == "2c"
    assert SnmpCredential.model_validate(V3).security_level == "authPriv"
    authonly = {k: v for k, v in V3.items() if not k.startswith("priv")}
    assert SnmpCredential.model_validate(authonly).security_level == "authNoPriv"
    for bad in (
        {"version": "2c"},
        {"version": "2c", "community": "c", "username": "u"},
        {**V3, "auth_protocol": None},
        {**V3, "priv_password": "short"},
        {**V3, "community": "c"},
        {"version": "3", "username": "u", "security_level": "authPriv"},
    ):
        with pytest.raises(ValidationError):
            SnmpCredential.model_validate(bad)


def test_credentials_are_encrypted_apart_from_the_job_and_erased_when_it_finishes(
    settings, store, api, monkeypatch
):
    job = submit(api, credentials=[{"version": "2c", "community": COMMUNITY}, V3])
    assert job["request"]["credential_count"] == 2 and "credentials" not in job["request"]
    with store.connect() as db:
        public = json.dumps([tuple(r) for r in db.execute("SELECT * FROM jobs")])
        secret = db.execute("SELECT secret FROM job_secrets WHERE job=?", (job["id"],)).fetchone()[0]
    assert COMMUNITY not in public and AUTH not in public and PRIV not in public
    assert secret and COMMUNITY.encode() not in secret
    Agent(monkeypatch, {COMMUNITY})
    run(settings, store)
    done = store.get(job["id"])
    assert done["status"] == "succeeded", done["result"]
    assert COMMUNITY not in json.dumps(done)
    with store.connect() as db:
        assert db.execute("SELECT secret FROM job_secrets WHERE job=?", (job["id"],)).fetchone()[0] == b""


def test_request_credentials_go_first_then_saved_profiles(settings, store, api, monkeypatch):
    job = submit(api, credentials=[{"version": "2c", "community": "wrong-community"}, V3])
    agent = Agent(monkeypatch, {"saved-user"})
    run(settings, store)
    done = store.get(job["id"])
    assert done["status"] == "succeeded", done["result"]
    assert [row["profile"] for row in done["credential_usage"] if row["outcome"] != "authenticated"] == [
        "request:1",
        "request:2",
    ]
    assert done["credential_summary"]["profiles_used"] == ["saved"]
    order = list(dict.fromkeys(identity for identity, _, _ in agent.seen))
    assert order == ["wrong-community", "request-user", "saved-user"]
    # The v2c credential went out as v2c (message processing model 1).
    assert {model for identity, model, _ in agent.seen if identity == "wrong-community"} == {1}


def test_a_working_request_credential_is_used_before_any_profile(settings, store, api, monkeypatch):
    job = submit(api, credentials=[V3])
    agent = Agent(monkeypatch, {"request-user", "saved-user"})
    run(settings, store)
    assert store.get(job["id"])["credential_summary"]["profiles_used"] == ["request:1"]
    assert "saved-user" not in {identity for identity, _, _ in agent.seen}


def test_use_profiles_false_tries_only_the_request_credentials(settings, store, api, monkeypatch):
    job = submit(api, credentials=[{"version": "2c", "community": "wrong-community"}], use_profiles=False)
    agent = Agent(monkeypatch, {"saved-user"})
    run(settings, store)
    done = store.get(job["id"])
    assert done["status"] == "failed"
    assert {identity for identity, _, _ in agent.seen} == {"wrong-community"}
    response = api.post(
        "/api/v1/snmp/walks", json={"device_ip": "192.0.2.40", "oids": [ROOT], "use_profiles": False}
    )
    assert response.status_code == 422


def test_v1_never_sends_getbulk(settings, store, api, monkeypatch):
    submit(api, credentials=[{"version": "1", "community": COMMUNITY}], use_profiles=False)
    agent = Agent(monkeypatch, {COMMUNITY})
    run(settings, store)
    assert {model for _, model, _ in agent.seen} == {0}
    assert {kind for _, _, kind in agent.seen} <= {"get", "next"}


def test_replays_and_unchanged_requests(settings, store, api):
    body = {"credentials": [V3]}
    headers = {"Idempotency-Key": "walk-creds"}
    payload = {"device_ip": "192.0.2.40", "oids": [ROOT], **body}
    first = api.post("/api/v1/snmp/walks", json=payload, headers=headers).json()
    assert api.post("/api/v1/snmp/walks", json=payload, headers=headers).json()["id"] == first["id"]
    other = {**payload, "credentials": [{**V3, "auth_password": "another-auth-passphrase"}]}
    assert api.post("/api/v1/snmp/walks", json=other, headers=headers).status_code == 409
    # A request without the new options is stored exactly as before.
    plain = submit(api)
    assert "credential_count" not in plain["request"] and "use_profiles" not in plain["request"]
    # The count is the executor's to set.
    forged = submit(api, credential_count=3)
    assert "credential_count" not in forged["request"]


def test_credentials_need_the_key_file(settings, store):
    settings.snmp_profiles = {
        "default": SnmpProfile(id="default", username="reader", security_level="noAuthNoPriv")
    }
    api = TestClient(create_app(settings), headers={"Authorization": "Bearer " + settings.token})
    response = api.post(
        "/api/v1/snmp/walks",
        json={
            "device_ip": "192.0.2.40",
            "oids": [ROOT],
            "credentials": [{"version": "2c", "community": "c"}],
        },
    )
    assert response.status_code == 409 and "NETOPS_CREDENTIAL_KEY_FILE" in response.text


def test_saved_profiles_take_v2c_and_more_ciphers(settings, store):
    vault = vault_for(settings, store)
    vault.put("v2", Credential(kind="snmp", version="v2c", community=COMMUNITY))
    with pytest.raises(ValidationError):
        Credential(kind="snmp", version="2c")
    saved = vault.candidates("snmp", ["v2"], ("192.0.2.40",))[0]
    assert saved["version"] == "2c" and saved["community"] == COMMUNITY
    assert all(row["id"] != COMMUNITY for row in vault.list())
    Credential(
        kind="snmp",
        username="u",
        auth_protocol="MD5",
        auth_password=AUTH,
        priv_protocol="DES",
        priv_password=PRIV,
    )


# Real UDP against a pysnmp agent: each version and a non-default cipher family.
AGENT_USERS = {
    "sha512-aes256c": (config.USM_AUTH_HMAC384_SHA512, config.USM_PRIV_CFB256_AES),
    "sha256-aes192": (config.USM_AUTH_HMAC192_SHA256, config.USM_PRIV_CFB192_AES_BLUMENTHAL),
    "md5-des": (config.USM_AUTH_HMAC96_MD5, config.USM_PRIV_CBC56_DES),
    "sha-3des": (config.USM_AUTH_HMAC96_SHA, config.USM_PRIV_CBC168_3DES),
}


@pytest.mark.parametrize(
    "credential",
    [
        {"version": "2c", "community": COMMUNITY},
        {"version": "1", "community": COMMUNITY},
        {**V3, "username": "sha512-aes256c"},
        {**V3, "username": "sha256-aes192", "auth_protocol": "SHA256", "priv_protocol": "AES192"},
        {**V3, "username": "md5-des", "auth_protocol": "MD5", "priv_protocol": "DES"},
        {**V3, "username": "sha-3des", "auth_protocol": "SHA", "priv_protocol": "3DES"},
    ],
    ids=["v2c", "v1", "sha512-aes256c", "sha256-aes192", "md5-des", "sha-3des"],
)
def test_real_agent_accepts_each_version_and_cipher(settings, store, credential):
    vault_for(settings, store)
    settings.snmp_profiles = {}

    async def exercise():
        agent = engine.SnmpEngine()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        config.add_transport(agent, udp.DOMAIN_NAME, udp.UdpTransport().open_server_mode(sock=sock))
        config.add_v1_system(agent, "netops-area", COMMUNITY)
        for model in (1, 2):
            config.add_vacm_user(agent, model, "netops-area", "noAuthNoPriv", (1, 3, 6, 1, 2, 1))
        for user, (auth, priv) in AGENT_USERS.items():
            config.add_v3_user(agent, user, auth, AUTH, priv, PRIV)
            config.add_vacm_user(agent, 3, user, "authPriv", (1, 3, 6, 1, 2, 1))
        snmp_context = context.SnmpContext(agent)
        responders = [
            cmdrsp.GetCommandResponder(agent, snmp_context),
            cmdrsp.NextCommandResponder(agent, snmp_context),
            cmdrsp.BulkCommandResponder(agent, snmp_context),
        ]
        try:
            request = SnmpWalkRequest(
                device_ip="127.0.0.1",
                port=port,
                oids=["1.3.6.1.2.1.1"],
                get_oids=["1.3.6.1.2.1.1.3.0"],
                use_profiles=False,
                credential_count=1,
                timeout=1,
                job_timeout=20,
            )
            plain = SnmpCredential.model_validate(credential).plaintext()
            cipher = Vault(store, settings.credential_key_file).cipher()
            store.submit(
                request.model_dump(mode="json"),
                "loopback",
                kind="snmp_walk",
                secret=cipher.encrypt(json.dumps([plain]).encode()),
            )
            runner = SnmpRunner(settings, store, store.claim("wire"), "wire")
            await runner.walk()
            assert runner.result["oids"][0]["status"] == "succeeded", runner.result
            assert runner.result["oids"][0]["rows"] > 0
            assert runner.result["gets"][0]["status"] == "succeeded"
            if credential["version"] == "1":
                assert runner.result["walk"]["method"] == "bulk"  # configured; v1 requests used GETNEXT
        finally:
            for responder in responders:
                responder.close(agent)
            agent.close_dispatcher()
            sock.close()

    asyncio.run(exercise())


def test_swagger_documents_request_credentials_with_valid_examples(api):
    spec = api.get("/openapi.json").json()
    walk = spec["paths"]["/api/v1/snmp/walks"]["post"]
    assert "v1, v2c or v3" in walk["summary"] and "AES256C" in walk["description"]
    examples = walk["requestBody"]["content"]["application/json"]["examples"]
    assert {"profiles", "v2c", "v3", "only"} <= set(examples)
    for example in examples.values():
        SnmpWalkRequest.model_validate(example["value"])
    schemas = spec["components"]["schemas"]
    assert schemas["SnmpWalkRequest"]["properties"]["credential_count"]["readOnly"] is True
    assert set(schemas["SnmpCredential"]["properties"]) >= {"version", "community", "priv_protocol"}
    saved = spec["paths"]["/api/v1/credentials/{profile}"]["put"]["requestBody"]["content"][
        "application/json"
    ]
    for example in saved["examples"].values():
        Credential.model_validate(example["value"])
