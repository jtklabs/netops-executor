"""Real UDP loopback coverage of SNMP v3 discovery, authentication and privacy."""

import asyncio
import socket

import pytest
from pysnmp.carrier.asyncio.dgram import udp, udp6
from pysnmp.entity import config, engine
from pysnmp.entity.rfc3413 import cmdrsp, context

from netops_executor.snmp import SnmpRunner
from netops_executor.snmp_models import SnmpProfile, SnmpWalkRequest


@pytest.mark.parametrize(
    "level,ipv6,bad_password,encrypted",
    [
        ("authPriv", False, False, False),
        ("authPriv", False, False, True),
        ("authNoPriv", False, False, False),
        ("noAuthNoPriv", True, False, False),
        ("authPriv", False, True, False),
    ],
)
def test_loopback_v3(settings, store, monkeypatch, level, ipv6, bad_password, encrypted):
    monkeypatch.setenv("TEST_SNMP_AUTH", "wrong-passphrase" if bad_password else "loopback-auth-passphrase")
    monkeypatch.setenv("TEST_SNMP_PRIV", "loopback-priv-passphrase")
    settings.snmp_profiles = {
        "default": SnmpProfile(
            id="default",
            username="test-reader",
            security_level=level,
            auth_password_env="TEST_SNMP_AUTH" if level != "noAuthNoPriv" else None,
            priv_password_env="TEST_SNMP_PRIV" if level == "authPriv" else None,
        )
    }

    if encrypted:
        from test_controls_credentials import vault_for

        from netops_executor.credentials import Credential

        vault = vault_for(settings, store)
        vault.put(
            "unknown",
            Credential(
                kind="snmp",
                username="unknown-user",
                auth_password="loopback-auth-passphrase",
                priv_password="loopback-priv-passphrase",
                priority=1,
            ),
        )
        vault.put(
            "valid",
            Credential(
                kind="snmp",
                username="test-reader",
                auth_password="loopback-auth-passphrase",
                priv_password="loopback-priv-passphrase",
                priority=2,
            ),
        )
        settings.snmp_profiles = {}

    async def exercise():
        agent = engine.SnmpEngine()
        sock = socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET, socket.SOCK_DGRAM)
        address = "::1" if ipv6 else "127.0.0.1"
        sock.bind((address, 0))
        port = sock.getsockname()[1]
        transport = udp6 if ipv6 else udp
        config.add_transport(
            agent,
            transport.DOMAIN_NAME,
            (udp6.Udp6Transport() if ipv6 else udp.UdpTransport()).open_server_mode(sock=sock),
        )
        config.add_v3_user(
            agent,
            "test-reader",
            config.USM_AUTH_HMAC192_SHA256 if level != "noAuthNoPriv" else config.USM_AUTH_NONE,
            "loopback-auth-passphrase" if level != "noAuthNoPriv" else None,
            config.USM_PRIV_CFB128_AES if level == "authPriv" else config.USM_PRIV_NONE,
            "loopback-priv-passphrase" if level == "authPriv" else None,
        )
        config.add_vacm_user(agent, 3, "test-reader", level, (1, 3, 6, 1, 2, 1))
        responder = cmdrsp.NextCommandResponder(agent, context.SnmpContext(agent))
        try:
            request = SnmpWalkRequest(
                device_ip=address, port=port, oids=["1.3.6.1.2.1.1", "1.3.6.1.2.1.999"], job_timeout=5
            )
            job = store.submit(request.model_dump(mode="json"), "loopback", kind="snmp_walk")
            runner = SnmpRunner(settings, store, store.claim("wire"), "wire")
            await runner.walk()
            if bad_password:
                assert runner.result["rows"] == 0
                assert all(r["status"] == "failed" for r in runner.result["oids"]), runner.result
                return
            assert all(r["status"] == "succeeded" for r in runner.result["oids"]), runner.result
            rows = store.snmp_results(job["id"])["rows"]
            assert rows
            assert all(row["oid"].startswith("1.3.6.1.2.1.1.") for row in rows)
            assert runner.result["oids"][1]["rows"] == 0
            if encrypted:
                audit = store.get(job["id"])["credential_usage"]
                assert any(c["profile"] == "unknown" and c["outcome"] == "rejected" for c in audit)
                assert store.get(job["id"])["credential_summary"]["profiles_used"] == ["valid"]
        finally:
            responder.close(agent)
            agent.close_dispatcher()
            sock.close()

    asyncio.run(exercise())
