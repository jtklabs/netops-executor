"""SNMPv3 credential fallback when an agent ignores a user instead of rejecting it."""

import asyncio

from pysnmp.proto.errind import RequestTimedOut
from test_controls_credentials import vault_for
from test_snmp import ROOT, FakeAgent, rows

from netops_executor.credentials import Credential
from netops_executor.snmp import NO_ANSWER, TIMED_OUT, SnmpRunner
from netops_executor.snmp_models import SnmpWalkRequest


class SelectiveAgent(FakeAgent):
    """Answers only the users it knows; drops everything else, as many agents do."""

    def __init__(self, monkeypatch, values, users, script=None):
        super().__init__(monkeypatch, values, script=script)
        self.users, self.seen = users, []

    async def request(self, kind, engine, auth, target, context, oids, repetitions=0):
        user = str(auth.userName)
        self.seen.append(user)
        if user not in self.users:
            self.calls.append((kind, repetitions if kind == "bulk" else None, [str(o) for o in oids]))
            return RequestTimedOut(), 0, 0, ()
        return await super().request(kind, engine, auth, target, context, oids, repetitions)


def profiles(settings, store, *users):
    vault = vault_for(settings, store)
    for priority, user in enumerate(users, 1):
        vault.put(
            user,
            Credential(
                kind="snmp",
                username=user,
                auth_password="auth-passphrase",
                priv_password="priv-passphrase",
                priority=priority,
            ),
        )
    settings.snmp_profiles = {}


def run(settings, store, **request):
    body = SnmpWalkRequest(device_ip="192.0.2.30", oids=[ROOT], get_oids=[ROOT + ".1"], **request)
    job = store.submit(body.model_dump(mode="json"), "device:192.0.2.30", kind="snmp_walk")
    runner = SnmpRunner(settings, store, store.claim("worker"), "worker")
    asyncio.run(runner.walk())
    return runner, store.get(job["id"])


def usage(job):
    return [(row["profile"], row["outcome"]) for row in job["credential_usage"]]


def test_an_ignored_user_moves_on_to_the_next_profile(settings, store, monkeypatch):
    profiles(settings, store, "primary", "secondary")
    agent = SelectiveAgent(monkeypatch, rows(ROOT, 3), users={"secondary"})
    runner, job = run(settings, store)
    assert [g["status"] for g in runner.result["gets"]] == ["succeeded"]
    assert runner.result["oids"][0]["status"] == "succeeded" and runner.result["oids"][0]["rows"] == 3
    assert ("primary", "no_response") in usage(job) and ("secondary", "authenticated") in usage(job)
    # The profile that answered goes first for the rest of the job.
    assert agent.seen.count("primary") == 1
    # Silence from the wrong user is not a GETBULK problem: the walk keeps GETBULK.
    assert runner.result["walk"]["method"] == "bulk" and runner.result["walk"]["fallbacks"] == []
    # No answer is not a rejection: no cooldown blocks the next job from trying it.
    with store.connect() as db:
        assert db.execute("SELECT COUNT(*) FROM credential_cooldowns").fetchone()[0] == 0


def test_no_answer_to_any_profile_fails_once_without_retrying_each_operation(settings, store, monkeypatch):
    profiles(settings, store, "primary", "secondary")
    agent = SelectiveAgent(monkeypatch, rows(ROOT, 3), users=set())
    runner, job = run(settings, store)
    assert runner.result["gets"][0]["status"] == "failed"
    assert runner.result["gets"][0]["error"] == NO_ANSWER
    assert runner.result["oids"][0]["error"] == NO_ANSWER
    assert usage(job) == [("primary", "no_response"), ("secondary", "no_response")]
    # Each profile was asked once; the walk afterwards did not ask again.
    assert agent.seen == ["primary", "secondary"]


def test_a_timeout_after_the_agent_has_answered_is_not_a_credential_problem(settings, store, monkeypatch):
    profiles(settings, store, "primary", "secondary")
    # The GET answers; then the agent goes silent for the whole walk.
    agent = SelectiveAgent(
        monkeypatch,
        rows(ROOT, 3),
        users={"primary", "secondary"},
        script={n: (RequestTimedOut(), 0, 0, ()) for n in range(2, 40)},
    )
    runner, job = run(settings, store)
    assert runner.result["gets"][0]["status"] == "succeeded"
    assert runner.result["oids"][0]["error"] == TIMED_OUT
    assert "secondary" not in agent.seen and ("secondary", "no_response") not in usage(job)
