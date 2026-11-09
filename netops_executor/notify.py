"""Email reports to the addresses in a request's notify_email.

A job whose request has notify_email gets one report when it finishes. A batch whose request has
notify_email gets one report when every device has finished, or when the devices left cannot
start because an earlier wave did not pass; if an operator then moves the batch on, a later report
follows. The API process sends reports, with retries, at least once.
"""

import hashlib
import html
import re
import smtplib
import ssl
import time
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import formatdate, make_msgid, parseaddr

from . import __version__
from .device import LTM_CATEGORIES

MAX_BACKOFF = 600
# LTM changes listed per category and device; the job record keeps the full list.
MAX_CHANGES = 25
# Devices in a batch report that get a detail section of their own.
MAX_DETAILS = 50
PASSED = ("succeeded", "completed_with_warnings", "manually_completed")
STOPPED = ("failed", "cancelled", "expired", "recovery_required", "resolved")

# Label, text color and background for each status.
STATUS = {
    "succeeded": ("Succeeded", "#116329", "#dafbe1"),
    "completed_with_warnings": ("Completed with warnings", "#7d4e00", "#fff8c5"),
    "manually_completed": ("Manually completed", "#0550ae", "#ddf4ff"),
    "resolved": ("Resolved by operator", "#0550ae", "#ddf4ff"),
    "failed": ("Failed", "#a40e26", "#ffebe9"),
    "recovery_required": ("Recovery required", "#a40e26", "#ffebe9"),
    "cancelled": ("Cancelled", "#424a53", "#eaeef2"),
    "expired": ("Expired before start", "#424a53", "#eaeef2"),
    "queued": ("Not started", "#424a53", "#eaeef2"),
    "running": ("Running", "#0550ae", "#ddf4ff"),
    "needs_review": ("Needs review", "#7d4e00", "#fff8c5"),
    "completed": ("Completed", "#116329", "#dafbe1"),
    "needs_attention": ("Needs attention", "#a40e26", "#ffebe9"),
}
KINDS = {
    "upgrade": "F5 BIG-IP upgrade",
    "rollback": "F5 BIG-IP rollback",
    "panos_upgrade": "PAN-OS upgrade",
    "eos_upgrade": "Arista EOS upgrade",
    "iosxe_upgrade": "Cisco IOS XE upgrade",
    "ios_upgrade": "Cisco IOS upgrade",
    "fortigate_upgrade": "FortiGate upgrade",
    "opengear_upgrade": "Opengear upgrade",
    "password_rotation": "Password rotation",
    "ssh": "SSH job",
    "http": "HTTP job",
    "cipher_scan": "Cipher scan",
    "snmp_walk": "SNMP walk",
}
CATEGORIES = {
    "virtual_servers": "Virtual servers",
    "pools": "Pools",
    "nodes": "Nodes",
    "virtual_ips": "Virtual addresses",
}
WORDS = {
    "ucs": "UCS",
    "ha": "HA",
    "waf": "WAF",
    "asm": "ASM",
    "ltm": "LTM",
    "ssh": "SSH",
    "http": "HTTP",
    "api": "API",
    "snmp": "SNMP",
    "ftp": "FTP",
    "ip": "IP",
}

FONT = "-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif"
MONO = "SFMono-Regular,Consolas,'Liberation Mono',Menlo,monospace"
INK, MUTED, LINE = "#1f2328", "#59636e", "#d1d9e0"


class Permanent(Exception):
    """The server refused the message itself; sending it again cannot succeed."""


# Report data


def when(timestamp):
    return datetime.fromtimestamp(timestamp, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def duration(seconds):
    seconds = int(max(0, seconds))
    hours, rest = divmod(seconds, 3600)
    minutes, seconds = divmod(rest, 60)
    if hours:
        return f"{hours}h {minutes:02d}m"
    return f"{minutes}m {seconds:02d}s" if minutes else f"{seconds}s"


def humanize(step):
    words = [WORDS.get(word, word) for word in str(step).split("_")]
    return " ".join([words[0][:1].upper() + words[0][1:], *words[1:]]) if words else ""


def status_label(status):
    return STATUS.get(status, (humanize(status), INK, "#eaeef2"))[0]


def finished(job):
    return job["status"] in PASSED + STOPPED


def software(job, short=False):
    """Running software before and after, and the target, as display text; None where unknown."""
    result, request = job["result"], job["request"]

    def text(version, build=None, volume=None):
        if not version or short:
            return version or None
        return version + (f" build {build}" if build else "") + (f" on {volume}" if volume else "")

    if job["kind"] == "rollback":
        target = result.get("rollback_target") or {}
        before = text(target.get("from_version"), target.get("from_build"), target.get("from_volume"))
    elif result.get("rollback"):
        saved = result["rollback"]
        before = text(saved.get("version"), saved.get("build"), saved.get("volume"))
    else:
        source = result.get("source") or {}
        before = text(source.get("version"), source.get("build"), source.get("volume"))
    booted = result.get("boot_verified") or {}
    after = text(booted.get("version"), booted.get("build"), booted.get("volume"))
    target = request.get("expected_version") or request.get("target_version")
    if not target and isinstance(request.get("image"), dict):
        target = request["image"].get("version")
    return before, after, target


def software_text(job, short=False):
    before, after, target = software(job, short)
    if after:
        return f"{before} → {after}" if before and before != after else after
    if target:
        return (
            f"{before or 'current'} → {target} (" + ("not reached" if short else "target, not reached") + ")"
        )
    return before


def waf_counts(job):
    result = job["result"]
    before = result.get("pre_validation", {}).get("waf_policy_names")
    after = result.get("post_validation", {}).get("waf_policy_names")
    return (len(before) if before is not None else None, len(after) if after is not None else None)


def ha_text(job):
    ha = job["result"].get("ha")
    if not ha:
        return None
    if not ha.get("cluster"):
        return "Standalone"
    # The cluster key is a digest; the sync-failover group and member addresses identify the pair.
    members = ", ".join(m.get("host") or m.get("name") for m in ha.get("members", []))
    groups = ", ".join(ha.get("groups") or []) or "HA pair"
    return f"{humanize(ha.get('role', 'member'))} at start, {groups} ({members})"


def drain_text(job):
    drain = job["result"].get("drain") or {}
    if drain.get("initial_connections") is None:
        return None
    text = f"{drain['initial_connections']} → {drain.get('final_connections', '?')} connections"
    if drain.get("reason"):
        text += f", ended by {drain['reason']}"
    if drain.get("changed_addresses"):
        count = len(drain["changed_addresses"])
        text += f"; {count} virtual address{'es' if count != 1 else ''} disabled"
        text += ", restored" if drain.get("restored") else ""
    return text


def facts(job, label):
    """Summary rows (label, value) for one job, in display order."""
    result = job["result"]
    rows = [("Device", label(job["device"])), ("Job", KINDS.get(job["kind"], humanize(job["kind"])))]
    text = software_text(job)
    if text:
        rows.append(("Software", text))
    if job.get("started_at"):
        rows.append(("Started", when(job["started_at"])))
        if finished(job):
            rows.append(("Finished", when(job["updated"])))
            rows.append(("Duration", duration(job["updated"] - job["started_at"])))
    elif finished(job):
        rows.append(("Ended", when(job["updated"]) + " (never started)"))
    for name, value in (("HA", ha_text(job)), ("Traffic drain", drain_text(job))):
        if value:
            rows.append((name, value))
    if result.get("reused_volume"):
        rows.append(("Install", f"Reused the existing install on {result['reused_volume']}"))
    if result.get("backup", {}).get("path"):
        backup = result["backup"]
        rows.append(("Backup", backup["path"] + (" (encrypted UCS)" if backup.get("encrypted") else "")))
    if result.get("config_sync"):
        rows.append(("Config sync", result["config_sync"]))
    check = result.get("waf_request_check")
    if check:
        text = humanize(check.get("status", "unknown"))
        if check.get("attempts"):
            text += f" after {check['attempts']} check{'s' if check['attempts'] != 1 else ''}"
        if check.get("reason"):
            text += f" ({check['reason']})"
        rows.append(("ASM request log", text))
    before, after = waf_counts(job)
    if before is not None:
        rows.append(("WAF policies", f"{before} before, {after} after" if after is not None else f"{before}"))
    return rows


def attention(job):
    """Items the reader should act on or know about, most important first."""
    result, items = job["result"], []
    if result.get("error"):
        items.append(str(result["error"]))
    if job["status"] == "recovery_required":
        items.append(
            "The device may be part-way through a change. Check it, then record the outcome with "
            f"POST /api/v1/jobs/{job['id']}/resolve."
        )
    if result.get("cancelled_at"):
        items.append(f"Cancelled during {humanize(result['cancelled_at']).lower()}.")
    if result.get("address_restore_failed"):
        items.append("Drained virtual addresses could not be re-enabled. Check them on the device.")
    if job["status"] not in PASSED and result.get("validation_issues"):
        items.append("Last validation: " + "; ".join(map(str, result["validation_issues"])))
    check = result.get("waf_request_check") or {}
    if check.get("status") not in (None, "passed", "skipped"):
        items.append(f"ASM request log check: {check['status']}.")
    if result.get("config_sync_forced"):
        items.append(
            "Config sync needed a full-load push from the active unit for: "
            + ", ".join(result["config_sync_forced"])
        )
    for decision in result.get("manual_validations") or []:
        items.append(
            f"Validation differences accepted by {decision.get('operator') or 'an operator'}"
            + (f": {decision['reason']}" if decision.get("reason") else "")
        )
    for difference in result.get("validation_differences") or []:
        if isinstance(difference, dict) and difference.get("category") not in LTM_CATEGORIES:
            items.append(
                f"{humanize(difference.get('category', 'difference'))}: "
                f"{difference.get('object', '')} {difference.get('change', 'changed')}".strip()
            )
    for warning in result.get("warnings") or []:
        items.append(str(warning))
    summary = job.get("credential_summary") or {}
    if summary.get("multiple_profiles_used"):
        items.append(
            "Signed in with more than one credential profile: " + ", ".join(summary["profiles_used"])
        )
    return items


def ltm_changes(job):
    return sum(len(c["changes"]) for c in (job["result"].get("ltm_report") or {}).values())


def reviews(job):
    """Validation gates the job stopped at, with the operator's decision."""
    rows = []
    for gate in job.get("validation_gates") or []:
        decision = gate.get("decision") or {}
        rows.append(
            (
                humanize(gate.get("phase", "validation")),
                humanize(decision.get("action", gate.get("state", "open"))),
                decision.get("operator", ""),
                decision.get("reason", ""),
            )
        )
    return rows


def timeline(events):
    if not events:
        return []
    start, rows = events[0]["time"], []
    for event in events:
        detail = ", ".join(
            f"{key.replace('_', ' ')} {value}"
            for key, value in list(event["data"].items())[:3]
            if isinstance(value, (str, int, float)) and not isinstance(value, bool) and len(str(value)) <= 60
        )
        rows.append(
            (
                datetime.fromtimestamp(event["time"], timezone.utc).strftime("%H:%M:%S"),
                "+" + duration(event["time"] - start),
                humanize(event["step"]) + (f" ({detail})" if detail else ""),
            )
        )
    return rows


def batch_state(jobs):
    """completed, stopped (nothing left can run) or None while devices still run or wait."""
    if all(job["status"] in PASSED for job in jobs):
        return "completed"
    for job in jobs:
        if job["status"] in ("running", "needs_review"):
            return None
        if job["status"] == "queued" and not any(
            other["wave"] < job["wave"] and other["status"] in STOPPED for other in jobs
        ):
            return None
    return "stopped"


def digest(jobs):
    """Identifies the member statuses a batch report describes, so the same state is sent once."""
    state = "|".join(f"{job['id']}:{job['status']}" for job in sorted(jobs, key=lambda job: job["id"]))
    return hashlib.sha256(state.encode()).hexdigest()[:32]


# HTML


def e(value):
    return html.escape(str(value), quote=True)


def pill(status):
    text, color, background = STATUS.get(status, (humanize(status), INK, "#eaeef2"))
    return (
        f'<span style="display:inline-block;padding:2px 10px;border-radius:12px;background:{background};'
        f'color:{color};font-size:12px;font-weight:600;white-space:nowrap">{e(text)}</span>'
    )


def heading(text):
    return (
        f'<h2 style="margin:28px 0 10px;font-size:15px;font-weight:600;color:{INK};'
        f'border-bottom:1px solid {LINE};padding-bottom:6px">{e(text)}</h2>'
    )


def table(headers, rows, mono=()):
    """rows hold HTML-safe cells; mono lists the column indexes shown in a fixed-width font."""
    cell = f"padding:6px 8px;border-bottom:1px solid {LINE};vertical-align:top;font-size:13px"
    head = "".join(
        f'<th align="left" style="{cell};color:{MUTED};font-weight:600;font-size:12px">{e(h)}</th>'
        for h in headers
    )
    body = "".join(
        "<tr>"
        + "".join(
            f'<td style="{cell}{";font-family:" + MONO if index in mono else ""}">{value}</td>'
            for index, value in enumerate(row)
        )
        + "</tr>"
        for row in rows
    )
    return (
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
        f'style="border-collapse:collapse;margin:0 0 8px">{"<tr>" + head + "</tr>" if headers else ""}{body}</table>'
    )


def fact_table(rows):
    cell = f"padding:5px 0;border-bottom:1px solid {LINE};vertical-align:top;font-size:13px"
    return (
        '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse">'
        + "".join(
            f'<tr><td width="150" style="{cell};color:{MUTED}">{e(name)}</td>'
            f'<td style="{cell};color:{INK}">{e(value)}</td></tr>'
            for name, value in rows
        )
        + "</table>"
    )


def callout(items, status):
    color = "#a40e26" if status not in PASSED else "#9a6700"
    background = "#ffebe9" if status not in PASSED else "#fff8c5"
    title = "Needs attention" if status not in PASSED else "Notes"
    return (
        f'<div style="margin:20px 0 0;padding:12px 16px;border-left:4px solid {color};background:{background};'
        f'border-radius:4px"><div style="font-weight:600;font-size:13px;color:{color};margin-bottom:4px">{title}</div>'
        f'<ul style="margin:0;padding-left:18px;font-size:13px;color:{INK}">'
        + "".join(f'<li style="margin:3px 0">{e(item)}</li>' for item in items)
        + "</ul></div>"
    )


def ltm_html(job):
    report = job["result"].get("ltm_report")
    if not report:
        return ""
    rows, changes = [], []
    for category, label in CATEGORIES.items():
        if category not in report:
            continue
        data = report[category]
        rows.append(
            [
                e(label),
                e(f"{data['before']['up']} of {data['before']['total']} up"),
                e(f"{data['after']['up']} of {data['after']['total']} up"),
                e(f"{data['unchanged_percent']:g}%"),
            ]
        )
        for change in data["changes"][:MAX_CHANGES]:
            colour = "#a40e26" if change["change"] in ("went down", "removed") else INK
            changes.append(
                [
                    e(label),
                    e(change["object"]),
                    f'<span style="color:{colour};font-weight:600;white-space:nowrap">{e(change["change"])}</span>',
                    e(change["before"] or "—"),
                    e(change["after"] or "—"),
                ]
            )
        if len(data["changes"]) > MAX_CHANGES:
            more = len(data["changes"]) - MAX_CHANGES
            changes.append([e(label), e(f"{more} more in the job record"), "", "", ""])
    body = table(["Category", "Before", "After", "Unchanged"], rows)
    if changes:
        body += (
            f'<p style="margin:12px 0 6px;font-size:13px;color:{MUTED}">Objects whose state changed '
            "between the pre-upgrade and final snapshots:</p>"
            + table(["Category", "Object", "Change", "Before", "After"], changes, mono=(1,))
        )
    else:
        body += f'<p style="margin:8px 0 0;font-size:13px;color:{MUTED}">No virtual server, pool, node or virtual address changed state.</p>'
    return heading("Traffic objects") + body


def page(title, subtitle, status, body, footer, preheader):
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light"><title>{e(title)}</title></head>
<body style="margin:0;padding:0;background:#f6f8fa;font-family:{FONT};color:{INK}">
<div style="display:none;max-height:0;overflow:hidden;opacity:0">{e(preheader)}</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f6f8fa">
<tr><td align="center" style="padding:24px 12px">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:720px;background:#ffffff;border:1px solid {LINE};border-radius:8px">
<tr><td style="padding:24px 28px 8px">
<div style="font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:{MUTED};font-weight:600">NetOps Executor</div>
<h1 style="margin:6px 0 4px;font-size:22px;line-height:1.3;color:{INK}">{e(title)}</h1>
<div style="font-size:14px;color:{MUTED};margin-bottom:10px">{e(subtitle)}</div>
{pill(status)}
</td></tr>
<tr><td style="padding:4px 28px 24px">{body}</td></tr>
<tr><td style="padding:14px 28px;border-top:1px solid {LINE};font-size:12px;color:{MUTED};background:#f6f8fa;border-radius:0 0 8px 8px">{footer}</td></tr>
</table></td></tr></table></body></html>"""


# Reports


def job_report(job, events, label, generated=None):
    """(subject, text, html) for one finished job."""
    generated = generated or time.time()
    kind = KINDS.get(job["kind"], humanize(job["kind"]))
    device = label(job["device"])
    status = status_label(job["status"]).lower()
    version = software(job)[1] or software(job)[2]
    subject = f"[NetOps] {kind} {status}: {device}" + (f" (to {version.split(' ')[0]})" if version else "")
    rows, notes, steps = facts(job, label), attention(job), timeline(events)

    body = heading("Summary") + fact_table(rows)
    if notes:
        body = callout(notes, job["status"]) + body
    body += ltm_html(job)
    if reviews(job):
        body += heading("Validation reviews") + table(
            ["Phase", "Decision", "Operator", "Reason"], [[e(c) for c in row] for row in reviews(job)]
        )
    if steps:
        body += heading("Timeline") + table(
            ["UTC", "Elapsed", "Step"], [[e(a), e(b), e(c)] for a, b, c in steps], mono=(0, 1)
        )
    footer = (
        f"Job {e(job['id'])} · executor {e(__version__)} · generated {e(when(generated))}<br>"
        f"Full record: GET /api/v1/jobs/{e(job['id'])}"
    )
    html_body = page(kind, device, job["status"], body, footer, f"{device}: {status}")

    text = [subject[len("[NetOps] ") :], "=" * 60, ""]
    if notes:
        text += ["NEEDS ATTENTION" if job["status"] not in PASSED else "NOTES"]
        text += [f"  - {item}" for item in notes] + [""]
    text += [f"{name + ':':<18}{value}" for name, value in [("Status", status_label(job["status"])), *rows]]
    text += ltm_text(job)
    if reviews(job):
        text += ["", "VALIDATION REVIEWS"]
        text += [
            f"  {phase}: {decision} by {who or '-'}" + (f" ({why})" if why else "")
            for phase, decision, who, why in reviews(job)
        ]
    if steps:
        text += ["", "TIMELINE (UTC)"] + [f"  {a}  {b:>9}  {c}" for a, b, c in steps]
    text += ["", f"Job {job['id']} · executor {__version__} · generated {when(generated)}"]
    return subject, "\n".join(text) + "\n", html_body


def ltm_text(job):
    report = job["result"].get("ltm_report")
    if not report:
        return []
    lines = ["", "TRAFFIC OBJECTS"]
    for category, label in CATEGORIES.items():
        if category not in report:
            continue
        data = report[category]
        lines.append(
            f"  {label + ':':<19}{data['before']['up']}/{data['before']['total']} up before, "
            f"{data['after']['up']}/{data['after']['total']} after, {data['unchanged_percent']:g}% unchanged"
        )
        for change in data["changes"][:MAX_CHANGES]:
            lines.append(
                f"    {change['object']}: {change['change']} ({change['before'] or '-'} -> {change['after'] or '-'})"
            )
        if len(data["changes"]) > MAX_CHANGES:
            lines.append(f"    {len(data['changes']) - MAX_CHANGES} more in the job record")
    return lines


def batch_report(batch, jobs, state, label, generated=None):
    """(subject, text, html) for a batch that has finished or stopped. jobs are full job records
    with the batch's wave numbers."""
    generated = generated or time.time()
    status = "completed" if state == "completed" else "needs_attention"
    passed = sum(job["status"] in PASSED for job in jobs)
    waiting = [job for job in jobs if job["status"] == "queued"]
    kind = KINDS.get(batch["kind"], humanize(batch["kind"]))
    subject = (
        f'[NetOps] {kind} batch "{batch["name"]}" '
        f"{'completed' if state == 'completed' else 'needs attention'}: {passed} of {len(jobs)} passed"
    )
    counts = {}
    for job in jobs:
        counts[status_label(job["status"])] = counts.get(status_label(job["status"]), 0) + 1
    started = [job["started_at"] for job in jobs if job.get("started_at")]
    ended = [job["updated"] for job in jobs if finished(job)]
    overview = [
        ("Devices", f"{len(jobs)} in {len(batch['waves'])} wave{'s' if len(batch['waves']) != 1 else ''}"),
        ("Outcome", ", ".join(f"{n} {name.lower()}" for name, n in counts.items())),
    ]
    if started:
        overview.append(("Started", when(min(started))))
    if started and ended:
        overview += [("Finished", when(max(ended))), ("Duration", duration(max(ended) - min(started)))]

    notes = []
    if waiting:
        notes.append(
            f"{len(waiting)} device{'s were' if len(waiting) != 1 else ' was'} not started because an earlier "
            "wave did not pass. Resolve or roll back the failed devices; the batch then continues, or "
            "cancel the devices left."
        )
    body = heading("Summary") + fact_table(overview)
    if notes:
        body = callout(notes, "failed") + body

    wave_rows = []
    for wave in batch["waves"]:
        members = [job for job in jobs if job["wave"] == wave["wave"]]
        wave_rows.append(
            [
                e(wave["wave"]),
                e(len(members)),
                e(sum(job["status"] in PASSED for job in members)),
                e(sum(job["status"] in STOPPED for job in members)),
                e(sum(job["status"] == "queued" for job in members)),
            ]
        )
    body += heading("Waves") + table(["Wave", "Devices", "Passed", "Did not pass", "Not started"], wave_rows)

    device_rows = []
    for job in jobs:
        changed = ltm_changes(job)
        traffic = (
            ("No changes" if not changed else f"{changed} changed")
            if job["result"].get("ltm_report")
            else "—"
        )
        notes_for = attention(job)
        device_rows.append(
            [
                e(label(job["device"])),
                e(job["wave"]),
                pill(job["status"]),
                e(software_text(job, short=True) or "—"),
                e(
                    duration(job["updated"] - job["started_at"])
                    if job.get("started_at") and finished(job)
                    else "—"
                ),
                e(traffic),
                e(f"{len(notes_for)} below" if notes_for else "—"),
            ]
        )
    body += heading("Devices") + table(
        ["Device", "Wave", "Status", "Software", "Duration", "Traffic objects", "Notes"], device_rows
    )

    detailed = [job for job in jobs if attention(job) or ltm_changes(job)]
    for job in detailed[:MAX_DETAILS]:
        body += (
            f'<h3 style="margin:24px 0 6px;font-size:14px;color:{INK}">{e(label(job["device"]))} '
            f"&nbsp;{pill(job['status'])}</h3>"
        )
        if software_text(job):
            body += f'<div style="font-size:13px;color:{MUTED}">{e(software_text(job))}</div>'
        if attention(job):
            body += callout(attention(job), job["status"])
        body += ltm_html(job).replace(heading("Traffic objects"), "")
    if len(detailed) > MAX_DETAILS:
        body += f'<p style="font-size:13px;color:{MUTED}">{len(detailed) - MAX_DETAILS} more devices with notes are in the batch record.</p>'

    footer = (
        f"Batch {e(batch['id'])} · executor {e(__version__)} · generated {e(when(generated))}<br>"
        f"Full record: GET /api/v1/upgrade-batches/{e(batch['id'])}"
    )
    html_body = page(f"{kind} batch", batch["name"], status, body, footer, subject[len("[NetOps] ") :])

    text = [subject[len("[NetOps] ") :], "=" * 60, ""]
    if notes:
        text += ["NEEDS ATTENTION"] + [f"  - {item}" for item in notes] + [""]
    text += [f"{name + ':':<18}{value}" for name, value in overview] + ["", "DEVICES"]
    for job in jobs:
        text.append(
            f"  wave {job['wave']}  {label(job['device'])}: {status_label(job['status'])}"
            + (f", {software_text(job)}" if software_text(job) else "")
        )
        text += [f"      - {item}" for item in attention(job)]
        if ltm_changes(job):
            text += ["    " + line for line in ltm_text(job)[2:]]
    text += ["", f"Batch {batch['id']} · executor {__version__} · generated {when(generated)}"]
    return subject, "\n".join(text) + "\n", html_body


# Delivery


def message(sender, recipients, subject, text, html_body, headers=None):
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    # Device and batch names come from requests; keep the subject on one line.
    msg["Subject"] = re.sub(r"[\x00-\x1f\x7f]+", " ", subject)[:240]
    msg["Date"] = formatdate(usegmt=True)
    msg["Message-ID"] = make_msgid(domain=parseaddr(sender)[1].rpartition("@")[2])
    msg["Auto-Submitted"] = "auto-generated"
    for name, value in (headers or {}).items():
        msg[name] = value
    msg.set_content(text)
    msg.add_alternative(html_body, subtype="html")
    return msg


class EmailSender:
    def __init__(self, settings, store, connect=None):
        self.settings, self.store = settings, store
        self.connect = connect or self.smtp
        # While the relay is failing, wait out the backoff instead of trying every queued report.
        self.paused_until = 0

    def smtp(self):
        s = self.settings
        context = ssl.create_default_context(cafile=str(s.smtp_ca_file) if s.smtp_ca_file else None)
        if s.smtp_security == "ssl":
            client = smtplib.SMTP_SSL(s.smtp_host, s.smtp_port, timeout=30, context=context)
        else:
            client = smtplib.SMTP(s.smtp_host, s.smtp_port, timeout=30)
        try:
            if s.smtp_security == "starttls":
                client.starttls(context=context)
            if s.smtp_username:
                client.login(s.smtp_username, s.smtp_password)
        except BaseException:
            client.close()
            raise
        return client

    def send(self, msg):
        """Returns the recipients the relay refused while accepting the others."""
        client = self.connect()
        try:
            refused = client.send_message(msg)
        except smtplib.SMTPRecipientsRefused as exc:
            codes = [code for code, _ in exc.recipients.values()]
            if all(code >= 500 for code in codes):
                raise Permanent("all recipients refused: " + ", ".join(sorted(exc.recipients))) from None
            raise
        except (smtplib.SMTPSenderRefused, smtplib.SMTPDataError) as exc:
            if exc.smtp_code >= 500:
                raise Permanent(f"{type(exc).__name__} {exc.smtp_code}") from None
            raise
        finally:
            try:
                client.quit()
            except (smtplib.SMTPException, OSError):
                client.close()
        return sorted(refused)

    def label(self, device):
        for item in self.settings.devices.values():
            if device in (item.id, item.host) and item.id != item.host:
                return f"{item.id} ({item.host})"
        return device

    def build(self, delivery):
        """(message, status) to send, or the reason to skip the delivery."""
        if delivery["kind"] == "job":
            job = self.store.get(delivery["subject"])
            recipients = job["request"].get("notify_email")
            if not recipients:
                return "no notify_email"
            if self.store.email_last_sent("job", job["id"]) == job["status"]:
                return "already reported"
            subject, text, html_body = job_report(job, self.store.milestones(job["id"]), self.label)
            headers = {"X-NetOps-Job": job["id"], "X-NetOps-Status": job["status"]}
            return message(self.settings.smtp_from, recipients, subject, text, html_body, headers), job[
                "status"
            ]
        batch = self.store.batch(delivery["subject"])
        recipients = batch.get("notify_email")
        if not recipients:
            return "no notify_email"
        state = batch_state(batch["jobs"])
        if state is None:
            return "batch still running"
        mark = digest(batch["jobs"])
        if self.store.email_last_sent("batch", batch["id"]) == mark:
            return "already reported"
        waves = {job["id"]: job["wave"] for job in batch["jobs"]}
        jobs = [{**self.store.get(job["id"]), "wave": waves[job["id"]]} for job in batch["jobs"]]
        subject, text, html_body = batch_report(batch, jobs, state, self.label)
        headers = {"X-NetOps-Batch": batch["id"], "X-NetOps-Status": state}
        return message(self.settings.smtp_from, recipients, subject, text, html_body, headers), mark

    def deliver_due(self, now=None, limit=20):
        now = time.time() if now is None else now
        if now < self.paused_until:
            return 0
        sent = 0
        for due in self.store.email_due(now, limit):
            delivery = self.store.email_attempt(due["id"], now)
            if delivery is None:
                continue
            delay = min(MAX_BACKOFF, 30 * 2 ** (delivery["attempts"] - 1))
            try:
                built = self.build(delivery)
            except Exception as exc:
                # A report that cannot be built is this delivery's problem, not the relay's.
                self.store.email_failed(delivery["id"], "report: " + type(exc).__name__, now + delay)
                continue
            if isinstance(built, str):
                self.store.email_done(delivery["id"], "skipped", now, error=built)
                continue
            msg, status = built
            try:
                refused = self.send(msg)
            except Permanent as exc:
                self.store.email_failed(delivery["id"], str(exc), now + delay, permanent=True)
                continue
            except (smtplib.SMTPException, OSError) as exc:
                code = getattr(exc, "smtp_code", None)
                self.store.email_failed(
                    delivery["id"], type(exc).__name__ + (f" {code}" if code else ""), now + delay
                )
                self.paused_until = now + delay
                break
            error = "refused: " + ", ".join(refused) if refused else None
            self.store.email_done(delivery["id"], "delivered", time.time(), status=status, error=error)
            sent += 1
        return sent

    def test(self, recipients):
        body = (
            f"This is a test message from NetOps Executor {__version__}. "
            "Job and batch reports will arrive from this address."
        )
        html_body = page(
            "SMTP test",
            f"{self.settings.smtp_host}:{self.settings.smtp_port} ({self.settings.smtp_security})",
            "succeeded",
            f'<p style="font-size:14px">{e(body)}</p>',
            f"executor {e(__version__)} · {e(when(time.time()))}",
            body,
        )
        msg = message(self.settings.smtp_from, recipients, "[NetOps] SMTP test", body + "\n", html_body)
        return self.send(msg)

    def run(self, stop):
        while not stop.is_set():
            try:
                sent = self.deliver_due()
            except Exception:
                # A database or report error must not end delivery for the life of the API.
                sent = 0
            stop.wait(0 if sent else 5)
