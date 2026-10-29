"use strict";
const $ = (id) => document.getElementById(id);
let selectedJob = null,
  jsonPending = "",
  jsonKey = "",
  token = "",
  selected = null,
  polling = false,
  pendingBody = "",
  pendingKey = "";
const bools = [
  "transfer",
  "install",
  "reboot",
  "create_ucs",
  "ucs_unencrypted",
  "images_on_device",
  "drain",
  "reboot_on_drain_timeout",
];
const numbers = [
  "drain_connections",
  "drain_percent",
  "drain_timeout",
  "install_timeout",
  "reboot_timeout",
  "validation_timeout",
];
function message(text, error = false) {
  $("message").textContent = text;
  $("message").className = error ? "error" : "";
}
async function api(path, method = "GET", body, key) {
  const headers = {
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
  };
  if (key) headers["Idempotency-Key"] = key;
  const r = await fetch("api/v1/" + path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!r.ok) {
    const error = await r.json();
    throw new Error(JSON.stringify(error.detail));
  }
  return r.json();
}
function request() {
  const r = {
    device: $("device").value,
    images: JSON.parse($("images").value),
    allowed_source_versions: $("allowed_source_versions")
      .value.split(",")
      .map((x) => x.trim())
      .filter(Boolean),
  };
  bools.forEach((k) => (r[k] = $(k).checked));
  numbers.forEach((k) => {
    if ($(k).value !== "") r[k] = Number($(k).value);
  });
  [
    "target_volume",
    "expected_version",
    "expected_build",
    "backup_directory",
  ].forEach((k) => {
    if ($(k).value.trim()) r[k] = $(k).value.trim();
  });
  if ($("credential_profiles").value.trim())
    r.credential_profiles = $("credential_profiles")
      .value.split(",")
      .map((x) => x.trim())
      .filter(Boolean);
  return r;
}
async function refresh() {
  if (!token || polling) return;
  polling = true;
  try {
    const jobs = await api("jobs");
    $("jobs").replaceChildren();
    if (!jobs.length)
      $("jobs").textContent =
        "No jobs yet. Preview a job to see its inherited steps.";
    jobs.forEach((j) => {
      const b = document.createElement("button");
      b.className = "job";
      const title = document.createElement("strong");
      title.textContent = `${j.device} · ${j.kind}`;
      const detail = document.createElement("span");
      detail.className = "status";
      detail.textContent = `${j.status.replaceAll("_", " ")} · ${new Date(j.created * 1000).toLocaleString()} · ${j.id.slice(0, 8)}`;
      b.append(title, detail);
      b.onclick = async () => {
        try {
          await select(j.id);
          $("detail").scrollIntoView({ behavior: "smooth" });
        } catch (e) {
          message(e.message, true);
        }
      };
      $("jobs").append(b);
    });
    const [batches, workers, credentials] = await Promise.all([
      api("upgrade-batches"),
      api("workers"),
      api("credentials"),
    ]);
    $("batches").replaceChildren();
    batches.forEach((batch) => {
      const button = document.createElement("button");
      button.className = "job";
      button.textContent = `${batch.name} · ${batch.status} · ${batch.device_count} devices`;
      button.onclick = async () => {
        try {
          $("batch-report").textContent = JSON.stringify(
            await api("upgrade-batches/" + batch.id),
            null,
            2,
          );
        } catch (e) {
          message(e.message, true);
        }
      };
      $("batches").append(button);
    });
    $("workers").textContent = JSON.stringify(workers, null, 2);
    $("credentials").textContent = JSON.stringify(credentials, null, 2);
    if (selected) await select(selected);
  } catch (e) {
    message(e.message, true);
  } finally {
    polling = false;
  }
}
async function select(id) {
  selected = id;
  const j = await api("jobs/" + id),
    events = await api("jobs/" + id + "/events?limit=1000");
  if (selected !== id) return;
  selectedJob = j;
  $("detail").hidden = false;
  $("detail-title").textContent = j.device + " · " + j.kind;
  $("detail-status").textContent =
    j.status +
    (j.lock_held ? " (device/group locked)" : "") +
    " · " +
    j.id +
    (j.result.error ? " · " + j.result.error : "");
  $("cancel").disabled = !["queued", "running", "needs_review"].includes(
    j.status,
  );
  const gate = j.validation_gates?.findLast((g) => g.state === "open");
  $("gate-summary").textContent = gate
    ? `Waiting for ${gate.phase} · revision ${gate.revision}`
    : "No validation decision is pending.";
  $("accept-validation").disabled = $("retry-validation").disabled =
    !gate || j.status !== "needs_review";
  $("mark-done").disabled = [
    "succeeded",
    "completed_with_warnings",
    "manually_completed",
  ].includes(j.status);
  $("resolve").disabled =
    !j.lock_held ||
    !["recovery_required", "failed", "manually_completed"].includes(j.status);
  $("credential-summary").textContent =
    `Credentials used: ${(j.credential_summary?.profiles_used || []).join(", ") || "none recorded"}${j.credential_summary?.multiple_profiles_used ? " · Multiple profiles were used; inspect the credential audit in the report." : ""}`;
  $("rollback").disabled =
    !j.result.rollback ||
    ![
      "succeeded",
      "completed_with_warnings",
      "failed",
      "resolved",
      "recovery_required",
      "manually_completed",
    ].includes(j.status);
  $("backup").disabled = !j.result.backup;
  $("report").textContent = JSON.stringify(j, null, 2);
  $("events").textContent = events
    .map(
      (e) =>
        `${new Date(e.time * 1000).toLocaleTimeString()}  ${e.step}  ${JSON.stringify(e.data)}`,
    )
    .join("\n");
  $("counts").replaceChildren();
  const table = document.createElement("table");
  const rows = [["Validation", "Before (up / total)", "After (up / total)"]];
  for (const [key, label] of [
    ["virtual_servers", "Virtual servers"],
    ["pools", "Pools"],
    ["nodes", "Nodes"],
    ["virtual_ips", "Virtual IPs"],
  ]) {
    const format = (s) => (s?.[key] ? `${s[key].up} / ${s[key].total}` : "—");
    rows.push([
      label,
      format(j.result.pre_validation),
      format(j.result.post_validation),
    ]);
  }
  rows.push([
    "WAF policies",
    j.result.pre_validation?.waf_policies ?? "—",
    j.result.post_validation?.waf_policies ?? "—",
  ]);
  rows.forEach((row, i) => {
    const tr = document.createElement("tr");
    row.forEach((v) => {
      const td = document.createElement(i ? "td" : "th");
      td.textContent = v;
      tr.append(td);
    });
    table.append(tr);
  });
  $("counts").append(table);
}
$("auth").onsubmit = async (e) => {
  e.preventDefault();
  token = $("token").value;
  try {
    const ds = await api("devices");
    $("inventory").replaceChildren();
    ds.forEach((d) => {
      const o = document.createElement("option");
      o.value = d.id;
      o.textContent = d.id + " · " + d.host;
      $("inventory").append(o);
    });
    $("token").value = "";
    $("login").hidden = true;
    $("workspace").hidden = false;
    message("Connected");
    await refresh();
  } catch (err) {
    token = "";
    message(err.message, true);
  }
};
$("preview").onclick = async () => {
  try {
    $("plan").textContent = JSON.stringify(
      await api("plan", "POST", request()),
      null,
      2,
    );
    message("Plan only: no device commands executed.");
  } catch (e) {
    message(e.message, true);
  }
};
$("new-job").onsubmit = async (e) => {
  e.preventDefault();
  const button = e.submitter;
  button.disabled = true;
  try {
    const body = request(),
      serialized = JSON.stringify(body);
    if (serialized !== pendingBody) {
      pendingBody = serialized;
      pendingKey = crypto.randomUUID();
    }
    const j = await api("jobs", "POST", body, pendingKey);
    pendingBody = "";
    pendingKey = "";
    selected = j.id;
    message("Job queued: " + j.id);
    await refresh();
  } catch (err) {
    message(err.message, true);
  } finally {
    button.disabled = false;
  }
};
$("refresh").onclick = refresh;
$("cancel").onclick = async () => {
  try {
    await api("jobs/" + selected + "/cancel", "POST", {});
    await refresh();
  } catch (e) {
    message(e.message, true);
  }
};
$("rollback").onclick = async () => {
  if (
    !confirm("Reboot this device to the original volume recorded by this job?")
  )
    return;
  try {
    const j = await api(
      "jobs/" + selected + "/rollback",
      "POST",
      { worker_stopped: $("worker-stopped").checked },
      "rollback-" + selected,
    );
    selected = j.id;
    message("Rollback queued");
    await refresh();
  } catch (e) {
    message(e.message, true);
  }
};
$("backup").onclick = async () => {
  try {
    const r = await fetch("api/v1/jobs/" + selected + "/backup", {
      headers: { Authorization: "Bearer " + token },
    });
    if (!r.ok) throw new Error("Backup download failed");
    const url = URL.createObjectURL(await r.blob());
    const a = document.createElement("a");
    a.href = url;
    a.download =
      (r.headers.get("content-disposition") || "").match(/filename="?([^";]+)/)?.[1] ||
      selected + ".ucs";
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (e) {
    message(e.message, true);
  }
};
setInterval(refresh, 5000);

const examples = {
  "upgrade-batches": {
    name: "Change123",
    defaults: {
      install: true,
      reboot: true,
      allowed_source_versions: ["16.1.5"],
      images: [
        {
          name: "BIGIP-target.iso",
          sha256: "REPLACE_WITH_SHA256",
          kind: "image",
          version: "17.1.2",
          build: "0.0.5",
        },
      ],
      standalone_drain: {
        enabled: true,
        remaining_connections: 100,
        timeout_seconds: 600,
      },
      validation_policy: {
        noncritical_differences: "warn",
        on_timeout: "needs_review",
      },
    },
    waves: [
      { wave: 1, upgrade_at_a_time: 2, ips: ["192.0.2.10", "192.0.2.11"] },
      { wave: 2, upgrade_at_a_time: 1, ips: ["192.0.2.12"] },
    ],
  },
  "panos/upgrade-batches": {
    name: "Change456",
    defaults: {
      panorama: "panorama",
      target_version: "11.1.6-h3",
      allowed_source_versions: ["10.2.9-h1", "10.2.10-h2"],
      validation_policy: { on_timeout: "needs_review" },
    },
    waves: [
      { wave: 1, upgrade_at_a_time: 2, serials: ["007951000123456", "007951000123457"] },
      { wave: 2, upgrade_at_a_time: 20, serials: ["007951000123458"] },
    ],
  },
  "panos/jobs": {
    serial: "007951000123456",
    panorama: "panorama",
    target_version: "11.1.6-h3",
    allowed_source_versions: ["10.2.9-h1"],
    f5_drain: { device: "192.0.2.51", remaining_connections: 50 },
  },
  "eos/upgrade-batches": {
    name: "Change789",
    defaults: {
      target_version: "4.32.2F",
      allowed_source_versions: ["4.30.5M", "4.31.3M"],
      image: { name: "EOS-4.32.2F.swi", sha256: "REPLACE_WITH_SHA256" },
    },
    overrides: { "192.0.2.31": { mlag_peer: "192.0.2.32" } },
    waves: [
      { wave: 1, upgrade_at_a_time: 1, devices: ["192.0.2.31"] },
      { wave: 2, upgrade_at_a_time: 10, devices: ["192.0.2.32", "192.0.2.33"] },
    ],
  },
  "eos/jobs": {
    device: "192.0.2.31",
    target_version: "4.32.2F",
    allowed_source_versions: ["4.30.5M"],
    image: { name: "EOS-4.32.2F.swi", sha256: "REPLACE_WITH_SHA256" },
  },
  "iosxe/upgrade-batches": {
    name: "Change790",
    defaults: {
      target_version: "17.12.6",
      allowed_source_versions: ["17.9.5", "17.12.4"],
      image: {
        name: "cat9k_iosxe.17.12.06.SPA.bin",
        sha256: "REPLACE_WITH_SHA256",
      },
      config_policy: {
        ignore: [{ name: "site-exec-banner", line: "^banner exec " }],
        removed: "warn",
      },
    },
    overrides: { "192.0.2.41": { peers: ["192.0.2.42"] } },
    waves: [
      { wave: 1, upgrade_at_a_time: 1, devices: ["192.0.2.41"] },
      { wave: 2, upgrade_at_a_time: 10, devices: ["192.0.2.42", "192.0.2.43"] },
    ],
  },
  "iosxe/jobs": {
    device: "192.0.2.41",
    target_version: "17.12.6",
    allowed_source_versions: ["17.9.5"],
    image: { name: "cat9k_iosxe.17.12.06.SPA.bin", sha256: "REPLACE_WITH_SHA256" },
  },
  "iosxe/config-compare": {
    before: "PASTE show running-config FROM BEFORE THE UPGRADE",
    after: "PASTE show running-config FROM AFTER THE UPGRADE",
    config_policy: { ignore: [], rewrite: [] },
  },
  "ssh/jobs": {
    device: "192.0.2.10",
    device_type: "cisco_ios",
    commands: [{ command: "show version", timeout_seconds: 60 }],
  },
  "http/jobs": {
    target: "panorama",
    requests: [
      {
        method: "POST",
        path: "/api/",
        form: {
          type: "op",
          target: "FIREWALL_SERIAL",
          cmd: "<show><system><info/></system></show>",
        },
      },
    ],
  },
  "snmp/walks": { device_ip: "192.0.2.10", oids: ["1.3.6.1.2.1.1"] },
};
$("json-example").onclick = () => {
  $("json-body").value = JSON.stringify(
    examples[$("json-kind").value],
    null,
    2,
  );
};
$("json-submit").onsubmit = async (e) => {
  e.preventDefault();
  const button = e.submitter;
  button.disabled = true;
  try {
    const body = JSON.parse($("json-body").value),
      path = $("json-kind").value,
      signature = path + JSON.stringify(body);
    if (signature !== jsonPending) {
      jsonPending = signature;
      jsonKey = crypto.randomUUID();
    }
    const result = await api(path, "POST", body, jsonKey);
    $("json-result").textContent = JSON.stringify(result, null, 2);
    jsonPending = "";
    jsonKey = "";
    if (!path.endsWith("upgrade-batches")) selected = result.id;
    message("Queued: " + result.id);
    await refresh();
  } catch (err) {
    message(err.message, true);
  } finally {
    button.disabled = false;
  }
};
async function decision(action) {
  if (!$("operator-controls").reportValidity()) return;
  try {
    const gate = selectedJob.validation_gates.findLast(
      (g) => g.state === "open",
    );
    await api(
      "jobs/" + selected + "/validation-decisions",
      "POST",
      {
        action,
        gate_id: gate.id,
        validation_revision: gate.revision,
        operator: $("operator").value,
        reason: $("reason").value,
      },
      gate.id + "-" + action,
    );
    message("Decision saved; a worker will apply it.");
    await refresh();
  } catch (e) {
    message(e.message, true);
  }
}
$("accept-validation").onclick = () => decision("accept");
$("retry-validation").onclick = () => decision("retry");
$("mark-done").onclick = async () => {
  if (!$("operator-controls").reportValidity()) return;
  try {
    await api("jobs/" + selected + "/mark-done", "POST", {
      operator: $("operator").value,
      reason: $("reason").value,
    });
    message(
      "Completion recorded. A running worker must acknowledge cancellation; unresolved reservations remain held.",
    );
    await refresh();
  } catch (e) {
    message(e.message, true);
  }
};
$("resolve").onclick = async () => {
  if (!$("operator-controls").reportValidity()) return;
  if (!$("worker-stopped").checked) {
    message(
      "Confirm the worker is stopped and the device inspected before releasing recovery.",
      true,
    );
    return;
  }
  try {
    await api("jobs/" + selected + "/resolve", "POST", {
      worker_stopped: true,
      device_inspected: true,
      note: $("operator").value + ": " + $("reason").value,
    });
    await refresh();
  } catch (e) {
    message(e.message, true);
  }
};

$("operator-controls").onsubmit = (e) => e.preventDefault();
