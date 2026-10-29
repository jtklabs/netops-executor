# NetOps Executor

A standalone remote for a central controller, with a versioned API, web console,
CLI and durable SQLite queue. It runs F5 upgrades over **SSH/SFTP only**, PAN-OS
firewall upgrades through **Panorama's XML API**, Arista EOS, Cisco IOS XE
(Catalyst 9300, 9350, 3650 and 3850) and classic IOS (Catalyst 2960-X/2960-XR) switch
upgrades over **SSH**, arbitrary SSH commands, HTTPS
requests (including Panorama requests targeting a firewall), asynchronous SNMP v3
walks, and Nmap SSH/HTTPS cipher scans. It has no NetBox dependency.

The main application submits jobs and polls their results. F5 and PAN-OS upgrade
sequencing, reconnection, HA checks, backups and validation live on the remote.
For generic commands, the main application interprets the returned output and
submits a **separate** remediation job, optionally linked with `parent_job_id`.

API and worker processes share one local SQLite database, image cache, backup
root and credential keyring. Scale workers on **one host** with Docker or systemd.
SQLite WAL must not be placed on NFS/SMB or shared between hosts. Separate remotes
have independent reservations: the central application must assign an entire HA
pair/batch to one remote and prevent overlap across remotes.

## API contract

All `/api/v1` routes require `Authorization: Bearer <NETOPS_API_TOKEN>`. The token
is a shared service identity loaded from `.env` or the service environment.
`/docs` and `/openapi.json` expose the schema; `/healthz` reports API availability.
`GET /api/v1/workers` reports worker heartbeats separately. The web console at `/`
keeps the token only in tab memory and uses the same API.

| Method | Endpoint | Purpose |
| --- | --- | --- |
| GET | `/api/v1/devices` | Optional inventory IDs and connection addresses |
| POST | `/api/v1/plan` | Normalize a single upgrade and show inherited steps without device access |
| POST | `/api/v1/jobs` | Queue one F5 upgrade/backup/validation job |
| POST | `/api/v1/upgrade-batches` | Queue ordered waves with per-wave concurrency |
| GET | `/api/v1/upgrade-batches` or `/{id}` | F5 or PAN-OS batch membership, wave progress and item results |
| POST | `/api/v1/panos/plan` | Normalize a PAN-OS upgrade and show its steps without device access |
| POST | `/api/v1/panos/jobs` | Queue one PAN-OS firewall upgrade through Panorama |
| POST | `/api/v1/panos/upgrade-batches` | Queue ordered PAN-OS waves by serial with per-wave concurrency |
| POST | `/api/v1/eos/plan` | Normalize an Arista EOS upgrade and show its steps without device access |
| POST | `/api/v1/eos/jobs` | Queue one Arista EOS switch upgrade |
| POST | `/api/v1/eos/upgrade-batches` | Queue ordered EOS waves by inventory ID or IP with per-wave concurrency |
| POST | `/api/v1/iosxe/plan` | Normalize a Cisco IOS XE upgrade and show its steps without device access |
| POST | `/api/v1/iosxe/jobs` | Queue one Cisco IOS XE switch or stack upgrade |
| POST | `/api/v1/iosxe/upgrade-batches` | Queue ordered IOS XE waves by inventory ID or IP with per-wave concurrency |
| POST | `/api/v1/iosxe/config-compare` | Compare two running configurations the way IOS XE validation does |
| POST | `/api/v1/ios/plan` | Normalize a Catalyst 2960-X classic IOS upgrade and show its steps without device access |
| POST | `/api/v1/ios/jobs` | Queue one Catalyst 2960-X switch or stack upgrade |
| POST | `/api/v1/ios/upgrade-batches` | Queue ordered 2960-X waves by inventory ID or IP with per-wave concurrency |
| POST | `/api/v1/ssh/jobs` | Queue one or more SSH commands |
| POST | `/api/v1/http/jobs` | Queue one or more HTTPS requests |
| GET | `/api/v1/http/targets` | Configured HTTP targets |
| POST | `/api/v1/cipher-scans` | Queue a single-IP SSH/HTTPS cipher scan |
| GET | `/api/v1/cipher-scans/{id}` | Scan status, structured cipher data and readable output |
| POST | `/api/v1/snmp/walks` | Queue SNMP v3 OID subtree walks |
| GET | `/api/v1/snmp/walks/{id}` | Walk status and per-root progress |
| GET | `/api/v1/snmp/walks/{id}/results?after=0&limit=500` | Paginated partial/final rows |
| GET | `/api/v1/jobs?limit=100&offset=0` or `/jobs/{id}` | Jobs and full results/credential audit |
| GET | `/api/v1/jobs/{id}/events?after=0&limit=500` | Ordered events; advance cursor to last `seq` |
| GET | `/api/v1/jobs/{id}/backup` | Download completed UCS backup (or the first PAN-OS config backup) |
| GET | `/api/v1/jobs/{id}/artifacts/{name}` | Download a saved PAN-OS running config or tech support file |
| POST | `/api/v1/jobs/{id}/cancel` | Durable cancellation request |
| POST | `/api/v1/jobs/{id}/validation-decisions` | Accept/retry a particular validation gate |
| POST | `/api/v1/jobs/{id}/mark-done` | Manually complete an item for the wave barrier |
| POST | `/api/v1/jobs/{id}/rollback` | Reboot to the original recorded volume |
| POST | `/api/v1/jobs/{id}/resolve` | Release an inspected recovery reservation |
| GET | `/api/v1/credentials` | Credential metadata only |
| PUT | `/api/v1/credentials/{profile}` | Idempotent full replacement/upsert |
| POST | `/api/v1/credentials/rotate` | Re-encrypt records using the first key in the keyring |

Job creation returns HTTP `202` with an `id`, `kind`, `status`, normalized
`request`, `result`, `lock_held`, credential audit and validation gates. Poll
`GET /api/v1/jobs/{id}`. Batch creation returns a batch ID and `status_url`, child
job IDs, wave progress and item statuses. No synchronous device work occurs in
API handlers.

Use a durable, unique `Idempotency-Key` for each submission, batch, rollback or
validation decision. Reuse the **same key and body** after a lost API response.
A conflicting reuse returns `409`. Invalid input is `422`, missing resources
`404`, and invalid authentication `401`. Validation errors exclude submitted
values so malformed credential requests do not echo passwords.

Terminal job states are `succeeded`, `completed_with_warnings`, `failed`,
`cancelled`, `expired`, `recovery_required`, `resolved` and `manually_completed`.
`needs_review` waits for an operator decision; it is not completion.
`queued` and `running` need continued polling. A terminal state may still hold
reservations: inspect `lock_held`. Batch `needs_attention` requires action on its
items; `completed` means every item passed its wave barrier.

## Job start windows

Every job submission accepts optional `start_at` and `latest_start_at`, including
F5 jobs, rollback requests, SSH commands, HTTP requests, SNMP walks and cipher
scans. For example, `POST /api/v1/cipher-scans`:

```json
{
  "device_ip": "192.0.2.10",
  "protocol": "https",
  "port": 8443,
  "start_at": "2026-11-01T02:00:00Z",
  "latest_start_at": "2026-11-01T04:00:00Z"
}
```

- `start_at` is the earliest allowed start. Omitted, null or in the past means
  eligible as soon as a worker and the required resources are available.
- `latest_start_at` is the latest allowed start, inclusive. Omitted or null means
  no start deadline. If an unstarted job misses it, the job becomes `expired`,
  with `result.error_code: "start_window_expired"` and an event of the same name.
  A request with an already-past deadline is accepted as an expired job and never
  dispatched. Past `start_at` alone does not expire a job.
- Use ISO 8601 timestamps with `Z` or an explicit UTC offset, such as
  `2026-11-01T02:00:00-05:00`. The API normalizes them to UTC. Dates without a time,
  timezone-free timestamps and numeric Unix inputs are rejected. If both are
  supplied, `latest_start_at` must be at or after `start_at`; otherwise `422`.

These are queue admission windows, not execution or completion deadlines.
Workers poll for eligible jobs; exact-time dispatch is not guaranteed. A future
job stays `queued`, holds no device reservation and does not block other ready
jobs. At claim, the worker admits the job and records `started_at` as Unix
seconds, matching the existing `created`/`updated` format. Jobs also expose the
normalized `start_at` and `latest_start_at` at the response top level. Start
windows are checked atomically with worker claims and persist across restarts.
A reservation attempt that defers before work clears `started_at` and is subject
to the window again. F5 HA discovery can occur during that attempt. Actual
commands and reboot may occur later within an admitted workflow.

Once started, crossing `latest_start_at` does not cancel or interrupt a job.
An operator's manual-validation continuation retains the original start and can
resume after the deadline. Runtime timeout and cancellation controls continue to
apply separately. An expired job can be marked manually done using the existing
endpoint; to actually run it, submit a new job/window with a new idempotency key.
Repeating the original request/key returns its original job, including expiry.

For an upgrade batch, put a shared window at the top level:

```json
{
  "name": "maintenance-window",
  "start_at": "2026-11-01T02:00:00Z",
  "latest_start_at": "2026-11-01T06:00:00Z",
  "defaults": {"create_ucs": true},
  "overrides": {
    "192.0.2.20": {"start_at": "2026-11-01T03:00:00Z"}
  },
  "waves": [
    {"wave": 1, "upgrade_at_a_time": 1, "ips": ["192.0.2.10"]},
    {"wave": 2, "upgrade_at_a_time": 1, "ips": ["192.0.2.20"]}
  ]
}
```

The shared window applies to **each device job**, including later waves.
`defaults` and per-IP `overrides` can set individual windows, but cannot widen
the batch window: the effective earliest start is the later time and the
effective deadline is the earlier time. Empty intersections are rejected.
The normal wave barriers, concurrency limits and HA reservations still apply.
An expired item makes the batch `needs_attention` and blocks later waves until
that item is explicitly marked done; expiry never silently counts as success.

Swagger includes the fields on each submission schema. The CLI `plan`, `submit`
and `rollback` commands accept `--start-at` and `--latest-start-at`; JSON requests
use the same fields. Upgrading from an older release adds nullable scheduling
columns without replacing jobs or credentials. Unscheduled jobs keep their
existing behavior. For legacy jobs already started or completed, `started_at`
is backfilled from `created` because the exact historical start was not stored.
Deploy API and workers together using the existing stop/drain deployment flow;
older workers do not enforce start windows.

## SSH and HTTPS cipher scans

Submit `POST /api/v1/cipher-scans` with the usual bearer token and an optional
`Idempotency-Key`. The API returns `202` with a job ID immediately. Workers run
Nmap locally on the remote; no device login or credential profile is needed.

HTTPS on a nonstandard port, optionally selecting a TLS virtual host:

```json
{
  "device_ip": "192.0.2.10",
  "protocol": "https",
  "port": 8443,
  "server_name": "management.example.com",
  "job_timeout": 300
}
```

SSH with the default port:

```json
{"device_ip": "192.0.2.10", "protocol": "ssh"}
```

`device_ip` accepts one IPv4 or IPv6 address. Hostnames, ranges, arbitrary Nmap
arguments and scripts are not accepted. `protocol` is `ssh` or `https`; omitted
or null `port` becomes 22 or 443 respectively. Any explicit TCP port from 1 to
65535 is allowed for either protocol. `job_timeout` defaults to 300 seconds and
is bounded to 1–3600 seconds. `server_name` is optional and HTTPS-only; it sends
TLS SNI without changing or resolving the target IP. Use ASCII/punycode DNS names.

Poll `GET /api/v1/cipher-scans/{id}` or the generic `GET /api/v1/jobs/{id}`.
While `queued` or `running`, continue polling. The dedicated response schema,
request fields and interactive requests are available under **Cipher scans** in
`/docs`. A successful HTTPS result has this shape (illustrative, abbreviated):

```json
{
  "id": "<job-id>",
  "kind": "cipher_scan",
  "status": "succeeded",
  "result": {
    "nmap_version": "7.95",
    "script": "ssl-enum-ciphers",
    "port_state": "open",
    "data": {
      "TLSv1.2": {
        "ciphers": [
          {"name": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "strength": "A"}
        ],
        "cipher preference": "server"
      },
      "least strength": "A"
    },
    "output": "Human-readable NSE output including any warnings",
    "exit_code": 0,
    "error_code": null,
    "error": null
  }
}
```

`result.data` preserves Nmap's structured script output: SSH algorithm categories
map to arrays, including encryption ciphers, key exchanges, host keys, MACs and
compression. Direction-specific categories remain separate when Nmap reports
different client/server lists. HTTPS results contain protocol-version tables,
cipher objects, preference and any warnings reported by Nmap. Fields and protocol
coverage depend on the installed Nmap version; missing data is not proof that a
protocol or cipher is disabled. Grades come from Nmap, not an application
compliance policy. The main application can evaluate the structured results.

Closed/filtered ports, missing cipher data, tool errors, timeouts and excessive
output produce `failed` with an `error_code` and `error`; they never become a
successful empty assessment. `result.stderr`, `exit_code`, port state and readable
output are retained when available. `succeeded` means enumeration returned cipher
data, not that the configuration is secure or the enumeration is exhaustive.
Cancel with `POST /api/v1/jobs/{id}/cancel`; workers terminate the Nmap process
group. Events use the existing `/api/v1/jobs/{id}/events` endpoint. Scan jobs on
the same IP/port are serialized; different targets can use multiple workers.
A stale scan worker becomes `failed`, releases its scan reservation and is not
automatically retried. Nmap's own host/script deadlines also bound a scan if its
worker is killed abruptly.

Scans use unprivileged TCP connect mode and only the selected
[`ssh2-enum-algos`](https://nmap.org/nsedoc/scripts/ssh2-enum-algos.html) or
[`ssl-enum-ciphers`](https://nmap.org/nsedoc/scripts/ssl-enum-ciphers.html) script.
The script is explicitly forced on the requested port, so a nonstandard port
works without relying on service-name detection. HTTPS cipher enumeration makes
multiple TLS connections. Total captured Nmap output is limited to 4 MiB.
Docker and the Ubuntu 24/RHEL 9 Ansible playbook install the OS `nmap` package
including its NSE scripts; manual installations must install it on every worker.
No root user, raw-socket capability or privileged container is needed.

## Upgrade payload

```json
{
  "name": "Change123",
  "defaults": {
    "install": true,
    "reboot": true,
    "allowed_source_versions": ["16.1.5"],
    "images": [{
      "name": "BIGIP-approved.iso",
      "kind": "image",
      "version": "17.1.2",
      "build": "0.0.5",
      "sha256": "REPLACE_WITH_64_CHARACTER_SHA256"
    }],
    "backup_directory": "Change123",
    "admin_password": {"credential_profile": "f5-admin-standard"},
    "standalone_drain": {
      "enabled": true,
      "remaining_connections": 100,
      "timeout_seconds": 600,
      "reboot_on_timeout": true
    },
    "ha_policy": {
      "allow_active_first": true,
      "require_healthy_peer": true,
      "sync_after_upgrade": true
    },
    "validation_policy": {
      "noncritical_differences": "warn",
      "on_timeout": "needs_review",
      "consecutive_passes": 2,
      "settling_seconds": 30
    },
    "validation_timeout": 600
  },
  "waves": [
    {"wave": 1, "upgrade_at_a_time": 2, "ips": ["192.0.2.10", "192.0.2.11", "192.0.2.12"]},
    {"wave": 2, "upgrade_at_a_time": 1, "ips": ["192.0.2.20", "192.0.2.21"]}
  ],
  "overrides": {
    "192.0.2.12": {"target_volume": "HD1.3", "credential_profiles": ["ssh-local"]}
  }
}
```

Send this to `/api/v1/upgrade-batches`. For a single job, send the defaults plus
`"device":"192.0.2.10"` to `/api/v1/jobs`. Device can be an inventory ID or IP.
Version/build examples are illustrative; your allowlist is the upgrade policy,
not an embedded vendor compatibility database.

Omit `target_volume` to discover a destination: prefer an inactive complete
volume matching the final requested version/build, otherwise reuse the lowest
eligible inactive volume for installation, otherwise create the next volume on
the active disk. A reboot-only request requires a matching existing volume.
The active volume is always preserved as the rollback target. The selected volume
is recorded in `result.target_volume`. Never pass an administrative partition
such as `/Common` as a boot volume.

Omit `credential_profiles` to try all enabled, eligible profiles for that
transport, ordered by `priority` then profile ID. An explicit list restricts the
attempts and establishes their initial order. A connection prefers its last
successful profile on reconnect, then falls back after authentication rejection.
Inventory/HTTP target defaults may restrict the eligible profiles for a target.

| Upgrade option | Behavior/default |
| --- | --- |
| `transfer` | Upload images from `NETOPS_IMAGE_ROOT`; verify SHA-256 and vendor catalog metadata |
| `images` | Ordered `{name,sha256,version,build,kind}`; optional HTTPS `source_url` downloads to local cache |
| `images_on_device` | Skip inherited upload; still verify checksum/metadata |
| `create_ucs` | Save config, create UCS, download and verify size/checksum |
| `ucs_unencrypted` | Implies UCS; no encryption passphrase, private keys remain included |
| `ucs_credential` | Optional UCS passphrase profile; otherwise first eligible UCS profile |
| `backup_directory` | Relative directory beneath `NETOPS_BACKUP_ROOT`; implies UCS |
| `install` | Implies UCS, transfer unless already on device, image checks, installation and configuration copy |
| `reboot` | Implies UCS and configuration copy; verify new boot identity and exact volume/version/build |
| `expected_version`, `expected_build` | Required for reboot-only; inferred from final image when installing |
| `allowed_source_versions` | Required exact running-version allowlist for install/reboot |
| `approved_models` | Optional allowlist matching marketing name or platform ID |
| `license_check_date` | Optional minimum license service-check date, `YYYY-MM-DD` |
| `minimum_free_bytes` | Required free reserve on image filesystem; default 1,500,000,000 bytes |
| `cleanup_images` | Opt-in deletion of catalogued old installers, excluding requested images, if space is insufficient |
| `install_timeout` | Per-image install and configuration-copy timeout; default 3600 seconds |
| `reboot_timeout` | Verified reboot timeout; default 900 seconds |
| `validation_timeout` | Bounded validation window; default 600, maximum 86400 seconds |

The installer reuses an exact final version/build when available. **It always
saves the current configuration and runs `cpcfg --source=<current> <target>`,
including reused volumes.** It requires a verified zero exit status. Copy progress
and its private on-device log directory are recorded. An ambiguous install/copy
is never automatically replayed.

Verified images already on the device skip SFTP upload. HTTPS cache downloads
require SHA-256, verified TLS and no redirects or embedded credentials. A download
is limited to 30 GiB/two hours and committed atomically. SFTP uses a temporary
remote filename and verifies it before rename. Transfer progress includes bytes
and percentage. Installer cleanup never deletes boot volumes.

### Verify and enforce the local admin password

Enable this step by adding `admin_password` to an upgrade request, or to batch
`defaults`. Existing requests that omit this field keep their existing behavior.
Create the expected password profile first through
`PUT /api/v1/credentials/f5-admin-standard`:

```json
{
  "kind": "f5_admin",
  "password": "REPLACE_WITH_EXPECTED_PASSWORD",
  "targets": ["192.0.2.10", "192.0.2.11", "192.0.2.12"]
}
```

This credential is encrypted in the local vault. It is separate from SSH login
profiles and is never tried as a connection credential. Provision or update it
using the existing Ansible credential PUT task with `no_log:true`.

Add the following to your upgrade payload:

```json
{
  "admin_password": {
    "credential_profile": "f5-admin-standard",
    "remediate": true,
    "before": true,
    "after": true
  }
}
```

`remediate`, `before`, and `after` all default to true. Set `remediate:false` for
verification only. At least one stage must be enabled. With `admin_password:{}`,
the highest-priority eligible `f5_admin` profile defines the expected password.
The selected profile ID stays fixed for the job; each check records its current
revision, so an intentional credential update is visible. `targets` restricts
selection to the requested device's inventory ID or address. The expected
password itself is never accepted in an upgrade job payload.

Before an upgrade, check the local `admin` password after device prechecks and
before backup/install/draining. After an upgrade, check again after validation,
traffic restoration and any HA sync. No-reboot jobs check the current runtime
before and after their requested work. Each check reads the local account hash
through SSH and compares it on the worker. A matching password causes no write.
For a confirmed mismatch, set the expected password through tmsh stdin, save the
configuration, then read back and verify. This avoids process-argument exposure
and does not require enabling SSH access for the admin account.

The SSH account must be permitted to view and modify local user accounts.
If the worker logs in as `admin`, keep its separate SSH login profile aligned
with the expected password so it can reconnect after a reset or reboot.
Supported hashes are SHA-256 Crypt (`$5$`) and SHA-512 Crypt (`$6$`), up to one
million rounds. Missing profiles/accounts, inaccessible hashes and unsupported
formats open a `needs_review` gate without a blind reset. A mismatch remaining
after reset also opens a gate. An interrupted password write or save requires
recovery inspection and is never automatically replayed.

The local admin account is synchronized HA configuration, so a reset leaves the
pair `Changes Pending`. When both members run the same version/build and the
pair was in sync before the reset, the job syncs from the reset member and waits
for `In Sync` before failover or completion. Otherwise the check records
`config_sync` as deferred (mixed versions; the post-upgrade sync carries it) or
skipped (other changes were already pending).

Poll the normal job endpoint. `result.admin_password` includes account, selected
profile, and a chronological `checks` list with stage, timestamp, profile revision,
`status`, `initial_match`, `reset_attempted` and `remediated`. Statuses include `matched`, `mismatch`,
`unavailable`, `unverifiable`, and in-progress `checking` / `remediating`. Passwords
and hashes are excluded from results and events. A successful reset has
`status:matched`, `initial_match:false`, `reset_attempted:true`, and
`remediated:true`. A reset attempt that cannot be verified never reports
`remediated:true`.

The existing validation-decision endpoint handles gates named
`admin_password_before` and `admin_password_after`. `retry` rechecks the password
and may remediate; `accept` records a manual waiver. A post-upgrade retry does not
repeat install, reboot, restoration or sync. A manually accepted mismatch remains
visible in the report and completes with warnings. This verifies the configured
local password; lockout, expiry and GUI/SSH login availability are separate checks.

F5 command reference: [auth user](https://clouddocs.f5.com/cli/tmsh-reference/latest/modules/auth/auth_user.html).

### Drain and HA behavior

Standalone draining disables **virtual addresses**, never virtual servers. It
records original enabled states and changes only enabled addresses. Choose a
remaining count or `reduction_percent` (not both) in `standalone_drain`.
A 90% reduction from 1,000 connections means 100 remaining. Counts sum clientside
virtual-server connections; they are not a complete system connection-table count.

The flat fields `drain`, `drain_connections`, `drain_percent`, `drain_timeout`, and
`reboot_on_drain_timeout` remain supported. Their default timeout is 300 seconds;
`standalone_drain.timeout_seconds` defaults to 600. With no threshold, drain to zero.
Draining requires reboot. Timeout restores addresses and stops unless forced
reboot on timeout was explicitly selected.

Disabled states are saved and copied into the target so traffic stays drained
through reboot and validation. After successful or manually accepted validation,
restore only addresses disabled by this job, save, and collect the final snapshot.
Before reboot, cancellation/error attempts restoration. Uncertain boots retain
recovery state and reservations instead of issuing blind cleanup.

HA discovery verifies a two-member sync-failover pair through both members and
locks the cluster plus both management endpoints across workers and batches.
Only submitted members are upgraded. The current active member may run first:
verify healthy peer/traffic ownership, explicitly fail over to it, confirm the
handoff, then reboot. HA jobs **do not disable shared virtual addresses**.
Before upgrading the second member, verify that the upgraded peer has completed
validation and can carry traffic. Mixed-version handoffs need that saved peer
validation; a manually completed peer counts only if its post-upgrade validation passed. Sync is deferred while versions/builds differ; when equal, use the
active member as the sync source and verify completion. Unknown topology,
active-active groups, unhealthy peers and changing ownership stop the operation.

Within each wave, devices are claimed in submitted order when eligible, up to
`upgrade_at_a_time`; a reserved pair cannot overlap. A later wave starts only
after every previous item is `succeeded`, `completed_with_warnings` or
`manually_completed`. A validation pause frees a worker slot but retains device
and HA reservations. This permits unrelated devices to progress.

### Validation and manual control

Pre/post reports include WAF policy counts, names and attributes; ASM readiness;
up/total and per-object state for virtual servers, pools, nodes and virtual IPs;
pool active members; VLANs, self IPs, routes, management routes/IPs, provisioning,
interfaces, trunks, iRule names and certificate expiry fields. Collection gaps
are explicit. Dynamic `_auto` nodes are excluded from stable inventory comparisons.

Object deltas are reported individually. Minor monitor or inventory differences
are **warnings by default**, so a few nodes going down cannot trap the wave.
ASM readiness, boot identity/version and HA health are blocking checks. Validation
has bounded settling/retries. `on_timeout` chooses `needs_review` (default) or
`fail`. Strict environments may select `noncritical_differences: require_review`
and set `ltm_min_unchanged_percent`/`waf_min_unchanged_percent`; both default to 100.
Other configuration changes still require review in strict mode. Two consecutive
acceptable samples are the default; a zero-second validation window takes one.
No-reboot jobs validate the current runtime, not the staged software.

A waiting job exposes a gate with `id`, `revision`, `phase` and `findings`. Send:

```http
POST /api/v1/jobs/JOB_ID/validation-decisions
Idempotency-Key: change123-accept-gate1
Content-Type: application/json

{"action":"accept","gate_id":"GATE_UUID","validation_revision":1,"operator":"jason","reason":"Validated application traffic manually"}
```

`retry` runs that validation again. `accept` records the waiver and continues with
the remaining restoration/traffic/sync steps. It does **not** reinstall or reboot.
The decision transitions `pending` → `applied`, with stale revisions rejected.
The audit retains the findings and operator reason; acceptance is not a fake pass.

`POST /jobs/{id}/mark-done` takes `{"operator":"jason","reason":"..."}`.
It advances the wave barrier for a stopped item but **retains unresolved
reservations**. For a running item it requests cancellation first; the worker
must acknowledge before status becomes `manually_completed`. Unrelated devices
may continue, but its HA peer stays blocked until recovery is reconciled.

`POST /jobs/{id}/cancel` cancels queued jobs immediately. Running workers observe
safe checkpoints: transfers can stop; install/cpcfg must finish; drains restore
before reboot; a requested reboot must reconnect/verify first. Cancellation after
reboot retains recovery for inspection. Killing a worker never means a remote
command stopped. Missing heartbeats fence SSH/HTTP/F5 jobs as `recovery_required`;
there is no automatic replay. `SIGTERM` gracefully finishes the current job.

To release recovery, stop the owning worker, inspect any in-flight device commands,
boot state and saved drain state, then send:

```json
{"worker_stopped":true,"device_inspected":true,"note":"Worker stopped; device and address states reconciled"}
```

Use `/jobs/{id}/resolve`. These are operator attestations, not remotely proven
facts. Resolving a manually completed item preserves its wave completion status.

Optional `validation_policy.waf_request_check: true` checks for new WAF traffic
after restoration. Standby units and units without policies skip it. Configure a
read-only inventory `waf_request_command` that emits JSON
`{"id":"request-id","timestamp":"2026-10-28T12:00:00+00:00"}` over SSH from your
local request-log adapter. The timestamp must be timezone-aware and between the
reboot request and now. No HTTP calls or log-byte-growth guesses are used.
Without an adapter/new request, the bounded gate requires manual validation;
request logging and incoming traffic must exist for automatic proof.

### Rollback

The original active volume/version/build is saved before mutation. Submit `{}`
to `/jobs/{id}/rollback` with its own idempotency key. The linked job checks that
the device still runs the upgrade target and the original volume is intact,
performs a healthy HA handoff when needed (if only this member was upgraded, the
peer must run the recorded rollback version/build), reboots to the original volume,
restores tracked drain state and validates. An uncertain source job holding a
reservation requires `{"worker_stopped":true}`; ownership transfers atomically
to the rollback job. A staged-only job must actually boot its target first.

Rollback does not import UCS, recreate deleted partitions, or automatically
carry later configuration changes back. Keep database, backups and keyring as a
recovery set. Back up SQLite with its online backup API, or stop all processes
before copying its database/WAL files. No automatic purge removes rollback history.

## PAN-OS upgrades through Panorama

Every firewall operation is a Panorama XML API request with `target=<firewall
serial>`, so the remote needs HTTPS to Panorama only. By default, software is
**pushed from Panorama's software repository** ("Panorama > Device Deployment >
Software"), so firewalls need no internet access: `request batch software upload
file <PanOS_<family>-<version>> devices <serial>`. The platform family comes from
Panorama's device list (`PanOS_3200-11.1.6-h3`, `PanOS_vm-11.1.6-h3`); override it
with `software_family`. A file missing from the repository is downloaded by
Panorama (`request batch software download file`) unless `panorama_download` is
false; an offline Panorama can use files uploaded to it manually. Concurrent jobs
that need the same file wait for one shared repository download. With
`software_source: update_server`, each firewall instead downloads from its own
update server (`request system software download`). Installation always runs on
the firewall (`request system software install version`) after it reports the
image as downloaded.

Provision the Panorama HTTP target and its API key profile as described under
[Generic SSH and HTTP jobs](#generic-ssh-and-http-jobs) (`scheme:header`,
`header:X-PAN-KEY`, read-only `type=version` probe). The key's Panorama admin role
needs operational, configuration, commit and export requests for the managed
firewalls, plus Panorama's batch software requests. Then send this to
`/api/v1/panos/upgrade-batches`:

```json
{
  "name": "Change456",
  "start_at": "2026-11-01T02:00:00Z",
  "latest_start_at": "2026-11-01T08:00:00Z",
  "defaults": {
    "panorama": "panorama",
    "target_version": "11.1.6-h3",
    "allowed_source_versions": ["10.2.9-h1", "10.2.10-h2"],
    "approved_models": ["PA-3220", "PA-3410"],
    "validation_policy": {"on_timeout": "needs_review", "min_route_percent": 90}
  },
  "waves": [
    {"wave": 1, "upgrade_at_a_time": 2, "serials": ["007951000123456", "007951000123457"]},
    {"wave": 2, "upgrade_at_a_time": 20, "serials": ["007951000123458", "007951000123459"]}
  ],
  "overrides": {"007951000123459": {"validation_policy": {"min_session_percent": 50}}}
}
```

### Pushing images from the executor and preloading

When Panorama is far from some firewalls, the executor nearer to them can push the
image itself: `software_source: executor` uploads each `PanOS_<family>-<version>` file
from `NETOPS_IMAGE_ROOT` (or downloads it first from an HTTPS `source_url`, with the
same SHA-256 checks as F5 images) straight to the firewall's management API
(`type=import&category=software`). Listing, install and everything else still go
through Panorama. The firewall must be reachable from the executor on HTTPS, with an
API key in an `http` credential profile whose `targets` name the serial or address.
Certificates are verified; set `NETOPS_FIREWALL_CA_FILE` for a private CA, and use
`management_addresses` hostnames when certificates do not carry IP addresses. After an
upload the firewall must list the image with the same SHA-256. A firewall's web front
end can answer 504 on a large import that still completes (seen on PA-VM 12.1.6 at
about seven minutes), so an unconfirmed upload is confirmed from the software list.

Preload is `stage_only: true`, usually with `software_source: executor`, run as a batch
days before the maintenance window. It checks the firewall is connected, on an allowed
version and idle, then stages the base (when needed) and target images on every member
of each pair. It takes no backups and skips uncommitted-change, HA-health and traffic
gates, because staging does not touch traffic; the upgrade job enforces them later and
skips images already present with a matching checksum:

```json
{
  "name": "Preload-456",
  "defaults": {
    "stage_only": true,
    "software_source": "executor",
    "target_version": "12.2.2",
    "allowed_source_versions": ["12.1.6"],
    "images": [{"name": "PanOS_vm-12.2.2", "sha256": "15cb673b4cf66c2dd8a1c5ade5892beaf522612ec7545b976abf56376d5d956c"}]
  },
  "waves": [{"wave": 1, "upgrade_at_a_time": 10, "serials": ["007951000123456", "007951000123457"]}]
}
```

### Progress

Poll `GET /api/v1/jobs/{id}` and read `result.progress`:

```json
{
  "step": "stage:007951000123456",
  "steps_completed": 3,
  "steps_total": 14,
  "percent": 21,
  "operation": {"kind": "upload", "serial": "007951000123456", "percent": 42.5,
                "file": "PanOS_vm-12.2.2", "bytes": 725614592, "total_bytes": 1707326960},
  "updated_at": "2026-11-01T02:14:09.512000+00:00"
}
```

`percent` counts completed steps against the planned total for this job, including
both members of a pair. `operation` describes what is running now, with a real
`percent` where one exists: `upload` (bytes sent by the executor), `software_upload`,
`software_download`, `panorama_download`, `install` and `commit` (the PAN-OS job's own
percentage) and `f5_drain` (connections drained towards the threshold). `reboot`
(elapsed/timeout), `validation` (consecutive passes), `tech_support`, `settle` and
`upload_confirmation` carry status fields instead. The same operations appear as
`progress` events in `GET /api/v1/jobs/{id}/events`, written at most every five
seconds or when the whole percent changes, alongside every step's own events.

A batch holds up to 1,000 serials. Wave barriers, start windows, `defaults`,
`overrides` and idempotency behave exactly as for F5 batches; poll
`/api/v1/upgrade-batches/{id}` (`kind: panos_upgrade`). Put a small canary wave
first. A failed or `needs_review` item stops later waves but not its own wave.
For one firewall, send the defaults plus `"serial"` to `/api/v1/panos/jobs`.

**An HA pair is one unit of work.** The job for either member upgrades both, one at
a time, and reserves both. When the batch also lists the peer, the peer's item runs
afterwards, finds the pair on the target and only validates. A job holds a worker
while it waits for backups, transfers, installs and reboots, so run at least as many
workers as the largest `upgrade_at_a_time` (`executor_workers`, or
`--scale worker=N`).

| Option | Behavior/default |
| --- | --- |
| `target_version` | Version to install, such as `11.1.6-h3` |
| `allowed_source_versions` | Required exact running-version allowlist; members already on the target only validate |
| `software_source` | `panorama` (default), `executor` or `update_server` |
| `images` | For `executor`: `{name, sha256, source_url?}` per `PanOS_<family>-<version>` file, any families |
| `management_addresses` | For `executor`: firewall management address per serial; default Panorama's `ip-address` |
| `firewall_credential_profiles` | For `executor`: HTTP API key profiles for the firewalls; default profiles whose `targets` match the serial or address |
| `panorama_download` | Default true: Panorama downloads a missing file into its repository |
| `software_family` | Override the family used in Panorama filenames |
| `download_versions` | Extra versions to stage, not install, such as intermediate base images for a skip-version upgrade |
| `auto_base_image` | Default true: when changing feature release, first stage the lowest release of the target's feature release that the source offers below the target (base releases are not always `X.Y.0`); without one, install the target directly |
| `approved_models` | Optional model allowlist matching `show system info` |
| `stage_only` | Preload: stage images only, ahead of the window; no backups, install, reboot or traffic/HA-health gates. A later full job reuses the staged images |
| `config_backup`, `tech_support` | Default true: save each member's running configuration XML and a tech support file under `NETOPS_BACKUP_ROOT` (`backup_directory`, default `panos/<serial>`) |
| `ha_policy.upgrade_order` | `standby_first` (default) or `active_first` |
| `ha_policy.after_reboot` | `validate_in_service` (default): validate a member its reboot returned to service where it is, and suspend it only if validation fails; `suspend_until_validated` suspends it again first |
| `ha_policy.disable_preemption` | Default true: disable preemption and commit before the first suspend, then restore and commit after both members validate; false leaves preemption alone |
| `ha_policy.failback` | Default true: return traffic to the other member when the member left carrying it fails validation |
| `ha_policy.require_running_sync` | Default true: same-version pairs must report running configuration synchronized |
| `job_wait_timeout` | Wait for running firewall jobs before starting; default 600 seconds |
| `tech_support_timeout`, `commit_timeout` | Defaults 1800 and 900 seconds |
| `download_timeout`, `install_timeout` | Per transfer or install job; default 3600 seconds each |
| `reboot_timeout` | Verified reboot window; default 2700, maximum 7200 seconds |
| `validation_timeout` | Bounded window for each validation step; default 900 seconds |

Steps, in order:

1. **Discover and reserve.** Panorama's `show devices all` must list the firewall as
   connected. The HA peer comes from Panorama's `ha/peer/serial`.
2. **Prechecks for every member** (failure here changes nothing): serial,
   `operational-mode normal`, allowed source version, approved model, chassis ready,
   no running firewall jobs, no uncommitted local changes (`check pending-changes`),
   connected to Panorama. HA pairs must be active/passive (one active, one passive)
   or active/active (both active), with peer connections up and running
   configuration synchronized when both run the same version.
3. **Baseline:** hardware interface link states, legacy routing-table routes, BGP
   peer states, IPsec tunnel states, active session count and ARP count. An
   active/passive pair has one baseline from its active member; active/active
   members and standalone firewalls each have their own. A command that fails, such
   as routes with the Advanced Routing Engine, is recorded as a gap and never compared.
4. **Backups** of each member to be upgraded: running configuration and tech support
   file (`type=export&category=tech-support`). Download them with
   `GET /api/v1/jobs/{id}/artifacts/{name}`.
5. **Stage** every required image on each member to be upgraded.
6. **Disable preemption** (`ha_policy.disable_preemption`, default true). Members
   whose HA state reports preemptive `yes` get `preemptive no` in their local HA
   election settings, committed and read back. With the flag false, preemption is
   left alone; a suspended member never preempts, but a higher-priority member can
   take traffic back as soon as it is made functional.
7. **Upgrade each member in order.** `standby_first` takes the passive member
   (active-secondary in active/active) first:
   1. Suspend it. Suspending a member that carries traffic is a **handoff**: the
      peer must then pass traffic validation against the baseline while carrying
      everything. A member is never suspended unless its peer is functional.
   2. Install, then reboot. A new boot is verified by the target version and an
      uptime shorter than the time since the restart request. PAN-OS 12.1.6 brings a
      suspended member back into service when it reboots (seen in the lab: it returned
      passive). With `ha_policy.after_reboot: validate_in_service` (default) it is
      validated where it is: a passive member carries no traffic and stays available
      for failover, while an active/active member carries traffic during validation.
      `suspend_until_validated` suspends it again as soon as its HA state settles.
   3. **System validation**: target version, chassis ready,
      latest auto-commit finished `OK`, connected to Panorama on the target. Content
      version changes are reported. A member that fails it is suspended (when its peer
      is functional) before the review gate or failure.
   4. Make it functional (`request high-availability state functional`), then
      validate the pair: every member functional with its peer connection up, one
      active member (active/passive) or every functional member active
      (active/active), and traffic on each active member against its baseline.

   In an active/passive pair this means: upgrade the standby, validate it, fail
   over to it by suspending the active, validate the upgraded member carrying
   traffic, then upgrade the former active.
8. **Restore preemption** where this job disabled it, commit, and run a final pair
   validation, which also requires synchronized running configuration.

Traffic validation: with `restore_required` (default), every baseline interface
that was up, BGP peer that was Established and IPsec tunnel that was active must
recover. Routes must stay at `min_route_percent` (default 90) of the baseline.
Session and ARP counts fail only an explicit `min_session_percent`/`min_arp_percent`.
Other differences (added/removed routes, state changes) are warnings. Samples run
every `sample_interval_seconds` (15), after `settling_seconds` (60) following a
reboot, and need `consecutive_passes` (2) clean samples. On timeout, `on_timeout`
selects `needs_review` (default) or `fail`; `noncritical_differences:
require_review` also gates on warnings.

**Failback.** If the member left carrying traffic after a handoff fails
validation, the job makes the suspended member functional again and suspends the
failing one before it stops. In the standby-first order that returns traffic to the
original active member on its original software, with the upgraded member
suspended for inspection.

Review gates are named after the step (`handoff:<serial>`,
`validate_system:<serial>`, `validate_traffic:<serial>`, `validate_final`,
`validate_current`) and use the existing validation-decision endpoint. `retry`
samples again; for a handoff gate it returns the failed-back member to service and
hands off again. `accept` records the waiver and continues. A decision resumes
after the completed steps and never repeats a backup, transfer, install or reboot.

Failures before any install, and installs the firewall reports as failed, end as
`failed` and release the reservations: suspended members return to service and
preemption is restored first. An install with an unknown outcome, a staged image or
a reboot that did not pass validation ends as `recovery_required`. Both HA
reservations stay held, preemption stays disabled, and an upgraded but unvalidated
member that failed validation is left suspended so its peer keeps carrying traffic. A
failure while waiting for the new boot leaves whatever HA state the member booted
into. Inspect the
firewalls, make them functional and restore preemption manually if appropriate,
then resolve the job. Cancellation during prechecks, backups or staging is clean.
An install is never interrupted; cancellation is honored after it finishes. Results
contain per-member `members` (role, source, software, install, boot, validation),
`upgrade_plan`, `completed_steps`, `preemption`, `artifacts`, `pre_validation`,
`post_validation`, `validation_findings` and `validated_version`.

### Draining a related F5

Where a standalone firewall has a 1:1 related F5 whose virtual addresses keep an
upstream load balancer (such as a GCP internal load balancer) sending traffic through
the firewall, add `f5_drain`. Disabling those addresses fails the load balancer's
health checks, so traffic moves off this firewall before it is upgraded:

```json
{
  "defaults": {
    "target_version": "11.1.6-h3",
    "allowed_source_versions": ["10.2.9-h1"],
    "f5_drain": {"remaining_connections": 50, "timeout_seconds": 900}
  },
  "overrides": {
    "007951000123456": {"f5_drain": {"device": "192.0.2.51"}},
    "007951000123457": {"f5_drain": {"device": "192.0.2.52", "addresses": ["/Common/10.1.1.10"]}}
  }
}
```

PAN-OS batch overrides merge into nested defaults, so a per-serial F5 address keeps the
shared thresholds. `device` is an F5 inventory ID or management IP reached over SSH
with the usual encrypted SSH profiles (`credential_profiles` optional). The drain
reuses the F5 upgrade job's logic and reserves the same F5 keys as F5 upgrade, SSH and
HTTP jobs, so none can overlap it.

| `f5_drain` option | Behavior/default |
| --- | --- |
| `device` | Required: the related F5 |
| `addresses` | Virtual addresses to drain, such as `/Common/10.1.1.10`; default every enabled address |
| `remaining_connections` or `reduction_percent` | Drain target from F5 clientside virtual-server connections; neither means zero |
| `timeout_seconds` | Default 600 |
| `proceed_on_timeout` | Default false: restore the addresses and stop; true upgrades anyway |

Prechecks also require the F5 to be standalone and active, with no automatic config
sync, and every listed address to exist. After backups and staging, the job disables
the enabled addresses (recording each before the command) and waits for connections
to reach the threshold. It then installs, reboots and validates the firewall; session
and ARP thresholds are skipped while drained. Next it re-enables only the addresses it
disabled, saves the F5 configuration, reads the states back, and runs
`validate_restored` with all thresholds. A failure before the install restores the F5.
An upgraded firewall that has not passed validation leaves the F5 drained, so no
traffic reaches it, and ends `recovery_required` or at a review gate; accepting or
retrying the gate continues to the restore. `result.f5_drain` records the original
address states, changed addresses, connection counts, threshold, timeout and restore.
HA pairs move traffic with failover instead, so `f5_drain` is refused for them.

Preemption is restored by setting the original value locally. If HA election
settings come from a Panorama template, this leaves a local override equal to the
template value. Mixed-version pairs may not synchronize sessions across a
feature-release difference, so a handoff can drop sessions.

## Arista EOS upgrades

EOS jobs run over the same audited SSH session as `arista_eos` SSH jobs (encrypted SSH
profiles, `known_hosts` or `NETOPS_SSH_HOST_KEYS=pin`). Reads use EOS's structured
`| json` output. The image is copied from the executor's `NETOPS_IMAGE_ROOT` (or its
HTTPS `source_url`) to `flash:` with SCP over that session, then checked on the switch
with `verify /sha512` against the executor's verified copy. The upgrade itself is EOS's
native install mode, `install source flash:<image> now reload`, which points
boot-config at the image and reloads; boot variables are never set by hand.

```json
{
  "name": "Change789",
  "defaults": {
    "target_version": "4.32.2F",
    "allowed_source_versions": ["4.30.5M", "4.31.3M"],
    "image": {"name": "EOS-4.32.2F.swi", "sha256": "REPLACE_WITH_SHA256"},
    "validation_policy": {"on_timeout": "needs_review"}
  },
  "overrides": {
    "leaf1a": {"mlag_peer": "leaf1b"},
    "leaf1b": {"mlag_peer": "leaf1a"}
  },
  "waves": [
    {"wave": 1, "upgrade_at_a_time": 1, "devices": ["leaf1a"]},
    {"wave": 2, "upgrade_at_a_time": 10, "devices": ["leaf1b", "leaf2a", "leaf3"]}
  ]
}
```

Send this to `/api/v1/eos/upgrade-batches`, or one request with `"device"` to
`/api/v1/eos/jobs`. Devices are inventory IDs or management IPs; an inventory entry must
be `arista_eos` (or untyped). Batch overrides merge into nested defaults, wave barriers
and start windows behave as for F5 batches, and `result.progress` reports steps and the
current operation, with byte percentages for the image copy.

| Option | Behavior/default |
| --- | --- |
| `target_version`, `image` | Target release and its `.swi` (`name`, `sha256` of the executor's copy, optional `sha512` and `source_url`) |
| `allowed_source_versions` | Required exact running-release allowlist; a switch already on the target and booting its image only validates |
| `approved_models` | Optional `modelName` allowlist |
| `mlag_peer` | The MLAG peer's inventory ID or IP: reserved for the whole job and checked healthy from its own side right before the reload |
| `stage_only` | Preload: copy and verify the image only; no backups, saves, MLAG gates or reload |
| `config_backup`, `tech_support` | Default true: save `show running-config` and `show tech-support` under `NETOPS_BACKUP_ROOT` (`eos/<device>`) |
| `save_config` | Default true: `write memory` when running and startup configuration differ; false stops instead |
| `minimum_free_bytes` | Flash reserve kept after the image; default 500,000,000 |
| `upload_timeout`, `install_timeout`, `reboot_timeout`, `validation_timeout` | Defaults 3600, 1800, 1800 and 900 seconds |

Steps: reserve the switch (and `mlag_peer`, with the same keys F5, SSH and EOS jobs use,
so peers never reload together; giving MLAG peers the same inventory `lock_group` also
serializes them); prechecks (allowed release and model; MLAG either disabled or active
with negotiation connected, peer link up and consistent configuration; a target already
running must also be in boot-config); baseline; backups; image copy and SHA-512 check
(skipped when the image is already on flash with the right checksum, after a free-space
check); `write memory` if needed; then, immediately before the install, a recheck that
the running configuration (normalized, ignoring EOS metadata comments), release and MLAG
health are unchanged. After `install source ... now reload` the job waits for the switch
to answer on the target release with a fresh uptime, settles (`settling_seconds`, default
120), then validates.

System validation requires the target release, the same model and system MAC, and
boot-config on the target image; unsaved or changed configuration and an unexpected
reload cause are reported as warnings. Traffic validation compares the baseline: with
`restore_required` (default), every interface that was `connected`, every LLDP neighbor
(same device and port), every Established BGP peer, every FULL OSPF neighbor and every
active port-channel member must recover; a switch that was in MLAG must return to
`active` with the peer link up; routes must stay at `min_route_percent` (90); MAC and ARP
counts fail only an explicit `min_mac_percent`/`min_arp_percent`. A command that cannot
be read before the upgrade is a gap and never compared. Gates, decisions and timeouts
work as for PAN-OS (`validate_system`, `validate_traffic`, `validate_current`).

Failures before the install end `failed` with nothing changed on the switch beyond a
copied image and a saved configuration. Once the install is sent, a failure ends
`recovery_required` and keeps the reservations. `result.rollback` records the previous
release and boot image, which stays on flash: recovery is
`install source flash:<previous> now reload`. EOS upgrades are tested against simulated
switches and canned EOS JSON only; lab acceptance on your EOS releases is required,
especially for the `| json` fields, SCP to `/mnt/flash` and the install reload.

## Cisco IOS XE upgrades

IOS XE jobs upgrade a Catalyst C9300 (including C9300L/C9300X), C9350, WS-C3650 or
WS-C3850 switch or stack over the same audited SSH session as `cisco_ios` SSH jobs.
The upgrade is install mode's one-shot `install add file flash:<image> activate commit`,
which copies the image to every stack member, activates it, reloads and commits. The
only boot change ever made is `boot system flash:packages.conf`, which install mode
requires.

```json
{
  "name": "Change790",
  "defaults": {
    "target_version": "17.12.6",
    "allowed_source_versions": ["17.9.5", "17.12.4"],
    "image": {"name": "cat9k_iosxe.17.12.06.SPA.bin", "sha256": "REPLACE_WITH_SHA256",
              "sha512": "CISCO_PUBLISHED_SHA512"},
    "config_policy": {"removed": "warn"},
    "validation_policy": {"on_timeout": "needs_review"}
  },
  "overrides": {"idf1-a": {"peers": ["idf1-b"]}},
  "waves": [
    {"wave": 1, "upgrade_at_a_time": 1, "devices": ["idf1-a"]},
    {"wave": 2, "upgrade_at_a_time": 20, "devices": ["idf1-b", "idf2", "idf3"]}
  ]
}
```

Send this to `/api/v1/iosxe/upgrade-batches`, or one request with `"device"` to
`/api/v1/iosxe/jobs`. Devices are inventory IDs or management IPs; an inventory entry
must be `cisco_ios` (or untyped). Use one batch per platform family, because each
family has its own image package.

| Option | Behavior/default |
| --- | --- |
| `target_version`, `image` | Target release (`17.12.6` and `17.12.06` are equal) and its `.bin`: `name` (its release must match the target), `sha256` of the executor's copy, optional Cisco-published `sha512` or `md5`, `verify` (`sha512` default, or `md5`), HTTPS `source_url` for the executor and `device_url` for the switch |
| `allowed_source_versions` | Required running-release allowlist; a stack already on the target in INSTALL mode only validates |
| `approved_models` | Optional exact `show version` model allowlist (3650/3850 `show version` omits the -L/-S/-E license suffix) |
| `peers` | Inventory IDs or IPs reserved for the whole job, so HSRP partners or redundant uplink switches never reload at the same time |
| `stage_only` | Preload: copy and verify the image only (with `remove_inactive` when needed); no backups, saves, boot changes or install |
| `tech_support` | Default true: save `show tech-support` under `NETOPS_BACKUP_ROOT` (`iosxe/<device>`). The running configuration is always saved there, because validation compares with it |
| `save_config` | Default true: `write memory` when running and startup configuration differ before the upgrade; false stops instead |
| `save_after_validation` | Default true: `write memory` after validation, so startup-config uses the new release's syntax. Skipped when configuration lines were removed |
| `remove_inactive` | Default true: `install remove inactive` before the copy when inactive packages exist or flash is short. It also deletes unused `.bin` files, so it never runs after the copy |
| `allow_bundle_conversion` | Default false: a BUNDLE-mode switch stops; true lets the install convert it to INSTALL mode |
| `config_policy` | How the post-upgrade configuration is compared (below) |
| `minimum_free_bytes` | Flash kept free on every member beyond the image, for package expansion; default 1,500,000,000 |
| `upload_timeout`, `install_timeout`, `reboot_timeout`, `validation_timeout` | Defaults 5400, 3600, 2700 and 1200 seconds |

Steps: reserve the switch and `peers` (the same keys every job takes for those devices);
prechecks; baseline; tech support; image copy and checksum; `write memory` if needed;
`boot system flash:packages.conf` if missing; a recheck that release, stack membership,
install state and configuration are unchanged; the install; a wait until every original
member is back on the target in INSTALL mode, Ready, with a fresh uptime; settling
(`settling_seconds`, default 180); system and configuration validation; traffic
validation; and the final `write memory`.

Prechecks refuse: a member that is not Ready or disagrees between `show version` and
`show switch`; mixed releases or boot modes; hardware outside one supported family or
`approved_models`; an image package for another family (`cat9k_iosxe` for C9300,
`cisco9k_iosxe` or `cisco9k_iosxe_npe` for C9350, `cat3k_caa-universalk9` or its `ldpe`
variant for 3650/3850); a release outside the one-shot install range (C9300 16.6.2 or
later, C9350 17.18.1 or later and 26.1.1a for the C9350-24HX and C9350-48HXN, 3650/3850
16.8.1a through 16.12.x); a C9350 stack going from 17.18.1 to 17.18.3 (Cisco CSCwt90927
can corrupt the primary ROMMON); uncommitted install state or an active auto-abort timer;
and a committed image that does not match the running release on every member.

The image comes from the executor over SCP on the job's own SSH session (the switch needs
`ip scp server enable`), with byte progress in `result.progress`. With `image.device_url`
the switch copies it itself (`copy <url> flash:<image>`); when the switch answers that
the copy failed, the partial file is deleted and the executor pushes the image instead.
A copy that times out is never retried. The switch then runs `verify /sha512` (or
`/md5`) against the published checksum or the executor's verified copy, and every member
must keep `minimum_free_bytes` free.

The install runs as one bounded dialogue that answers only the reload, save-configuration
and packages.conf questions IOS XE asks; any other question stops the job. The latest
installer line is reported as `result.progress.operation.status`, so pollers see the add,
activate and reload phases. The command is sent once; a dropped session is expected, and
only a fresh boot of every member on the target proves the outcome.

### Configuration comparison across releases

A new IOS XE release re-renders the same configuration, so a text diff fails nearly every
upgrade. Validation instead canonicalizes the baseline and post-upgrade running
configurations the same way and compares them as a tree:

- Metadata above `version`, comments, boot lines, certificate bodies and whitespace are
  dropped. Banners compare as one line.
- Order is ignored everywhere except where it is semantic: the entries of IPv4, IPv6 and
  MAC access lists and the classes of a policy map stay ordered.
- Numbered access lists (`access-list 10 permit ...`) and their `ip access-list standard
  10` form are the same list, and access-list sequence numbers are ignored while the
  entry order is still compared.
- Built-in rewrites map `ip domain-name`, `ip domain-lookup` and `ip domain-list` to
  `ip domain name|lookup|list`.
- Built-in ignores drop sections the switch generates itself: the `system-cpp-*` control
  plane class maps and policy, the `SLA-TrustPoint` trustpoint and chain, `service
  call-home` and `call-home`, `license smart` lines, the default `service-template`s,
  `interface AppGigabitEthernet*` and `memory free low-watermark processor`.

Whatever remains is reported as removed or added lines, each with its parent path, such
as `interface GigabitEthernet1/0/1 > spanning-tree portfast`. `result.config_comparison`
holds the counts, the first 50 lines of each with secrets masked, and the `tolerated`
list: each rule that hid a difference, with before and after counts, and the sections
whose order alone changed. The full unmasked differences and the post-upgrade
configuration are private files next to the baseline (`config_differences` artifact).

| `config_policy` | Behavior/default |
| --- | --- |
| `removed`, `added` | `warn` (default; the job ends `completed_with_warnings`), `critical` (validation does not pass, so the job waits for review or fails per `on_timeout`) or `ignore` |
| `rewrite` | Extra `{"name", "line", "parent", "replace"}` rules applied to both configurations: `line` is a regex for a canonical line, `parent` limits it to children of a matching parent line, `replace` may use `\1` |
| `ignore` | Extra `{"name", "line", "parent"}` rules; a matching line is dropped with its children on both sides |
| `ordered_sections` | Extra parent-line regexes whose children are compared in order |
| `builtin_rules` | Default true; false compares with only your rules |

To tune rules, post a configuration from before and after an upgrade you have already
done to `/api/v1/iosxe/config-compare` (`{"before": ..., "after": ..., "config_policy":
{...}}`, or `netops-executor request --kind iosxe-config-compare`). It returns exactly
what validation would report, contacts no device and stores nothing. Add each
difference you accept as a rule in the batch defaults.

System validation requires every original member on the target in INSTALL mode and
Ready, the same models and serial numbers, the target committed on every member, and
`boot system flash:packages.conf`; then the configuration comparison runs. Traffic
validation compares the baseline: with `restore_required` (default), every interface that
was up/up, every CDP and LLDP neighbor (same device and port), every Established BGP
peer, every FULL OSPF neighbor and every bundled port-channel member must recover; routes
(default VRF plus each IPv4 VRF) must stay at `min_route_percent` (90); MAC, ARP and
802.1X/MAB session counts fail only an explicit `min_mac_percent`, `min_arp_percent` or
`min_access_session_percent`; HSRP state changes are reported as warnings. A category
that cannot be read before the upgrade is a gap and is never compared. Gates, decisions
and timeouts work as for PAN-OS (`validate_system`, `validate_traffic`,
`validate_current`).

Failures before the install end `failed` with nothing changed beyond a removed inactive
package set, a copied image, a saved configuration and, on an INSTALL-mode switch, a
corrected boot variable. Once the install is sent, a failure ends `recovery_required`
and keeps the reservations; so does a failure after the boot variable was changed on a
BUNDLE-mode switch. `result.rollback` records the previous release and mode. Recovery
uses the switch's own rollback points (`show install rollback`, then `install rollback
to id <n>`), or a new job to the previous release. IOS XE upgrades are tested against
simulated stacks and canned IOS XE output only; lab acceptance on your hardware and
releases is required, especially for the table parsers, SCP to `flash:`, the install
dialogue and the configuration rules.

## Cisco Catalyst 2960-X upgrades (classic IOS)

Classic IOS jobs upgrade WS-C2960X and WS-C2960XR switches and FlexStack-Plus stacks on IOS
15.2. They take the same request as IOS XE jobs, minus the install-mode options, and use
`/api/v1/ios/plan`, `/api/v1/ios/jobs` and `/api/v1/ios/upgrade-batches` (CLI kinds `ios`
and `ios-batch`):

```json
{
  "name": "Change791",
  "defaults": {
    "target_version": "15.2(7)E10",
    "allowed_source_versions": ["15.2(7)E3", "15.2(7)E8"],
    "image": {"name": "c2960x-universalk9-tar.152-7.E10.tar", "sha256": "REPLACE_WITH_SHA256",
              "md5": "CISCO_PUBLISHED_MD5",
              "device_url": "http://images.example.com/c2960x-universalk9-tar.152-7.E10.tar"}
  },
  "waves": [
    {"wave": 1, "upgrade_at_a_time": 1, "devices": ["access1"]},
    {"wave": 2, "upgrade_at_a_time": 20, "devices": ["access2", "access3"]}
  ]
}
```

The image is the release's `.tar` (`c2960x-universalk9-tar.<release>.tar`; the name must
carry the target release, so `15.2(7)E10` needs `152-7.E10`). The switch verifies it with
`verify /md5` by default (`image.verify` can be `sha512`). `minimum_free_bytes` defaults to
3,000,000; the other options (`peers`, `stage_only`, `tech_support`, `save_config`,
`save_after_validation`, `config_policy`, `validation_policy`, timeouts) behave as for IOS
XE.

The upgrade uses Cisco's own `archive download-sw`, never a hand-set boot variable:

1. Prechecks: every member Ready and agreeing between `show version` and `show switch`, one
   release, WS-C2960X/WS-C2960XR hardware (and `approved_models`), a `c2960x-universalk9`
   image, an allowed source release, and no extracted target image already on flash.
2. The `.tar` goes to the master's `flash:` with `copy <device_url> flash:` first and SCP
   from the executor as the fallback, then is checksum-verified. The master needs room for
   the `.tar` plus the extracted image, and every other member (`flash<N>:`) room for the
   extracted image, plus `minimum_free_bytes`. When the master cannot hold both but
   `device_url` is set, `archive download-sw` reads the `.tar` straight from the URL
   instead; the switch then checks the archive itself, not against the request's checksum.
   `stage_only` preloads the `.tar` and needs that room.
3. A recheck that release, membership, configuration and boot paths are unchanged.
4. `archive download-sw /imageonly /safe flash:<tar>` (or the URL). `/safe` keeps the running
   image until the new one is in place, and the command extracts the image onto every
   member and points each member's boot path at it. `show boot` must then name the target on
   every member, or the job stops before the reload. The `.tar` is deleted.
5. `write memory` if only the boot path changed the saved configuration, then `reload`,
   answering only `Proceed with reload? [confirm]`.
6. The wait for every original member back on the target, Ready, with a fresh uptime, then
   settling, system validation (members, models, serials, boot paths and the configuration
   comparison described for IOS XE) and traffic validation.

Failures before `archive download-sw` end `failed`, leaving at most a copied `.tar` and a
saved configuration. From `archive download-sw` on, a failure ends `recovery_required`,
because boot paths may already name the new image. `result.rollback` records the previous
release and boot paths. `archive download-sw` removes the old image after a successful
install, so recovery is another job to the previous release's `.tar`. 2960-X upgrades are
tested against simulated stacks only; lab acceptance is required, especially for the
`archive download-sw` output, `show boot` on a stack, member flash names and the reload
prompt.

## Generic SSH and HTTP jobs

```json
{"device":"192.0.2.10","commands":[{"command":"tmsh show sys version","timeout_seconds":60},{"command":"tmsh list sys provision","timeout_seconds":60}],"stop_on_error":true}
```

Submit to `/api/v1/ssh/jobs`. Results contain each command index, stdout, stderr,
exit code, elapsed seconds and authenticated profile. Nonzero shell exit is failure.
Network CLIs return `exit_code:null`, `completion:prompt`, and `cli_error` for
recognizable CLI rejection messages; this is not a full semantic check of output. `stop_on_error:false` continues
the sequence. Maximum 100 operations, 32 MiB command/job results and a configurable
`job_timeout` (default 7200 seconds). A lost/timeout command response is fenced,
not retried. Closing SSH cannot guarantee the command stopped on the device.

### Device types and command modes

`device_type` selects how SSH communicates; it does not translate command syntax.
Set it per request or on a device in `devices.json`. Requests override inventory,
and the API persists the resolved type when queuing. If neither supplies a type,
`linux` keeps the original shell behavior. There is no automatic platform probing;
for a switch submitted by IP alone, specify its type. F5 upgrade jobs already use
the dedicated F5 workflow and need no additional field.

| `device_type` | SSH behavior | Example command |
| --- | --- | --- |
| `linux` | Shell exec, process exit code | `uname -a` |
| `f5` | Bash shell exec, process exit code | `tmsh show sys version` |
| `cisco_ios` | Interactive IOS / IOS-XE CLI | `show version` |
| `cisco_nxos` | Interactive NX-OS CLI | `show version` |
| `arista_eos` | Interactive EOS CLI | `show version` |

Discover supported types and modes through authenticated
`GET /api/v1/ssh/device-types`. Device inventory responses also include the type.
The F5 profile expects a bash-capable account, as the upgrade workflow does.

```json
{
  "device": "192.0.2.30",
  "device_type": "cisco_ios",
  "commands": [
    {"command": "show version", "timeout_seconds": 60},
    {"command": "show interfaces status", "timeout_seconds": 60}
  ]
}
```

Network platforms use [Netmiko's platform drivers](https://github.com/ktbyers/netmiko)
to manage prompts and disable session paging. Send one line per command. To make
configuration changes, use `mode:config` on each configuration command:

```json
{
  "device": "192.0.2.30",
  "device_type": "cisco_ios",
  "commands": [
    {"command": "interface GigabitEthernet1/0/1", "mode": "config"},
    {"command": "description Application uplink", "mode": "config"},
    {"command": "show interfaces description", "mode": "exec"}
  ]
}
```

Configuration submode is preserved between configuration entries; switching to
`exec` exits configuration mode. No configuration save is implicit. Config mode
requests privilege elevation automatically. Use job-level `enable:true` for
privileged exec commands. The selected encrypted SSH credential may contain an
`enable_password`; it is encrypted and redacted like the login password. An
enable/authorization failure does not trigger credential replay. Login fallback
still tries eligible profiles when none are specified and reports all attempts.

Commands that require interactive confirmation or an additional dialogue are not
supported by this API. Use native noninteractive command variants. A timeout,
cancellation, or lost session stops dispatch and retains the recovery fence; it
never retries a potentially applied command. The central application remains
responsible for interpreting successful output and submitting remediation jobs.

Configure HTTPS targets in `NETOPS_HTTP_TARGETS_FILE` (see
`http-targets.example.json`). Each has a fixed HTTPS origin and an explicitly
read-only authentication probe. This probe is required even for GET jobs because
some device APIs perform operations through GET. TLS certificates are verified;
`ca_file` supports a private CA. Redirects and environment proxies are disabled.

For Panorama, provision an HTTP profile using `scheme:header`, `header:X-PAN-KEY`
and an encrypted API key in `token`. The example probe uses `type=version`.
Then submit this to `/http/jobs`:

```json
{"target":"panorama","requests":[{"method":"POST","path":"/api/","form":{"type":"op","target":"FIREWALL_SERIAL","cmd":"<show><system><info/></system></show>"}}]}
```

The probe selects a credential **before** sending an operation. An HTTP 401 or
Panorama authentication rejection can move to the next profile. Permission errors,
network failures, and ambiguous operation replies do not trigger credential replay.
The actual operation is sent once. Results include HTTP status, response body,
selected content/location/retry headers, duration and profile. HTTP 2xx determines
transport success; the main application must interpret vendor body errors.
Responses are bounded to 4 MiB each/32 MiB per job. Basic, bearer and named-header
credentials are supported. Use `params`, `form`, `json_body` or `body` as appropriate;
paths must remain relative to the configured target. Authentication belongs in
profiles rather than submitted headers. `parent_job_id` links follow-up jobs.

## Device trust: self-signed certificates and host keys

Devices usually present self-signed certificates. Firewall management APIs used by
PAN-OS executor uploads, and HTTP targets configured with `"tls": "pin"`, trust the
certificate an endpoint presents the **first** time and pin its SHA-256 fingerprint in
the job store (shared by every worker). Afterwards only that certificate is accepted.
The check runs during the TLS handshake, before any request, API key or password is
sent, so a changed certificate stops the job without exposing credentials. Set
`NETOPS_FIREWALL_CA_FILE` to verify firewall certificates against a CA instead.

SSH works the same way with `NETOPS_SSH_HOST_KEYS=pin`: a host missing from
`NETOPS_KNOWN_HOSTS` has its key pinned on first use and a different key is rejected.
Entries in the known_hosts file always take precedence. The default remains
`known_hosts`, which rejects unknown hosts.

After a certificate or host key is legitimately replaced, inspect the device, then
reset its pin; the next connection pins the new one:

```http
GET /api/v1/pins
DELETE /api/v1/pins/tls:192.0.2.10:443
DELETE /api/v1/pins/ssh:192.0.2.10:22
```

Pinning trusts the first connection. Make that first connection from the executor's
network, ideally during a preload, or pre-seed known_hosts where SSH keys are known.

### PAN-OS device API keys from saved credentials

Firewall management APIs can use an `http` profile with `scheme: keygen` instead of a
stored API key. At connection time the executor exchanges the saved username and
password for an API key (`type=keygen`, password in the POST body, never the URL),
uses it for that connection only and never stores it. A rejected login moves to the
next eligible profile and cools down for 60 seconds, as for other credentials:

```json
{"kind": "http", "scheme": "keygen", "username": "automation", "password": "SECRET", "targets": ["007951000123456", "198.51.100.20"]}
```

`targets` limits the profile to firewall serials or management addresses. Panorama
targets keep their stored `X-PAN-KEY` profile.

## Encrypted credentials and Ansible

Device credentials are encrypted in SQLite with authenticated Fernet encryption.
The independent keyring file is owner-only and configured by
`NETOPS_CREDENTIAL_KEY_FILE`. It contains one Fernet key per line; the first encrypts,
all can decrypt. Back up it separately from the database. This protects a stolen
DB copy, not a compromised remote/root account: the running service can decrypt.

Generate once with `netops-executor init-key /path/credentials.key`. Upsert profiles
using the API; GET returns only ID, kind, priority, enabled, revision and timestamp.
Identical PUTs do not bump revisions; changed secrets/metadata do. Omit profiles
from requests for automatic selection; `targets` can limit them to exact IPs or
inventory/HTTP target IDs. Disable a profile with a full PUT containing
`enabled:false`. Existing established sessions finish; reconnects read current
profile revisions without restarting workers.

Example credential bodies for `PUT /api/v1/credentials/PROFILE_ID`:

```json
{"kind":"ssh","username":"root","password":"SECRET","priority":20,"targets":["192.0.2.10"]}
```

```json
{"kind":"snmp","username":"reader","security_level":"authPriv","auth_protocol":"SHA256","auth_password":"SECRET_AT_LEAST_8_BYTES","priv_password":"SECRET_AT_LEAST_8_BYTES"}
```

```json
{"kind":"http","scheme":"header","header":"X-PAN-KEY","token":"SECRET"}
```

```json
{"kind":"ucs","passphrase":"SECRET"}
```

SSH also accepts private-key PEM in `private_key` and its optional `passphrase`.
HTTP basic uses `scheme:basic`, `username`, `password`; bearer uses `token`.
UCS encryption selects the first eligible passphrase profile, since archive
creation has no remote authentication test. A specified `ucs_credential`
restricts that choice. Unencrypted UCS must be explicitly requested.

Authentication fallbacks record profile ID, revision, target, protocol, phase,
time and outcome. `credential_summary.profiles_used`, `current_profile`, and
`multiple_profiles_used` distinguish successful credentials from rejected attempts.
The complete `credential_usage` history identifies TACACS before reboot and local
credentials afterward. Known secret strings are redacted from generic command
responses; treat arbitrary device output as sensitive regardless. Do not embed
secrets in commands or HTTP payloads, which are retained as job requests.

Only positive authentication rejection triggers fallback; transport/host-key/
permission failures do not. Rejected target/profile revisions cool down for
60 seconds, shared across workers. SNMP agents may silently discard bad digests;
a timeout alone cannot prove bad credentials and does not trigger guessing.
All eligible profiles are tried when no selection is specified. Pin a smaller
list per job or target when appropriate for device authentication policies.

For key rotation: atomically write an owner-only keyring containing **new key
first, old keys after it**; call `/credentials/rotate`; retain old keys until all
processes/backup recovery needs are accounted for, then remove them. Rotation
rewrites ciphertext transactionally without changing credential IDs or revisions.
Never overwrite the only key before rotating the database.

`deploy/ansible/deploy.yml` provisions Ubuntu 24.04/RHEL 9, systemd API/workers,
private directories, a key generated **only if missing**, and idempotent credential
upserts over the remote's loopback API. Supply `executor_api_token` and
`executor_credentials` from **Ansible Vault**, not plaintext repository variables.
Credential tasks have `no_log:true`; only the API token/key path is in service.env.

```yaml
# Encrypt this file with ansible-vault before storing it.
executor_api_token: REPLACE_WITH_RANDOM_TOKEN_AT_LEAST_32_CHARACTERS
executor_workers: 3
executor_credentials:
  ssh-tacacs:
    kind: ssh
    username: automation
    password: REPLACE_WITH_SECRET
    priority: 10
  ssh-local:
    kind: ssh
    username: root
    password: REPLACE_WITH_SECRET
    priority: 20
  ucs:
    kind: ucs
    passphrase: REPLACE_WITH_SECRET
  f5-admin-standard:
    kind: f5_admin
    password: REPLACE_WITH_EXPECTED_ADMIN_PASSWORD
    targets: [192.0.2.10, 192.0.2.11, 192.0.2.12]
```

```bash
ansible-playbook -i inventory deploy/ansible/deploy.yml -e @vault.yml --ask-vault-pass
```

Set `executor_devices`, `executor_http_targets`, and verified
`executor_known_hosts` for your environment. Existing workers drain before code
updates; new workers start after credential provisioning. The playbook does not
set up your external TLS proxy. To change credentials without redeploying code,
use the same `ansible.builtin.uri` PUT task with `no_log:true`; full replacements
are idempotent. Rebuilt remotes can generate a fresh key and repopulate credentials
from Vault, but lost job/backup volumes cannot reconstruct rollback history.

Legacy inventory references (`password_env`, `key_file`, `key_passphrase_env`,
`ucs_passphrase_env`) and SNMP profile files remain supported for migration.
Once encrypted profiles of a protocol exist, automatic selection uses them.
Explicit legacy SNMP `profile` can still select a configured environment profile.
New deployments should use encrypted profiles.

## SNMP v3 walks

Submit an IPv4/IPv6 address and numeric OID subtrees to `/snmp/walks`:

```json
{"device_ip":"192.0.2.10","oids":["1.3.6.1.2.1.1","1.3.6.1.4.1.3375"]}
```

`credential_profiles` optionally restricts selection. SNMP v3 only: authPriv,
authNoPriv or noAuthNoPriv, SHA/SHA224/SHA256/SHA384/SHA512, AES128 privacy.
Authentication/privacy passphrases need at least eight UTF-8 bytes. Profiles
support a context name. Credentials never appear in walk job requests.

Walks use GETNEXT, one root at a time, and stop at the subtree boundary. To retrieve
a scalar instance, walk its parent. Roots can overlap; results retain `root_oid`.
An accessible empty subtree succeeds, but SNMP cannot distinguish absent data
from data hidden by the agent's access controls.

Poll the job and `/snmp/walks/{id}/results?after=0&limit=500`. Rows contain
`seq,root_oid,oid,type,value,encoding`; the page contains `finished`, `has_more`
and `next_cursor`. Advance `after` to `next_cursor`. Stop only when `finished`
is true **and** `has_more` is false. Empty live pages require continued polling.
Octet strings are base64; integers/counters and other textual values are strings
to preserve precision. IP addresses are dotted text.

Bounds: 1–64 roots; port 161 default; per-request timeout 2 seconds (0.1–30),
retries 1 (0–5); job timeout 300 seconds (1–3600); maximum rows 10000
(1–100000). A fixed 16 MiB result limit also applies. Limits/timeouts fail the job
with partial results retained. Authentication fallback is allowed before a root
produces data; partial roots are never replayed with another identity.

Walks to the same IP/port serialize; SNMP reads may overlap upgrades and observe
transitional state. Stale SNMP workers fail and release their read reservations.
Cancellation retains committed rows. Job/result retention is manual.

## Deployment and CLI

Python 3.11+ is required. Ubuntu 24.04 supplies 3.12; use the Python 3.11 suite
on RHEL 9.2+. Install pinned `requirements.lock`, then the package with `--no-deps`.
Native systemd units and environment example are in `deploy/`; the Ansible
playbook automates this setup. API/workers must share the same paths and user.
The image/cache directory must be writable for URL downloads.

Docker, from this directory:

```bash
cp .env.example .env
mkdir -p config images
printf '[]\n' > config/devices.json
cp http-targets.example.json config/http-targets.json
# Populate token in .env, target configuration and VERIFIED config/known_hosts.
# Generate config/credentials.key once using the installed CLI, or the image:
docker compose build
docker compose run --rm --no-deps --user "$(id -u):$(id -g)" \
  -v "$PWD/config:/key-output:z" api netops-executor init-key /key-output/credentials.key
# Set private key/config ownership to container UID 10001; never world-readable.
# Also grant UID 10001 write access to images/ for the cache.
chmod 600 .env
docker compose up -d --scale worker=3
```

Use an HTTPS reverse proxy for central API access; default bind is loopback.
To publish it under a path such as `https://<server>/netops-executor/`, set
`NETOPS_ROOT_PATH=/netops-executor` and restart the API, so `/docs` and batch
`status_url` values carry the prefix; the console already uses relative links.
`deploy/apache-netops-executor.conf` is a tested Apache httpd 2.4 configuration for
that layout. The proxy may strip the prefix or pass it through, and direct requests to
the listener (health checks, the CLI on the host) keep working without it.
Persist `data`, `backups`, and the external keyring. Do not use `down -v` if job
history is needed. SELinux mounts use `:z` for sharing. Containers run as UID 10001.

SSH uses verified known_hosts and rejects unknown/changed keys. The device account
needs bash, SFTP, tmsh administrator rights and filesystem access for images/UCS;
no implicit sudo or restricted-shell bypass is attempted. Use canonical inventory
addresses and do not change identities/lock groups while jobs are active.

```bash
netops-executor plan --device 192.0.2.10 --install --images images.json \
  --allowed-source-version 16.1.5 --no-reboot
netops-executor request --kind batch --file batch.json --idempotency-key change123
netops-executor request --kind ssh --file commands.json
netops-executor request --kind http --file requests.json
netops-executor request --kind snmp --file walk.json
netops-executor request --kind panos-batch --file panos-batch.json --idempotency-key change456
netops-executor request --kind panos --file panos-upgrade.json
netops-executor request --kind eos-batch --file eos-batch.json --idempotency-key change789
netops-executor request --kind eos --file eos-upgrade.json
netops-executor request --kind iosxe-batch --file iosxe-batch.json --idempotency-key change790
netops-executor request --kind iosxe --file iosxe-upgrade.json
netops-executor request --kind iosxe-config-compare --file before-after.json
netops-executor request --kind ios-batch --file c2960x-batch.json --idempotency-key change791
netops-executor credential-put ssh-local --file -       # JSON from stdin
netops-executor job JOB_UUID
netops-executor batch BATCH_UUID
netops-executor cancel JOB_UUID
netops-executor validation JOB_UUID --action accept --gate-id GATE_UUID --revision 1 \
  --operator jason --reason 'Application traffic verified'
netops-executor mark-done JOB_UUID --operator jason --reason 'Handled manually'
netops-executor rollback JOB_UUID --idempotency-key change123-rollback
netops-executor resolve JOB_UUID --worker-stopped --device-inspected \
  --note 'Worker stopped; boot and address state reconciled'
```

Use `request --file -` for stdin. Flat upgrade options have named CLI flags;
JSON exposes every advanced policy. Set `NETOPS_API_URL`/`NETOPS_API_TOKEN` in `.env`
or use `--url`/`--env-file`. Secrets are never command-line credential arguments.

## Verification and platform scope

Tests cover SQLite concurrency and wave barriers, credential encryption/rotation,
fallback/audit, cancellation, manual continuation without replay, HA active-first
handoff, HTTP operation fencing, image/config/drain/rollback sequencing, synthetic
F5 parsers, and real SNMP v3 loopback exchanges. Run:

```bash
pip install -e '.[test]'
pytest -q
ruff check .
ruff format --check .
node --check netops_executor/static/app.js
```

Prevalidation, HA discovery and reservations, traffic ownership, peer health,
validation sampling and virtual-address disable/enable were exercised against
BIG-IP VE 17.5.1.9/17.5.1.10 lab units. Installation, reboot and rollback were not.
Real-appliance acceptance on your exact TMOS versions is still required. Supported
scope is single-system BIG-IP appliances/VE and verified two-member active/standby
pairs. F5OS, VIPRION slot orchestration, vCMP hosts, active-active traffic groups
and multi-host shared queues are not implemented. Unrecognized critical device
output fails closed. The WAF traffic gate requires the configured log adapter or
manual acceptance; it does not assume a universal SSH request-log interface.

PAN-OS upgrades are tested against a simulated Panorama and firewalls, and partly
against a PA-VM 12.1.6 active/passive lab pair without a Panorama using
`tests/lab/panos_direct.py`. That harness runs the real runner and sends every
proxied request straight to the firewall's XML API; only Panorama's own commands are
emulated. Lab-verified on 12.1.6: prechecks, HA state parsing (including disabled
config sync), traffic baselines, running config and tech support export, HA election
set and commit, the standby-first suspend, functional, failover and validation
sequence, image import and staging of 12.2.2, an executor preload (`software_source: executor`)
that uploaded 1.7 GB in about two minutes with live byte progress, survived the
firewall's HTTP 504 and confirmed the image by SHA-256 about 16 minutes later while the
other member was skipped as already staged, and an install refused by the firewall
(unlicensed VM: "Base license is not valid") returning the suspended standby to
service and failing cleanly, and a same-version reboot of a suspended standby, which
showed that PAN-OS 12.1.6 returns a suspended member to service (passive) after a
reboot. Not yet verified on real devices: Panorama's device list fields, the batch
software commands (taken from published community automation rather than the API
reference), the `target` relay itself, install and reboot on a newer image,
suspending a member after failed validation, active/active state names and the F5 drain against a real
BIG-IP. A successful install needs licensed firewalls. Lab acceptance through a
real Panorama is required before production use. Supported scope is standalone
firewalls and active/passive or active/active pairs managed by one Panorama. Firewall
clusters, Advanced Routing Engine route comparison and automatic downgrade are not
implemented.

Command references: [virtual addresses](https://clouddocs.f5.com/cli/tmsh-reference/latest/modules/ltm/ltm_virtual-address.html),
[UCS](https://clouddocs.f5.com/cli/tmsh-reference/latest/modules/sys/sys_ucs.html),
[software installation](https://clouddocs.f5.com/cli/tmsh-reference/latest/modules/sys/sys_software_image.html),
[volumes](https://clouddocs.f5.com/cli/tmsh-reference/latest/modules/sys/sys_software_volume.html),
[traffic groups](https://clouddocs.f5.com/cli/tmsh-reference/latest/modules/cm/cm_traffic-group.html).

## Updating from f5-upgrade

Version 0.4 renames the directory to `services/netops-executor`, the Python package
to `netops_executor`, the executable/image to `netops-executor`, and units to
`netops-executor-api` / `netops-executor-worker@N`. The old `f5-upgrade` executable
remains an alias. Use `NETOPS_*` environment names; legacy `F5_*` names still work
when the corresponding new name is absent. API URLs, job IDs, SQLite tables,
credential encryption format and reservation keys are unchanged.

Before updating, stop/drain every old worker and the API. Preserve the database
(including WAL files if present), backups and encryption key together. Never run
old and new workers concurrently against separate databases for the same devices.

The Ansible playbook drains/disables both sets of units, moves legacy `/etc`,
`/var/lib` and `/var/backups/f5-upgrade` directories to `netops-executor`, preserves
the encryption key, and refuses to overwrite an existing destination store. It
leaves an `/etc/f5-upgrade` compatibility symlink for inventory key paths. Supply
the same inventory and credential variables on redeploy. Legacy application files
and the disabled service account can be removed after verification.

Compose retains the historical default project name `f5-upgrade` so directory
renaming does not silently allocate empty data/backup volumes. If your deployment
uses a custom project name, keep it with `docker compose -p YOUR_EXISTING_PROJECT`
or `NETOPS_COMPOSE_PROJECT`. Stop the old stack without `--volumes`, copy its
`.env`, `config` and `images` directories into the new service directory, and
rebuild/start with the same project name. New installations may set
`NETOPS_COMPOSE_PROJECT=netops-executor`. UID 10001 is unchanged. Host installations
can retain old storage paths through environment variables; update all unit
paths together if moving them. Reinstall into a clean virtual environment so
obsolete Python package entry points cannot select old code.
