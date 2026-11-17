# After deploying 0.27.0

A checklist for moving a production executor from 0.24.x to 0.27.0. It covers the
releases in between: Opengear sudo for TACACS logins (0.24.1), the BIG-IP VE serial
fallback and poller-scoped NetBox matching (0.24.2–0.24.3), and the 0.27.0 review
fixes, SSH host-key alerts and metrics changes. The README describes each feature in
full.

## 1. Confirm the release

- [ ] `GET /healthz` returns `"version": "0.27.0"`.
- [ ] `GET /api/v1/workers` shows every worker on 0.27.0. Restart any still on the
      old release.

## 2. Configuration

- [ ] **Opt in an SSH profile for discovery.** Hosts found by SNMP discovery that are
      not in the inventory now receive only SSH profiles opted in for discovery or
      listing their IP in `targets`. Without one, F5 license serials and SSH
      enrichment are skipped, and the job reports the reason. Use a read-only account:

      ```http
      PUT /api/v1/credentials/discovery-ro
      {"kind":"ssh","username":"netops-ro","password":"SECRET","discovery":true}
      ```

      `PUT` replaces the whole profile, so send every field again (password
      included) when updating an existing one.
- [ ] **Email.** Set the `NETOPS_SMTP_*` relay settings and `NETOPS_ALERT_EMAIL`.
      Leave `NETOPS_SMTP_USERNAME` and `NETOPS_SMTP_PASSWORD` empty for a relay
      without login. Restart the API and workers, then send a test:

      ```http
      POST /api/v1/email/test
      {"to": ["netops@example.com"]}
      ```

      `GET /api/v1/email` shows the relay and any delivery failures.
- [ ] **Prometheus.** Set `NETOPS_METRICS_TOKEN` (32+ characters, different from the
      API token) and point Prometheus's `credentials_file` at it (see
      `deploy/prometheus/netops-executor.yml`). It opens `/metrics` only. Confirm
      the scrape returns 200 and the Grafana dashboard shows data.
- [ ] **Host-key mode.** Check `NETOPS_SSH_HOST_KEYS`. With `pin`, a changed key is
      trusted through the API. With `known_hosts` (the default), update
      `NETOPS_KNOWN_HOSTS` instead.
- [ ] **F5 upgrade accounts** must use the bash (Advanced Shell) login shell. F5
      upgrades now refuse a tmsh-shell account before changing anything.

## 3. Check each feature

- [ ] **Opengear with a TACACS login.** Run a `stage_only` upgrade job. It should pass
      pre-validation, upload the image and verify its SHA-256 without flashing. The
      selected SSH credential's password must be the one the account uses for
      `sudo -i`.
- [ ] **BIG-IP VE serial.** Rerun discovery and check `result.discovery`:
  - `serial_source` is `license` when SSH worked, otherwise `snmp`.
  - `license_lookup.status` and `license_lookup.reason` explain the outcome.
  - The NetBox serial and the Lifecycle license records are filled.
- [ ] **Primary IPs (for example Arista).** Rerun discovery and confirm the device has
      its primary IP in NetBox. If it does not, read
      `result.discovery.management_ip`, `management_ip_lookup` and
      `management_ip_sync`: a null `management_ip` means SNMP did not report the
      polled address; a failed `management_ip_sync` gives NetBox's reason.
- [ ] **Poller ownership.** After the next discovery, devices carry the
      `discovery_poller` custom field. The executor creates it automatically.
- [ ] **Regional manual devices.** For a device seeded from manual data under a
      regional poller, run discovery from the poller that can reach it. The job
      shows `result.discovery.netbox_takeover`, and the device carries only the new
      poller's tag.
- [ ] **Host-key alerts.** `GET /api/v1/host-keys/alerts?state=open` should be empty.
      Anything listed is a real key change to review.

## 4. Watch the first few days

- [ ] Jobs that complete with warnings can be expected. Check:
  - `result.discovery.manual_fields`: SNMP returned blanks and an existing NetBox
    value was kept (`netbox-existing`).
  - `license_lookup` or `management_ip_sync` failures.
- [ ] Each changed SSH host key sends one email. Trust a key only after confirming
      the change is expected (`POST /api/v1/host-keys/alerts/{id}/trust` in pin
      mode).
