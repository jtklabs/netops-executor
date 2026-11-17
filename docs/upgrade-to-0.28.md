# After deploying 0.28.0

0.28.0 extends local password rotation. Linux and Opengear logins without UID 0 (such
as TACACS users) now elevate with sudo. Every platform proves that the device
accepted the change. It also adds a Panorama-wide rotation job and preview support
for Junos, ArubaOS 8, Check Point Gaia, ClearPass and Infoblox. The README's
"Local account password rotation" section describes each in full.

## 1. Confirm the release

- [ ] `GET /healthz` returns `"version": "0.28.0"`.
- [ ] `GET /api/v1/workers` shows every worker on 0.28.0.

## 2. Linux and Opengear with a TACACS login

- [ ] Rotate a test account on one Linux host and one Opengear where the SSH
      credential is a TACACS user. The selected credential's password must be the
      one `sudo -i` asks for.
- [ ] Check the job result: `privilege` is `sudo`, `change_accepted` is `true`,
      and `confirmed` is `["account_changed"]`.

## 3. Palo Alto with a TACACS admin role

- [ ] Rotate a test account on one firewall, directly and through Panorama, with
      the TACACS login you use in production. A successful job shows
      `confirmed: ["candidate_hash", "commit", "running_hash"]`.
- [ ] If the role may not edit administrators or commit, the job fails with
      `change_accepted: false` and "permission denied". Check that the firewall has
      no leftover candidate change or lock (`show config-locks`, `show commit-locks`).
      Then fix the role or use a different credential.

## 4. Panorama-wide rotation (preview)

- [ ] On a non-production Panorama, or with a test account, run
      `POST /api/v1/password-rotation/panorama/plan`, then the job with
      `allow_preview: true`. Start with `"templates": false` and a few `serials` to
      check the firewall phase on its own.
- [ ] Check `result.templates`, `result.firewalls`, `result.summary` and
      `result.push_required`. Push the listed template stacks from Panorama when
      you are ready; the job never pushes.

## 5. Preview platforms (only those you use)

- [ ] **Junos, ArubaOS, Check Point:** rotate a test account on a lab or
      non-production device with `allow_preview: true` and review `confirmed`.
      ArubaOS refuses to start while any node has pending changes.
- [ ] **ClearPass:** add an `http-targets.json` entry with a read-only
      `auth_probe_path`, and an `oauth2` credential (client-credentials API client)
      for it. For `api_login`, also add a second API client with the password grant,
      saved as `<http_target>-password-grant`. Configure a ClearPass service that
      authenticates the Admin User Repository for that grant.
- [ ] **Infoblox:** add an `http-targets.json` entry whose `auth_probe_path` names
      the WAPI version (for example `/wapi/v2.12/grid`) and a `basic` credential.
      Passwords must be printable ASCII.

## 6. After each successful rotation

- [ ] Rotation never updates saved credential profiles. If the executor itself logs
      in with the rotated account, update that profile with
      `PUT /api/v1/credentials/{profile}`.
