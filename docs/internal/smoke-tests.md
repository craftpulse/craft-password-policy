# Smoke tests — manual-only scenarios

Pest already covers what can be expressed against PHP unit + integration boundaries. This document covers the rest — anything that requires a browser, an email client, an external network endpoint, a real Craft session, a multi-site install, or a human eye on visual rendering. **Walk this end-to-end before tagging 5.2.0.**

This is the surface that pure code review can't validate. A clean Pest pass + clean PHPStan/ECS + a manual sign-off across this document = ship-ready.

## How to use

- Each scenario carries an ID like `S<area>.<n>` (e.g. `S5.3`). Use it to file failures.
- **Preconditions** — set up before running the steps. Reusable preconditions live in `## Pre-flight` below.
- **Steps** — numbered, terse, no editorialising.
- **Expected** — the observable signal that proves the scenario passes.
- **If it fails** — capture: page URL, browser console error, Network tab (if AJAX), Mailpit body snapshot (if email), plugin log tail (`storage/logs/password-policy-*.log`), commit hash (`git rev-parse HEAD`). Then either reproduce in Pest or record the failure on the scenario row.

Scenarios marked `(Pro)` or `(Enterprise)` require the project-config edition flip first — see `S13.x` for the flip procedure.

## Pre-flight

| ID | Setup |
|---|---|
| **P.1** Playground state | `git pull` on the plugin; `ddev craft up` on the playground; verify `composer test` is green; verify `CRAFT_AUDIT_PII_KEY` env var present; verify Mailpit is reachable (`ddev describe \| grep -i mailpit`). |
| **P.2** Edition flip recipe | Edit `config/project/project.yaml` → `plugins.password-policy.settings.edition: lite\|pro\|enterprise`. Bump the top-of-file `dateModified` timestamp. Run `ddev craft up`. Refresh the CP. |
| **P.3** Reset between blocks | If a block leaves user-state mutations (force-reset flags, history entries, notification log rows): `ddev craft password-policy/gc/run --force` to flush retention-eligible rows; or restore a baseline DB snapshot if available. |
| **P.4** Dev vs production Craft mode | Some scenarios depend on `CRAFT_DEV_MODE` posture. Default is dev; flip to production via `CRAFT_DEV_MODE=false` in `.env` to verify the friendly error template path. |
| **P.5** Browser matrix | At minimum: Chrome 120+, Firefox 120+, Safari 17+. iOS Safari + Android Chrome for touch interactions in §17. |

---

## §1 Onboarding & first policy

Goal: a fresh Craft 5 install + plugin install + first policy works end-to-end. The full install flow can't be Pest-tested because it exercises the actual Plugin Store install action, schema migration through Craft's migration runner, and CP form rendering.

> **Execution order note (2026-05-22):** `S1.1` and `S1.2` are **deferred to the very end of the walk**, just before `§20` pre-tag sanity. Both are destructive against the existing populated playground (S1.1 wipes all 6 tables; S1.2 needs a 5.1.x-baseline site). Run them last so the rest of §2–§19 has the fixtures it depends on (audit chain history, notification log rows, blocklist entries, password history, group policies).

### S1.1 Fresh `composer require` + plugin install on Lite

Steps:
1. Fresh Craft 5.0+ site (no prior plugin install).
2. `ddev composer require craftpulse/craft-password-policy`.
3. `ddev craft plugin/install password-policy`.

Expected: install completes with no errors; CP shows "Password Policy" entry under Settings → Plugins; plugin reports as Lite edition; six new `passwordpolicy_*` tables exist (`ddev craft password-policy/dump-tables`).

### S1.2 Upgrade from 5.1.x

Steps:
1. Site running `craftpulse/craft-password-policy:^5.1` with existing `pwned: true` + `groupPolicies` config + at least one password change history row written under the 5.1 schema.
2. `ddev composer update craftpulse/craft-password-policy`.
3. `ddev craft up`.

Expected: migration `m260429_224908_UpgradeTo520Schema` runs cleanly; `pwned` renamed to `hibp` in project config; `groupPolicies` dropped; existing user passwords seeded into the new `passwordpolicy_password_history` table with `changeReason = MigrationSeed`; schema version reads `2.11.0`; no debug log contains a bcrypt hash from the seed loop (`grep '\$2y' storage/logs/*.log | grep -i password.policy` returns empty).

### S1.3 First global policy save

Steps:
1. From `S1.1`. Navigate to Settings → Password Policy → Configuration.
2. Set `minLength = 12`, enable HIBP, save.
3. Open Users → New user, enter weak password `Password123`.

Expected: settings save with green toast; new-user form rejects with per-rule pass/fail next to the field; strength meter renders red.

### S1.4 Strength indicator toggle

Steps:
1. Settings → Password Policy → **Configuration** → toggle "Show strength indicator" on. (NOT under Validators — corrected 2026-05-22 during Phase H walk.)
2. Navigate to **My Account → Change password** (the user's own password change form). The indicator does NOT render on Users → New user (admin-side user creation); it's scoped to the self-service password change surface.
3. Type into the password field, watch the strength meter.

Expected: strength meter visible; bars update on input with ~250ms debounce; `aria-valuenow` attribute updates on the `<div role="progressbar">`.

Known open findings (see `progress.md` Phase H smoke-test findings log):
- Strength meter does not render in the playground's custom user-edit modal. Scope: asset registration fires only on `View::EVENT_BEFORE_RENDER_PAGE_TEMPLATE`, which modal partial renders skip. Deferred to a broader modal-rework pass.
- Debounce feels laggier than ~250ms on the live page — perf review pending before tag.

### S1.5 CSP nonce flow

Steps:
1. Settings → Password Policy → Validation → enable "Generate CSP nonce".
2. Configure a Content-Security-Policy response header that requires script nonces (via `config/general.php` or a reverse proxy).
3. Reload the Users index.

Expected: strength meter script tag carries `nonce="<value>"`; browser console has no CSP violation; meter still functions.

### S1.6 Force-change-on-first-login

Steps:
1. Settings → Password Policy → Configuration → enable "Force change on first login".
2. Create a new user via Users → New user with a temporary password.
3. Log out of admin. Log in as the new user.

Expected: new user is redirected to a force-change-password form on first sign-in; admin session remains untouched (`maxInvalidLogins` not triggered).

---

## §2 CP settings forms

Goal: every settings subnav renders, saves, and gates correctly across editions. Pest covers the strip-on-save defense logic; this verifies the actual form rendering + browser submission.

### S2.1 Every subnav renders without console error

Steps:
1. Cycle through every Settings → Password Policy subnav item: Configuration, Password Rules, Password Retention, Password History, Validators, Group Policies, Compliance Presets, Audit Logging.
2. Open browser DevTools console before clicking each.

Expected: every page renders without JavaScript errors. Pro-gated subnavs (Group Policies, Compliance Presets) show the Pro badge on Lite. Audit Logging shows the Enterprise badge on non-Enterprise.

### S2.2 Strip-on-save defense — crafted POST

Steps:
1. Switch to Lite via `P.2`.
2. Open Configuration subnav. Open browser DevTools → Network tab.
3. Capture the save POST request. Replay with `curl` adding a Pro-only payload field — e.g. `settings[checkSequentialChars]=1` or an Enterprise field like `settings[siemEnabled]=1`.

Expected: response is success (settings save with the legitimate fields); `ddev craft project-config/get plugins.password-policy.settings` shows no `checkSequentialChars` or `siemEnabled` value persisted. The strip block ate the crafted field.

### S2.3 `allowAdminChanges=false` posture

Steps:
1. Set `allowAdminChanges = false` in `config/general.php`.
2. Open Settings → Password Policy → Configuration.
3. Attempt to save.

Expected: page renders in read-only mode (admins can VIEW); save submission returns 403 with the plugin-specific error `"Unable to edit Password Policy plugin settings because admin changes are disabled in this environment."`. **NOT** the generic Craft "Administrative changes are disallowed" message — the plugin's own.

### S2.4 Compliance Presets — Pro gate

Steps:
1. On Lite. Open Settings → Password Policy → Compliance Presets.
2. Observe the page.

Expected: presets list renders; every Apply button disabled with tooltip "Pro edition required to apply this preset."; `:::tip` edition gate callout shows above the table. No 403, no broken page — visible but locked.

### S2.5 Compliance Presets — apply on Pro

Steps:
1. Flip to Pro. Open Settings → Password Policy → Compliance Presets.
2. Apply the NIST 800-63B preset.

Expected: success toast; `ddev craft project-config/get plugins.password-policy.settings.minLength` returns `15`; `checkCommonPasswords` = `true`; `hibp` = `true`; `cases`/`numbers`/`symbols` = `false`; `expiryAmount` = `null`.

### S2.6 Compliance Presets — STRICT_ENTERPRISE on Pro

Steps:
1. From `S2.5`. Apply the Strict Enterprise preset.

Expected: warning callout displayed before apply or in the apply flow indicating composition/contextual/sequential/repeated checks will be enabled; after apply, those four checkboxes are on in Validators subnav.

### S2.7 `checkCommonPasswords` toggle behaviour

Steps:
1. On Lite. Settings → Password Policy → Validators. Toggle "Block common passwords" on (was off). Save.
2. Observe the Notice toast.
3. `ddev craft queue/run --verbose`.
4. Query the blocklist table count: `ddev craft password-policy/blocklist/count`.

Expected: toast says "Common password blocklist will be seeded in the background." Queue runs `SeedBlocklist` job. Count returns >= 9,500 entries (the bundled SecLists Common-Credentials list — ~10,000 entries).

---

## §3 Validators on real password input

Goal: each validator rejects the right inputs, accepts the right inputs, and surfaces the right error message in the CP New User form. Pest verifies validator logic in isolation; this verifies the validator → CP error message → strength meter pipeline.

### S3.1 Min/max length

Setup: `minLength = 12`, `maxLength = 64`.

Steps:
1. New user form. Enter `Short`.
2. Submit.
3. Enter a 65-char string. Submit.

Expected: 1) rejected with `"The password must be at least 12 characters."`. 2) rejected with the max-length error.

### S3.2 Complexity (individual) — `cases`, `numbers`, `symbols`

Setup: `cases = true`, `numbers = true`, `symbols = true`.

Steps:
1. Enter `alllowercase`. Submit.
2. Enter `Cases12345`. Submit.
3. Enter `Cases1234!`. Submit.

Expected: 1) rejected, missing uppercase. 2) rejected, missing symbol. 3) accepted.

### S3.3 Complexity (minimum) — X-of-4

Setup: `complexityMode = minimum`, `minimumCharacterTypes = 3`.

Steps:
1. Enter `alllowercase` (1 type). Submit.
2. Enter `Cases1234` (3 types). Submit.

Expected: 1) rejected, "at least 3 of 4 character types". 2) accepted.

### S3.4 HIBP at change time

Setup: HIBP enabled, `hibpFailMode = open`, real network.

Steps:
1. Enter known-breached `Password1234`. Submit.

Expected: rejected with breach-database error message. Network tab shows a GET to `https://api.pwnedpasswords.com/range/<5-char-prefix>`.

### S3.5 HIBP fail-mode closed during outage

Setup: HIBP enabled, `hibpFailMode = closed`. Block outbound HIBP (e.g. `/etc/hosts` → `127.0.0.1 api.pwnedpasswords.com`).

Steps:
1. Enter a never-breached strong password. Submit.

Expected: rejected with a "could not verify against breach database" error message. Plugin log captures a warning, NOT an error. Restore networking after.

### S3.6 Sequential characters (Pro)

Setup: Pro. Validators → enable "Block sequential characters".

Steps:
1. Enter `Welcome_qwerty`. Submit.
2. Enter `Welcome_abc123`. Submit.
3. Enter `Welcome_pqr789`. Submit (ASCII adjacency).

Expected: all three rejected with sequential-chars message.

### S3.7 Repeated characters (Pro)

Setup: Pro. Validators → enable "Block repeated characters".

Steps:
1. Enter `Welcomeaaa`. Submit.
2. Enter `Welcome111`. Submit.
3. Enter `Welcome!!!`. Submit.

Expected: all three rejected.

### S3.8 Contextual (Pro)

Setup: Pro. Validators → enable "Block contextual passwords". New user with `email = jdoe@example.com`, `firstName = John`, `lastName = Doe`.

Steps:
1. Enter `Jdoe2024!Abc` (contains username local-part). Submit.
2. Enter `John1234Doe!`. Submit.
3. Enter `Example1234!` (site name). Submit.

Expected: all three rejected with contextual-match message.

### S3.9 Common-password blocklist

Setup: `checkCommonPasswords = true`, blocklist seeded.

Steps:
1. Enter `password1234`. Submit.
2. Add a custom word via Blocklist editor: `acme-corp-2024`. Save. Try `acme-corp-2024` as a new user password.

Expected: both rejected. Source-aware messages: bundled hit says "This password is too common."; custom hit says "This password has been blocked."

### S3.10 Password history (every edition)

Setup: `passwordHistoryCount = 5`. User with a known recent password (e.g. `OldPass123!`).

Steps:
1. As that user, change password to `OldPass123!` (reuse).

Expected: rejected with reuse message. Then change to `NewPass123!` → accepted.

---

## §4 Front-end Twig render builders (Pro)

Goal: each builder renders, AJAX-validates, gates submit, and respects a11y. The playground's demo templates at `cms/templates/_demo/password-policy/*.twig` exercise these.

### S4.1 `passwordChangeForm()` — happy path

Preconditions: Pro. Logged-in user. Demo template at `/demo/password-policy/change`.

Steps:
1. Navigate to the demo page.
2. Enter current password + new password meeting all rules.
3. Submit.

Expected: redirect to `successRedirect` URL; user's password updated; `passwordResetRequired = false` post-change; next sign-in does NOT prompt for change.

### S4.2 `passwordChangeForm()` — AJAX live validation

Steps:
1. On the demo page from `S4.1`.
2. Open DevTools → Network. Type a password into the new-password field.

Expected: AJAX POST to `password-policy/validation/validate` fires after ~250ms debounce; response includes a per-rule pass/fail map; the requirements `<li>` elements toggle state classes accordingly; strength meter `aria-valuenow` updates.

### S4.3 `passwordChangeForm()` — submit gate

Steps:
1. On the demo page. Enter an invalid (too short) new password.
2. Observe the submit button.

Expected: submit button has `disabled` attribute. The `submitGate` selector controls the button. Enter a valid password — disabled drops.

### S4.4 `loginForm()` builder

Preconditions: Pro. Demo `/demo/password-policy/login`.

Steps:
1. Navigate to the page.
2. Try login with wrong password (5+ times to trigger lockout).
3. Try with correct credentials.

Expected: lockout fires per Craft `maxInvalidLogins` after threshold; correct credentials log in and redirect.

### S4.5 `passwordResetForm()` — token-based flow

Preconditions: Pro. User triggered a password reset (Mailpit captures the reset email with a token URL).

Steps:
1. Click the reset link in the Mailpit-captured email.
2. Land on the demo reset page (`/demo/password-policy/reset?code=...&id=...`).
3. Enter a new password and submit.

Expected: reset succeeds; user can sign in with the new password; old password rejected.

### S4.6 Show/hide toggle a11y

Steps:
1. On any demo form. Tab focus to the eye toggle.
2. Press Space/Enter.

Expected: password input `type` flips between `password` and `text`. The `<button aria-label>` flips between `"Show password"` and `"Hide password"`. The inner SVG swaps eye-open ↔ eye-slash via `style="display:none"` toggle (not class swap — verify in DevTools).

### S4.7 Strength meter as ARIA progressbar

Steps:
1. Demo page. Open DevTools → Accessibility tab.
2. Inspect the strength meter element.

Expected: role is `progressbar`; `aria-valuemin = 0`; `aria-valuemax = 4`; `aria-valuenow` updates on input. The score label (`weak`/`fair`/`good`/`strong`) is the accessible name.

### S4.8 Requirements list `aria-describedby`

Steps:
1. Demo page. Inspect the password input.

Expected: input has `aria-describedby` listing the requirements list `<ul>` id; each `<li>` has `data-pp-requirement="<key>"`. JS toggles `aria-current`/state classes on each `<li>` based on AJAX response.

### S4.9 Builder throws on Lite — dev mode

Preconditions: flip to Lite via `P.2`. `CRAFT_DEV_MODE=true`.

Steps:
1. Navigate to any demo template that uses a builder.

Expected: full Twig exception view renders, showing `craftpulse\passwordpolicy\exceptions\EditionRequiredException` as the class name, the method name (e.g. `passwordChangeForm`), and the message "requires the Pro edition. Front-end Twig render builders are a Pro feature. Lite installs should render password forms with their own markup using the universal data accessors: requirements(), requirementsText(), requirementRules()."

### S4.10 Builder throws on Lite — production mode

Preconditions: Lite. `CRAFT_DEV_MODE=false` (or `.env` `DEV_MODE=false`).

Steps:
1. Navigate to any demo template that uses a builder.

Expected: Craft's friendly error template renders ("An error occurred"). Exception details NOT exposed to the visitor. Plugin log captures the exception class + message at error level.

### S4.11 Data accessors on Lite

Preconditions: Lite. A custom template using `requirements()` / `requirementsText()` / `requirementRules()` directly.

Steps:
1. Navigate to the custom template.

Expected: accessors return the global policy as data; no throw; no edition gate. Rolling your own markup against these works on Lite.

---

## §5 Mailpit visual verification

Goal: every notification email renders correctly with token interpolation. Mailpit captures the rendered HTML; this scenarios open each captured email and inspect the body.

### S5.1 Expiry reminder — Lite stock template

Preconditions: Lite. Set `expiryReminderDays = 14`. Create a user whose password is 14 days from expiring (manipulate `lastPasswordChangeDate` directly via `ddev craft password-policy/test/set-last-change-date --user=<id> --days-ago=<N>` or DB tweak).

Steps:
1. `ddev craft password-policy/notification/send-expiry-reminders --user=<id>`.
2. Run queue: `ddev craft queue/run`.
3. Open Mailpit.

Expected: one email captured; subject mentions password expiry; body renders the user's name and days until expiry; sender matches Craft's `fromEmail`.

### S5.2 Expiry reminder — Pro editable template

Preconditions: Pro. Edit the `expiry-reminder` template via Notifications → Templates: change the subject to `"<your custom> {{ siteName }}"`. Save. Run `S5.1`.

Expected: Mailpit captures the email with the custom subject; tokens interpolated; activity log row written.

### S5.3 Breach-detected email (Pro)

Preconditions: Pro. HIBP-on-login enabled. A user with a known-breached password (`Welcome2024` or similar).

Steps:
1. Log in as that user.
2. Open Mailpit.

Expected: one `breach-detected` email captured; body mentions the breach and prompts a password change; `passwordResetRequired = true` on the user record.

### S5.4 New-device alert (Pro)

Preconditions: Pro. `enableNewDeviceAlerts = true`. User has at least one logged login previously.

Steps:
1. Clear cookies / use a private window or different browser.
2. Log in as the user.
3. Open Mailpit.

Expected: `new-device-alert` email captured; body shows the device label (e.g. `"Chrome on macOS"`) and masked IP; redacted format — no raw IP, no full UA string.

### S5.5 Admin security alert (Enterprise)

Preconditions: Enterprise. `adminAlertEmail = "admin@example.com"`. `adminAlertEvents = ['hibp_breach_detected', 'audit_chain_break']`. Trigger a breach detection (via `S5.3` user log-in).

Steps:
1. Open Mailpit.

Expected: TWO emails captured — one breach-detected to the user, one admin security alert to `admin@example.com`. Admin alert body summarises the event class and affected user identifier (HMAC'd, not raw).

### S5.6 Token chips render in test-send (Pro)

Preconditions: Pro. Notification template editor for `expiry-reminder` open.

Steps:
1. Click each token chip (`{{ user }}`, `{{ daysUntilExpiry }}`, `{{ siteName }}`).
2. Observe the textarea.
3. Click "Test send".

Expected: each chip inserts the Twig token at cursor position with click-to-copy CP notice toast; test send delivers an email to the current admin via Mailpit with the tokens interpolated.

### S5.7 Cooldown suppression — duplicate within window

Preconditions: Pro. `expiry-reminder` cooldown window = `expiryReminderDays * 86400 = 14 * 86400` seconds. From `S5.1`, run the reminder once.

Steps:
1. Immediately re-run `ddev craft password-policy/notification/send-expiry-reminders --user=<id>`.
2. Run queue.
3. Open Mailpit.

Expected: still only ONE email (the original from `S5.1`); cooldown suppressed the second send. Plugin log shows a "suppressed by cooldown" entry.

### S5.8 Resend from activity log (Pro)

Preconditions: Pro. A failed notification log row (force a failure by misconfiguring Craft's mail transport, queueing a send, restoring transport).

Steps:
1. Open Settings → Password Policy → Notifications → Activity log.
2. Find the failed row. Click Resend.
3. Open Mailpit.

Expected: a fresh email captured; activity log row updated to `sent`; cooldown gate is BYPASSED by the resend action (this is the documented admin-override path).

### S5.9 Custom Twig template path (Enterprise)

Preconditions: Enterprise. Create `templates/_emails/expiry-reminder.twig` in the playground with custom markup. Notification template editor → Advanced tab → set "Custom Twig template" to `_emails/expiry-reminder.twig`.

Steps:
1. Run `S5.1` again.

Expected: Mailpit captures the custom-template rendering, not the default seeded one.

---

## §6 HIBP integration (real network)

Goal: real HIBP API behaviour — k-anonymity, 429 backoff, TLS verification, dedup. The plugin's `GuzzleHibpClient` is unit-tested with a stub; this verifies actual wire behaviour.

### S6.1 K-anonymity prefix sent

Steps:
1. Open Wireshark or `tcpdump` filtering on `host api.pwnedpasswords.com`. (Or rely on browser DevTools if the AJAX validate endpoint is what's calling.)
2. Trigger an HIBP check via a CP password change or the front-end demo validate.

Expected: the only outbound traffic is `GET /range/<5-char-prefix>` — never the full SHA-1, never the plaintext, never the suffix.

### S6.2 429 backoff sentinel

Preconditions: a way to force HIBP to return 429 (rare in practice). Alternative: temporarily point `api.pwnedpasswords.com` at a local mock that returns 429 with `Retry-After: 30`.

Steps:
1. Trigger one HIBP check. Mock returns 429.
2. Trigger five more HIBP checks within 30 seconds.

Expected: only the first one hits the network (mock receives one request); the subsequent five short-circuit on the cache sentinel `pp:hibp-429-backoff` value `'1'`; cache entry expires after 30s.

### S6.3 TLS verification override

Preconditions: site `config/guzzle.php` sets `verify => false` globally (some sites do this for internal proxied traffic).

Steps:
1. Trigger an HIBP check.
2. Inspect outbound TLS via `curl --verbose` against `api.pwnedpasswords.com` from the same host as a sanity check.

Expected: the HIBP request enforces `verify => true` regardless of site Guzzle config; if the chain is broken, the request fails with a TLS error and the plugin logs at WARNING, not ERROR.

### S6.4 HIBP-on-login dedup per user

Preconditions: Pro. HIBP-on-login enabled. A user with a known-breached password.

Steps:
1. Log in as the user. (First HIBP-on-login check fires.)
2. Log out + log in again within 24h.

Expected: first login fires the HIBP API call AND sends the breach-detected email. Second login does NOT re-fire the API (per-user cache sentinel `pp:hibp-login:<userId>`) and does NOT re-send the email. Plugin log captures the dedup.

### S6.5 HIBP cache key does NOT include SHA-1 prefix

Steps:
1. Trigger an HIBP-on-login check.
2. Inspect cache keys: `ddev exec redis-cli KEYS 'pp:*'` (if Redis) or check Craft's cache backend.

Expected: cache keys are `pp:hibp-login:<userId>` and `pp:hibp-429-backoff` — NEVER any cache key containing the SHA-1 prefix. (Prior security audit caught the leak; this verifies the fix holds.)

---

## §7 Audit log chain (Enterprise)

Goal: chain initialisation, sequential linkage, corruption detection, retention purge tolerance, PII hashing. Pest covers each unit in isolation; this verifies end-to-end on real Craft elements.

### S7.1 Chain initialises on first event

Preconditions: Enterprise. Fresh `passwordpolicy_audit_log` table.

Steps:
1. Trigger any auditable event (e.g. log in as a user).
2. Inspect the table: `ddev craft password-policy/audit/inspect --limit=5`.

Expected: first row has `previousHash = '0' x 64`; `rowHash` computed against canonical JSON + previousHash; element row exists in `craft_elements` for the audit log element.

### S7.2 Sequential linkage

Steps:
1. Trigger 5 successive events.
2. Inspect with `audit/inspect`.

Expected: each row's `previousHash` matches the previous row's `rowHash`; `audit/verify --from=<earliest>` exits 0.

### S7.3 Manual rowHash corruption → verifier breaks

Steps:
1. `ddev mysql -e "UPDATE passwordpolicy_audit_log SET details = JSON_SET(details, '$.foo', 'bar') WHERE id = 3;"` (or pick an existing row).
2. `ddev craft password-policy/audit/verify --from=<earliest>`.

Expected: exits 1; output identifies row id 3 as the break point; subsequent rows ALSO flagged because the chain propagated. Restore the row before continuing.

### S7.4 Retention purge tolerance

Preconditions: rows older than `auditLogRetentionDays`. Run `password-policy/gc/run` to purge them.

Steps:
1. After purge: `ddev craft password-policy/audit/verify --from=<surviving-earliest>`.

Expected: exits 0. Verifier walks surviving rows and verifies the chain among them; doesn't fail just because earlier rows were retention-deleted.

### S7.5 PII hashing — no plaintext in DB

Steps:
1. Query: `ddev mysql -e "SELECT userIdentifier, ipHash FROM passwordpolicy_audit_log LIMIT 10;"`.

Expected: every `userIdentifier` is a 64-char hex (SHA-256 HMAC of email); every `ipHash` is a 64-char hex; no raw email addresses, no raw IPs visible.

### S7.6 PII key rotation drill

Steps:
1. Capture an existing `userIdentifier` for a known user from `S7.5`.
2. `ddev craft password-policy/audit/generate-pii-key --rotate`. (Writes new key to `.env`.)
3. Restart `ddev` if needed. Trigger a new audit event for the same user.
4. Query the new row's `userIdentifier`.

Expected: new row's hash DIFFERS from the captured old hash. Old rows remain correlate-able with the previous key (which the operator retains or destroys per compliance policy).

### S7.7 Audit-export download token — bind to requester

Preconditions: Enterprise. Two admin users.

Steps:
1. Admin A: open Audit Export utility. Configure a date range. Run export. Email arrives with the download link.
2. Forward the email to Admin B.
3. Admin B clicks the link.

Expected: Admin B gets 403 "This export was not requested by your account." Admin A clicks the link directly: download succeeds.

### S7.8 Chain verifier on Lite/Pro

Steps:
1. Flip to Lite. `ddev craft password-policy/audit/verify`.

Expected: exits with non-zero; message indicates verifier requires Enterprise. Same on Pro.

---

## §8 SIEM forwarders (Enterprise)

Goal: real SIEM destination verification — RFC 5424 frame, TLS handshake, circuit breaker, cooldown dedup. Pest covers the service logic with a fake socket; this verifies the wire.

### S8.1 Test event reaches local `nc` receiver

Preconditions: Enterprise. A local TCP receiver listening: `nc -l 6514` (or `ncat -l 6514`). Forwarder configured with `destinationType = syslog`, `endpointUrl = tcp://host.docker.internal:6514`.

Steps:
1. Settings → Password Policy → SIEM Forwarders → click forwarder → click "Test event".
2. Watch the `nc` output.

Expected: `nc` receives a syslog frame; structure matches RFC 5424 (`<priority>1 timestamp hostname app procid msgid - msg`); content includes the test event payload.

### S8.2 Real Splunk HEC

Preconditions: a real Splunk Cloud or local Splunk instance with an HEC token. Forwarder configured: `destinationType = http`, `endpointUrl = https://splunk.example.com/services/collector`, `authType = header`, `customHeaders = {"Authorization": "Splunk <token>"}`.

Steps:
1. Test event from the CP.
2. Open Splunk → search `index=main sourcetype=password-policy`.

Expected: event indexed within 10-30 seconds; structured JSON shows event class, userIdentifier (HMAC), ipHash.

### S8.3 Real Datadog Logs

Preconditions: Datadog account, API key. Forwarder configured for HTTP to `https://http-intake.logs.datadoghq.com/api/v2/logs` with `Authorization: DD-API-KEY <key>`.

Steps:
1. Test event from CP.
2. Datadog → Logs → search by service tag.

Expected: log entry appears within 30s.

### S8.4 Circuit breaker — consecutive failures

Preconditions: forwarder pointed at an endpoint that returns 5xx (e.g. `https://httpstat.us/500`).

Steps:
1. Trigger forwarding via the queue: `ddev craft queue/run` (forces a forward attempt).
2. Repeat 5+ times.
3. Open the forwarder index page.

Expected: after 5 consecutive failures (`siemCircuitFailureThreshold`), forwarder status shows "Circuit open" with a 5-minute cooldown timer (`siemCircuitCooldownSeconds`). Subsequent forwards short-circuit; no network calls.

### S8.5 Circuit breaker — half-open probe

Steps:
1. After `S8.4`, wait the 5-minute cooldown.
2. Trigger one more forwarding via queue.
3. Inspect.

Expected: forwarder enters half-open; the next attempt is the probe; if it succeeds, circuit closes; if it fails, circuit re-opens for another window.

### S8.6 IP handling mode — masked vs hashed vs excluded

Steps:
1. Switch `siemIpHandling` between `masked`, `hashed`, `raw` (NEVER), `excluded`. For each, trigger a forward and inspect the payload at the receiver.

Expected: each mode produces the right shape (`masked = 192.168.0.0`, `hashed = <sha256>`, `excluded` = field omitted).

---

## §9 Webhooks (Enterprise)

Goal: real HMAC signature verification by an external consumer, replay-window enforcement, secret rotation drill.

### S9.1 Signature verifies at `webhook.site`

Preconditions: Enterprise. Webhook endpoint configured at `https://webhook.site/<uuid>`. Secret captured from the create-flow.

Steps:
1. Trigger any audit event.
2. Run queue: `ddev craft queue/run`.
3. Open webhook.site, find the request.

Expected: request body is the audit row JSON; headers include `X-PasswordPolicy-Signature: sha256=<hex>`, `X-PasswordPolicy-Timestamp`, `X-PasswordPolicy-Event-Id`. Verify the HMAC manually: `echo -n "$timestamp.$eventId.$body" | openssl dgst -sha256 -hmac "$secret"` matches the signature suffix.

### S9.2 Replay-window enforcement (consumer-side discipline)

Steps:
1. Capture a webhook request from `S9.1`.
2. Replay it 24h+ later (or with a stale timestamp).

Expected: the plugin's documentation tells consumers to reject if `now() - timestamp > replay_window`. Verify the docs are clear on this; the plugin itself doesn't enforce on the consumer.

### S9.3 Secret rotation — grace window

Steps:
1. On the webhook endpoint edit page → click "Rotate secret". Confirm.
2. Capture the new secret from the flash session display.
3. Inspect the endpoint: `secretCurrent` is new; `secretPrevious` is the old one; `secretRotatedAt` is now.
4. Trigger an event. Consumer sees a signature signed with the NEW secret.

Expected: rotation flow renders the new secret once with a copy button; consumer-facing docs describe how to verify both `secretCurrent` and `secretPrevious` during the grace window; after `webhookSecretGracePeriodHours` (default 24h), `RotateWebhookSecretJob` clears `secretPrevious`.

### S9.4 No HMAC plaintext in JSON response

Steps:
1. After saving an endpoint, inspect the AJAX save response via DevTools → Network.

Expected: response JSON does NOT include `secretCurrent` or `secretPrevious` fields. (`WebhookEndpointModel::fields()` strips them.) Only the create-flow flash session reveals the secret, once.

### S9.5 Per-endpoint event-class filtering

Steps:
1. Configure two webhook endpoints. Endpoint A subscribes to `audit_log` only; Endpoint B subscribes to a custom set excluding `account_locked`.
2. Trigger both a password change and an account-lock event.

Expected: Endpoint A receives both; Endpoint B receives only the password change.

---

## §10 Audit export + compliance dashboard (Enterprise)

### S10.1 Streaming CSV export — local filesystem

Steps:
1. Utilities → Audit Export. Date range "Last 30 days". Format CSV. Destination: local runtime.
2. Click Run export.
3. Wait for "ready" email. Click the download link.

Expected: CSV downloads with headers + audit row rows; row count matches expected; file streams (large exports don't OOM PHP).

### S10.2 JSONL export

Steps: same as `S10.1` with format JSONL.

Expected: one JSON object per line; valid JSON per row.

### S10.3 S3 filesystem export

Preconditions: an S3 filesystem configured in Craft with handle `auditExports`. `auditExportFilesystem` setting set.

Steps:
1. Run export. Confirm bucket receives the file.

Expected: file written to S3 bucket; object-lock semantics intact if configured.

### S10.4 Compliance dashboard widgets

Steps:
1. Utilities → Compliance Dashboard.

Expected: four widgets render:
- Audit chain status (green tip + last verifier run + checked-row-count)
- Activity in last 24h (event-class table)
- Pending SIEM forwarding (count + oldest age)
- Retention (per-table windows + projected next prune)

### S10.5 HTML report export

Steps:
1. From the dashboard, click "Run HTML report".

Expected: a tab opens with a printable HTML report; framework anchors cited (NIS2 §21(2)(g), NIST 800-63B Rev 4, PCI DSS §10).

### S10.6 CSV report export

Steps: same as `S10.5` with CSV.

Expected: tabular data exports.

---

## §11 Per-group policies (Pro)

### S11.1 Create named policy

Steps:
1. Settings → Password Policy → Group Policies. Click "New policy".
2. Name: "Editors (NIST)". Apply NIST preset. Assign group: Editors. Save.

Expected: policy persists; appears in the policies index with divergence indicator + "Editors" in the assigned-groups column.

### S11.2 Tri-state rule override

Steps:
1. Edit the policy. Rules tab.
2. For `cases`: set explicit On. For `numbers`: set explicit Off. For `symbols`: Inherit Global.
3. Save.
4. Inspect via `craft.passwordPolicy.requirements({groups: ['editors']})` on a Twig page.

Expected: resolved `cases = true`, `numbers = false`, `symbols = <global value>`.

### S11.3 Multi-group merge — most-restrictive wins

Preconditions: user belongs to two groups, each with a policy having a different `minLength`.

Steps:
1. Set Group A policy `minLength = 12`, Group B policy `minLength = 16`.
2. Add user to both groups.
3. Inspect resolved policy for user.

Expected: resolved `minLength = 16` (max wins).

### S11.4 Multi-group merge — explicit Off carve-out

Preconditions: Group A policy with `cases = On`. Group B policy with `cases = explicit Off`.

Steps:
1. User in both groups. Inspect resolved policy.

Expected: resolved `cases = false` (explicit Off overrides explicit On per documented merge rule). Verify against per-group-policies.md.

### S11.5 Conflict UX

Steps:
1. Edit a policy. Set a rule to a value that contradicts an assigned group's other policy.

Expected: CP shows a conflict notice in the policy edit screen identifying the conflict; user must resolve before saving.

### S11.6 Group deletion → CASCADE on policy_groups

Steps:
1. Create a user group. Assign it to a policy.
2. Delete the user group.
3. Inspect `passwordpolicy_policy_groups`.

Expected: junction row removed; policy survives with one fewer assigned group; observability listener logs the cascade.

---

## §12 Notification template editor (Pro)

### S12.1 Edit and save a template

Steps:
1. Settings → Password Policy → Notifications → Templates. Click `expiry-reminder`.
2. Modify subject and body. Save.

Expected: per-(key, siteId) row in `passwordpolicy_notification_templates` persists. Re-render uses the new content.

### S12.2 Per-site override

Preconditions: multi-site Craft install (NOT the single-site playground — see §15).

Steps:
1. Edit `expiry-reminder` on Site A. Save.
2. Edit on Site B with different content. Save.
3. Trigger expiry reminder for users on each site.

Expected: each site's template applies; Mailpit shows per-site rendering.

### S12.3 Reset to defaults

Steps:
1. From the editor, click "Reset to defaults".

Expected: the row updates back to seeded `EmailDefaults` values; CP confirms.

### S12.4 Activity index — element index view

Steps:
1. Settings → Password Policy → Notifications → Activity.

Expected: element-index renders with status pill column (Sent/Failed); filters work; detail panel shows rendered subject+body for a selected row.

### S12.5 Permission gating

Steps:
1. Create a user without `pp:notification-templates-manage` permission.
2. Log in as that user. Try to navigate to the templates editor.

Expected: 403 with the plugin-specific message; CP nav item hidden if user lacks permission.

---

## §13 Edition flips + crafted POST defense

### S13.1 Lite → Pro flip

Steps:
1. From Lite. Apply procedure `P.2` setting edition to `pro`.
2. Refresh CP. Open Settings → Password Policy.

Expected: Group Policies + Validators subnavs lose Pro badges; HIBP-on-login toggle appears; existing settings persist; no migration runs (schema already at 2.11.0).

### S13.2 Pro → Lite flip

Steps:
1. From Pro with several Pro settings configured. Apply `P.2` to `lite`.
2. Try to save a settings page that previously included Pro fields (e.g. Validators with `checkSequentialChars` on).

Expected: Pro fields disappear from CP form; save POST gets stripped of Pro keys; on next load, Pro values still in project config but not visible/editable. (Strip is on incoming WRITE, not on display; switch back to Pro restores access.)

### S13.3 Pro → Enterprise flip

Steps:
1. From Pro. Apply `P.2` to `enterprise`.

Expected: Audit Logging subnav loses Enterprise badge; Compliance Dashboard utility appears under Utilities; existing audit rows (captured on Pro) become VISIBLE in the audit log index (capture was universal).

### S13.4 Enterprise → Pro flip

Steps:
1. From Enterprise. Apply `P.2` to `pro`.

Expected: audit log index hides; rows STAY in DB; flip back to Enterprise → rows reappear.

### S13.5 Crafted POST defense — Lite Pro key

Steps:
1. On Lite. Capture a save POST for the Configuration page. Replay with `settings[checkSequentialChars]=1` added.

Expected: response success; project config shows the field absent. Strip-on-save defense ate the crafted field.

### S13.6 Crafted POST defense — Pro Enterprise key

Steps:
1. On Pro. Capture a save POST and add `settings[siemEnabled]=1`.

Expected: same as `S13.5`. Enterprise-only key stripped.

---

## §14 Edition-gate error rendering

### S14.1 Twig builder on Lite — dev mode

Covered in `S4.9`.

### S14.2 Twig builder on Lite — production mode

Covered in `S4.10`.

### S14.3 Controller throw — 403 response

Preconditions: Lite. Attempt to POST to `/admin/password-policy/settings/apply-preset` with a valid preset name.

Steps:
1. `curl -X POST -d 'preset=nist_800_63b' -H "X-CSRF-Token: <token>" <base>/admin/password-policy/settings/apply-preset`.

Expected: HTTP 403 with response body containing "Compliance presets require the Pro edition." Craft's error template renders for the browser case; the JSON response shape for the AJAX case.

### S14.4 Queue job skip — log warning

Preconditions: Lite. Queue a `SiemForwardJob` directly (would normally only happen post-Enterprise).

Steps:
1. `ddev craft queue/run --verbose`.

Expected: job runs but skips with a `Craft::warning` log "SiemForwardJob skipped — SIEM forwarding requires the Enterprise edition."; job marked complete (NOT failed); no email, no audit row.

### S14.5 Console command — stderr + non-zero exit

Preconditions: Lite. Try `ddev craft password-policy/webhook/list`.

Expected: stderr writes "Webhook management requires the Enterprise edition."; exit code 1 (or `ExitCode::UNSPECIFIED_ERROR`).

---

## §15 Multi-site behavior

These need a multi-site Craft install — the playground is single-site. Use a separate site (e.g. the developer's multi-site test project) to run these.

### S15.1 Site soft-delete → notification_templates CASCADE

Preconditions: multi-site install with Sites A + B. `expiry-reminder` template edited per-site.

Steps:
1. Soft-delete Site B via CP.
2. Inspect `passwordpolicy_notification_templates`.

Expected: Site B rows soft-deleted (or hard-deleted per CASCADE rule). Restore via Craft's site-undelete: rows return. Verify via T9.7 if it's been Pest-covered.

### S15.2 New site → template propagation

Steps:
1. Multi-site install with one site. Edit `expiry-reminder` template.
2. Add a second site via Settings → Sites.
3. Inspect `passwordpolicy_notification_templates`.

Expected: new row for Site B with the seeded `EmailDefaults` content (NOT the edited Site A content). Per-site editing remains independent.

### S15.3 Per-site policy resolution

Steps:
1. Multi-site Pro install. Different global policy settings per site (via project config per-site override).
2. Resolve policy from a Twig page on each site.

Expected: resolved policy uses the per-site value. Cross-site users get site-context-correct policies.

---

## §16 GC + cron + console

### S16.1 GC handler — password history

Preconditions: history rows older than `passwordHistoryExpiryDays`. Some users with > `passwordHistoryCount` rows.

Steps:
1. `ddev craft password-policy/gc/run --force --verbose`.

Expected: rows beyond N kept per user; rows older than the day window deleted; output reports rows pruned.

### S16.2 GC handler — alert cooldowns

Preconditions: cooldown rows older than `alertCooldownRetentionDays`.

Steps:
1. `ddev craft password-policy/gc/run --force`.

Expected: pruned, but not below the `AlertCooldownService::PRUNE_FLOOR_SECONDS` floor (cooldowns active in the configured window are retained regardless of retention setting).

### S16.3 GC handler — audit log

Preconditions: Enterprise. Audit rows older than `auditLogRetentionDays`.

Steps:
1. `ddev craft password-policy/gc/run --force`.

Expected: rows hard-deleted via `craft_elements` DELETE + FK CASCADE. Verifier still passes on surviving chain.

### S16.4 Cron — expiry reminders nightly

Preconditions: a cron schedule per `cron-setup.md` recommendations.

Steps:
1. Set the cron job. Wait for the next nightly run (or trigger manually).

Expected: queue picks up `SendPasswordExpiryRemindersJob`; runs once; sends reminders for the right users.

### S16.5 Cron — audit verifier daily

Preconditions: Enterprise.

Steps:
1. `0 4 * * * ddev craft password-policy/audit/verify --from=yesterday`.

Expected: exits 0 on clean; exit 1 with the row id on break.

---

## §17 Accessibility deep verification

These need an actual screen reader running. Sample with NVDA (Windows), VoiceOver (macOS), JAWS if available.

### S17.1 NVDA — strength meter announces as progressbar

Steps:
1. Open the front-end demo password change page in Firefox + NVDA on Windows.
2. Tab to the password input. Type.

Expected: NVDA announces "progress bar, <label>, <value> of 4" as the meter updates.

### S17.2 VoiceOver — show/hide toggle

Steps:
1. Same demo in Safari + VoiceOver on macOS.
2. Tab to the eye toggle. Press VO + Space.

Expected: VO reads "Show password, button" → after press → "Hide password, button". Toggle state announced.

### S17.3 Live region — validation errors

Steps:
1. Demo page with screen reader running.
2. Enter an invalid password.

Expected: SR announces the validation error from a `role="status"` or `aria-live` region without requiring focus to move to the error.

### S17.4 Keyboard-only navigation

Steps:
1. Demo page. Mouse disconnected.
2. Tab through every interactive element. Submit.

Expected: every interactive element reachable in logical order; eye toggle, requirements list, submit button all reachable; submit works.

### S17.5 High-contrast mode

Steps:
1. Windows high-contrast mode on. Open the CP password fields.

Expected: status pills retain visible borders; strength meter has a visible track outline; eye toggle visible.

### S17.6 Reduced motion

Steps:
1. `prefers-reduced-motion: reduce` in browser. Trigger the strength meter animation.

Expected: no easing animations on the progressbar; instant state change.

---

## §18 Browser & extension compatibility + edge cases

### S18.1 Safari autofill + show/hide toggle

Steps:
1. iOS Safari. Open the demo change-password page.
2. Use the iOS keychain autofill suggestion.
3. Tap the eye toggle.

Expected: autofill works; eye toggle still flips the type attribute; no double-input bug.

### S18.2 1Password / Bitwarden compatibility

Steps:
1. Browser with 1Password extension. Navigate to the change-password form.
2. Trigger autofill from the extension.

Expected: extension fills correctly; AJAX validation still fires on the filled value (input event triggered by the extension).

### S18.3 Mobile touch — eye toggle

Steps:
1. Mobile Safari. Tap the eye toggle several times in quick succession.

Expected: no double-tap zoom; toggle responsive; no console errors.

### S18.4 Long password handling

Steps:
1. Enter a 200-character password into the demo change form.

Expected: input accepts; AJAX validate handles; max-length rejection if configured.

### S18.5 Special-character handling

Steps:
1. Enter password containing emoji, RTL characters, combining diacritics: `Pässwörd𝟏𝟐𝟑😀אבג`.

Expected: validators handle gracefully; UTF-8 round-trips intact through save+history; verifier-chain ops unaffected by exotic input.

### S18.6 Performance — large user pool

Preconditions: > 10k users with expiry enabled.

Steps:
1. Run `ddev craft password-policy/notification/send-expiry-reminders`.
2. Watch `ddev craft queue/info` and the queue job batching.

Expected: job batches at `expiryReminderBatchSize` (default 500); each batch completes within seconds; no OOM; total run completes in reasonable time.

### S18.7 Empty states

Steps:
1. Fresh install. Navigate to: Notifications → Activity (empty); Audit Log index (empty on non-Enterprise); Webhooks index (empty); Blocklist index before seeding.

Expected: each empty state renders gracefully with a "no rows" message and a CTA where appropriate; no PHP warnings, no JS errors.

### S18.8 Failed export state

Steps:
1. Trigger an audit export to a misconfigured filesystem (wrong S3 credentials).
2. Watch the queue.

Expected: job marked failed; admin email NOT sent (no successful completion to email); plugin log captures the error; cache token NOT written.

---

## §19 Plugin Store readiness

These are the final gates before publishing the 5.2.0 listing.

### S19.1 Capture all 30 screenshot placeholders

Steps:
1. Walk every block above. For each `> 📷 *Screenshot:* …` placeholder in `docs/user/` + `README.md`, capture the described screen.
2. Save into `docs/user/_screenshots/<slug>.png`. Replace each placeholder with `![Description](../_screenshots/<slug>.png)`.

Expected: all 30 placeholders replaced; the Plugin Store hero, the audit log index, the policies index, and the three onboarding shots captured first per the priority list in `manual-tests.md` "Capturing screenshots".

### S19.2 README hero shot composite

Steps:
1. Compose the README hero shot (Compliance Dashboard + policy edit screen + front-end strength meter) into one image.

Expected: 16:9 or 2:1 aspect; all three surfaces visible; no DDEV banner or debug toolbar; retina/2x.

### S19.3 Plugin Store description copy

Steps:
1. Cross-check the Plugin Store description against `editions.md` feature matrix + `README.md` "What you get" table.

Expected: marketing copy aligns with shipped features; compliance positioning leads (NIS2, NIST 800-63B Rev 4, PCI DSS v4.0.1, ISO 27001, SOC 2, GDPR per `project_compliance_positioning.md`); no claims that don't match the matrix.

### S19.4 5.1.x backport channel sanity

Steps:
1. Switch to `5.1.x` branch. Verify `composer test` is green.
2. Verify no current backport candidates are pending.

Expected: branch idle and shippable; the 5.2.0 tag doesn't disturb the 5.1.x channel.

---

## §20 Pre-tag final sanity

Single-pass checklist of the load-bearing things before tagging.

| Check | Command | Expected |
|---|---|---|
| Pest green | `composer test` (via DDEV) | All passing, no skipped |
| ECS clean | `composer check-cs` | No errors |
| PHPStan clean | `composer phpstan` | No errors (baseline unchanged) |
| Schema version | `ddev craft password-policy/schema` | `2.11.0` |
| Composer version | `cat composer.json \| grep version` | `5.2.0-alpha.1` (stays per user direction) |
| Memory store synced | `cat ~/.claude/projects/.../memory/MEMORY.md \| wc -l` | All durable rules indexed |
| Architecture rule current | `.claude/rules/architecture.md` | Edition-gate convention + non-exhaustive controller list intact |
| Internal docs reflect ship state | `docs/internal/handover.md` + `progress.md` | Last commit referenced; Phase H complete |
| User docs match code | grep across `docs/user/` for "Pro:" / "graceful" / "every edition.*preset" | No stale realignment language |
| Screenshots captured | `grep -rn "📷 \*Screenshot:" docs/user/ README.md` | Zero placeholder lines remaining |
| 5.1.x branch state | `git log --oneline 5.1.x -1` | At `5.1.2` tag |

When every row is checked → tag `5.2.0` from `5.x`. Push tag. Update Plugin Store listing. Announce.
