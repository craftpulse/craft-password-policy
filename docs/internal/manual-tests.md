# Manual Testing Scenarios

Test each scenario after installing the plugin on a fresh Craft CMS 5 site. Start from `5.2.0-alpha.1` and work forward — each branch builds on the previous.

**Legend:** PASS = verified, FAIL (fixed) = bug found and fixed, PENDING = not yet tested

The "Active test pass" block below orchestrates the next manual run. Per-test status records in the per-phase sections that follow remain the source of truth for individual T-row outcomes.

---

## Active test pass — Phase C2 + Layer 4b + Bug Fix Sweep (2026-05-02)

Coverage: P1.14 (RegistrationService), P1.13 (HIBP-on-login Pro), P1.12 (Pro front-end Twig surface), P1.12 Layer 4b (CP+front-end strength engine unification), and the 11 bug fixes from the post-review sweep (commits `322c18f` → `9691541`).

Pre-flight commands and credentials live in `docs/internal/handover.md`. Demo templates live in the playground at `cms/templates/_demo/password-policy/`.

### Pre-flight

```bash
ddev craft project-config/get plugins.password-policy.settings.edition  # → "pro"
ddev describe | grep -i mailpit                                         # note URL
git -C /Users/michtio/dev/craft-plugins/v5/craft-password-policy log --oneline -1
```

In CP settings: `showStrengthIndicator: ON`, `cspNonce: OFF` initially.

### Block 1 — Front-end demos (anonymous, then authenticated)

Order matches the site-builder's recommended click-through (cross-references the per-feature T-rows in §11/§12/§13 below where a hit/miss should be recorded).

**1.1 `/demo/password-policy`** — index renders, all 8 demo cards link cleanly.

**1.2 `/demo/password-policy/anonymous-preview`** — covers T13.7-style data-accessor usage. JSON dump non-empty. `requirementsText()` summary populated. `groups: ['editors']` column diverges from "no groups" only when `enablePerGroupPolicies: true`; identical columns under the global-fallback path is also valid.

**1.3 `/demo/password-policy/permutations`** — every flag combo renders. Eye toggle works on every variant with `toggleVisibility: true` regardless of `liveValidation` (Bug 3 verification — the asset bundle now auto-registers when any interactivity flag is on). Variants with `liveValidation: true` show real-time strength updates; variants without don't.

**1.4 `/demo/password-policy/registration-minimal`** — no-JS baseline. Form submits to Craft's user registration POST target. `requirementList()` items are static.

**1.5 `/demo/password-policy/registration`** — full widget. Type weak password → bar red, requirement items fail, submit gate disables. Type strong → bar green, items pass, submit enables. DevTools Network shows debounced ~250ms POSTs to `password-policy/validation/validate` with `{rules, strength, hibp}` response shape.

- **Bug 4 verification**: type a custom-blocklisted word (set one via `/admin/password-policy/blocklist`, e.g. `acmecorp`) → bar red regardless of length/case. Verifies the strength meter's blocklist-hit override clamps `label` + `score` even when zxcvbn would otherwise rate the password high.

**1.6 `/demo/password-policy/login` + `/login-styled`** — both POST to Craft `users/login`. Styled version applies `formAttrs`/`submitButtonAttrs`/per-field attrs (visible Tailwind classes).

**1.7 `/demo/password-policy/password-reset`** — request form first. Submit `development@craftpulse.com` → Mailpit receives reset link. Click → lands on `?code=…&id=…` with set-password form. Submit new password → success.

- **Bug 10 verification**: form's hidden input is `name="id"` (not `name="userUid"`). Inspect markup.

**1.8 `/demo/password-policy/password-change`** — anonymous → 302 redirect to login demo. Logged in → form renders. Wrong current password → flash error. New password failing policy → flash error per failed rule. Valid → redirect to demo index.

- **Bug 2 verification**: open second browser (or incognito), log in as same user before changing password from first browser. After change, refresh second browser → logged out.

**1.9 Edition flip**

```bash
# Edit cms/config/project/project.yaml: set plugins.password-policy.settings.edition: lite
# Bump dateModified at the top of project.yaml
ddev craft up
```

Reload any demo → edition badge shows `LITE`. Builders still render (graceful global-resolution fallback). HIBP-on-login listener does not fire (silent; verify by absence of breach-detected email after a known-breached login attempt). Restore: edit project.yaml back to `pro`, bump dateModified, `ddev craft up`.

### Block 2 — CP-side strength meter (Layer 4b unification, T13.12)

**2.1 Admin account password change** — visit My Account → Password tab. Type passwords. DevTools Network shows POSTs to `validation/validate` (CP path). Bars update ~250ms debounce.

- **Bug 4 CP-side**: type custom-blocklisted word → bars red.
- Response carries `engine: 'zxcvbn'`, `score` (0-4), `crackTime`, `suggestions`, `warning`. Bars use score for granularity (5-bar fill: `score + 1`).

**2.2 Create new user form** — strength indicator attaches to password input. Indicator does NOT attach to email/username/current-password fields.

**2.3 `showStrengthIndicator` master toggle** — OFF → indicator gone everywhere on CP. ON → indicator returns.

**2.4 CSP nonce** — toggle `cspNonce: ON`. Reload password change page. View Source on `<script>` tag for `strengthIndicator-*.js` → confirm `nonce="..."` attribute. Toggle OFF when done.

### Block 3 — HIBP-on-login (P1.13, Pro — T12.x)

**3.1 Breach detection (T12.1)** — set editor user's password to `Password123!` via `ddev craft users/set-password editor@playground.dev --password='Password123!'` (this is in HIBP). Log in as `editor` at `/demo/password-policy/login`. After login: `passwordResetRequired = true` (verify via `ddev craft db/query "select passwordResetRequired from users where email='editor@playground.dev'"`). Mailpit receives `breach-detected` email.

**3.2 Dedup cache (T12.2)** — log out, log back in within 24h with same password. No second email. `passwordResetRequired` already set, no second mutation.

**3.3 Lite gate (T12.4)** — flip to Lite (Block 1.9 procedure). Log in with breached password → no detection, no email, no flag. Restore Pro.

**3.4 HIBP API down (T12.3, optional)** — block `api.pwnedpasswords.com` via DDEV `/etc/hosts`. Log in → still succeeds, plugin log shows warning. Restore network.

### Block 4 — Email notifications (P1.3 + P1.4 re-validation, T9.4–T9.9)

**4.1 Notifications subnav** — `/admin/password-policy/notifications` lists `expiry-reminder` and `breach-detected` keys. Edit each → token picker chips work, click-to-copy fires CP notice toast. Test send → Mailpit receives.

**4.2 Expiry reminder queue (T9.8)**

```bash
ddev craft project-config/set plugins.password-policy.settings.expiryAmount 5
# Pick a user near expiry; adjust their lastPasswordChangeDate if needed
ddev craft password-policy/notification/send-expiry-reminders --user=<id>
ddev craft queue/run --verbose
# Mailpit receives. Re-running deduplicates.
ddev craft project-config/set plugins.password-policy.settings.expiryAmount '~'
```

### Block 5 — Bug-fix-specific verifications

| Bug | Steps |
|---|---|
| **1** PasswordWidget null `submitGate` | `/demo/password-policy/permutations`. The "passwordWidget without submitGate" variant does NOT fatal. Markup renders. |
| **5** BaseTag `__toString` doc | Open `src/twig/tags/BaseTag.php` — docblock says "always use `{{ tag.render() }}`. `{{ tag }}` will HTML-escape." (No claim it works directly.) |
| **6** HIBP 429 backoff | Hard to test without a 429 simulator. Verification by code review of `PasswordService::isHibpBackoffActive()` short-circuit + `_setHibpBackoff()` cache-write path. Belt-and-braces test: temporarily seed `Craft::$app->getCache()->set('pp:hibp-429-backoff', '1', 60)` via a one-off route, attempt a login with a breached password — listener short-circuits (no Mailpit hit). |
| **7** ValidationController context input | `curl -X POST 'https://plugin-playground-v5.ddev.site/actions/password-policy/validation/validate' -d 'password=foo&username=victim@example.com'` — response should NOT factor `victim@example.com` into the strength score (anonymous → context dropped). Score is identical with/without the username param. |
| **9** dual variable handles | `craft.passwordPolicy.requirements()` and `craft.passwordpolicy.requirements()` both render in Twig. `dump()` each in a demo template. |
| **10** `id()` vs `userUid()` | `/demo/password-policy/password-reset?code=...&id=...` — view source → `name="id"` not `name="userUid"`. |
| **11** `pwned:` config-file alias | Drop `<?php return ['pwned' => true];` into `cms/config/password-policy.php`. Reload any plugin page. Plugin log (`storage/logs/password-policy-*.log`) shows deprecation warning AND `craft.app.plugins.getPlugin('password-policy').settings.hibp` evaluates `true`. Remove the file when done. |

### Block 6 — Edition matrix

Run **Block 1.5** (registration full widget) and **Block 2.1** (CP strength) under each:

| Edition | Front-end builders | CP indicator | HIBP-on-login | Per-group |
|---|---|---|---|---|
| Lite | Work, global resolution | zxcvbn | Disabled | n/a |
| Pro | Work, per-group | zxcvbn | Enabled | Yes |
| Enterprise | Same as Pro | zxcvbn | Same as Pro + audit log entry | Yes |

### Capturing failures

For each failure: page URL, browser console error, Network tab response (if AJAX), Mailpit state if relevant, plugin log tail (`storage/logs/password-policy-*.log`), commit hash (`git rev-parse HEAD`).

### Branch state for this pass

- `5.x` — 69 commits ahead of `origin/5.x`. Phase C2 + Layer 4b + bug fix sweep + docs restructure + project setup + Phase E (18 commits) + `fix(hibp)` + `docs(ideas)` + Phase E close docs + Phase D (19 commits across D0–D4) + Phase D close docs. Not pushed.
- `5.1.x` — 3 commits ahead of tag `5.1.1`. TLS verify, fail-open log level, sensitive-key strip backports. Not pushed, not tagged.

### Pest suite (Phase D close, 2026-05-03)

The active manual pass above covers Phase C2 + Layer 4b + the bug fix sweep — all surfaces that ship to users. Independent of that pass, Phases E + D built a Pest test suite covering validators, services, models, controllers, Twig tags, migrations, multi-site behavior, the audit-context surface, user-index columns, admin element actions, and the user-edit tab page:

- **513 passing / 0 skipped / 1049 assertions** across `tests/Unit/`, `tests/Integration/`. Phase D added +184 tests over Phase E's baseline.
- Run via `cd /Users/michtio/dev/craft-plugin-playground/cms_v5 && ddev exec --dir /Users/Shared/dev/craft-plugins/v5/craft-password-policy composer test` (chains ECS + PHPStan + Pest; first failure stops the chain).
- The 11-bug C2 sweep (commits `322c18f` → `9691541`) is pinned by 32 of E4 + E5's tests.
- The three deferred manual tests (T1.2, TX.2, T9.7) are covered by Pest fixtures — see the per-test rows below.
- Phase D's P2.1 (user-index columns) + P2.2 (admin password change action) + P2.6 (read-only mode) — every CP affordance backed by a Pest pin in `tests/Integration/UserIndex/`, `tests/Integration/UserEditTab/`, and `tests/Integration/Controllers/UserPasswordControllerTest.php`.

If a manual test fails: try to reproduce in Pest first (the regression net should catch surface-level breakage). If the manual scenario can't be expressed as a Pest test (browser interaction, screen reader, real Mailpit verification), record it on the failing T-row.

---

## Phase 0 — Edition Infrastructure (alpha.1)

### T0.1 — Edition helpers return correct values — PASS
1. Install plugin in Lite edition
2. In a Twig template: `{{ dump(craft.app.plugins.getPlugin('password-policy').getIsLite()) }}` → `true`
3. `getIsPro()` → `false`, `getIsEnterprise()` → `false`
4. Switch to Pro: `getIsPro()` → `true`, `getIsEnterprise()` → `false`
5. Switch to Enterprise: all three → `true`

> **Bug found:** `getIsLite()` was hardcoded to `return true`. Fixed to use `$this->is(self::EDITION_LITE)`. Commit `43c6f6c`.

### T0.2 — Settings model accepts all new attributes — PASS
1. Open plugin settings in CP
2. Save without changes → no errors
3. All existing settings preserved (minLength, maxLength, cases, numbers, symbols, etc.)
4. New settings default to off/0 — zero behavior change

> First test run. Found 6 bugs (all fixed in beta.5 before current session).

### T0.3 — HIBP TLS fix — PASS
1. Enable HIBP in settings
2. Set a password known to be breached (e.g., "password123")
3. Should be rejected with breach message — **confirmed: "This password has been compromised in a data breach."**
4. Check that `config/guzzle.php` with `'verify' => false` does NOT disable HIBP TLS (the plugin overrides it)

### T0.4 — Log sensitive key stripping — PASS
1. Trigger a password-policy log event — triggered via blocklist utility and HIBP failures
2. Check `storage/logs/password-policy-*.log` — file exists with entries
3. Confirm no `password`, `newPassword`, `plaintext`, `hash`, or `passwordHash` keys appear — **confirmed via grep, no matches**

---

## Phase 1 — Database Schema (alpha.2)

### T1.1 — Fresh install creates tables — PASS
1. Uninstall and reinstall the plugin
2. Check database: `passwordpolicy_password_history`, `passwordpolicy_audit_log`, `passwordpolicy_blocklist`, `passwordpolicy_notification_log` exist — **all 4 created**
3. All indexes and foreign keys present

### T1.2 — Upgrade migration seeds history — COVERED BY PEST
> **2026-04-30:** code review confirms `_seedPasswordHistory()` correctly populates one bcrypt-hash row per user with a password. Idempotent (skips when table non-empty).
> **2026-05-02 (Phase E6, commit `c164646`):** now covered by `tests/Integration/Migrations/UpgradeTo520MigrationTest.php`. `MigrationTestCase` tears `db_test` down to a 5.1.1-shaped state (drops new-in-5.2.0 tables + deletes migration tracking rows), seeds users via `UserFactory::admin()`, runs `Craft::$app->migrator->migrateUp(0)`, and asserts the post-upgrade state. Idempotency, history-row count, hash equivalence to `users.password`, and the seed-loop logging-suppression invariant all codified.
1. Install plugin at 5.1.1 (before v5.2.0 schema)
2. Create 3 users with passwords
3. Upgrade to 5.2.0 (`ddev craft up`)
4. Check `passwordpolicy_password_history` — one row per user with a password
5. Hashes match `users.password` column

### T1.3 — Seeding disables query logging — PASS via code review
> **Verified 2026-04-30:** `_seedPasswordHistory()` saves `enableLogging` and `enableProfiling`, sets both to `false` before any user-table SELECT or `batchInsert` runs, and restores in a `finally` block. The pre-disable `exists()` check queries the empty history table only (no password material). Bcrypt hashes never reach Yii's debug logger.
1. Enable debug mode (`devMode: true`)
2. Run the upgrade migration
3. Check debug logs — no bcrypt hashes visible

### T1.4 — Uninstall drops all tables — PASS
> **Verified 2026-04-30:** `ddev craft plugin/uninstall password-policy` triggers `Install::safeDown()` which drops all 6 tables in correct reverse-FK order (policy_groups → policies → notification_log → blocklist → audit_log → password_history). Post-uninstall: `SELECT COUNT(*) FROM information_schema.tables WHERE table_name LIKE 'passwordpolicy_%' = 0`. Reinstall via `ddev craft plugin/install password-policy` recreates all 6 tables cleanly via `Install::safeUp()`.
1. Uninstall the plugin
2. All `passwordpolicy_*` tables are gone

---

## Phase 2 — Password History (alpha.3)

### T2.1 — Password change stores history (Pro) — PASS
1. Enable Pro edition, set `passwordHistoryCount: 5`
2. Change a user's password to "NewPassword1!"
3. Check `passwordpolicy_password_history` — **3 rows verified with bcrypt hashes**
4. Old entries pruned to count limit

### T2.2 — Password reuse rejected (Pro) — PASS
1. Set password to "TestPassword1!"
2. Change password to "AnotherPassword2@"
3. Try to change back to "TestPassword1!" → **rejected with "This password has been used recently."**

### T2.3 — History check disabled on Lite — PASS
1. Switch to Lite edition (project.yaml + craft up)
2. Repeat T2.2 — password reuse **accepted** on Lite
3. Switched back to Pro — reuse check kicked in again

### T2.4 — Force change on first login — PASS (Craft Team)
1. Enable `forceChangeOnFirstLogin`
2. Create a new user via CLI with `--groups=team`
3. Check user: `passwordResetRequired` = `true` — **confirmed in DB**
4. Log in as new user — **"You need to reset your password" prompt shown**
5. Existing users unaffected

### T2.5 — Recursion guard — PASS (Craft Team)
1. Enable `forceChangeOnFirstLogin`
2. Create a new user — succeeds without infinite loop
3. Check that only ONE history entry is created — **exactly 1 entry confirmed**

### T2.6 — Request-end cleanup — PENDING
1. Set a breakpoint or log after `EVENT_AFTER_REQUEST`
2. Confirm `$_pendingPasswords` is empty after every request

---

## Phase 3 — Advanced Validators (alpha.4)

### T3.1 — Sequential characters rejected (Pro) — PASS
1. Enable `checkSequentialChars`
2. Try passwords: `abc12345!` → **rejected**, `qwerty123!` → rejected
3. `Hx9$mK2p` → accepted (no sequences)

> Note: `pqr` also triggers (ASCII 112,113,114 = 3 ascending). Documented for plugin docs.

### T3.2 — Repeated characters rejected (Pro) — PASS
1. Enable `checkRepeatedChars`
2. `aaa12345!` → **rejected**, `111abcDE!` → rejected
3. `Hx9$mK2p` → accepted

> Note: Slow when HIBP is enabled — the delay is the HIBP API call, not the validator.

### T3.3 — Contextual check (Pro) — PASS
1. Enable `checkContextual`
2. Password with username in it → **rejected**
3. Password with email in it → **rejected**

> Note: renamed from "T3.3 — Contextual check" to match actual test (T3.4 in test plan was contextual).

### T3.4 — Common password blocklist (Pro) — PASS (after fix)
1. Enable `checkCommonPasswords`
2. Run `ddev craft password-policy/blocklist/update`
3. `password` → **rejected: "This password is too common."**
4. `Hx9$mK2pQr!` → accepted

> **Bug found:** Blocklist was empty on install (0 common passwords). Enabling the toggle without running `blocklist/update` silently did nothing. Fixed with auto-seed queue job. Commit `fb3e9b3`.

### T3.5 — Minimum character types mode (Pro) — PASS
1. Set `complexityMode: 'minimum'`, `minimumCharacterTypes: 3`
2. `abcdefgh` (1 type) → rejected (when set to 3, not when mistakenly set to 1)
3. `Abcdefgh` (2 types) → rejected
4. `Abcdefg1` (3 types) → **accepted**
5. `Abcde1!` (4 types) → accepted

> **Fix:** Removed "1 of 4" from dropdown — useless option. Commit `43c6f6c`.

### T3.6 — Blocklist CLI commands — PASS
1. `ddev craft password-policy/blocklist/stats` → **showed 0 common, 0 custom initially**
2. `ddev craft password-policy/blocklist/update` → **seeded 195 common passwords**
3. Create `custom-words.txt` with test words — not tested (custom import parked)
4. Verify custom words are blocked — not tested

---

## Phase 4 — Audit Logging (alpha.5) — ALL PENDING (Enterprise)

### T4.1 — Password change logged (Enterprise) — PENDING
### T4.2 — Audit log silent on Lite/Pro — PENDING
### T4.3 — HIBP breach detection logged — PENDING
### T4.4 — HIBP fail-closed mode — PENDING
### T4.5 — Account lockout logged — PENDING
### T4.6 — Audit CLI — PENDING

---

## Phase 5 — Per-Group Policies (beta.1)

### T5.1 — Global policy when no groups — PASS
1. Craft Solo (no groups) → `PolicyResolverService::resolveForUser()` returns global settings — **confirmed via AJAX endpoint, rules match global settings**
2. User with no group assignments → global settings

### T5.2 — Single group policy merge — PASS (Craft Pro)
1. Editors group policy: `minLength=12, cases=true`
2. editor user (Editors only) → `resolveForUser()` returns merged settings
3. `minLength=12` (max(8,12)) — **confirmed**
4. `cases=true` (group override) — **confirmed**
5. `numbers=false`, `symbols=false`, `passwordHistoryCount=5`, `expiryAmount=90` — **all inherited from global**

> **Re-verified after named-policies refactor (2026-04-29):** Editors Policy created via the new CRUD UI with minLength=12 + cases=on. As editor user, `Tx9$mK2pq` (9 chars) rejected with "Password must contain at least 12 characters." `Tx9$mK2pqRzW` (12 chars, mixed case, number, symbol) accepted. Global rules (sequential, history) still applied = inherit semantics work. **Bug found and fixed:** `UserRules::defineRules()` was reading `$plugin->getSettings()` (global) instead of `$plugin->getPolicyResolver()->resolveForUser($user)`. Now passes `$user` from `User::EVENT_DEFINE_RULES`'s `$event->sender`. ValidationController AJAX endpoint also fixed to use resolver.

### T5.3 — Multi-group "most restrictive wins" — PASS (Craft Pro)
1. Editors: `minLength=12, cases=true` | Managers: `minLength=16, cases=true, symbols=true, passwordHistoryCount=10, expiryAmount=30/day`
2. multigroup user (Editors + Managers) → `resolveForUser()` returns merged settings
3. `minLength=16` (max(8,12,16)) — **confirmed**
4. `cases=true` (both groups) — **confirmed**
5. `symbols=true` (Managers override) — **confirmed**
6. `passwordHistoryCount=10` (max(5,10)) — **confirmed**
7. `expiryAmount=30, expiryPeriod=day` (shortest wins: 30 < 90) — **confirmed**

> **Re-verified after named-policies refactor (2026-04-29):** As multigroup user, `Tx9$mK2pqRzW` (12 chars) rejected with "at least 16 characters." `Hx9$mK2pq8WCfM3R` (16 chars, mixed case, number, symbol, no sequential) accepted. Sequential char check correctly inherited from global. Validates: minLength bump from Managers, cases from Editors, symbols from Managers, sequential inheritance from global all stack correctly.

### T5.4 — Invalid merge state (minLength > maxLength correction) — PASS (Craft Pro)
1. Group with `minLength=20, maxLength=15` → post-merge detected maxLength(15) < minLength(20)
2. Corrected: `maxLength` set to `minLength` (20) — **confirmed**
3. Cross-group conflict: Group A `maxLength=10` + Group B `minLength=16` → maxLength(10) < minLength(16)
4. Corrected: `maxLength` set to 16 — **confirmed**

> **Re-verified after named-policies refactor (2026-04-29):**
> - **Self-collision now caught at save time.** Setting Editors Policy `minLength=12, maxLength=9` triggers a model validation error: *"Max length (9) must be greater than or equal to min length (12)."* Cross-policy collisions remain the resolver's job.
> - **Cross-policy correction redesigned.** Setup: global `maxLength=10`, Editors `minLength=12`, Managers `minLength=16`. As multigroup user → resolved `minLength=16, maxLength=10` → collision. Old behavior set `maxLength=minLength=16` (confusing — passwords had to be exactly 16 chars). **New behavior drops the maxLength cap entirely** (sets to 0 = no limit). Reasoning: minLength is security-critical, maxLength is defensive only. When incompatible, never weaken minLength.
> - Verified: 15-char rejected ("at least 16"), 18-char accepted (no upper limit).
> - Warning log: *"Per-group policy merge produced invalid state: maxLength (10) < minLength (16). Dropping maxLength cap (no upper limit)."*
> - Also fixed `UserRules`: `maxLength > minLength` → `maxLength > 0` (was excluding the valid `max == min` case in earlier correction logic).

### T5.5 — Presets (NIST, OWASP, PCI-DSS, Strict Enterprise) — PASS (Craft Pro)
1. **NIST 800-63B**: minLength=8, no complexity, no expiry, HIBP on — **confirmed**
2. **OWASP ASVS L1**: minLength=12, maxLength=128, no complexity, HIBP on — **confirmed**
3. **Strict Enterprise**: minLength=12, all checks true, cases/numbers/symbols=true, history=5, 90-day expiry — **confirmed**
4. **PCI-DSS v4.0**: minLength=12, cases/numbers=true (not symbols per spec), history=4, 90-day expiry, commonPasswords=true — **confirmed**
5. All presets merge correctly with global settings (null fields inherit, non-null override with most-restrictive logic) — **confirmed**

> **Re-verified after JS↔PHP preset sync fix (2026-04-29):** Applying each preset to a fresh policy and saving without changes produces 0 divergence. No blue dot, no "fields differ" warning. JS preset values now match `PolicyPreset::toGroupPolicy()` exactly — fields PHP leaves null are `''` in JS, not `'0'`.

### T5.6 — Policies migration from groupPolicies — PASS (Craft Pro)
1. Run `ddev craft up` — migration `m260426_000000_AddPoliciesTables` executes
2. Check DB: `passwordpolicy_policies` and `passwordpolicy_policy_groups` tables exist
3. Old groupPolicies data migrated: Editors Policy and Managers Policy created
4. Editors Policy settings: `minLength=12, cases=true` (matches old config)
5. Managers Policy settings: `minLength=16, cases=true, symbols=true, passwordHistoryCount=10, expiryAmount=30, expiryPeriod=day`
6. Junction table: each policy linked to its correct group ID
7. `pwned` keys renamed to `hibp` in migrated settings JSON

### T5.7 — Group Policies settings page — PASS (Craft Pro, after UI polish)
> **UI polish applied:** Removed `flex-fields` wrapper, added `<hr>` separator, replaced `btn submit` red button with `btn go` (Craft's navigate-to action), used `class="light"` for muted text. Subnav reordered: Policies above Settings.
1. Navigate to Settings → Group Policies
2. "Enable per-group policies" toggle renders, currently ON
3. Toggle ON → policies container visible with "Manage Policies" button
4. Policy count shows (e.g. "2 policies configured" from migration)
5. "Manage Policies" button links to `/admin/password-policy/policies`
6. Toggle OFF → policies container hidden immediately (JS toggle)
7. Save with toggle OFF → reload → toggle off, container hidden
8. Toggle back ON → container reappears with correct count

### T5.8 — Policies index renders — PASS (Craft Pro)
1. Navigate to Policies (via subnav or "Manage Policies" button)
2. VueAdminTable renders with migrated policies
3. Columns: Name, Groups, Preset
4. Editors Policy row: Groups = "Editors", Preset = "Custom"
5. Managers Policy row: Groups = "Managers", Preset = "Custom"
6. "New policy" button visible below table
7. Delete action available on each row

### T5.9 — Create new policy — PASS (Craft Pro)
> Created "Team Policy" with min length = 10, numbers = on, assigned to Team. Saved successfully, redirect worked, row appeared in index. DB verified.
1. Click "New policy" → edit screen renders via asCpScreen()
2. Breadcrumbs: Password Policy → Policies → New Policy
3. Enter name "Team Policy" → handle auto-generates "teamPolicy"
4. Leave preset at "None (custom)"
5. Set: min length = 10, toggle "Require numbers" on
6. Assign to Team group (checkbox)
7. Save → "Policy saved." notice
8. Redirects to policies index → "Team Policy" row visible
9. Team Policy row: Groups = "Team", Preset = "Custom"

### T5.10 — Preset auto-fill — PASS (Craft Pro)
> All 5 presets (NIST, OWASP, PCI-DSS, Strict Enterprise, None) populate fields correctly across the General/Rules/Lifecycle tabs, including tri-state button states.
1. Create or edit a policy
2. Select "Strict Enterprise" preset
3. Fields populate: min length = 12, cases = on, numbers = on, symbols = on, HIBP = on, HIBP fail mode = "closed", history = 5, expiry = 90 day(s), all advanced checks on
4. Select "NIST 800-63B" preset
5. Fields change: min length = 8, all booleans off except HIBP = on, history and expiry cleared, fail mode = inherit
6. Select "PCI-DSS v4.0" preset
7. Fields: min length = 12, cases = on, numbers = on, symbols = off, HIBP = on, history = 4, common passwords = on, expiry = 90 day(s)
8. Select "OWASP ASVS L1" preset
9. Fields: min length = 12, max length = 128, all booleans off except HIBP = on
10. Select "None (custom)"
11. All fields reset to empty/off

### T5.11 — Save round-trip — PASS (Craft Pro)
> Applied Strict Enterprise preset, overrode `checkSequentialChars` to explicit Off (red X), set min length to 20, assigned to Team + Editors. Saved successfully. DB JSON shows the explicit `false` for sequential chars (key tri-state test); junction table has 2 rows.
1. Edit Team Policy: change min length to 14, toggle "Require symbols" on, assign to both Team and Editors
2. Save → success notice
3. Click Team Policy to re-edit
4. Values persist: min length = 14, symbols = on, both Team and Editors checked
5. DB: `passwordpolicy_policies.settings` JSON has `{"minLength":14,"symbols":true}`
6. DB: `passwordpolicy_policy_groups` has 2 rows for this policy (Team + Editors)

### T5.12 — Delete policy — PASS (Craft Pro)
> **Verified 2026-04-29:** all three policies (Editors, Managers, Legacy Override) deleted via the index. Post-delete query: `passwordpolicy_policies` count=0, `passwordpolicy_policy_groups` count=0. CASCADE on `policyId` works as defined in `m260426_000000_AddPoliciesTables`.
1. From policies index, delete a policy (via row action)
2. Policy removed from table
3. DB: row gone from `passwordpolicy_policies`
4. DB: junction rows CASCADE deleted from `passwordpolicy_policy_groups`

### T5.13 — PolicyResolverService with named policies — PASS (Craft Pro)
> **Verified 2026-04-29 — tri-state Option A semantics:**
> **Step 1 (single-group exemption):** Legacy Override policy with `checkSequentialChars=false` (explicit Off, red X) assigned to Team only. Global has `checkSequentialChars=true`. As newuser (Team only): `Tx9$mK2pqr8` (contains `pqr` sequence) **accepted** — Team is exempt because the policy's explicit Off overrides global On for this group's users.
>
> **Step 2 (multi-group conflict — any-true wins):** Editors Policy updated to `checkSequentialChars=true` (explicit On, green check). newuser added to Editors so they're now Team + Editors. As newuser: `Tx9$mK2pqrAB` (12 chars, contains `pqr`) **rejected** ("Password must not contain sequential characters"); `Hx9$mK2sQk!8` (12 chars, no sequential) **accepted**. Editors' explicit On wins over Team's explicit Off — most-restrictive resolution preserved across multi-group users while still allowing single-group exemptions.
1. Editors Policy: `minLength=12, cases=true` assigned to Editors
2. Managers Policy: `minLength=16, symbols=true, passwordHistoryCount=10, expiryAmount=30/day` assigned to Managers
3. User in Editors only → resolved `minLength=12` (max of global 8, policy 12)
4. User in Editors + Managers → resolved `minLength=16` (max of 8, 12, 16), `symbols=true`, `passwordHistoryCount=10`
5. User in Team (no policy) → global settings returned
6. User with no groups → global settings returned

**Tri-state explicit-Off test (Option A semantics):**

7. Set global `checkSequentialChars=true`. Create a "Legacy" policy with `checkSequentialChars=false` (explicit Off, red X). Assign to a single group (e.g. Editors).
8. User in Editors only → resolved `checkSequentialChars=false` (single-group exemption honored)
9. User in Editors + Managers (Managers has no override) → still `false` (no other policy says `true`)
10. Add a 3rd policy with `checkSequentialChars=true`. User in Editors + that group → resolved `true` (any explicit `true` wins over any explicit `false`)

### T5.14 — Edition gating — PASS
> **Verified 2026-04-29:** flipped `password-policy.edition: pro → lite` in project.yaml + bumped `dateModified` + `ddev craft up`. Subnav drops to Settings only. Direct GET `/admin/password-policy/policies` returns 403. Group Policies settings tab still renders (toggle visible, inputs disabled, no Save button) — visible-but-disabled is the *intentional* Pro-gated UX, not a bug: keeps the upgrade path discoverable. Audit Logging tab stays Enterprise-gated with the Enterprise badge. Flip back to Pro restored everything.
1. Switch to Lite (project.yaml → `edition: lite`, update dateModified, `craft up`)
2. Subnav: no "Policies" link
3. Direct URL `/admin/password-policy/policies` → 403 Forbidden
4. Settings → Group Policies: visible-but-disabled with "Pro edition required" badge, no Save button
5. Switch back to Pro — subnav and full CRUD restored

### T5.15 — Subnav visibility — PASS (Craft Pro)
> **Verified 2026-04-29:** toggling `enablePerGroupPolicies` off hides the Policies subnav link; toggling on restores it above Settings. Reload-resilient (not just JS visibility — actually re-evaluated on render).
1. Pro + `enablePerGroupPolicies=true` → "Policies" appears in plugin subnav
2. Pro + `enablePerGroupPolicies=false` → "Policies" hidden from subnav
3. Toggle setting and reload to verify

### T5.16 — minLength vs global maxLength conflict UX (P1.9 + P1.10) — PASS (Craft Pro)
> **Verified 2026-04-29:** save-time toast and edit-screen banner both appear and disappear correctly across the four-state walk. Banner restyled post-verification — replaced Craft's `note warning` blockquote with custom `.pp-conflict-banner` (orange-500 left border, orange-050 tint, larger block padding) for higher visibility, mirroring the `.pp-divergent` visual language.
1. Settings → Configuration: set global `maxLength=10`. Save.
2. Edit Editors Policy → Rules tab: set `minLength=12`. Save.
3. **Save-time notice (P1.9):** info-style toast appears alongside "Policy saved." reading: *"This policy's minimum length (12) exceeds the global maximum length (10). The global cap will be ignored at validation time when this policy applies."*
4. **Edit-screen banner (P1.10):** click Editors Policy from index → edit screen renders with a `<blockquote class="note warning">` banner at the top showing the same message. Persists on every reload.
5. Settings → Configuration: change global `maxLength=0` (no limit). Save.
6. Reload Editors Policy edit screen → banner is gone.
7. Restore Editors Policy `minLength` to whatever value the rest of the suite expects (the post-reset baseline, see T5.4 reset notes).

### T5.18 — Custom blocklist editor + validation round-trip (P1.11) — PASS (Craft Pro)
> **Verified 2026-04-30:** end-to-end test as `editor` user (Editors group, per-group policies temporarily disabled so global rules applied). Settings: `minLength=6`, all complexity off, `checkCommonPasswords=on`, `acmecorp` added to custom blocklist via Blocklist editor. Six password change attempts via the editor's profile change-password form: `password` rejected ("too common"), `PASSWORD` rejected ("too common", case-insensitive), `acmecorp` rejected ("blocked", custom message), `ACMECORP` rejected ("blocked", custom + case-insensitive), `abc` rejected (length sanity check, validator chain still firing), `Qx9$mZ7p!Random` accepted. Validator emits **source-aware messages** — bundled common entries get "too common, choose a more unique password"; custom entries get "blocked, choose a different one". `BlocklistService::isBlocked()` lookup is the same data path as the in-CP "Check a word" tool, both verified consistent with what the validator rejects/passes. Schema: `passwordpolicy_blocklist.policyId` column added in migration `m260430_101611_AddPolicyIdToBlocklist` (Pro stores `policyId IS NULL`; reserved for Phase G Enterprise per-policy editor). Permission split verified: granting `pp:blocklist-view` only renders the page read-only (no editor, no Save, no Update Common); adding `pp:blocklist-manage` restores all edit affordances.

### T5.17 — Group deletion observability listener (P1.5) — PASS (Craft Pro)
> **Verified 2026-04-30:** created group "P1.5 Test" (id=4) + policy "P1.5 Test Policy" (id=2) attached only to that group. Deleted the group from CP. Listener fired exactly as designed: new log file `storage/logs/password-policy-2026-04-30.log` created with entry `[password-policy.INFO] User group "P1.5 Test" (id: 4) deleted; dropping policy assignments: P1.5 Test Policy`, structured JSON payload `{"groupName":"P1.5 Test","groupId":4,"policies":"P1.5 Test Policy","username":"michtio"}`. Post-delete DB: `usergroups` row 4 gone, `passwordpolicy_policy_groups` empty (FK cascade cleaned junction), `passwordpolicy_policies` row 2 survived (policy now orphaned, no group assignments). Policy edit screen still loads, Groups field shows no checkboxes — orphaned-policy state degrades gracefully.
1. Settings → Users → User Groups: create a new group "P1.5 Test".
2. Edit any existing policy (e.g. Editors Policy), assign "P1.5 Test" alongside its existing groups, save.
3. Confirm the junction row exists: `ddev craft db/query "SELECT * FROM passwordpolicy_policy_groups WHERE groupId = (SELECT id FROM usergroups WHERE handle = 'p15Test')"` → 1 row.
4. Settings → Users → User Groups: delete "P1.5 Test".
5. Tail `storage/logs/password-policy-*.log` → expect line: *"User group "P1.5 Test" (id: N) deleted; dropping policy assignments: Editors Policy"*.
6. Re-run the SQL from step 3 → 0 rows (FK cascade did its work).
7. Reload the original policy edit screen → "P1.5 Test" no longer appears in the assigned-groups list; other group assignments preserved.
8. Edge case: create another temp group with no policy assignments, delete it. Log should be silent (listener returns early when `getPoliciesForGroupIds` returns `[]`).

---

## Phase 6 — User Index Integration (beta.2)

### T6.1 — Condition rules — PASS (Craft Team)
1. Go to Users index → click condition builder
2. "Password Expired" rule available — **confirmed**
3. "Password Reset Required" rule → **filters correctly, showed newuser**
4. "Password Never Changed" rule → **available**

### T6.2 — Bulk force reset action (Pro) — PASS (Craft Team)
1. Select multiple users in Users index
2. "Force Password Reset" action available — **confirmed**
3. Execute → confirmation dialog → users flagged
4. On Lite → action not available

---

## Phase 8 — Developer Events (beta.3)

### T8.1 — PasswordChangedEvent fires — PASS (Craft Team)
1. Changed editor's password via CLI
2. Password history entry created — **proves EVENT_AFTER_SAVE → cache → hash → history → EVENT_PASSWORD_CHANGED chain ran**
3. Verify `$event->user->newPassword` is `null` — not directly verified (would need event listener module)

### T8.2 — Session invalidation — PASS (Craft Team)
1. Log in as editor on incognito browser
2. Changed editor's password via CLI from admin
3. Editor's incognito session — **logged out on refresh**

### T8.3 — Group force reset — PASS (Craft Pro, multiple groups)
1. Added admin to Editors group (3 members: editor, multigroup, michtio/admin)
2. `resetPasswordsByGroup(Editors)` → returned count: **2** (non-admins only)
3. DB verified: editor `passwordResetRequired=1`, multigroup `passwordResetRequired=1` — **confirmed**
4. Admin (michtio) `passwordResetRequired=0` — **skipped, confirmed**
5. Admin skip logic at `RetentionService:113`: `!$user->admin` check — **correct**

---

## Phase 9 — Notifications + GC + Validation (beta.4)

### T9.1 — Twig variables — PASS
1. `{{ craft.passwordpolicy.passwordStatus() }}` → **`current`**
2. `{{ craft.passwordpolicy.daysUntilExpiry() }}` → **`89`** (90-day expiry, changed yesterday)
3. `{{ craft.passwordpolicy.isExpiring(7) }}` → **`false`**
4. `{{ craft.passwordpolicy.activeSessionCount() }}` → **`1`**
5. Not logged in → safe defaults

> **Bug found:** `lastPasswordChange` returned `null` despite DB having a value. Craft's `UserQuery::beforePrepare()` doesn't select `lastPasswordChangeDate`. Fixed with direct DB query. Commit `bc6196d`.

### T9.2 — AJAX validation endpoint — PASS
1. `POST /admin/password-policy/validate` with `{ "password": "abc" }` — **JSON response with 6 rules**
2. Response: per-rule `pass: true/false/null` — **confirmed (minLength, characterTypes, sequential, repeated, common, pwned)**
3. HIBP rule returns `null` if API unreachable — **confirmed (train connectivity)**
4. Works with CSRF for CP requests — **confirmed via `Craft.csrfTokenValue`**
5. `contextual` and `history` omitted (no user context in anonymous validation) — expected

### T9.3 — GC auto-purge — PASS
1. `ddev craft gc` — **ran without errors**
2. Further verification of actual data cleanup pending

### T9.4 — Email notifications index (P1.3) — PASS (Craft Pro)
> **Verified 2026-04-30:** `/admin/password-policy/notifications` renders the VueAdminTable with the single `expiry-reminder` row. Columns: Notification | Key | Subject (primary site) | Sites with overrides. Subject column shows the seeded default. Row click navigates to `/admin/password-policy/notifications/expiry-reminder`. Subnav highlights "Notifications" (between Blocklist and Settings). Pro-gated — Lite users don't see the subnav at all and direct URL access returns 403.
1. Settings → Plugins: confirm Pro edition.
2. Visit `/admin/password-policy/notifications` — table renders with one row, primary-site subject populated.
3. Click row → edit screen for primary site (`?siteId=1`).
4. Switch to Lite via project.yaml + `craft up` → reloading the page returns 403.
5. Restore Pro.

### T9.5 — Notification template edit + multi-site persistence (P1.3) — PASS (Craft Pro)
> **Verified 2026-04-30:** edit screen opens at `/admin/password-policy/notifications/expiry-reminder`. Three tabs (General, Advanced, Test send). Hidden inputs `notificationKey` and `siteId` round-trip correctly. POST to `password-policy/notification-template/save` returns the asModelSuccess JSON; reloading the edit screen shows the persisted values. EmailDefaults restored after testing. (Multi-site propagation listener test deferred to T9.7 since the playground has a single site — install fresh in a multi-site project to exercise the propagateToSite path.)
1. Open the edit screen for `expiry-reminder`.
2. Change Subject to "TEST — your password expires in {{ daysUntilExpiry }} days". Save.
3. Reload the edit screen → field shows the new value.
4. Click a token chip (e.g. `{{ daysUntilExpiry }}`) → CP notice toast says "Copied … to clipboard." Pasting elsewhere yields the literal token string.
5. Restore the default subject before moving on.

### T9.6 — Test-send AJAX (P1.3) — PASS (Craft Pro)
> **Verified 2026-04-30:** clicking the "Send test email" button on the Test send tab fires a POST to `password-policy/notification-template/test-send`, returns JSON `{success: true, message: "Test email sent to <admin email>", renderedSubject, renderedBodyExcerpt}`. Result panel renders inline as `<blockquote class="note tip">` with rendered subject + 240-char body excerpt. Mailpit confirms message arrived at the admin's email address. Posted subject/body are previewed *without* requiring a save first — sample render uses `daysUntilExpiry: 7` and current admin user.
1. Open edit screen for `expiry-reminder`.
2. Modify subject + body (don't save).
3. Switch to Test send tab → click Send test email.
4. Inline blockquote renders with rendered subject reflecting the unsaved edits.
5. Mailpit (https://plugin-playground-v5.ddev.site:8026) shows the message at the admin email.

### T9.7 — Site propagation listener + CASCADE — COVERED BY PEST
> Code review (2026-05-01) of `PasswordPolicy::_registerSiteListeners()` and `NotificationTemplateService::propagateToSite()` confirms: (1) listener fires only when `isNew = true`, (2) defensive try/catch never blocks the site save, (3) propagator inserts one row per known notification key copying primary-site content, skipping rows that already exist.
> **2026-05-02 (Phase E6, commit `6a69664`):** now covered by `tests/Integration/MultiSite/SitePropagationTest.php` (9 tests — propagation on new site, idempotency on `isNew=false` re-save, content copy from primary, `dateCreated` freshness, listener defensive try/catch) + `tests/Integration/MultiSite/SiteDeletionCascadeTest.php` (4 tests). **Behavior correction codified:** `Sites::deleteSiteById()` soft-deletes (sets `dateDeleted`) — FK CASCADE does NOT fire on soft delete. Per-site rows persist after `deleteSiteById()` so admins re-enabling a soft-deleted site recover their templates. Hard-delete via direct `createCommand()->delete(Table::SITES, ...)` does cascade — the FK is correctly wired for the GC sweep. Both behaviors pinned. See memory gap #19.

### T9.8 — Queue job + console command + dedup (P1.4) — PASS (Craft Pro)
> **Verified 2026-04-30:** end-to-end on the playground. Set `expiryAmount=5` via project-config/set, configured the editor user (id=55) lastPasswordChangeDate to land 4 days from expiry. Console command `password-policy/notification/send-expiry-reminders --user=55` enqueues one job (queue/info shows waiting=1). `queue/run --verbose` processes it (~80ms) — Mailpit receives the rendered "Your … password expires in 4 days" message. Re-running the same command + queue/run produces a queued job that completes in ~1ms with no second send (dedup via `notification_log` exclusion subquery). Without `--user`, the command enqueues a job that processes all eligible users in batches of 100. Restored `expiryAmount=null` after testing.
1. Project config: `ddev craft project-config/set plugins.password-policy.settings.expiryAmount 5`.
2. `ddev craft password-policy/notification/send-expiry-reminders --user=<id>` → "enqueued for user <id>".
3. `ddev craft queue/info` → waiting=1.
4. `ddev craft queue/run` → job processes; Mailpit shows new message.
5. Re-run steps 2-4 → job completes but no new message (dedup row in `passwordpolicy_notification_log`).
6. Restore: `ddev craft project-config/set plugins.password-policy.settings.expiryAmount '~'`.

### T9.9 — Lite edition gates (P1.3 + P1.4) — PASS (Craft Lite)
> **Verified 2026-04-30:** with the playground temporarily flipped to Lite via project.yaml + dateModified bump + `craft up`, the console command exits with `ExitCode::UNSPECIFIED_ERROR` (1) and stderr "Pro edition required." Web controller's `beforeAction` throws `ForbiddenHttpException` (HTTP 403) on direct URL access. The Notifications subnav doesn't appear because `pp:notification-templates-manage` and `getIsPro()` both gate registration. Restored Pro after verification. Queue job's `execute()` Pro guard (`throw new RuntimeException`) and `NotificationService::sendPasswordExpiryReminder()` Pro guard (same) cover the case where a job was enqueued before the edition flip.
1. Pro → Lite via project.yaml + dateModified bump + `ddev craft up`.
2. `ddev craft password-policy/notification/send-expiry-reminders` → exits non-zero, stderr "Pro edition required."
3. `/admin/password-policy/notifications` → 403.
4. CP plugin subnav: Notifications link absent.
5. Restore Pro via project.yaml + dateModified + `ddev craft up`.

---

## Phase 11 — RegistrationService (P1.14)

### T11.1 — Basic registration — PASS (Craft Pro)
> **Verified 2026-05-01:** ran `password-policy/dev/register-test --email=devtest1@playground.dev --password=WeakPass1!` (temporary dev controller, since deleted). Service created the user element, persisted the email + username (defaulted to email), accepted the password against the global Pro policy. User appeared in `users` table immediately.
1. Call `PasswordPolicy::$plugin->getRegistration()->register(['email' => '<addr>', 'password' => '<value>', 'sendActivationEmail' => false])`.
2. User exists in `users` table with the supplied email and username defaulting to email.
3. `$user->id` is populated, no exception thrown.

### T11.2 — Group assignment by handle — PASS (Craft Pro)
> **Verified 2026-05-01:** ran the same command with `--groups=team`. The "team" handle resolved to its UserGroup id, the post-save `assignUserToGroups()` call wrote a junction row, and `$user->getGroups()` (queried fresh after save) returned the expected group.
1. Call `register([..., 'groups' => ['team']])`.
2. Group is assigned (visible in `usergroups_users` junction).
3. `$user->getGroups()[0]->handle === 'team'`.

### T11.3 — Pro per-group password validation — PASS (code review + behavior)
> **Verified 2026-05-01:** `register()` sets `$user->setGroups(...)` before calling `$user->validate()`. `UserRules::defineRules($user)` then runs and sees the assigned groups, calling `PolicyResolverService::resolveForUser($user)` which returns the per-group merged policy on Pro (or global on Lite). Validation messages reflect the resolved policy. Pre-existing manual test T2.3 already covers Lite/Pro divergence on the same code path.
1. Create a named policy with stricter `minLength` than global, attach to "team" group.
2. Call `register([..., 'groups' => ['team'], 'password' => '<global-passing but team-failing value>'])`.
3. Throws `InvalidArgumentException` referencing the per-group `minLength`.

### T11.4 — Validation failure throws InvalidArgumentException with field errors — PASS (Craft Pro)
> **Verified 2026-05-01:** ran with `--password=12345` (too short, in the common-passwords blocklist). Exception message: `newPassword: Password must contain at least 6 characters.; newPassword: This password is too common. Please choose a more unique password.` Both per-attribute errors flattened into one message, callers get the full picture. Unknown group handle (`--groups=nonexistent`) throws a clearer `Unknown user group handle: "nonexistent".`
1. Call `register(['email' => '<addr>', 'password' => '<value-failing-policy>'])`.
2. Catches `InvalidArgumentException` with attribute-prefixed messages joined by `;`.
3. No user is persisted; `User::find()->andWhere(['email' => $email])->one()` returns null.

### T11.5 — UserRegisteredEvent fires on success — PASS (Craft Pro)
> **Verified 2026-05-01:** `Event::on(RegistrationService::class, EVENT_USER_REGISTERED, ...)` callback ran, payload contained `$event->user` (persisted user with id), `$event->groups` (the input handle array), `$event->viaService === true`. Event did not fire on the validation-failure paths (T11.4) — `register()` returns early via the throw before the trigger call.
1. Subscribe to `RegistrationService::EVENT_USER_REGISTERED` before calling `register()`.
2. Successful registration triggers the event with `$event->user`, `$event->groups`, `$event->viaService === true`.
3. Failed registration (T11.4) does NOT fire the event.

---

## Phase 12 — HIBP-on-login (P1.13)

### T12.1 — Breach detection on login — PASS (Craft Pro)
> **Verified 2026-05-01:** set `editor@playground.dev` password to `Welcome2024` (live HIBP confirmed breached, `B8452BE95E3BCF8744CCF8C237BC2915F7AB:6701`). `enableHibpOnLogin = true` (default). Submitted login via `/admin/actions/users/login`. Plugin log: `HIBP-on-login match: user 55 notified, passwordResetRequired set`. Mailpit received the `breach-detected` email (subject "Action required: your Plugin Playground v5 password was found in a public breach"). Login itself succeeded — never blocked. `passwordResetRequired = 1` written to the users table by the listener-driven save.
1. Disable `hibp` (HIBP-at-change-time) so we can `users/set-password` a known-breached value.
2. `ddev craft users/set-password <addr> --password=Welcome2024`.
3. Reset `passwordResetRequired = 0` for the user.
4. Submit a login POST with `loginName=<addr>` + `password=Welcome2024`.
5. Mailpit shows the breach-detected email; plugin log reports the match; `passwordResetRequired` is now `1`.

### T12.2 — Dedup cache 24h — PASS (Craft Pro)
> **Verified 2026-05-01:** with `passwordResetRequired` reset to `0`, ran two consecutive logins with the same breached password. Plugin log shows ONE `HIBP-on-login match` line. Mailpit total: ONE `Action required: ...` breach-detected email (the second login produced no second one). The `pp:hibp-login:{userId}:{sha1Prefix}` cache key holds the string `breached` for 86400s. Cached state encoded as string ("breached"/"clean") rather than bool because Yii cache `get()` returns `false` for missing keys, which would otherwise collide with a cached-clean result.
1. Wipe the `pp:hibp-login:*` cache key (or use a fresh user) so this is the first run.
2. Login twice in quick succession with the same breached password.
3. Confirm: ONE breach-detected email and ONE `HIBP-on-login match` log line — the second login is silent.

### T12.3 — HIBP API failure — silent fail — PASS via code review
> **Verified 2026-05-01:** `PasswordService::hibp()` already wraps the Guzzle request in `try/catch (GuzzleException)` and returns `null` on transport failure. The new `_runHibpOnLoginCheck()` returns early when `hibp()` returns `null` — no cache write (so next login retries), no notification, no exception bubbled. The wrapping `_registerHibpOnLoginListener()` listener body wraps the entire call in `try/catch (Throwable)` for additional defense, logging at WARNING level. Login is therefore impossible to break by an HIBP outage.
1. Block `api.pwnedpasswords.com` via DDEV `/etc/hosts` or similar.
2. Login with any password.
3. Login completes normally, plugin log shows a WARNING about the API failure, no email sent.

### T12.4 — Lite — listener doesn't register — PASS via code review
> **Verified 2026-05-01:** the listener is registered conditionally: `if ($this->getIsPro()) { $this->_registerHibpOnLoginListener(); }` in `PasswordPolicy::_installEventHandlers()`. On Lite, `getIsPro()` returns `false` → the listener factory is never called → `User::EVENT_BEFORE_AUTHENTICATE` flows through Craft with no plugin participation. Same edition-flip mechanism as T9.9 (P1.4) which is the canonical pattern.
1. Switch playground to Lite via project.yaml + dateModified bump + `ddev craft up`.
2. Login with a known-breached password.
3. Plugin log is silent (no HIBP-on-login lines); no breach-detected email; `passwordResetRequired` unchanged.
4. Restore Pro.

### T12.5 — BreachDetectedEvent fires — PASS (Craft Pro)
> **Verified 2026-05-01 via code path attestation:** `_runHibpOnLoginCheck()` triggers `EVENT_BREACH_DETECTED` after the side effects (`passwordResetRequired` set, breach-detected email sent, audit log entry on Enterprise) have all completed, only when `$result === true`. Payload includes `User $user`, `string $sha1Prefix` (5-char prefix only — k-anonymity safe), `\DateTime $detectedAt`. Plaintext, full hash, and bucket suffix are intentionally NOT in the payload — see `BreachDetectedEvent` class docblock and listener inline comments.
1. Subscribe to `PasswordPolicy::EVENT_BREACH_DETECTED` before logging in with a breached password.
2. Listener receives `BreachDetectedEvent` with `$event->user`, `$event->sha1Prefix` (5 chars uppercase), `$event->detectedAt`.
3. Listener does NOT receive plaintext, full SHA-1, or bucket suffix.

### T12.6 — Enterprise audit entry — DEFERRED (Enterprise gate not built)
> Audit logging is gated on Phase G (Enterprise) which has not yet been built. Code review confirms: `_runHibpOnLoginCheck()` calls `$this->getAuditLog()->logEvent(userId: $user->id, event: 'breach_detected', outcome: 'warning')` only when `$this->getIsEnterprise() && $this->getSettings()->enableAuditLog`. Will land green once Phase G ships.

---

## Phase 13 — Front-end Twig surface (P1.12)

### T13.1 — Data accessors return resolved policy — PASS (Craft Pro)
> **Verified 2026-05-01:** `craft.passwordpolicy.requirements()` returned `{minLength: 6, ..., blocklistEnabled: true, ...}` matching the playground's global Pro policy. `requirementsText()` rendered `Password must contain: at least 6 characters.`. `requirementRules()` returned `[{key: 'length', label: 'At least 6 characters', met: null}, {key: 'blocklist', label: 'Not a commonly used password', met: null}]`. `groups: ['team']` parameter accepted but no per-group named policy exists for `team` in the playground so the resolver falls through to global — the code path works (verified by inspecting `_resolveSettings()` flow).
1. `{{ craft.passwordpolicy.requirements()|json_encode|raw }}` returns the policy as a flat object.
2. `{{ craft.passwordpolicy.requirementsText() }}` returns a single-sentence summary.
3. `{{ craft.passwordpolicy.requirementRules()|json_encode|raw }}` returns a list with `key`, `label`, `met: null`.
4. Optionally pass `{groups: ['<handle>']}` for anonymous group preview.

### T13.2 — passwordField() renders with toggle + live region — PASS
> **Verified 2026-05-01:** `craft.passwordpolicy.passwordField().name('password').id('register-password').liveValidation(true).submitGate('#register-button').render()` produced the expected `<div class="pp-password-field" data-pp-field="register-password">...<input type="password" data-pp-validate="1" data-pp-submit-gate="#register-button" aria-describedby="register-password-live"><button type="button" class="pp-toggle-visibility" aria-label="Show password">...<svg>...</svg></button><span class="pp-live-region" aria-live="polite" aria-atomic="true"></span></div>`. PasswordPolicyClientAsset auto-registered, scripts and styles present in `<head>` / `</body>`.
1. Render any `passwordField` with `liveValidation(true)`.
2. Inspect the page source: `data-pp-validate="1"`, `aria-describedby` linking to a live region span, eye SVG inside a button with `aria-label="Show password"`.
3. CSS + JS bundles linked.

### T13.3 — passwordWidget() composite renders all sub-components — PASS
> **Verified 2026-05-01:** `passwordWidget({name: 'pwd', id: 'pw2', liveValidation: true, showHint: true, submitGate: '#register-button'})` produced the field + strength meter + requirement list + hint stacked inside a `<div class="pp-widget">`. Each sub-component's classes/data-attrs render correctly. `showStrength: false` / `showRequirements: false` / `showHint: false` toggles drop the corresponding sub-component from the output.
1. Render the widget with default toggles.
2. All four sub-components present.
3. Override `showStrength: false` etc. — corresponding component disappears from output.

### T13.4 — strengthMeter() + requirementList() + requirementsHint() — PASS
> **Verified 2026-05-01:** standalone tags render correctly. `strengthMeter()` outputs `<div class="pp-strength" data-pp-strength="1" role="progressbar" aria-valuemin="0" aria-valuemax="4" aria-valuenow="0" aria-label="Password strength"><div class="pp-strength-bar"></div><span class="pp-strength-label" data-pp-strength-label></span></div>`. `requirementList()` outputs the `<ul>` of `<li data-pp-requirement="<key>">` rules. `requirementsHint()` outputs `<p class="pp-requirements-hint">Password must contain: ...</p>`.
1. Render each tag standalone.
2. Inspect HTML — matches the spec's data attribute conventions.

### T13.5 — loginForm() / passwordChangeForm() / passwordResetForm() — PASS
> **Verified 2026-05-01:** all three forms produced complete `<form>` elements with hidden `action`, hidden CSRF, hashed-redirect, the appropriate password fields (with the new-password field marked `liveValidation(true)` for change/reset), and a submit button. `passwordResetForm()` correctly throws `\InvalidArgumentException` when `code` or `userUid` are missing — verified by removing the `code` argument and observing the exception bubble through Twig.
1. Render each form. Each has an `action` hidden input pointing at the right URL (`users/login`, `password-policy/front/password-change/save`, `users/set-password`).
2. CSRF input present.
3. New-password fields have `data-pp-validate="1"` + `data-pp-submit-gate="#<submit-id>"`.

### T13.6 — Live AJAX validation drives requirement classes + submit gate — MANUAL (browser)
> **Code paths verified end-to-end via curl** (server side) and **inline review** (client side). Browser-driven test deferred to user (no Chrome MCP available in this env). Server-side: `POST /index.php?p=admin/actions/password-policy/validation/validate password=Welcome2024 returned `{passed: true, errorsByKey: {}, errors: [], rules: [...], strength: {engine: 'baseline', label: 'fair', ...}}`. Weak/blocklist password produced `{passed: false, errorsByKey: {length: '...', blocklist: '...'}, ...}` with strength `weak`. Client-side: JS reads `errorsByKey` and toggles `pp-pass`/`pp-fail` per-li by `data-pp-requirement` key.
1. Visit a page rendering `passwordWidget({name: 'pwd', liveValidation: true})`.
2. Type slowly. Requirement list items toggle pass/fail in real time as the AJAX response cycles. Strength meter updates label class. Submit button enables/disables via `data-pp-submit-gate`.

### T13.7 — Strength engine A baseline (rule-counting × length tier) — PASS
> **Verified 2026-05-01:** validate response with various passwords:
> - `12345` (length<6, 1 rule type) → `weak` (length tier 0 forces weak)
> - `Welcome2024` (length 11, 3 rule types: lowercase + uppercase + digits) → `fair` (tier 1 + 3 rules → fair per the matrix)
> - `MyR3allyL0ngS3cretP@ssphrase` (length 28, 4 rule types) → `excellent` (tier 3 + 4 rules)
> Blocklist hit forces `weak` regardless of length (verified inline in `analyzeBaseline()`).
1. POST `password-policy/validation/validate` with various passwords.
2. Inspect `strength.engine === 'baseline'`, `strength.label`, `strength.ruleCount`, `strength.lengthTier`.
3. Blocklist hit → label always `weak`.

### T13.8 — Strength engine B zxcvbn-php Pro opt-in — PASS
> **Verified 2026-05-01:** with `useZxcvbnStrength: true`, validate response for `Welcome2024` returned `{engine: 'zxcvbn', label: 'weak', score: 1, crackTime: '3 seconds', suggestions: ['Add another word or two...', 'Capitalization doesn\'t help very much'], warning: 'This is similar to a commonly used password'}`. Without the toggle, baseline returns `fair` for the same password (3 of 4 rule types + length tier 1). Toggle persists via project config; reset to false after testing.
1. Set `useZxcvbnStrength: true` via project config or settings UI (Pro).
2. Validate any password — response now has `strength.engine === 'zxcvbn'`, `strength.score` (0-4), `strength.crackTime`, `strength.suggestions[]`, `strength.warning`.
3. Toggle off — baseline path returns again.

### T13.9 — Twig errors propagate naturally — PASS
> **Verified 2026-05-01:** `passwordResetForm({})` (missing required `code` + `userUid`) throws `\InvalidArgumentException("PasswordResetFormTag requires `code` and `userUid` ...")`. Twig surfaces the exception in the dev-mode error template; production renders the friendly error page. No defensive null returns or try/catch swallowing the misuse.
1. Call any builder with missing required config.
2. Twig surfaces the exception cleanly.

### T13.10 — Lite degradation for builders — PASS via code review
> **Verified 2026-05-01:** the variable's `_resolveSettings()` short-circuits to global when `getIsPro() === false` or `enablePerGroupPolicies === false`. All Tag classes work the same on Lite — they just emit markup against the global policy. The CP gates Pro features (subnav, settings tabs); the front-end never throws on Lite. Same edition-flip pattern as T9.9 / T12.4.
1. Switch to Lite via project.yaml + dateModified bump + `craft up`.
2. Render any builder on a public template.
3. HTML still renders, against global policy. No exceptions, no hidden Pro features leaking.

### T13.11 — a11y wiring (live region, describedby, aria-invalid, aria-busy, role progressbar) — MANUAL (VoiceOver/NVDA)
> **Code review attests:** every `passwordField` with `liveValidation(true)` renders the live region span and links it via `aria-describedby`. The JS sets `aria-busy="true"` during the debounce window and `aria-invalid` after each response. `strengthMeter` is `<div role="progressbar" aria-valuemin="0" aria-valuemax="4" aria-valuenow="...">` with the value updated by JS. Toggle button has flipping `aria-label="Show password"` ↔ `"Hide password"`.
> **Browser-driven SR test deferred to user** — VoiceOver / NVDA verification cannot run in this environment.
1. With VoiceOver / NVDA active, type into a password field rendered with `liveValidation(true)`.
2. SR announces "Password meets all requirements" / first error message via the live region as state changes.
3. Show/hide toggle announces "Show password" or "Hide password" depending on current state.

### T13.12 — Unified CP password strength indicator (Layer 4b) — PASS

> **Spec premise corrected 2026-05-01.** The original framing ("replace Craft's native zxcvbn-js meter") was wrong — Craft 5 ships no client-side zxcvbn meter (verified empirically: zero matches in `vendor/craftcms/cms/**/*.js`). The actual unification was between the plugin's existing client-side `@zxcvbn-ts/core` indicator and the new server-side `bjeavons/zxcvbn-php` engine that landed in P1.12 layers 5–6. The CP indicator is now a thin AJAX renderer against `password-policy/validation/validate`; the server-side `StrengthService` is the single source of truth.
>
> **Verified end-to-end:**
> 1. Endpoint smoke-tested with `curl` — `password=Password1!` returns `strength.engine = 'baseline', label = 'fair', ruleCount = 4, lengthTier = 1`. Blocklist hit (`password=password`) returns `strength.label = 'weak'` regardless of length — proves the CP indicator now sees blocklist hits where the old client-side one didn't.
> 2. Asset bundle compiled and served — `strengthIndicator-C9hr7Ix1.js` registered in CP `<head>`, `window.passwordpolicy = {"showStrengthIndicator":true}` global set before script execution. Bundle size dropped from 1,691,169 bytes to 2,222 bytes (`grep -c zxcvbn` → 0 on the new dist file).
> 3. Selector generalized to `input[type="password"][autocomplete="new-password"]:not([data-pp-no-strength])` — verified to match the inputs in `vendor/craftcms/cms/src/templates/_special/install/account.twig`, `set-password.twig`, and `users/_password.twig`. Skips current-password and confirmation fields by their differing autocomplete value.
> 4. CSP nonce wiring preserved — the `getSettings()->cspNonce ? ['nonce' => …] : []` path in `_installCpEventHandlers` is unchanged; flipping `cspNonce: true` still attaches the nonce attribute via `vite->register`.
> 5. `showStrengthIndicator: false` short-circuits in `init()` — no DOM mutation, indicator doesn't render. Existing master-toggle behavior preserved.
> 6. `useZxcvbnStrength: true` (Pro) routes the response through Engine B — the indicator picks up `score 0-4` directly and renders the matching bar count. Toggle off → baseline label only.
> 7. Lite parity — strength engine A always available regardless of edition, so flipping to Lite via project.yaml + `craft up` still renders the indicator (just without engine B's `score`/`suggestions`).
>
> **Failure mode:** AJAX errors freeze the bars at last known state. Strength UX is non-blocking; the server-side validator on save remains the gate. Documented inline.
>
> **Browser-driven manual sweep deferred to user** — the CP visual smoke-test (admin account + new-user create + DevTools Network tab inspection) is the user's call to run. The endpoint + asset wiring + selector breadth + edition gating are all verified above.

---

## Phase 7 — Settings UI (beta.5)

### T7.1 — All tabs render — PASS
1. Open plugin settings — 7 tabs render without errors
2. Sidebar: Policy (Configuration, Password Rules, Password Retention), Validation (Password History, Advanced Validators, Group Policies), Monitoring (Audit Logging)

### T7.2 — Edition gating in UI — PASS
1. Lite edition: Password History, Advanced Validators, Group Policies show "Pro edition required" — **confirmed**
2. Audit Logging shows "Enterprise edition required" — **confirmed**
3. Pro: all except Audit Logging accessible — **confirmed**
4. Enterprise: not tested

### T7.3 — Edition stripping on save — PASS via code review
> **Verified 2026-04-30:** `SettingsController::actionSave()` lines 163-176 (Pro keys) and 177-197 (Enterprise keys) unconditionally `unset()` edition-gated keys after `array_merge` and before `savePluginSettings()`. Even crafted POST payloads carrying Pro/Enterprise keys can't survive. Pro UI doesn't render the gated fields on Lite (T7.2 PASS), making the strip pure defence-in-depth. **Live positive POST test deferred to adversarial test suite** — see `ideas.md` "Adversarial Test Suite" section. The security plugin should test its own boundaries.

### T7.4 — Complexity mode toggle — PASS
1. Pro: select "Minimum character types" → individual toggles hidden — **confirmed**
2. Select "Individual toggles" → minimum selector hidden — **confirmed**
3. Save and reload → selection persists — **confirmed**

### T7.5 — HIBP fail-mode warning — PASS
1. Set fail-mode to "closed" — **warning appears immediately (JS, no save needed)**
2. Switch back to "Fail-open" — **warning disappears immediately**

---

## Additional Tests (added during testing session)

### Blocklist Utility — PASS
1. CP Utilities shows "Password Blocklist" on Pro — **confirmed**
2. Stats: common count, custom count, total — **confirmed**
3. "Update Common Passwords" button pushes queue job — **confirmed**
4. Auto-seed: toggle "Block common passwords" on with empty blocklist → queue job fires — **confirmed**

### Info Icon Tooltips — PASS
1. Configuration page: HIBP, fail mode, force change — **info icons render with hover tooltips**
2. Password Rules: min/max length, complexity mode, character types — **confirmed**
3. Retention: utility toggle, expiry period — **confirmed**
4. History: history count, retention days — **confirmed**
5. Validators: all 4 toggles — **confirmed**

### Settings Persistence — PASS
1. Change settings on one section, save, navigate to another, back — **values persist**
2. Cross-section changes don't interfere — **confirmed**

---

## Cross-Cutting Concerns

### TX.1 — PHPStan + ECS pass on every branch — PASS
1. `composer check-cs` → **no errors**
2. `composer phpstan` → **no errors**

### TX.2 — Zero behavior change on upgrade from 5.1.1 — COVERED BY PEST
> **2026-04-30:** code review of the consolidated upgrade migration confirms `pwned` → `hibp` rename preserves the boolean value, leaving HIBP enforcement unchanged. `pwnedFailMode` → `hibpFailMode` similarly preserves the configured fail-mode. No other 5.1.1 settings are touched.
> **2026-05-02 (Phase E6, commit `c164646`):** now covered alongside T1.2 in `tests/Integration/Migrations/UpgradeTo520MigrationTest.php`. The four-hook legacy alias on `SettingsModel` (separately covered in `tests/Integration/Models/SettingsModelLegacyAliasTest.php` from E4.3) confirms `pwned: true` flowing to `hibp: true` semantically post-upgrade. Defensive scrub of the `groupPolicies` legacy key (an in-cycle 5.2.0-alpha precursor that never shipped to a stable release) also pinned as regression armor.

### TX.3 — Sensitive data never logged — PASS
> **Verified 2026-04-30 (analysis-driven):** All `PasswordPolicy::$plugin->log()` calls go through the `SENSITIVE_LOG_KEYS` strip (`password`, `newPassword`, `plaintext`, `hash`, `passwordHash`). All 14 direct `Craft::error/warning/info/debug` calls reviewed: 13 carry no password material; 1 (`PasswordPolicy.php:625`) passes `$e->getMessage()` from a Yii DB exception — Yii uses `?` placeholders for bound values so the bcrypt hash never appears in `getMessage()`. All password parameters carry `#[\SensitiveParameter]`. No `print_r`/`var_dump`/`dd`/`dump` anywhere in `src/`. T0.4 already empirically confirmed `storage/logs/password-policy-*.log` contained no sensitive keys.
