# Manual Testing Scenarios

Test each scenario after installing the plugin on a fresh Craft CMS 5 site. Start from `5.2.0-alpha.1` and work forward — each branch builds on the previous.

**Legend:** PASS = verified, FAIL (fixed) = bug found and fixed, PENDING = not yet tested

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

### T1.2 — Upgrade migration seeds history — DEFERRED to P2.5
> **2026-04-30:** code review confirms `_seedPasswordHistory()` correctly populates one bcrypt-hash row per user with a password. Idempotent (skips when table non-empty). Manual fixture-based test (uninstall + manually inject `pwned` keys + mark migration not-applied + craft up) is fragile; deferred to Pest test infrastructure (P2.5) where proper fixturing makes the test re-runnable on every CI build.
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

### T9.4 — Notification dedup — PENDING

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
> **Verified 2026-04-30:** `SettingsController::actionSave()` lines 163-176 (Pro keys) and 177-197 (Enterprise keys) unconditionally `unset()` edition-gated keys after `array_merge` and before `savePluginSettings()`. Even crafted POST payloads carrying Pro/Enterprise keys can't survive. Pro UI doesn't render the gated fields on Lite (T7.2 PASS), making the strip pure defence-in-depth. **Live positive POST test deferred to adversarial test suite** — see `docs/IDEAS.md` "Adversarial Test Suite" section. The security plugin should test its own boundaries.

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

### TX.2 — Zero behavior change on upgrade from 5.1.1 — DEFERRED to P2.5
> **2026-04-30:** code review of the consolidated upgrade migration confirms `pwned` → `hibp` rename preserves the boolean value, leaving HIBP enforcement unchanged. `pwnedFailMode` → `hibpFailMode` similarly preserves the configured fail-mode. No other 5.1.1 settings are touched. Manual end-to-end verification (5.1.1 install + custom settings + upgrade + confirm same passwords accepted/rejected) is fragile and deferred to P2.5 Pest fixtures.

### TX.3 — Sensitive data never logged — PASS
> **Verified 2026-04-30 (analysis-driven):** All `PasswordPolicy::$plugin->log()` calls go through the `SENSITIVE_LOG_KEYS` strip (`password`, `newPassword`, `plaintext`, `hash`, `passwordHash`). All 14 direct `Craft::error/warning/info/debug` calls reviewed: 13 carry no password material; 1 (`PasswordPolicy.php:625`) passes `$e->getMessage()` from a Yii DB exception — Yii uses `?` placeholders for bound values so the bcrypt hash never appears in `getMessage()`. All password parameters carry `#[\SensitiveParameter]`. No `print_r`/`var_dump`/`dd`/`dump` anywhere in `src/`. T0.4 already empirically confirmed `storage/logs/password-policy-*.log` contained no sensitive keys.
