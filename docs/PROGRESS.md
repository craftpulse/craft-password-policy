# Progress Log

Session-level tracking of what was done, when, and what's next. Keeps PLAN.md clean
as the master reference and TESTING.md focused on test results.

---

## Session: 2026-04-21 to 2026-04-24

### Environment Setup
- Fixed playground: DDEV volume mounts, composer repos path, removed deprecated db.php
- Stopped old `plugin-playground` project (only v4 and v5 remain)
- Fixed admin credentials: `development@craftpulse.com` / `letmein-craftpulse`
- Plugin edition switching: project.yaml + dateModified + `craft up` (not app.php hacks)

### Manual Testing (28 tests completed)
- **Solo Lite (5):** T0.1, T0.2, T0.3, T0.4, T1.1
- **Solo Pro (17):** T2.1-T2.3, T3.1-T3.6, T7.1, T7.2, T7.4, T7.5, T9.1-T9.3, TX.1, blocklist utility, info tooltips
- **Craft Team (6):** T2.4, T2.5, T6.1, T6.2, T8.1, T8.2

### Bug Fixes (4 commits)
- `43c6f6c` — 7 fixes: getIsLite, validation order, UI corrections
- `e45c60a` — Info icon tooltips on all settings pages
- `fb3e9b3` — BlocklistUtility, auto-seed, SeedBlocklist queue job
- `bc6196d` — lastPasswordChangeDate direct query fix

### Features Built
- Info icon tooltips (NIST/PCI-DSS/GDPR references on all settings pages)
- BlocklistUtility (CP utility, stats, "Update Common Passwords" button, `pp:blocklist-manage` permission)
- SeedBlocklist queue job + auto-seed trigger when toggle enabled with empty blocklist
- lastPasswordChangeDate fix (Craft UserQuery doesn't select this column)

### Key Decisions
- Blocklist seeding: queue job on toggle enable (when allowAdminChanges enabled), CLI or utility button on production
- Custom dictionary: future editableTable UI, NOT file upload/textarea
- Separate DB source column (`common` vs `custom`) prevents flooding editableTable
- Compliance view: hybrid — extend Users index + ComplianceDashboardUtility
- Users are NOT multi-site — no multi-site edge cases

### Discoveries
- Craft's `UserQuery::beforePrepare()` doesn't select `lastPasswordChangeDate` — need direct DB query
- `pixelwerft/user-audit` plugin stores raw PII (IPs, emails, UAs) — our audit logging is materially more secure (hashed IPs, HMAC identifiers, no UAs)
- Security USPs documented for future marketing/docs

### Feature Requests Identified
- Admin password change action on Users index (not just "Copy reset URL")
- User index table attributes (password status, last change, expired, reset required)
- Sequential chars validator needs detailed documentation (ASCII sequences like `pqr`)

---

## Session: 2026-04-29

### UI overhaul: per-group named policies edit screen

The named-policies CRUD existed before this session but the policy edit screen was a long flat form with verbose captions and no real Craft-native UX. Rebuilt as proper Craft CP UI.

**Edit screen redesign:**
- 3 tabs via `asCpScreen()->tabs([...])`: General, Rules, Lifecycle
- Tri-state rule overrides — copied the `craftcms/webhooks` event-filter pattern: `<table class="data">` with `<div class="btn">` icon buttons (red X / hollow grey circle / green check) per rule row
- High-contrast active states using `var(--bg-enabled)` / `var(--bg-disabled)` (Craft semantic vars, dark-mode-aware, accessibility-tested) — replaced hardcoded `#27ae60` / `#d0021b`
- White hollow circle outline when "Global" is active (default `--gray-500` ring on Craft's dark `.btn.active` background was ~1.6:1 contrast → fails WCAG AA 3:1 for graphics)
- Override warnings via Craft's `warning:` field parameter (mirrors Blitz's `configWarning` macro pattern in `_macros.twig`) — sticks naturally inside `.field` wrapper
- Warnings only shown when value actually differs from global (not whenever explicit override exists)
- Divergence-from-preset blue left border via `.pp-divergent` class on changed fields/rows
- "Restore preset defaults" button under preset dropdown (re-applies preset values via JS)
- "Reset all to global" button in toolbar via `additionalButtonsHtml()` — clears every override

**Tri-state semantics (Option A):**
- Refactored `PolicyResolverService` with two-phase boolean merge: any explicit `true` wins → else any explicit `false` wins → else global. Lets single-group "Off" override global "On" without weakening multi-group resolution
- `GroupPolicyModel::booleanOverrideFields()` static returns the list, `mergeWithGlobal()` no longer touches booleans
- `PolicyController::_normalizeSettings()` handles `'0'`/`'1'`/`''` for tri-state booleans
- `PolicyModel::setSettingsFromArray()` resets fields to null first — fixes "Reset all to global" save bug

**Policies index UX:**
- Two columns: "Preset" and "Changes" (count of fields differing from preset, or `—`)
- Blue dot indicator next to policy names for divergent policies (via `iconColor: 'blue'` + inline SVG)
- Smart row link: divergent policies deep-link to `#rules` (Rules tab); non-divergent to General tab

**Settings → Group Policies page polish:**
- Removed `flex-fields` wrapper, added `<hr>` separator
- Replaced `btn submit` (red, primary) with `btn go` (Craft's "navigate" pattern with arrow icon)
- Subnav reordered — Policies above Settings (when per-group toggle on)

**Bug fixes during the session:**
- `expiryPeriod` saved without `expiryAmount` (orphaned in JSON)
- Preset auto-fill JS used `btn.click()` on the lightswitch DOM element instead of Craft's Lightswitch API (now uses tri-state `setRuleValue()` which clicks the right button)
- `_index.twig` dropped the inline group cards and links to the dedicated policies CRUD

**Static analysis blocked:** `composer phpstan` / `check-cs` fail in the playground because vendor was installed against PHP 8.4 on host but the DDEV container runs PHP 8.3. Reinstalling vendor inside DDEV would fix this.

### Manual tests passed

- T5.6 — Migration creates policies tables, migrates legacy `groupPolicies` to named policies (Editors Policy, Managers Policy)
- T5.7 — Group Policies settings page (toggle + link, subnav gating)
- T5.8 — Policies index renders (VueAdminTable with Name/Groups/Preset/Changes)
- T5.9 — Create new policy (Team Policy with min length 10 + numbers, assigned to Team)
- T5.10 — Preset auto-fill (NIST, OWASP, PCI-DSS, Strict Enterprise, None)
- T5.11 — Save round-trip (Strict Enterprise + custom override of `checkSequentialChars=false` persisted; junction table updated to Team + Editors)

### Skill gaps documented

CP UI patterns missing from `craftcms` skill (in case we want to land them in the skill itself later):

1. `asCpScreen()->tabs([...])` and `additionalButtonsHtml()` not in cp.md — found in `web/CpScreenResponseBehavior.php`
2. Tri-state inheritance UI — `craftcms/webhooks` `_manage/edit.html` is the canonical pattern; uses `<div class="btn">` not `<button>`, `data-icon="remove"`/`"checkmark"` (not `"check"`), and `<div class="status inactive">` for the hollow circle
3. `.status` class changed in Craft 5 — bare `.status` renders invisibly; needs modifier (`.gray`, `.inactive`, `.green`, etc.)
4. `[hidden]` attribute is overridden by Craft's `.warning.has-icon { display: flex }` — avoid by using server-rendered `warning:` instead of dynamic show/hide
5. `warning:` field parameter is the canonical "overridden by..." UI — Blitz pattern with `_macros.twig`, no custom markup
6. Use `var(--bg-enabled)` / `var(--bg-disabled)` / `var(--white)` — accessibility-tested and dark-mode-aware
7. `forms.buttonGroupField` is the wrong tool for tri-state inheritance — too uniform, not the right semantics
8. VueAdminTable cells escape HTML — only `title`/`handle`/`checkbox` slots are baked in; rich cell rendering requires a custom Vue component (like `nystudio107/craft-retour`)

---

### Conflict UX (P1.9 + P1.10)

`PolicyController` now surfaces the `policy.minLength > globalSettings.maxLength` collision both at save and on edit-screen load.

- `actionSave()` calls `Craft::$app->getSession()->setNotice()` after a successful save when the conflict is present. Sits next to the "Policy saved." success toast (different flash keys — both render).
- `actionEdit()` builds a custom `.pp-conflict-banner` div via `noticeHtml()` — orange-500 left border, orange-050 background tint, larger block padding. Persistent on every load while the collision is present. Replaces the original `note warning` blockquote which was visually too subtle.
- Combined with the existing read-only environment notice — when both apply, both render concatenated, instead of the previous "either/or" branch.
- Added private helpers `_hasMinLengthConflict()` and `_buildEditNoticeHtml()` to keep the conflict check single-sourced.
- T5.16 written into TESTING.md covering the four-state walk: configure → save (notice fires) → reload edit (banner sticky) → resolve global → reload (banner gone).

Static analysis still blocked by host PHP 8.4 vs DDEV PHP 8.3 vendor mismatch — fixed locally with `php -l` syntax checks until vendor is reinstalled inside DDEV.

### Track A — audit fix-ups

- **A1 — RetentionController route mismatch:** the audit reported `_users/password-security.twig:105` posting to `password-policy/retention/force-reset` with no matching action. Verified the bug is *latent*, not active — the template is an orphan, never registered as a user-edit tab anywhere. Added `actionForceReset()` to `RetentionController` (calls existing `RetentionService::requirePasswordReset($user)`, which already handles admin guard + audit logging). When Phase 6 tab registration lands, the button will work. Tab registration itself is P2 feature work.
- **A2 — Migration project config writes:** added `$projectConfig->muteEvents = true` (with try/finally restore) around the `pwned → hibp` rename `set()` call in `m260426_000000_AddPoliciesTables`. Audit's suggested syntax (`set('...', $val, muteEvents: true)`) was invalid — `ProjectConfig::set()` has no `muteEvents` parameter. Used the public property API instead. Risk was theoretical (no internal subscribers register for `plugins.password-policy.settings` changes).
- **A3 — `_index.twig` json_encode flags:** **non-issue.** Craft's `|json_encode` Twig filter auto-applies `JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_QUOT` whenever the response content-type is `text/html` (see `vendor/craftcms/cms/src/web/twig/Extension.php:251` `jsonEncodeFilter()`). CP responses qualify. The double-quote-delimited JS context (`var tableData = {{ … }}`) means missing `JSON_HEX_APOS` is not exploitable. No code change.
- **A4 — Group UID validation in `_normalizeGroupPolicies`:** initially patched defensively, then **reverted** as part of the dead-code deletion below. The function had no callers — the user-edit path it served had been removed earlier in this same unreleased 5.2.0 cycle.

Two of four audit findings turned out wrong-as-stated (A2 syntax, A3 entirely). Treat audit subagent output as a starting point, verify before applying.

### P1.2 — Common passwords 195 → 10,000

`src/data/common-passwords.php` rewritten from a hand-curated 195-entry alpha set to the canonical SecLists top-10k list (`Passwords/Common-Credentials/10k-most-common.txt`).

- Sourced via `curl` from raw.githubusercontent.com — cached SHA in the file lookup so the source is reproducible.
- Built via a one-shot PHP script: lowercase + trim + dedupe + escape for PHP single-quoted strings (only `\` and `'` need escaping).
- One artifact in source data — `pic\'s` was double-escaped in SecLists' raw file. Unescaped to `pic's` (5 chars) and re-escaped for PHP, so the stored password is the actual character sequence the user would type.
- File grew from 3.4KB → 143KB (still well within sane bundle size).
- CLI seed verified end-to-end: `ddev craft password-policy/blocklist/update` reports "10000 common passwords loaded"; DB has exactly 10000 rows with `source='common'`; the `pic's` row round-trips correctly (apostrophe, 5 chars).
- The `BlocklistService::seedCommonPasswords()` flow already chunks inserts in batches of 1000, so memory pressure is bounded.
- Removed the `@TODO Expand to 10,000 entries before stable release` doc note — it's done.

### Track B — pre-release security tests (4 PASS, 2 deferred)

- **T7.3 — PASS via code review.** `SettingsController::actionSave()` lines 163-176 (Pro keys) and 177-197 (Enterprise keys) unconditionally `unset()` after `array_merge` and before `savePluginSettings`. Crafted POSTs carrying gated keys cannot survive. Live-POST positive test deferred to a future "Adversarial Test Suite" entry in `docs/IDEAS.md` — the security plugin should test its own boundaries.
- **T1.3 — PASS via code review.** `_seedPasswordHistory()` saves `enableLogging`/`enableProfiling`, sets both `false` before any user-table SELECT or `batchInsert`, restores in `finally`. Bcrypt hashes never reach the Yii debug logger.
- **T1.4 — PASS empirically.** `ddev craft plugin/uninstall password-policy` triggers `Install::safeDown()` which drops all 6 tables in correct reverse-FK order. Verified `SELECT COUNT(*)... LIKE 'passwordpolicy_%' = 0` post-uninstall. `ddev craft plugin/install password-policy` recreates everything cleanly. Edition defaulted to Lite on reinstall — flipped back to Pro via project.yaml + `craft up` to restore the playground baseline.
- **TX.3 — PASS via analysis.** All 14 direct `Craft::error/warning/info/debug` calls reviewed for sensitive payloads — clean. All `PasswordPolicy::$plugin->log()` calls go through `SENSITIVE_LOG_KEYS` strip. `#[\SensitiveParameter]` on every plaintext/hash function arg. Zero `print_r`/`var_dump`/`dd` in `src/`. Yii DB exception messages use `?` placeholders for bound values, so `getMessage()` never inlines bcrypt hashes. Empirical grep on actual log files already PASS via T0.4.
- **T1.2 + TX.2 — DEFERRED to P2.5.** Manual fixturing for "5.1.1-state simulation" is fragile (uninstall + manually inject `pwned` keys + force migration not-applied + craft up). Proper home is Pest tests where setup is repeatable and runs on every CI build. Migration logic itself code-reviewed PASS.

PLAN.md status: 49/50 manual tests passing, 2 explicitly deferred to test infrastructure.

### Migrations consolidated to a single 5.1.1 → 5.2.0 upgrade

Three legacy migration files removed:
- `m250419_000000_AddPasswordPolicyTables.php` (year-old, abandoned alpha attempt)
- `m250419_100000_AddNotificationLogTable.php` (year-old, abandoned alpha attempt)
- `m260426_000000_AddPoliciesTables.php` (recent in-cycle alpha helper)

Replaced with a single `m260429_224908_UpgradeTo520Schema.php` — generated via `ddev craft migrate/create UpgradeTo520Schema --plugin=password-policy` so the timestamp reflects the actual authoring time (host clock, not hand-picked).

What it does:
1. `(new Install())->safeUp()` — creates all 6 tables idempotently (tableExists guards on every one)
2. Seeds `passwordpolicy_password_history` from existing user password hashes — **idempotent guard added** (skipped when the table already has rows; the original m250419 lacked this and would have corrupted state on re-run)
3. Renames `pwned` → `hibp` and `pwnedFailMode` → `hibpFailMode` in project config
4. Drops legacy `groupPolicies` project config key (defensive — never shipped, but cleans dev environments)

Project config writes are wrapped in `muteEvents` try/finally. Bcrypt hashes are kept out of debug logs by toggling `enableLogging`/`enableProfiling` off during the seed loop.

Verified by re-running `ddev craft up` on the playground — applied in 6ms, all idempotency guards held (tables existed, history had rows, pwned keys already renamed). Playground migrations table now has stale tracking rows for the 4 deleted/replaced filenames; harmless cosmetic, Craft ignores them.

Process change: from now on, all new migrations are generated via `ddev craft migrate/create <Name> --plugin=password-policy` so timestamps come from the container clock instead of being hand-picked. Saved as a feedback memory.

### Dead `groupPolicies` code path deleted

User-flagged: marking code `@deprecated in 5.2.0` makes no sense when 5.2.0 is the version doing the deprecating *and nothing has shipped*. The legacy `groupPolicies` settings-array approach was an in-cycle iteration replaced by named policies before any release.

Surface check confirmed the path was fully dead:
- No template in `src/templates/` submits `groupPolicies` via POST
- `SettingsController::actionSave()` `array_key_exists('groupPolicies', ...)` branch unreachable from any real request
- `SettingsModel::$groupPolicies` had zero readers (the migration reads project config directly)

Removed:
- `SettingsController::_normalizeGroupPolicies()` — the entire ~85-line method, including my A4 UID-validation patch
- The `array_key_exists('groupPolicies', $submittedSettings)` block in `actionSave()`
- `unset($settings['groupPolicies'])` from the Lite edition-strip (no-op once the model field was gone)
- `SettingsModel::$groupPolicies` field

Kept:
- `_migrateGroupPolicies()` in the install migration — legitimate one-shot upgrade path for dev environments still carrying `groupPolicies` in their project.yaml from earlier 5.2.0 alphas. Reads project config directly, doesn't touch the model. After it runs, the legacy `groupPolicies` key remains orphaned in project.yaml but is harmless (no readers).
- `unset($settings['groupPolicies'])` could optionally be added to the migration to scrub project.yaml — deferred as a separate cleanup, not required.

### Env var support on policy length inputs

Policy edit form now mirrors the global Settings page for `minLength` / `maxLength` — env references resolve at validation time the same way they do globally.

- `PolicyModel`: types widened from `?int` to `int|string|null` on both attributes; registered `EnvAttributeParserBehavior` via `defineBehaviors()` so beforeValidate resolves `$PP_MIN_LENGTH` style refs and afterValidate restores the raw string for persistence.
- `PolicyModel::mergeWithGlobal()` now resolves env refs and casts to int before copying onto the `?int`-typed `GroupPolicyModel` attributes — otherwise the resolver would TypeError when an env-saved policy is loaded for a logged-in user.
- `PolicyModel::validateMaxLengthAgainstMin()` casts both attributes to int before comparing — defensive against mid-validation states where values may be numeric strings.
- `PolicyController::_normalizeSettings()`: split `minLength` / `maxLength` out of the int-cast loop. Numeric values still get cast; `$VAR` / `@alias` strings pass through unchanged.
- `PolicyController::_hasMinLengthConflict()` and the conflict messages resolve via `App::parseEnv()` so the banner still surfaces accurate values when env-driven.
- `_edit.twig`: replaced `forms.textField` with `forms.autosuggestField` + `suggestEnvVars: true` for both length inputs. Visual parity with the global rules tab.
- 3rd field (`passwordHistoryCount`) intentionally left as `forms.textField` — global Settings page (`history.twig`) doesn't env-parse it either, so adding env support there would *diverge* from global, not converge.

---

## Session: 2026-04-30 (end of day — P1.7 + P1.11 + GC refactor)

### P1.7 — `notificationLogRetentionDays` UI field

Added `forms.textField` to `src/templates/_settings/retention.twig` inside the existing Pro block (after `expiryReminderDays`, with `<hr>` separator). Field has its own `info` span explaining what notification log entries are (dedup window for expiry reminders). Added to `SettingsController::actionSave` Pro-strip list for parity with `expiryReminderDays`. PROGRESS.md got a new memory `feedback_retention_gc_framing.md` after a UX iteration: don't say "pruned automatically" — `password-policy/gc/run` cron is recommended production setup, not edge case. Operational pointer "(see documentation)" deferred to instructions field once P1.8 docs exist.

Manual test: change value 30 → 60, save, reload, value persists.

### Refactor — single source of truth for retention purges

While in P1.7 territory, consolidated the duplicated GC orchestration. Pre-refactor: `GcController::actionRun` had three guarded service calls (passwordHistory + notification + audit) with stdout reporting; `_registerGarbageCollection()` listener had the same three calls without stdout. Adding a fourth retention table required updating both. Post-refactor: new `PasswordPolicy::runGc(): array` is the single source of truth — returns `[tableKey => purgedCount]` for tables that ran, skipped tables absent. Listener becomes `fn() => $this->runGc()`. Controller iterates the result map, prints contextual stdout per table that ran, drops the "skipped (disabled or Lite)" else branches per UX feedback (noise, not signal).

### P1.11 — Top-level Blocklist page with custom dictionary editor + word-check tool (Pro)

Originally specced as "EditableTable inside `BlocklistUtility` (Pro)". Significant scope iteration during the session ended at a different shape. Final architecture:

- **New top-level subnav** "Blocklist" between Policies and Settings (not a Settings sub-tab, not a Utility — both rejected). Reasoning: Settings communicates "deploy via project config" mental model, which is wrong for per-environment DB state; Utilities communicates "diagnostic/one-off action", which doesn't fit configuration data. A top-level page signals "manageable on production directly without dev team intervention."
- **Permission split** — new `pp:blocklist-view` (read-only access to the page) with `pp:blocklist-manage` nested (gates writes: editor saves and "Update Common Passwords" seed action).
- **Single page houses everything blocklist-related:** stats prose with SecLists 10k source citation (lineage / auditor transparency), `<blockquote class="note tip">` Last Seeded callout (escalates to `note warning` when never-seeded), Update Common Passwords button (cron-driven seed, production-runnable), the editable custom-words table (`forms.editableTableField` with diff-on-save: numeric rowId = keep, non-numeric = insert, missing = delete), and a "Check a word" AJAX tool with native validation-error / notice-tip rendering. `BlocklistUtility` and `_utilities/blocklist.twig` deleted.
- **Schema** — new migration `m260430_101611_AddPolicyIdToBlocklist` adds nullable `policyId` to `passwordpolicy_blocklist` (FK CASCADE to policies). Pro stores rows with `policyId IS NULL`. Phase G uses the column for per-policy custom-dictionary entries (Enterprise differentiator). Reordered `Install.php` so policies table is created before blocklist (FK target requirement) for fresh installs.
- **Validator now emits source-aware messages** — `CommonPasswordValidator` queries word + source, caches `[word => source]` map (cache key bumped to `passwordpolicy_blocklist_word_sources` to avoid colliding with old `[word => true]` shape). Bundled common returns "too common, choose a more unique password"; custom returns "blocked, choose a different one". User caught the misleading-message issue during T5.18 manual test.
- **Form-nesting bug fixed** — earlier draft had two nested `<form>`s on the page (Update Common + editor). Browser drops the inner `<form>` tag but keeps its inner `<input name=action value=update-common>`, so the outer form ends up with two `name=action` inputs, last one wins; clicking Save submitted to the wrong action and the editor's words were never saved. Final architecture: no `fullPageForm`, two explicit body forms (Update Common + customWordsForm), Save button in actionButton block uses HTML5 `form="customWordsForm"` attribute to bind to the editor form despite living in the page header.
- **UX iteration** — multiple rounds tightening copy, callout treatment, timestamp display. Notable lessons captured in memory: `feedback_native_callout_components.md` (default to `<blockquote class="note tip|warning">` instead of hand-rolled custom CSS callouts; `|timestamp` is compact-only and drops the date for today — use `|datetime`/`|time` for locale-aware full timestamps); `feedback_editable_table_default.md` (default to `forms.editableTableField` instead of hand-rolled HTML tables for admin-managed lists).

T5.18 in TESTING.md — validation round-trip end-to-end PASS as `editor` user (per-group policies temporarily disabled for global-rules test, six password change attempts: 5 rejects with correct messages, 1 accept). Confirmed source-aware messages work.

### Refactor — `.pp-conflict-banner` → native `<blockquote class="note warning">`

Tangential cleanup while polishing the blocklist page. The custom `.pp-conflict-banner` div (orange left border + tinted background + custom CSS in `_policies/_edit.twig`) was the previous approach for the policy min/max conflict notice. Replaced with native `<blockquote class="note warning">` in `PolicyController::_buildEditNoticeHtml()`. Visual consistency across the plugin: every high-visibility callout now uses the same Craft-native primitive. ~14 lines of custom CSS deleted.

### P1.3 + P1.4 path locked — Path B (plugin-managed editor + queue)

Decision discussion captured in PLAN.md row P1.3 + memory `project_release_strategy.md`. Three options weighed: A (Craft SystemMessages, minimal), A+sender-overrides (medium), B (plugin-managed Email Notifications tab with token picker + test-send + queue). Selected B for the Pro differentiation positioning. Enterprise notification types (`new-device-alert`, `admin-security-alert`) deferred to Phase G — same UI accommodates them when Phase 10–12 land.

### Process

- 13 commits ahead of `origin/5.x`, unpushed. Working tree clean.
- Memory store grew by 3 entries: retention/GC framing, native callout components, editable table defaulting.
- Updated PLAN.md, CHANGELOG.md, TESTING.md (T5.17 + T5.18), NEXT-SESSION.md to reflect end-of-session state.

---

## Session: 2026-04-30 (continued — P1.5)

### P1.5 — Group deletion cleanup listener

Registered an observability listener on `craft\services\UserGroups::EVENT_BEFORE_APPLY_GROUP_DELETE` (not `AFTER` as the original spec called for — see below). Hooked via new private method `PasswordPolicy::_registerUserGroupListeners()`, called from `init()` next to `_registerCraftSecurityListeners()`.

**Hook choice rationale.** The handover doc said use `EVENT_AFTER_DELETE_USER_GROUP`, but that event fires *after* `Db::delete(Table::USERGROUPS, ...)` runs — and the FK `ON DELETE CASCADE` on `passwordpolicy_policy_groups.groupId` triggers during that delete. So by the time `AFTER` fires, the junction rows are already gone — nothing to enumerate, no useful log payload. Switched to `BEFORE_APPLY_GROUP_DELETE` (fires immediately before the cascade runs, after project config has resolved). Junction rows still exist, so we can query affected policies and log meaningful info: *"User group 'Editors' (id: 3) deleted; dropping policy assignments: Editor Policy, Strict Policy"*.

**Defensive shape.** The closure body is wrapped in `try/catch (Throwable)` — if anything throws (DB unavailable, model hydration fails) the listener logs a warning and swallows the error. Never blocks the group deletion itself; the listener is observability-only, the FK cascade owns data integrity.

**No explicit `DELETE`.** Could have run a redundant `DELETE FROM passwordpolicy_policy_groups WHERE groupId = ?` for defense-in-depth, but kept it observation-only — clearer single responsibility, and the FK cascade is the canonical guarantee.

**Future audit-log seam.** When Phase 10–12 (Enterprise) lands, this listener gets the audit-log entry written here — `$plugin->getAuditLog()->logEvent(...)` slots in alongside the existing `$plugin->log()` call. The data needed (group id/name + affected policy ids/names) is already in scope.

**Verification.** `php -l` clean. Plugin loads without fatal error (`ddev craft` lists all plugin commands). PHPStan + ECS still blocked by host PHP 8.4 vs DDEV 8.3 vendor mismatch (unchanged from prior session). Manual CP test path documented in TESTING.md as T5.17.

---

## Session: 2026-04-30 (P1.3 + P1.4 — Email Notifications)

### Architecture: Path B with corrections

Locked path was Path B (plugin-managed editor + queue). Implementation diverged from initial Path B sketch on the storage shape — rather than three separate Twig template files, one per notification, we used the Craft 5 element-content idiom: a single `passwordpolicy_notification_templates` table with one row per `(notificationKey, siteId)` and a JSON `content` column. That gives FK CASCADE on `siteId`, race-free per-site editing, and zero schema migrations when fields evolve. The shape mirrors how Craft 5 stores element content on `elements_sites` — same reasoning, same trade-offs.

Memory entry added earlier in the day (`feedback_craft5_json_content_pattern.md`) was directly relevant — followed it.

### Layered build, 7 commits

1. `feat(notifications): add notification_templates table + per-site default seed (P1.3)` — schema migration generated via `ddev craft migrate/create AddNotificationTemplatesTable --plugin=password-policy` (never hand-pick timestamps), eager-seeds one row per (key × enabled site) using new `EmailDefaults::expiryReminder()` factory. `Install.php` updated with idempotent `_createNotificationTemplatesTable()` + `_seedNotificationTemplateDefaults()` for fresh installs. Schema bumped to `2.2.0`.
2. `feat(notifications): add NotificationTemplateRecord and NotificationTemplateModel` — record maps to `{{%passwordpolicy_notification_templates}}` with property hints. Model has typed properties for the editable content fields, `fromRecord()` decodes the JSON `content` column with the same single/double-encoded handling pattern PolicyService uses. `getCpEditUrl()` constructs the per-site edit URL with siteId query param. `defineRules()` covers required + email-format + length validation.
3. `feat(notifications): NotificationTemplateService + Pro-only send pipeline + site listener` — service has `getTemplate(key, siteId)` (with primary-site fallback), `getAllForKey()`, `saveTemplate()` (validate + upsert), `propagateToSite(int $siteId)` (copy primary-site rows into a new site, skip existing). Registered in `ServicesTrait` with proper getter. Updated `NotificationService::sendPasswordExpiryReminder()` to load from the templates table, render subject + body via `View::renderString()`, apply per-template sender overrides via `App::parseEnv()` (or fall back to system mailer defaults). Pro guard at the top — Lite throws `RuntimeException`. New `_registerSiteListeners()` on `PasswordPolicy` hooks `Sites::EVENT_AFTER_SAVE_SITE` with `isNew` check, defensive `try/catch (Throwable)` so site save never blocks. `composeFromTemplate()` exposed publicly so the test-send web controller reuses the same render pipeline.
4. `feat(notifications): add NotificationTemplateController + permission + subnav + URL rules` — new `pp:notification-templates-manage` permission registered alongside the existing ones. Notifications subnav between Blocklist and Settings, gated on Pro + permission. URL rules for `index`, `edit` (with `siteId` query), `save`, `test-send`. Controller's `beforeAction` requires CP request + Pro + permission. `actionIndex` lists known notification keys with primary-site subject + a "sites with overrides" count computed by JSON-encoding each per-site content blob and comparing to primary. `actionEdit` uses `asCpScreen()` with General/Advanced/Test tabs. `actionSave` validates + persists via service. `actionTestSend` accepts posted unsaved subject/body so the admin can test edits *before* saving, renders against the current admin user with sample `daysUntilExpiry: 7`, sends through the real pipeline, returns JSON with rendered subject + body excerpt for inline preview.
5. `feat(notifications): CP templates for index + edit (token picker + test-send)` — VueAdminTable index, tabbed edit screen with a site switcher (only when more than one site), `forms.textareaField` body with `rows: 12, class: 'code'`, token-picker `<blockquote class="note tip">` with click-to-copy chips using `navigator.clipboard.writeText` + `Craft.cp.displayNotice` for feedback. Advanced tab uses `forms.autosuggestField` + `suggestEnvVars: true` for the email overrides. Test-send AJAX panel renders result inline as `<blockquote class="note tip|warning">` with rendered subject + 240-char body excerpt. Pure Twig + inline JS, no new asset bundle.
6. `feat(notifications): batched job + console command for expiry reminders (P1.4)` — `ExpiringPasswordUserBatcher implements \craft\base\Batchable` recomputes the pending-recipients query each `getSlice()` call so retries are naturally idempotent — already-notified users drop out via the `notification_log` exclusion subquery. Query is straight Yii2 `Query` against `Table::USERS` with `users.suspended/locked/pending` filters, a `lastPasswordChangeDate` threshold, and the dedup `not exists` subquery. Single-user mode via `--user=<id>`. `SendPasswordExpiryRemindersJob extends BaseBatchedJob`, `batchSize=100`, `ttr=300`, `canRetry($attempt) < 5`, Pro guard at top of `execute()` throws RuntimeException, per-user soft-fail in `processItem` via catch(Throwable). `defaultDescription()` (not `getDescription()` — that's final on BaseBatchedJob). Console command at `password-policy/notification/send-expiry-reminders`; Lite returns `ExitCode::UNSPECIFIED_ERROR` with stderr "Pro edition required" so cron monitoring catches the misconfiguration loudly. **No `actionPrune`** — `gc/run` already handles notification log retention.
7. `docs/test/changelog` — TESTING.md grew T9.4–T9.9, PLAN.md struck P1.3 and P1.4 + closed Phase C, CHANGELOG got entries under [5.2.0] - Unreleased, NEXT-SESSION.md handover refreshed for Phase D.

### Bugs caught during verification

- **`UserQuery` doesn't select `lastPasswordChangeDate`** (already documented in earlier commit `bc6196d` for the variable; same bug bites the queue job). Job's `_lastPasswordChangeDate(int $userId)` direct-queries the column from `Table::USERS`. Otherwise `_daysRemaining` returns null and processItem silently no-ops. Caught when the queue worker reported "Done" with no email.
- **`getDescription` is final on `BaseBatchedJob`.** First-run threw "Cannot override final method." Switched to `defaultDescription()` per Craft's BaseBatchedJob contract.
- **Project config `set` of same value is a no-op.** Trying to push `expiryAmount=5` via `$pc->set` from a one-off CLI script didn't take when the previous value was `null` — used `ddev craft project-config/set` to land it. Cosmetic, came up only during testing.

### Architectural decisions made during build

- **Storage shape: JSON content per (key, site) row.** Memory entry `feedback_craft5_json_content_pattern.md` was the deciding factor. Mirrors Craft 5 elements_sites. Phase G adds `new-device-alert` and `admin-security-alert` keys to the same table — no schema change.
- **Eager-seeding at install / on new-site listener.** Runtime never falls back to translation files — admins always see editable content from the moment the plugin is installed. `EmailDefaults::all()` is the manifest of known notification keys.
- **Site resolution at send time** uses `$user->getPreferredLanguage()` to map onto a site's language; falls back to primary site. Doesn't try to be clever about "user's home site" because Craft users live at install level (single-site truth across the install for users).
- **Test-send accepts unsaved POST values.** Lets admins dial in the copy + click Send test before committing. Render path is identical to the queue job, so what the admin sees is what eligible users will receive.

### Process notes

- All migrations generated via `ddev craft migrate/create <Name> --plugin=password-policy` per the durable rule.
- Verification gates per layer ran clean: Layer 1 (migrate up + idempotency), Layer 2 (model hydration + validate), Layer 3 (service round-trip), Layer 4 + 5 paired (HTTP login + GET index + GET edit + POST save + reload-confirms-persist + POST test-send + Mailpit confirm), Layer 6 (queue/info shows waiting=1, queue/run --verbose shows job started + done, Mailpit confirms send, re-run shows dedup), Layer 7 (Lite via project.yaml + dateModified bump + craft up — exits non-zero with stderr message; restored Pro).
- ECS still blocked by host PHP 8.4 vs DDEV PHP 8.3 vendor mismatch (unchanged from prior session). PHPStan ran clean throughout.
- 7 commits, all conventional. Working tree clean after Layer 7.

---

## Next Session

Phase A (audit fix-ups), Phase B (pre-release security tests), and **Phase C (P1 backlog)** all closed. Next is Phase D — user index integration.

**Priority 1 (Phase D):**
- P2.1 — User index table attributes via `EVENT_REGISTER_TABLE_ATTRIBUTES` + `EVENT_SET_TABLE_ATTRIBUTE_HTML`. Columns: password status (badge), last change, expired, reset required. Lite edition.
- P2.2 — Admin password change action. Element action with elevated session + `changedByUserId` tracking. Storage: Option A (see PLAN.md §6.2). New permission `pp:change-user-passwords`. Migration: nullable column on password history table.

After Phase D → Phase E (P2.5 Pest tests, including the deferred T1.2 + TX.2 + T9.7 site propagation listener) → Phase F (P2.4/2.6 polish) → **Phase G (Enterprise — Phase 10/11/12)** → Phase H (release prep + tag 5.2.0).

**Read first (in order):**
1. `docs/NEXT-SESSION.md` — single-page handover with playground state + commands
2. `docs/PLAN.md` — master plan, build order, gating
3. `docs/PROGRESS.md` — this file, full session history
4. `docs/TESTING.md` — per-test PASS/PENDING/DEFERRED status

**Memory store:** `~/.claude/projects/-Users-michtio-dev-craft-plugins-v5-craft-password-policy/memory/MEMORY.md` indexes all durable rules including release strategy (single 5.2.0 covers all editions; nothing tags until Enterprise done), the migration generator rule (`ddev craft migrate/create <Name> --plugin=password-policy`), and the Craft 5 JSON content pattern.
