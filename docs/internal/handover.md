# Next Session — Handover (2026-05-02, Phase E closed)

Building **v5.2.0** of `craft-password-policy`. Single release covers Lite + Pro + Enterprise. Nothing tags until Enterprise (Phase G) is built and tested. Features either land in 5.2.0 (at the right edition tier) or drop to `ideas.md`. **The "no v5.3 deferral" rule is no longer absolute** — once the Phase G build plan is drafted (P2.8), if Phase G grows past one comfortable build cycle, deferring its lower-priority subset to 5.3 is allowed. 5.2.x stays reserved for security patches only.

---

## Read in this order, no skipping

1. `plan.md` — master plan; sections 1 (status), 3 (backlog), 4 (build order). **Phase E closed; Phase D is now next.**
2. `progress.md` — current-phase session log; tail has the current "Next Session" priorities (older phases including E rotated to `history/`).
3. `manual-tests.md` — top of file is the active test pass plan (Phase C2 + Layer 4b + bug fix sweep). Per-phase T-row register below it. 78/79 PASS plus the three previously-deferred tests (T1.2, TX.2, T9.7) now covered by Pest.
4. This file (`handover.md`) — playground state + commands.

Memory store: `~/.claude/projects/-Users-michtio-dev-craft-plugins-v5-craft-password-policy/memory/MEMORY.md` — durable rules across sessions. Includes: release strategy, retention/GC framing, native callout components, editableTable defaulting, **Craft 5 JSON content pattern**, and others. **Read it.**

Project guide: `CLAUDE.md` at the repo root + `.claude/rules/*.md` import targets — coding-style, architecture, git-workflow, scaffolding, security, migrations, testing.

---

## State at handover

**Branch:** `5.x`, **49 commits ahead of `origin/5.x` and unpushed**. Working tree clean.

**Recent commits (newest first — Phase E + 2 follow-ups):**
```
6a69664 test(multisite): cover site propagation + FK CASCADE (T9.7) (E6.2)
c164646 test(migrations): cover 5.1.1 → 5.2.0 upgrade replay (T1.2 + TX.2) (E6.1)
503455a chore(test): add MigrationTestCase + MultiSiteTestCase non-transactional bases (E6.0)
2efabbe docs(ideas): capture Phase E cleanup candidates (validator Unicode + log levels)
fd8149b fix(hibp): downgrade non-2xx fail-open log to WARNING (matches security.md)
19e557e test(controllers): cover ValidationController context hardening + response shape (E5.3)
ca18af7 test(controllers): cover destroyOtherSessions web + console paths (E5.2)
38914c4 test(twig-tags): cover PasswordWidgetTag composite null-gating (E5.1)
49e0023 test(settings): cover pwned→hibp legacy alias four-hook (E4.3)
4d512a0 test(strength): cover engine B blocklist propagation (E4.2)
f96f890 test(hibp): cover 429 backoff cache + short-circuit (E4.1)
cfeb14d test(resolver): cover PolicyResolverService merge + auto-correction (E3.4)
fec8a68 test(models): cover GroupPolicyModel merge + boolean tri-state (E3.3)
72332d5 test(history): cover PasswordHistoryValidator (E3.2)
bb9f7d1 test(blocklist): cover BlocklistService + CommonPasswordValidator (E3.1)
a0a2fcb chore(test): add factories for DB-touching service tests (E3.0)
5156cdc test(validators): add Pest coverage for pure validators (E2)
8f49223 test: add smoke + Craft bootstrap proof tests (E1.3)
08c0702 refactor(hibp): extract HibpClientInterface + GuzzleHibpClient (E1.2)
df26265 chore(test): scaffold Pest config + bootstrap (E1.1)
```

(Older commits — Phase C2 + bug fix sweep + docs restructure + project setup — listed in prior handover snapshot at `history/progress-phase-c2.md`.)

**5.1.x branch (parked):** 3 commits ahead of tag `5.1.1` — TLS verify, fail-open log level, sensitive-key strip backports. NOT pushed, NOT tagged. Tag-or-park decision still pending — discuss before resuming.

**Pest suite:** **329 passing / 0 skipped / 634 assertions.** ECS clean, PHPStan clean (3-entry baseline unchanged from E1). Run via `cd /Users/michtio/dev/craft-plugin-playground/cms_v5 && ddev exec --dir /Users/Shared/dev/craft-plugins/v5/craft-password-policy composer test`.

**Manual tests:** **78/79 PASS** for the active C2 + Layer 4b + bug fix sweep pass. **T1.2 + TX.2 + T9.7 now covered by Pest** (no longer deferred). T12.6 (Enterprise audit) gated on Phase G. T13.6 + T13.11 (browser-driven AJAX UX + screen-reader a11y) require manual browser/SR verification — environment-gated, not code-gated.

**Pending — focused manual test session committed (2026-05-02).** The active test pass at the top of `manual-tests.md` (Phase C2 + Layer 4b + bug fix sweep walkthrough — 6 blocks: front-end demos, CP strength, HIBP-on-login, email notifications, bug-fix-specific verifications, edition matrix) needs to be run end-to-end in a multi-hour focused session driven by the user (browser + Mailpit work, not agent-suitable). Phase D continues in parallel; the manual session is independent. Run before tagging 5.2.0 in any case.

**Phase status (`plan.md` §4):**
- A — audit fix-ups: **done 2026-04-29**.
- B — pre-release security tests: **done 2026-04-30**.
- C — P1 backlog: **done 2026-04-30**. P1.8 (deployment docs) deferred to Phase H since Enterprise must exist first.
- C2 — Pro front-end surface bundle (P1.12 + P1.13 + P1.14 + P1.15): **fully closed 2026-05-01** including P1.12 Layer 4b (CP-side strength engine unified with the front-end pipeline via AJAX `/validate`).
- Bug fix sweep — **done 2026-05-02** (6 commits, all PHPStan clean). Twig tag layer + controllers + client asset + HIBP 429 backoff + dual variable handle + SettingsModel legacy alias.
- Docs restructure + project setup — **done 2026-05-02.** `docs/` split into `user/` + `internal/`. `CLAUDE.md` + `.claude/rules/*.md` + `.claude/settings.json` scaffolded.
- **E — Pest test infrastructure (P2.5 scope-expanded): done 2026-05-02.** 18 commits total (E1 bootstrap + HibpClient extraction; E2 pure validators; E3 DB-touching services + factories; E4 HIBP backoff + StrengthService + SettingsModel alias; E5 ValidationController + destroyOtherSessions + PasswordWidgetTag; E6 migration replay + multi-site propagation + FK CASCADE; plus a `fix(hibp)` log-level downgrade and a `docs(ideas)` cleanup-candidates capture). 329 tests, 0 skipped. Phase E session log: `history/progress-phase-e.md`.
- **D — User index integration: next.**
- F, G, H — pending.

---

## Playground

- URL: `https://plugin-playground-v5.ddev.site/admin`
- Path: `/Users/michtio/dev/craft-plugin-playground/cms_v5`
- Login (admin): `development@craftpulse.com` / `Letmein-Craftpulse1!`
- Plugin edition: **Pro** (project.yaml). Craft license: Pro.
- Mailpit: `https://plugin-playground-v5.ddev.site:8026` (or `ddev mailpit`).

**Plugin DB state at end of session:**
- 7 tables. `passwordpolicy_notification_templates` now has 2 rows on the playground: `expiry-reminder` (siteId=1) + `breach-detected` (siteId=1) — both with default content from `EmailDefaults`.
- Notification log has 1 `breach_detected` entry from T12.1 verification (editor user 55) — clear it via `DELETE FROM passwordpolicy_notification_log WHERE notificationType = 'breach_detected'` if you need a fresh fixture.
- `useZxcvbnStrength` toggled true during T13.8 verification, then back to false. Now `false` in project config.
- `editor@playground.dev` password was set to `Welcome2024` (live HIBP-breached) for T12.1; `passwordResetRequired` flipped on/off during testing. Reset via `ddev craft users/set-password editor@playground.dev --password='<new>'` if you need a known starting value.
- 3 named policies in `passwordpolicy_policies` (NIST → Team, OWASP → Editors+Managers, "Enterprise With Changes" → Managers — harmless test fixtures).
- `bjeavons/zxcvbn-php ^1.4` added to plugin's composer.json (require, not require-dev). Installed at playground level.

**Test users (Craft, persist across plugin uninstall):**
- `editor` / `editor@playground.dev` / **password unknown** — was changed during T5.18 manual testing. Reset via `ddev craft users/set-password editor@playground.dev --password='<value>'` if you need a known starting value.
- `newuser` / `newuser@playground.dev` / (last-saved value — reset if needed)
- `multigroup` / `multigroup@playground.dev` / (last-saved value — reset if needed)

---

## What to build first

### Phase D — User index integration

Phase E just landed 329 Pest tests with 0 skipped — the regression net is in place. Phase D adds new CP affordances on top of that net.

**P2.1 — User index table attributes.** `EVENT_REGISTER_TABLE_ATTRIBUTES` + `EVENT_SET_TABLE_ATTRIBUTE_HTML`. Columns: password status (badge), last change, expired, reset required. **Lite edition** (this is the headline Lite-tier feature — no edition gating beyond what Craft already provides).

**P2.2 — Admin password change action.** Element action with elevated session + `changedByUserId` tracking. Storage: Option A (see `reference.md` §6.2 — store `changedByUserId` on password history table for all editions; not exposed via UI/API on non-Enterprise). New permission `pp:change-user-passwords`. Needs a migration to add the nullable `changedByUserId` column to `passwordpolicy_password_history`. **Author via `ddev craft migrate/create AddChangedByUserIdToPasswordHistory --plugin=password-policy`** — never hand-pick filenames or timestamps.

**P2.6 absorbed — verification gate.** When adding new CP affordances, verify they respect `allowAdminChanges = false` read-only mode. Not a separate Phase F item; a Phase D quality bar.

**Also in Phase D scope:** the half-built `_users/password-security.twig` user-edit tab — template exists with a working POST target (`actionForceReset`), but no event handler registers the template as a CP user-edit tab. Hooks into the same User element work as P2.1/P2.2.

### Then in order: F → G → H

- **F** — Polish + draft Phase G build plan (**P2.8** — use `internal/history/phase-c2-build-plan.md` as template; lock hash-chain row format, verifier CLI exit codes, SIEM forwarders, webhook HMAC, AlertCooldownService scope, streaming export pattern before any Phase G code lands).
- **G** — Enterprise (Phase 10/11/12 + per-policy custom blocklist editor + Enterprise email notification types) — driven by P2.8 build plan.
- **H** — Release prep (tag, Plugin Store listing, marketing copy, **deployment docs P1.8**).

### Pest suite — keep it green during Phase D

Phase D will touch User element behavior, the password history table (new migration adds `changedByUserId`), and CP routing. Several E3/E5 tests cover this surface:
- `tests/Integration/Validators/PasswordHistoryValidatorTest.php` — history validation
- `tests/Integration/Services/DestroyOtherSessionsTest.php` — session helper called from password change flows
- `tests/Integration/Migrations/UpgradeTo520MigrationTest.php` — migration replay (extend if D adds a new migration)
- `tests/Integration/Models/SettingsModelLegacyAliasTest.php` — settings model

Run `ddev exec --dir /Users/Shared/dev/craft-plugins/v5/craft-password-policy composer test` after each commit. If a Phase D commit breaks an existing E3/E5 test, that's the regression net working — fix before the commit lands.

### Test infrastructure — what's there

The Pest scaffold lives at `tests/`. Key files for Phase D extension:
- `tests/Pest.php` — `uses()` rules. **Must register most-specific paths first** (memory gap #18) — adding new `tests/Integration/Foo/` requires either explicit enumeration or a new specific rule.
- `tests/TestCase.php` — base class with per-test transaction wrapper (rolls back DB state).
- `tests/Support/MigrationTestCase.php` — non-transactional base for migration tests; `restorePluginSchema()` runs in `tearDown`.
- `tests/Support/MultiSiteTestCase.php` — non-transactional base for site-creating tests; cleans up non-primary sites.
- `tests/Support/Factories/` — UserFactory, GroupFactory, PolicyFactory, BlocklistFactory, PasswordHistoryFactory, SessionFactory.
- `tests/Support/HibpClientFake.php` — implements `HibpClientInterface`; swap via `$plugin->set('hibpClient', $fake)`.
- `tests/Support/WebRequestStub.php` + `tests/Support/UserStub.php` — request mocking for controller tests.

Memory entry `feedback_skill_gaps.md` has 19 entries' worth of "things future Pest setups should know"; gaps #15–19 are testing-specific.

---

## Hard guards (still active — read MEMORY.md too)

- **5.2.0 is the release vehicle for the entire vision.** Features either land at the right edition tier in 5.2.0 or get dropped to `ideas.md`. **The "no v5.3 deferral" rule loosens once the Phase G build plan is drafted (P2.8)** — if Phase G grows past one comfortable build cycle, deferring its lower-priority subset to 5.3 is allowed. 5.2.x stays reserved for security patches only.
- **Don't tag 5.2.0 until Enterprise (Phase G) is built and tested.** Single coordinated release.
- **Always generate migrations via `ddev craft migrate/create <Name> --plugin=password-policy`.** Never hand-pick filenames or timestamps.
- **Use `ddev` shorthand commands.** Never `php`, `composer`, or `npm` on the host.
- **Don't introduce `@deprecated` markers on code added in the same unreleased version.** Delete dead code instead.
- **Don't blindly trust audit subagent reports.** Earlier audit had 2 of 4 findings wrong-as-stated.
- **Default to native Craft components.** `forms.editableTableField` for admin-managed lists; `<blockquote class="note tip|warning">` for high-visibility callouts; `|datetime`/`|time` for locale-aware timestamps. See feedback memory entries.
- **Pruning is not "automatic".** Don't tell admins their data gets cleaned up automatically — `password-policy/gc/run` cron is the recommended production setup.
- **Craft 5 storage idiom.** For per-(entity, site) editable content, prefer one row per (key, siteId) with a JSON `content` column over Craft-4-style relational columns. Memory entry `feedback_craft5_json_content_pattern.md`.

---

## Cross-doc drift watch

The repo now maintains state in five overlapping places: `internal/plan.md`, `internal/handover.md`, MEMORY.md (durable rules), `CLAUDE.md` (project orientation), and `.claude/rules/*.md` (PHP / architecture / git / security / migrations / testing / scaffolding rule files for fresh sessions). When changing anything in this list — **release strategy, edition tiering, migration policy, security invariants, build order** — update both the plan/handover docs AND the corresponding `.claude/rules/*.md` file. There's no automated sync; drift is a real risk. Belt-and-braces: when in doubt, grep across `docs/internal/`, `MEMORY.md`, `CLAUDE.md`, and `.claude/rules/` for the term you're changing.

---

## Known follow-ups (deferred, not blocking)

- **Phase 6 user-edit tab is half-built.** `_users/password-security.twig` exists with a working POST target (`actionForceReset`), but no event handler registers the template as a CP user-edit tab. Belongs in P2.1/P2.2 user index work.
- **`db_test` setup may need recreating after a fresh `ddev start` from snapshot.** Pest tests run against a dedicated `db_test` MySQL DB. Created during Phase E1 with `GRANT ALL ON db_test.* TO 'db'@'%'`. If a snapshot restore wipes it: `cd /Users/michtio/dev/craft-plugin-playground/cms_v5 && ddev mysql -uroot -proot -e "CREATE DATABASE IF NOT EXISTS db_test; GRANT ALL ON db_test.* TO 'db'@'%'; FLUSH PRIVILEGES;"`. The Pest bootstrap will reinstall the plugin schema on first run.
- **Soft-delete vs hard-delete on sites.** `Sites::deleteSiteById()` soft-deletes (sets `dateDeleted`); FK CASCADE on `passwordpolicy_notification_templates.siteId` only fires on physical row removal (Craft GC sweep). The current behavior is intentional — admins re-enabling a soft-deleted site recover their templates. Documented in memory gap #19. If Phase G changes this contract, update the cascade test in `tests/Integration/MultiSite/SiteDeletionCascadeTest.php`.
- **Stale tracking rows in playground `migrations` table** for the deleted/replaced migration filenames. Cosmetic, Craft ignores them.
- **Adversarial Test Suite** — `ideas.md`. Future P3+ work after P2.5 lands.
- **Per-policy custom blocklist editor (Phase G, Enterprise tier).** Schema column `policyId` already shipped in P1.11. Phase G adds the editor tab on the policy edit screen + validator merge logic.
- **Enterprise notification keys** (`new-device-alert`, `admin-security-alert`) ship in Phase G — same table, same UI, just two more entries in `EmailDefaults::all()`.

---

## Don't bother re-doing

These were tested or analyzed and are clean — don't waste a session re-verifying:

- All P1.x items marked done in PLAN.md (P1.2, P1.3, P1.4, P1.5, P1.6, P1.7, P1.9, P1.10, P1.11)
- T1.4 uninstall/reinstall, T7.3 edition stripping, T1.3 query log suppression, TX.3 sensitive data grep
- P1.2 common-passwords expansion (10k rows end-to-end verified)
- Migration consolidation (single `m260429_224908_UpgradeTo520Schema.php` is canonical, plus `m260430_101611_AddPolicyIdToBlocklist.php` and `m260430_170841_AddNotificationTemplatesTable.php`)
- T9.4 / T9.5 / T9.6 (notifications index, edit + persist, test-send AJAX) — verified end-to-end via curl + Mailpit
- T9.8 (queue + console + dedup) — verified end-to-end with `expiryAmount=5` then restored to null
- T9.9 (Lite gates) — verified by flipping playground to Lite via project.yaml + dateModified bump + craft up, then back to Pro
- All Phase E test surfaces (validators, services, models, controllers, Twig tags, migrations, multi-site) — 329 Pest tests / 0 skipped / 634 assertions; run via `ddev exec --dir /Users/Shared/dev/craft-plugins/v5/craft-password-policy composer test`
