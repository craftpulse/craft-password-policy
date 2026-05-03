# Next Session — Handover (2026-05-03, Phase D closed)

Building **v5.2.0** of `craft-password-policy`. Single release covers Lite + Pro + Enterprise. Nothing tags until Enterprise (Phase G) is built and tested. Features either land in 5.2.0 (at the right edition tier) or drop to `ideas.md`. **The "no v5.3 deferral" rule is no longer absolute** — once the Phase G build plan is drafted (P2.8), if Phase G grows past one comfortable build cycle, deferring its lower-priority subset to 5.3 is allowed. 5.2.x stays reserved for security patches only.

---

## Read in this order, no skipping

1. `plan.md` — master plan; sections 1 (status), 3 (backlog), 4 (build order). **Phase D closed; Phase F is now next.**
2. `progress.md` — current-phase session log; tail has the current "Next Session" priorities (older phases including D + E rotated to `history/`).
3. `manual-tests.md` — top of file is the active test pass plan (Phase C2 + Layer 4b + bug fix sweep). Per-phase T-row register below it. 78/79 PASS plus the three previously-deferred tests (T1.2, TX.2, T9.7) now covered by Pest. P2.1 / P2.2 / P2.6 surfaces covered by Phase D's Pest tests.
4. This file (`handover.md`) — playground state + commands.

Memory store: `~/.claude/projects/-Users-michtio-dev-craft-plugins-v5-craft-password-policy/memory/MEMORY.md` — durable rules across sessions. Includes: release strategy, retention/GC framing, native callout components, editableTable defaulting, **Craft 5 JSON content pattern**, and others. **Read it.**

Project guide: `CLAUDE.md` at the repo root + `.claude/rules/*.md` import targets — coding-style, architecture, git-workflow, scaffolding, security, migrations, testing.

---

## State at handover

**Branch:** `5.x`, **69 commits ahead of `origin/5.x` and unpushed** (49 from Phase E close + 19 Phase D commits + 1 Phase D close docs commit). Working tree clean.

**Recent commits (newest first — Phase D + close docs):**
```
b15c460 feat(user-edit-tab): wire Password Security page into user edit screen (D4)
76cd0e0 docs(actions): correct ChangeUserPassword modal docblock — controller uses asJson, not asModelSuccess
ec3382b test(actions): policy-validation gate + UserStateService explicit-context coverage (D3.4)
c0f70f7 feat(actions): SendPasswordResetEmail bulk + pending-reason setter coverage (D3.3)
be569de feat(actions): ChangeUserPassword end-to-end + audit propagation (D3.2)
e12de46 feat(actions): permission + ChangeUserPassword + SendPasswordResetEmail skeletons (D3.1)
e5486e0 refactor(user-index): centralise expiry-interval parsing (D2 cleanup)
aa48b93 feat(rules): condition rules for D2 columns (D2.3)
beaf5b8 test(user-index): Pro-tier columns + Craft-edition gate (D2.2)
6f1574d feat(user-index): UserIndexService + Lite-tier table attributes (D2.1)
02c76da docs(handover): note pending focused manual test session
1290468 test(audit): cover audit context propagation through every change site (D1.4)
bf66716 fix(force-reset): pre-load passwordResetRequired column for short-circuit (D1.3 follow-up)
41aed57 feat(audit): wire ForcePasswordReset + expiry triggers to UserStateService (D1.3)
1739df9 feat(audit): consume pending reason in central history listener (D1.1 + D1.2)
e09e6d6 test(audit): cover audit shape migration + UserStateRecord (D0.4)
e7c45dd feat(audit): UserStateService + PasswordHistoryService audit-context API (D0.3)
1c85466 feat(audit): migrate audit shape on password_history + user_state table (D0.2)
ab1d456 feat(audit): add ChangeReason enum + AuditContext model (D0.1)
79f126e docs(internal): record Phase E completion + roll handover to Phase D
```

(Older commits — Phase C2 + bug fix sweep + docs restructure + project setup + Phase E — listed in `history/progress-phase-c2.md` and `history/progress-phase-e.md`.)

**5.1.x branch (parked):** 3 commits ahead of tag `5.1.1` — TLS verify, fail-open log level, sensitive-key strip backports. NOT pushed, NOT tagged. Tag-or-park decision still pending — discuss before resuming.

**Pest suite:** **513 passing / 0 skipped / 1049 assertions.** ECS clean, PHPStan clean (3-entry baseline unchanged from E1). Run via `cd /Users/michtio/dev/craft-plugin-playground/cms_v5 && ddev exec --dir /Users/Shared/dev/craft-plugins/v5/craft-password-policy composer test`.

**Manual tests:** **78/79 PASS** for the active C2 + Layer 4b + bug fix sweep pass. **T1.2 + TX.2 + T9.7 now covered by Pest** (no longer deferred). T12.6 (Enterprise audit) gated on Phase G. T13.6 + T13.11 (browser-driven AJAX UX + screen-reader a11y) require manual browser/SR verification — environment-gated, not code-gated.

**Pending — focused manual test session committed (2026-05-02).** The active test pass at the top of `manual-tests.md` (Phase C2 + Layer 4b + bug fix sweep walkthrough — 6 blocks: front-end demos, CP strength, HIBP-on-login, email notifications, bug-fix-specific verifications, edition matrix) needs to be run end-to-end in a multi-hour focused session driven by the user (browser + Mailpit work, not agent-suitable). Phase D continues in parallel; the manual session is independent. Run before tagging 5.2.0 in any case.

**Phase status (`plan.md` §4):**
- A — audit fix-ups: **done 2026-04-29**.
- B — pre-release security tests: **done 2026-04-30**.
- C — P1 backlog: **done 2026-04-30**. P1.8 (deployment docs) deferred to Phase H since Enterprise must exist first.
- C2 — Pro front-end surface bundle (P1.12 + P1.13 + P1.14 + P1.15): **fully closed 2026-05-01** including P1.12 Layer 4b (CP-side strength engine unified with the front-end pipeline via AJAX `/validate`).
- Bug fix sweep — **done 2026-05-02** (6 commits, all PHPStan clean). Twig tag layer + controllers + client asset + HIBP 429 backoff + dual variable handle + SettingsModel legacy alias.
- Docs restructure + project setup — **done 2026-05-02.** `docs/` split into `user/` + `internal/`. `CLAUDE.md` + `.claude/rules/*.md` + `.claude/settings.json` scaffolded.
- E — Pest test infrastructure (P2.5 scope-expanded): **done 2026-05-02.** 18 commits + `fix(hibp)` + `docs(ideas)`. 329 tests, 0 skipped. Phase E session log: `history/progress-phase-e.md`.
- **D — User index integration (P2.1, P2.2; P2.6 verification gate): done 2026-05-03.** 19 commits across D0–D4 (D0 audit context surface; D1 audit listener wiring; D2 user-index columns + condition rules; D3 admin element actions + UserPasswordController; D4 user-edit "tab" via sidebar pointer + UserSecurityController). 513 tests, 0 skipped. Phase D session log: `history/progress-phase-d.md`.
- **F — Polish + draft Phase G build plan (P2.8): next.**
- G, H — pending.

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
- T13.8 verification flipped a now-removed setting (`useZxcvbnStrength`) on/off; the setting and Engine A baseline are gone in Phase F polish (single zxcvbn-php engine across CP + front-end builders).
- `editor@playground.dev` password was set to `Welcome2024` (live HIBP-breached) for T12.1; `passwordResetRequired` flipped on/off during testing. Reset via `ddev craft users/set-password editor@playground.dev --password='<new>'` if you need a known starting value.
- 3 named policies in `passwordpolicy_policies` (NIST → Team, OWASP → Editors+Managers, "Enterprise With Changes" → Managers — harmless test fixtures).
- `bjeavons/zxcvbn-php ^1.4` added to plugin's composer.json (require, not require-dev). Installed at playground level.

**Test users (Craft, persist across plugin uninstall):**
- `editor` / `editor@playground.dev` / **password unknown** — was changed during T5.18 manual testing. Reset via `ddev craft users/set-password editor@playground.dev --password='<value>'` if you need a known starting value.
- `newuser` / `newuser@playground.dev` / (last-saved value — reset if needed)
- `multigroup` / `multigroup@playground.dev` / (last-saved value — reset if needed)

---

## What to build first

### Phase F — Polish + draft Phase G build plan (P2.8)

Phase D just landed (19 commits, +184 Pest tests, audit-context surface + user-index columns + admin element actions + user-edit tab pointer). Phase F is the design phase before Enterprise (Phase G) code lands. Use `internal/history/phase-c2-build-plan.md` as the structural template.

**P2.8 — Phase G build plan (the load-bearing deliverable).** Lock these architectural decisions before any Phase G code lands:

1. **Hash-chained audit row format.** Canonical JSON shape for the `passwordpolicy_audit_log` rows. `previousHash` column. Decision: include `dateCreated` in the canonical shape or not (timezone normalisation matters)?
2. **Independent verifier CLI.** `password-policy/audit/verify` chain-walk semantics: exit codes (0 = chain valid; 1 = first break, with row id; 2 = unreadable / schema drift), output format (machine-parseable for CI use cases), behavior on a partial chain (e.g. retention-purged early rows — graceful, not catastrophic).
3. **SIEM forwarders.** Which protocols (syslog over TCP/UDP/TLS? HTTP webhook? both?). Queue-driven via the existing `\craft\queue\BaseBatchedJob` pattern from P1.4 + P1.3.
4. **Webhook HMAC scheme.** Signature header (`X-PasswordPolicy-Signature: sha256=…`?). Payload canonicalisation rules (whitespace, key order). Replay-attack window.
5. **`AlertCooldownService` scope.** Which event classes register cooldowns. HIBP-on-login mass detections, group-deletion cascades, force-reset bursts at minimum. Reuses the `notificationLogRetentionDays` dedup pattern from P1.3 but per-event-class — generalise the data model.
6. **Streaming audit-log export pattern.** Extending `AuditController::actionExport` to stream CSV/JSON via `BaseBatchedJob` with no PHP memory ceiling, queue-driven for large date ranges.

Also: re-evaluate at draft time whether any Phase G subset can defer to 5.3 if scope expands beyond one comfortable build cycle. Plan-doc rule loosens once P2.8 is drafted (per the release strategy at the top of this file).

### Then in order: G → H

- **G** — Enterprise (Phase 10/11/12 + per-policy custom blocklist editor + Enterprise email notification types) — driven by P2.8 build plan.
- **H** — Release prep (tag, Plugin Store listing, marketing copy, **deployment docs P1.8**).

### Test infrastructure — what's there for Phase F + G

The Pest scaffold lives at `tests/`. Key files extended in Phase D:
- `tests/Pest.php` — `uses()` rules. **Must register most-specific paths first** (memory gap #18). Phase D added `Integration/UserEditTab/` and `Integration/UserIndex/` — explicit enumeration pattern.
- `tests/TestCase.php` — base class with per-test transaction wrapper (rolls back DB state).
- `tests/Support/MigrationTestCase.php` — non-transactional base for migration tests; `restorePluginSchema()` runs in `tearDown`.
- `tests/Support/MultiSiteTestCase.php` — non-transactional base for site-creating tests; cleans up non-primary sites.
- `tests/Support/Factories/` — UserFactory (with `nonAdmin()` added in D), GroupFactory, PolicyFactory, BlocklistFactory, PasswordHistoryFactory, SessionFactory.
- `tests/Support/HibpClientFake.php` — implements `HibpClientInterface`; swap via `$plugin->set('hibpClient', $fake)`.
- `tests/Support/WebRequestStub.php` — request mocking for controller tests + (D4 addition) `getPathInfo()` + `getUrl()` stubs for CP-template rendering tests.
- `tests/Support/UserStub.php` — extended in D3 with `stubHasElevatedSession`.

Memory entry `feedback_skill_gaps.md` has 20 entries; gaps #15–20 are testing-specific. Memory entry #20 (the console-bootstrap CP-test trifecta) is the load-bearing one for any Phase G CP controller tests.

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
- All Phase E test surfaces (validators, services, models, controllers, Twig tags, migrations, multi-site) — 329 Pest tests; run via `ddev exec --dir /Users/Shared/dev/craft-plugins/v5/craft-password-policy composer test`
- All Phase D test surfaces (audit context propagation, user-index columns + condition rules, admin element actions + UserPasswordController, user-edit tab + UserSecurityController) — 184 additional Pest tests bringing the total to 513 passing / 0 skipped / 1049 assertions
- P2.6 verification gate (read-only mode) for every Phase D CP affordance — `ChangeUserPassword` action, `SendPasswordResetEmail` action, user-edit tab page; all gated, all Pest-pinned
