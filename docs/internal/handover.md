# Next Session — Handover (2026-05-02, Phase C2 closed-closed + bug fix sweep + docs restructure + project setup)

Building **v5.2.0** of `craft-password-policy`. Single release covers Lite + Pro + Enterprise. Nothing tags until Enterprise (Phase G) is built and tested. Features either land in 5.2.0 (at the right edition tier) or drop to `ideas.md`. **The "no v5.3 deferral" rule is no longer absolute** — once the Phase G build plan is drafted (P2.8), if Phase G grows past one comfortable build cycle, deferring its lower-priority subset to 5.3 is allowed. 5.2.x stays reserved for security patches only.

---

## Read in this order, no skipping

1. `plan.md` — master plan; sections 1 (status), 3 (backlog), 4 (build order). **Phase E is now next, not Phase D** (build order swap signed off 2026-05-02).
2. `progress.md` — current-phase session log; tail has the current "Next Session" priorities (older phases rotated to `history/`).
3. `manual-tests.md` — top of file is the **active test pass plan** (Phase C2 + Layer 4b + bug fix sweep walkthrough). Per-phase T-row register below it. 78/79 PASS.
4. This file (`handover.md`) — playground state + commands.

Memory store: `~/.claude/projects/-Users-michtio-dev-craft-plugins-v5-craft-password-policy/memory/MEMORY.md` — durable rules across sessions. Includes: release strategy, retention/GC framing, native callout components, editableTable defaulting, **Craft 5 JSON content pattern**, and others. **Read it.**

Project guide: `CLAUDE.md` at the repo root + `.claude/rules/*.md` import targets — coding-style, architecture, git-workflow, scaffolding, security, migrations, testing.

---

## State at handover

**Branch:** `5.x`, **25 commits ahead of `origin/5.x` and unpushed**. Working tree clean.

**Recent commits (newest first):**
```
1c02bd5 chore: complete craft-project-setup scaffolding (rules + settings + attribution)
71fb42f docs(testing): add active test pass plan for Phase C2 + Layer 4b + bug fix sweep
cd6b21c docs: add project CLAUDE.md pointing fresh sessions at the new docs structure
225396f docs: add docs/README.md orientation page
db3a2bb docs: split user/features/notifications.md into notifications + ops/gc + reference/ajax-validate
833a8fc docs: drop event-catalog duplicate from force-reset.md
6878a4b docs: rotate completed-phase PROGRESS sessions into internal/history/
1d2b022 docs: split internal/plan.md into active plan + completed reference
838905d docs: fixup — apply internal cross-link updates missed in restructure commit
c2b1e0d docs: restructure docs/ — split user-facing from internal handover docs
aa61b8b docs: capture C2 bug fix sweep — CHANGELOG, PROGRESS, PLAN status block
9691541 fix(settings): alias deprecated pwned/pwnedFailMode on SettingsModel for 5.1.1 file-config compat
2388ae9 fix(variables): register both passwordpolicy and passwordPolicy handles
2537d1a fix(security): site-wide HIBP 429 backoff cache
b2ef8ca fix(client-asset): auto-register on toggleVisibility, fix cpTrigger fallback, blocklist hit propagation
b5d602f fix(controllers): session invalidation on password change + ValidationController context input hardening
322c18f fix(twig-tags): defensive null gating + render docblock correction
c84aef3 refactor(strength): unify CP and front-end strength engines via AJAX (P1.12 layer 4b)
3b92c8e docs(events): catalog of plugin events with example listeners (P1.15)
ffa7aa9 feat(frontend): Pro front-end Twig surface — fluent builders, JS asset, strength engine A+B (P1.12)
6a0ffc7 feat(hibp): HIBP-on-login Pro listener + breach-detected notification + BreachDetectedEvent (P1.13)
262c09e feat(registration): RegistrationService + UserRegisteredEvent + Pro per-group validation (P1.14)
```

**5.1.x branch (parked):** 3 commits ahead of tag `5.1.1` — TLS verify, fail-open log level, sensitive-key strip backports. NOT pushed, NOT tagged. Tag-or-park decision pending — discuss before resuming.

**Manual tests:** **78/79 PASS**. T1.2 + TX.2 + T9.7 deferred to P2.5 Pest fixtures. T12.6 (Enterprise audit) gated on Phase G. T13.6 + T13.11 (browser-driven AJAX UX + screen-reader a11y) require manual browser/SR verification — environment-gated, not code-gated.

**Phase status (`plan.md` §4):**
- A — audit fix-ups: **done 2026-04-29**.
- B — pre-release security tests: **done 2026-04-30**.
- C — P1 backlog: **done 2026-04-30**. P1.8 (deployment docs) deferred to Phase H since Enterprise must exist first.
- C2 — Pro front-end surface bundle (P1.12 + P1.13 + P1.14 + P1.15): **fully closed 2026-05-01** including P1.12 Layer 4b (CP-side strength engine unified with the front-end pipeline via AJAX `/validate`).
- **Bug fix sweep — done 2026-05-02 (6 commits, all PHPStan clean).** Twig tag layer + controllers + client asset + HIBP 429 backoff + dual variable handle + SettingsModel legacy alias.
- **Docs restructure + project setup — done 2026-05-02.** `docs/` split into `user/` + `internal/`. `CLAUDE.md` + `.claude/rules/*.md` + `.claude/settings.json` scaffolded.
- **E** — Pest tests (P2.5, scope-expanded): **next**.
- D, F, G, H — pending.

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

### Phase E — Pest test infrastructure (scope-expanded)

Build order swap signed off 2026-05-02: **Pest before Phase D**. The C2 bug-fix sweep just demonstrated the cost of having no automated coverage — adding Phase D's new CP surfaces on top of an untested codebase compounds the testing debt. Pest covers C2 first; Phase D extends after.

**P2.5 scope** (full list in `plan.md` §3):

- **Original targets**: validators, GroupPolicyModel merge, PolicyResolverService (incl. tri-state Option A semantics + auto-correction).
- **Bug-fix sweep additions** (so the next refactor doesn't regress the same fix twice):
  - HIBP 429 site-wide backoff cache — sentinel set/cleared, per-call short-circuit, `Retry-After` parsing, `HIBP_DEFAULT_BACKOFF_SECONDS` fallback. Mock the HIBP HTTP layer; don't hit live API.
  - `PasswordWidgetTag` null-gating — composite forwards only non-null `submitGate`/`groups` to child setters.
  - `PasswordChangeController::destroyOtherSessions()` belt-and-braces helper — both web + console paths covered.
  - `ValidationController` context input hardening — anonymous can't pass `username`/`email` to zxcvbn; authenticated pulls from session identity.
  - `StrengthService::analyzeZxcvbn` `blocklistHit` propagation — engine B forces `weak` + clamps `score` to 0 mirroring engine A.
  - `SettingsModel` four-hook legacy alias (`attributes`, `canGet/SetProperty`, `__get`, `__set`) — `pwned: true` in static `config/password-policy.php` flows to `hibp` with deprecation warning.
- **Deferred manual tests**: T1.2 (5.1.1 → 5.2.0 upgrade migration seeds history), TX.2 (zero behavior change on 5.1.1 upgrade), T9.7 (multi-site propagation listener + FK CASCADE — single-site playground can't exercise).

Pest scaffold already exists in `composer.json` (`pestphp/pest ^4.6`) — no test files yet. `composer test` is wired.

### Then in order: D → F → G → H

- **D** — User index integration (P2.1 table attributes, P2.2 admin password change action, P2.6 `allowAdminChanges` verification absorbed as a verification gate — when adding new CP affordances, verify they respect read-only mode).
- **F** — Polish + draft Phase G build plan (**P2.8** new — use `internal/history/phase-c2-build-plan.md` as template; lock hash-chain row format, verifier CLI exit codes, SIEM forwarders, webhook HMAC, AlertCooldownService scope, streaming export pattern before any Phase G code lands).
- **G** — Enterprise (Phase 10/11/12 + per-policy custom blocklist editor + Enterprise email notification types) — driven by P2.8 build plan.
- **H** — Release prep (tag, Plugin Store listing, marketing copy, **deployment docs P1.8**).

### Phase D context (when E completes)

**P2.1 — User index table attributes.** `EVENT_REGISTER_TABLE_ATTRIBUTES` + `EVENT_SET_TABLE_ATTRIBUTE_HTML`. Columns: password status (badge), last change, expired, reset required. **Lite edition** (this is the headline Lite-tier feature — no edition gating beyond what Craft already provides).

**P2.2 — Admin password change action.** Element action with elevated session + `changedByUserId` tracking. Storage: Option A (see `reference.md` §6.2 — store `changedByUserId` on password history table for all editions; not exposed via UI/API on non-Enterprise). New permission `pp:change-user-passwords`. Needs a migration to add the nullable `changedByUserId` column to `passwordpolicy_password_history`.

**Also in Phase D scope:** the half-built `_users/password-security.twig` user-edit tab — template exists with a working POST target (`actionForceReset`), but no event handler registers the template as a CP user-edit tab. Hooks into the same User element work as P2.1/P2.2.

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
- **T9.7 — Site propagation listener test deferred.** Single-site playground can't exercise the `Sites::EVENT_AFTER_SAVE_SITE` `isNew = true` path or the FK CASCADE. Will land in P2.5 Pest tests with a multi-site fixture.
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
