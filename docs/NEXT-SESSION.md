# Next Session — Handover (2026-05-01, end of Phase C2)

Building **v5.2.0** of `craft-password-policy`. Single release covers Lite + Pro + Enterprise. Nothing tags until Enterprise (Phase G) is built and tested. **No "v5.2.x" or "v5.3" deferral framing for features** — features either land in 5.2.0 (at the right edition tier) or are dropped to IDEAS.md. 5.2.x is reserved for security patches only.

---

## Read in this order, no skipping

1. `docs/PLAN.md` — master plan; sections 1 (status), 3 (backlog), 4 (build order)
2. `docs/PROGRESS.md` — full session history; tail has the current "Next Session" priorities
3. `docs/TESTING.md` — per-test status (54/57 PASS, 3 deferred)
4. This file (NEXT-SESSION.md) — playground state + commands

Memory store: `~/.claude/projects/-Users-michtio-dev-craft-plugins-v5-craft-password-policy/memory/MEMORY.md` — durable rules across sessions. Includes: release strategy, retention/GC framing, native callout components, editableTable defaulting, **Craft 5 JSON content pattern**, and others. **Read it.**

---

## State at handover

**Branch:** `5.x`, ~7 commits ahead of `origin/5.x` and unpushed. Working tree clean.

**Latest commits (top → bottom = newest → oldest):**
```
<latest> docs(events): catalog of plugin events with example listeners (P1.15)
<...>    feat(frontend): Pro front-end Twig surface — fluent builders, JS asset, strength engine A+B (P1.12)
<...>    feat(hibp): HIBP-on-login Pro listener + breach-detected notification + BreachDetectedEvent (P1.13)
<...>    feat(registration): RegistrationService + UserRegisteredEvent + Pro per-group validation (P1.14)
607d69c docs: pull CP-side strength meter into P1.12 scope
10c6e13 docs: scope Phase C2 — Pro front-end surface bundle (P1.12-P1.15)
76ddfc8 docs: refresh PLAN.md status block — Phase C closed, P1 empty, front-end Twig gap surfaced
```

**Manual tests:** core suite still 54/57 PASS for the legacy phases. Phase C2 added T11.1–T11.5 (RegistrationService PASS), T12.1–T12.5 PASS + T12.6 deferred (Enterprise gate), T13.1–T13.5 + T13.7 + T13.8 + T13.9 + T13.10 PASS, T13.6 + T13.11 require browser/SR verification, T13.12 deferred (Layer 4b CP-side strength meter replacement).

**Phase status (PLAN.md §4):**
- A — audit fix-ups: **done 2026-04-29**
- B — pre-release security tests: **done 2026-04-30**
- C — P1 backlog: **done 2026-04-30**. P1.8 (deployment docs) deferred to Phase H since Enterprise must exist first.
- C2 — Pro front-end surface bundle (P1.12 + P1.13 + P1.14 + P1.15): **done 2026-05-01**. P1.12 Layer 4b (CP-side strength meter replacement) deferred to a separate session before tag.
- D, E, F, G, H — pending.

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

### P1.12 Layer 4b — CP-side strength meter replacement (Pro)

Deferred from Phase C2 — the only remaining piece of P1.12 before Phase C2 is fully closed. Replaces Craft's native zxcvbn-js meter on Pro CP password inputs with the plugin's strength engine (so per-group policy + blocklist hits + zxcvbn-php-when-enabled surface consistently across every place a user enters a password). The plan section in `docs/C2-BUILD-PLAN.md` Layer 4b has the spec; PROGRESS.md "Layer 4b deferral" section captures the research checklist.

Implementation requires:
1. Reading bundled CP JS (`vendor/craftcms/cms/src/web/assets/cp/dist/cp.js`) to confirm the DOM signature and any submit-gating semantics.
2. New `cp-strength.js` asset bundle that hides Craft's native meter (CSS or DOM remove) and re-renders the plugin's requirement-list + strength-meter markup in the same slot.
3. Auto-register the bundle on every CP request, gated to `getIsPro()`.
4. Preserve Craft's submit-gating (never weaker than Craft).

### Then Phase D — User index integration

**P2.1 — User index table attributes.** `EVENT_REGISTER_TABLE_ATTRIBUTES` + `EVENT_SET_TABLE_ATTRIBUTE_HTML`. Columns: password status (badge), last change, expired, reset required. **Lite edition** (this is the headline Lite-tier feature — no edition gating beyond what Craft already provides).

**P2.2 — Admin password change action.** Element action with elevated session + `changedByUserId` tracking. Storage: Option A (see PLAN.md §6.2 — store `changedByUserId` on password history table for all editions; not exposed via UI/API on non-Enterprise). New permission `pp:change-user-passwords`. Needs a migration to add the nullable `changedByUserId` column to `passwordpolicy_password_history`.

**Also in Phase D scope:** the half-built `_users/password-security.twig` user-edit tab — template exists with a working POST target (`actionForceReset`), but no event handler registers the template as a CP user-edit tab. Hooks into the same User element work as P2.1/P2.2.

### Then in order: E → F → G → H

- **E** — Pest test infrastructure (P2.5; absorbs deferred T1.2 + TX.2 + T9.7)
- **F** — Polish (P2.4 `passwordField()`, P2.6 `allowAdminChanges` verification)
- **G** — Enterprise (Phase 10/11/12 + per-policy custom blocklist editor + Enterprise email notification types)
- **H** — Release prep (tag, Plugin Store listing, marketing copy, **deployment docs P1.8**)

---

## Hard guards (still active — read MEMORY.md too)

- **5.2.0 is the release vehicle for the entire vision.** Features either land at the right edition tier in 5.2.0 or get dropped to IDEAS.md. No "v5.2.x" or "v5.3" deferral.
- **Don't tag 5.2.0 until Enterprise (Phase G) is built and tested.** Single coordinated release.
- **Always generate migrations via `ddev craft migrate/create <Name> --plugin=password-policy`.** Never hand-pick filenames or timestamps.
- **Use `ddev` shorthand commands.** Never `php`, `composer`, or `npm` on the host.
- **Don't introduce `@deprecated` markers on code added in the same unreleased version.** Delete dead code instead.
- **Don't blindly trust audit subagent reports.** Earlier audit had 2 of 4 findings wrong-as-stated.
- **Default to native Craft components.** `forms.editableTableField` for admin-managed lists; `<blockquote class="note tip|warning">` for high-visibility callouts; `|datetime`/`|time` for locale-aware timestamps. See feedback memory entries.
- **Pruning is not "automatic".** Don't tell admins their data gets cleaned up automatically — `password-policy/gc/run` cron is the recommended production setup.
- **Craft 5 storage idiom.** For per-(entity, site) editable content, prefer one row per (key, siteId) with a JSON `content` column over Craft-4-style relational columns. Memory entry `feedback_craft5_json_content_pattern.md`.

---

## Known follow-ups (deferred, not blocking)

- **Phase 6 user-edit tab is half-built.** `_users/password-security.twig` exists with a working POST target (`actionForceReset`), but no event handler registers the template as a CP user-edit tab. Belongs in P2.1/P2.2 user index work.
- **T9.7 — Site propagation listener test deferred.** Single-site playground can't exercise the `Sites::EVENT_AFTER_SAVE_SITE` `isNew = true` path or the FK CASCADE. Will land in P2.5 Pest tests with a multi-site fixture.
- **Stale tracking rows in playground `migrations` table** for the deleted/replaced migration filenames. Cosmetic, Craft ignores them.
- **Adversarial Test Suite** — `docs/IDEAS.md`. Future P3+ work after P2.5 lands.
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
