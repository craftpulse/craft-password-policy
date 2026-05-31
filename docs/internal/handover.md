# Next Session — Handover (2026-05-18, Phase H prep)

Building **v5.2.0** of `craft-password-policy`. Single release covers Lite + Pro + Enterprise. **Phase G shipped (2026-05-14), security audit polish landed (2026-05-14 → 15), Phase 2 edition realignment landed (2026-05-15), `docs/user/` rewrite for 5.2.0 ship state complete (2026-05-15).** Next gate: the full Phase H QA pass — every block, every T-row, browser + Mailpit work. After QA passes end-to-end, tag.

`composer.json` stays at `5.2.0-alpha.1` per user direction.

---

## Read in this order, no skipping

1. `plan.md` — master plan; sections 1 (status), 2 (manual testing remaining), 3 (backlog), 4 (build order). All gates cleared through Phase G; Phase H release prep ready to start.
2. `manual-tests.md` — **start with the "Full pre-tag QA pass" active block at the top.** It orchestrates every test block in the file (Phases 0–25). Per-test register below it. T14.x–T25.x rows authored 2026-05-18 cover every Phase G surface + Phase 2 edition realignment + security audit polish.
3. This file (`handover.md`) — playground state + commands.
4. Historical context if needed: `history/progress-phase-{a-c, c2, d, e, f, g, h-prep}.md`.

Memory store: `~/.claude/projects/-Users-michtio-dev-craft-plugins-v5-craft-password-policy/memory/MEMORY.md` — durable rules across sessions. 25 entries including release strategy, **audit capture principle** (capture on every edition; gate exposure not capture — load-bearing for the Phase 2 edition realignment), **foundation-first** (no refactor deferrals), **P2/P3 polish ships before tag**, Craft 5 JSON content pattern, retention/GC framing. **Read it.**

Project guide: `CLAUDE.md` at the repo root + `.claude/rules/*.md` import targets — coding-style, architecture, git-workflow, scaffolding, security, migrations, testing.

---

## State at handover

**Branch:** `5.x`, fully synced with `origin/5.x`. Working tree clean.

**`5.1.x` branch:** `5.1.2` tagged 2026-05-02 (`833a038`), pushed. Channel idle until a new security signal warrants 5.1.3 — no current backport candidates (post-5.1.2 5.x fixes all target 5.2.0-only surfaces).

**Pest suite:** **802 passing / 0 skipped / 1924 assertions.** Last run 2026-05-18. ECS clean, PHPStan clean (3-entry baseline unchanged from E1). Run via `cd /Users/michtio/dev/craft-plugin-playground/cms_v5 && ddev exec --dir /Users/Shared/dev/craft-plugins/v5/craft-password-policy composer test`.

**Schema:** `2.11.0`. `composer.json` version: `5.2.0-alpha.1` (stays).

**Manual tests:**

- **Pre-Phase-G surface (T0.1 → T13.12):** 78/79 PASS for the Phase C2 + Layer 4b + bug fix sweep active pass. T1.2 + TX.2 + T9.7 covered by Pest. T12.6 (Enterprise audit) was deferred — **now unblocked**, see T14.x.
- **Phase G surface (T14.x → T23.x):** authored 2026-05-18, all PENDING. Hash chain, verifier CLI, compliance dashboard, SIEM forwarders, signed webhooks, audit export, alert cooldowns, per-policy custom blocklist, custom email template paths, Enterprise notification keys.
- **Phase 2 edition realignment (T24.x):** authored 2026-05-18, all PENDING. Password history universal, presets universal, expiry-reminder email universal, Strict Enterprise still Pro-gated, sub-edition strip-on-save preserved for audit/SIEM/webhook keys.
- **Security audit polish (T25.x):** authored 2026-05-18, all PENDING. ~13 T-rows covering authorization scopes, info disclosure, secret stripping, cache-key privacy, listener attribution.

The full QA pass is multi-hour and requires browser + Mailpit + a multi-site Craft install to run end-to-end. **No agent run can complete it** — this is a user-driven walkthrough.

**Recent commits (newest first — Phase 2 edition realignment + security audit polish):**
```
d8f49fe docs(editions,features): reflect Phase 2 — Lite-expanded history + presets + expiry
ac04e01 feat(notifications): expiry-reminder emails universal across editions
c2ae7b6 feat(presets): CIS Controls v8 + global preset apply on every edition
3fdeee5 feat(history): move password history from Pro to all editions
00e6c33 fix(webhooks,siem,cp): P3 polish bundle — exception strings, button class, hidden attr
e41878e fix(audit,webhooks): P2 bundle — canonicalisation, uninstall cleanup, confirm UX
e45b9aa fix(webhooks): strip plaintext HMAC secrets from asModelSuccess JSON
924f5e7 fix(audit): resolve user via UserEvent::$user on lock/unlock listeners
c6be81c docs(reference): add SiemForwardAttemptEvent + rewrite database-schema + refresh ajax-validate
c7cdf7d docs(operations): add upgrade-from-5.1, cron-setup, compliance-frameworks + refresh gc-and-retention
d2966d3 docs(features): add Phase G feature docs — verifier, dashboard, blocklist, SIEM, webhooks, export, cooldowns
52ac336 docs(features): rewrite per-group-policies, password-history, validators + polish user-index
61c4017 docs(features): rewrite audit-logging, force-reset, notifications for 5.2.0 ship state
584d9c0 docs(readme,index): refresh entry-point docs for 5.2.0 ship state
732974a docs(ideas): record 5.3 candidate bundle — MFA / passkey / SSO audit coverage
149400b docs(changelog): comprehensive 5.2.0 rewrite + bring forward 5.1.2 entry
1ca4433 docs(editions): add NIST Rev 4 alignment + compliance phrasing discipline
60a3090 docs(compliance): correct framework clause citations across audit-logging doc
61f47d1 fix(presets): NIST preset enables checkCommonPasswords for §3.1.1.2 conformance
8cad6ad chore(events,audit-export,cp-nav): preventative polish from the security audit
2c7c91d fix(audit-export): bind download token to requesting admin
6703c88 fix(hibp): drop sha1Prefix from login dedup cache key
99f395e fix(webhooks): don't leak exception message from actionRotateSecret
9285f37 fix(password-history): route password compare through Craft Security service
ebae56e docs(audit-logging): name Splunk HEC + Datadog explicitly as supported SIEM destinations
6125dc4 fix(cp): polish — spacing utilities, button styling, divergent indicator, async→.then style
20013a6 fix(notifications,permissions): sendNewDeviceAlert Pro guard + activity breadcrumbs + log-view permission
baaf5c3 feat(notifications,siem,webhooks): native Cp::statusLabelHtml status pills
6bef758 refactor(users): move force-reset action from RetentionController to UserSecurityController
47c1b46 fix(cp,a11y): edition gating + radiogroup keyboard + translator XSS + readOnly on CP UI
71d8beb fix(controllers): allowAdminChanges guards + exception leaks on notification-template surfaces
dfd656b docs(plan): correct stale 5.1.x state — 5.1.2 shipped 2026-05-02
5c2e954 docs(plan): close Phase G — G1–G12 all shipped, Phase H unblocked
be33546 feat(compliance): dashboard utility + aggregate service + HTML/CSV report controller (G3)
```

Earlier history rotated: Phase A–C → `history/progress-phase-a-c.md`; Phase C2 → `history/progress-phase-c2.md`; Phase D → `history/progress-phase-d.md`; Phase E → `history/progress-phase-e.md`; Phase F+F2+F3 → `history/progress-phase-f.md`; Phase G + post-G remediation Steps 1–8 → `history/progress-phase-g.md`; security audit polish + edition realignment → `history/progress-phase-h-prep.md`.

**Phase status (`plan.md` §4):**
- A — done 2026-04-29
- B — done 2026-04-30
- C — done 2026-04-30
- C2 — fully closed 2026-05-02
- E — done 2026-05-02
- D — done 2026-05-03
- F + F2 + F3 — done 2026-05-06
- **G — done 2026-05-14** (G1–G12 + post-review remediation Steps 1–8)
- **Phase 2 edition realignment + security audit polish — done 2026-05-15**
- **H — release prep + full QA pass: in flight from 2026-05-18.**

---

## Playground

- URL: `https://plugin-playground-v5.ddev.site/admin`
- Path: `/Users/michtio/dev/craft-plugin-playground/cms_v5`
- Login (admin): `development@craftpulse.com` / `Letmein-Craftpulse1!`
- Plugin edition: **Pro** (project.yaml). Craft license: Pro.
- Mailpit: `https://plugin-playground-v5.ddev.site:8026` (or `ddev mailpit`).

**Playground state to verify before QA pass starts:**

- Schema at `2.11.0` (run `ddev craft up` to apply pending migrations from a snapshot restore).
- `db_test` DB exists for Pest (`ddev mysql -uroot -proot -e "SHOW DATABASES LIKE 'db_test'"`). Recreate via `CREATE DATABASE IF NOT EXISTS db_test; GRANT ALL ON db_test.* TO 'db'@'%'; FLUSH PRIVILEGES;` if missing.
- `CRAFT_AUDIT_PII_KEY` env var present in `.ddev/.env` or `.env` (generated via `ddev craft password-policy/audit/generate-pii-key`).
- Notification templates seeded: `expiry-reminder`, `breach-detected`, `new-device-alert`, `admin-security-alert` × siteId 1.
- Audit log chain intact — `ddev craft password-policy/audit/verify` should exit `0`.

For the **Phase G Enterprise QA blocks** (T14.x–T23.x): the plugin needs to be on the **Enterprise edition**. Flip via `cms/config/project/project.yaml` → `plugins.password-policy.settings.edition: enterprise` + bump `dateModified` + `ddev craft up`. Flip back to Pro for the Pro-only blocks. Same edition-flip pattern as T9.9 / T12.4 / T13.10.

For the **Phase 2 edition realignment Lite blocks** (T24.x): flip to Lite the same way. Verify history validator runs, preset apply works, expiry email dispatches.

For the **multi-site QA blocks**: the playground is single-site. Use the project the developer has set up for multi-site testing — see memory entry `feedback_skill_gaps.md` #19 if site soft-delete cascade needs re-verification.

---

## What to build first

**Run the full QA pass.** Order suggested in `manual-tests.md`'s "Full pre-tag QA pass" active block:

1. Block 1 — Front-end demos (anonymous + authenticated). Existing Phase 13 surface.
2. Block 2 — CP-side strength meter (Layer 4b). Existing Phase 13 surface.
3. Block 3 — HIBP-on-login (Pro). Existing Phase 12 surface.
4. Block 4 — Email notifications (Pro + Lite expiry). Existing Phase 9 surface + new Phase 24 row.
5. **Block 5 — Phase G Enterprise audit (NEW).** T14.x–T16.x — hash chain, verifier CLI, compliance dashboard.
6. **Block 6 — Phase G Enterprise integrations (NEW).** T17.x–T19.x — SIEM forwarders, signed webhooks, audit export.
7. **Block 7 — Phase G Enterprise polish (NEW).** T20.x–T23.x — alert cooldowns, per-policy custom blocklist, custom email template paths, Enterprise notification keys.
8. **Block 8 — Phase 2 edition realignment (NEW).** T24.x — universal history + presets + expiry email on Lite.
9. **Block 9 — Security audit polish (NEW).** T25.x — authorization scopes, info disclosure, secret stripping, cache-key privacy.
10. Block 10 — Edition matrix verification across every block above.
11. Block 11 — bug-fix-specific verifications. Existing Phase C2 surface.

Capture every failure: page URL, browser console error, Network tab response, Mailpit state, plugin log tail (`storage/logs/password-policy-*.log`), commit hash (`git rev-parse HEAD`).

**On any FAIL:** try to reproduce in Pest first. If the regression net catches it, write a test, fix forward, mark T-row PASS, move on. If it can't be expressed as a Pest test (browser interaction, screen reader, real Mailpit verification), record the failure on the T-row with reproduction steps.

### After QA passes

- Plugin Store listing rewrite — per `project_competitive_landscape.md` memory rule, the current listing is pre-v5.2.0 and needs rewriting against the new feature matrix + Enterprise positioning.
- Marketing copy — per `project_compliance_positioning.md`, lead with NIS2 / NIST 800-63B Rev 4 / PCI-DSS / GDPR framework anchors. Trails is the audit-log competitor to differentiate against.
- Tag 5.2.0. `composer.json` does NOT bump — user stays on alpha.1 versioning.

---

## Hard guards (still active — read MEMORY.md too)

- **5.2.0 is the release vehicle for the entire vision.** Features either land at the right edition tier or get dropped to `ideas.md`. Phase G shipped in full per the 2026-05-06 P2.8 scope confirmation. Phase 2 edition realignment expanded the Lite tier. 5.2.x patch channel reserved for SECURITY only — never UI polish (memory rule `feedback_p2_p3_ship_before_tag.md`).
- **Foundation-first.** No refactor deferrals — record-to-element conversions ship in 5.2.0 (NotificationLog, AuditLog, Policy all completed in post-G remediation). Memory rule `feedback_foundation_first_no_refactor_deferrals.md`.
- **Don't tag 5.2.0 until the QA pass completes end-to-end and `composer test` is clean.**
- **Always generate migrations via `ddev craft migrate/create <Name> --plugin=password-policy`.** Never hand-pick filenames or timestamps.
- **Use `ddev` shorthand commands.** Never `php`, `composer`, or `npm` on the host.
- **Don't introduce `@deprecated` markers on code added in the same unreleased version.** Delete dead code instead.
- **Default to native Craft components.** `forms.editableTableField` for admin-managed lists; `<blockquote class="note tip|warning">` for high-visibility callouts; `Cp::statusLabelHtml()` for index status pills; `|datetime`/`|time` for locale-aware timestamps.
- **Capture on every edition; gate exposure not capture.** Memory rule `project_audit_capture_principle.md`. Codified in F2; load-bearing for the Phase 2 edition realignment.
- **Pruning is not "automatic".** `password-policy/gc/run` cron is the recommended production setup. Memory rule `feedback_retention_gc_framing.md`.

---

## Cross-doc drift watch

State persists in five places: `internal/plan.md`, `internal/handover.md`, MEMORY.md (durable rules), `CLAUDE.md` (project orientation), `.claude/rules/*.md` (PHP / architecture / git / security / migrations / testing / scaffolding). When changing release strategy, edition tiering, migration policy, security invariants, or build order — update both the plan/handover docs AND the corresponding `.claude/rules/*.md` file. No automated sync; drift is a real risk. When in doubt, grep across `docs/internal/`, `MEMORY.md`, `CLAUDE.md`, and `.claude/rules/` for the term you're changing.

---

## Known follow-ups (deferred, not blocking)

- **`db_test` setup may need recreating after a fresh `ddev start` from snapshot.** See playground notes above.
- **Stale tracking rows in playground `migrations` table** for the deleted/replaced migration filenames. Cosmetic, Craft ignores them.
- **Adversarial Test Suite** — `ideas.md`. Future P3+ work.
- **RFC 6587 octet-count framing as opt-in** — `ideas.md`. Half-day work post-5.2.0.
- **Phase D leftovers (BREACHED_RECENT_DAYS / EXPIRING_SOON_DAYS hardcoded thresholds + per-user policy resolver iteration in user-index preload)** — `ideas.md`. Park unless customer signal surfaces.
- **5.3 candidate bundle — auth-event coverage (MFA / passkey / SSO).** `ideas.md`. Strongest single 5.3 wedge; upstream PR opportunity against Craft core for `Auth::EVENT_AFTER_METHOD_*` events.
- **Phase 12 § REST surface (ApiTokenService + ApiController)** — explicitly deferred to 5.3 per the P2.8 scope confirmation.

---

## Don't bother re-doing

- All P1.x items marked done in plan.md.
- All P2.x items marked done.
- All Phase G build-plan items G1–G12.
- All post-G remediation Steps 1–8.
- All Phase 2 edition realignment commits.
- All security audit polish commits.
- 5.1.x maintenance line — `5.1.2` tagged + pushed; channel idle.
- 802 Pest tests — green at handover.
- `composer.json` version bump — user direction is to STAY at `5.2.0-alpha.1`. Don't propose a bump.
