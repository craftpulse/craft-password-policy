# Progress Log

Session-level tracking of what was done, when, and what's next. Keeps `plan.md` clean as the master reference and `manual-tests.md` focused on test results.

**Current phase:** H — release prep + full QA pass. In flight from 2026-05-18.

When a phase closes, its session log rotates to `history/progress-phase-<id>.md` and this file becomes a small pointer until the next phase opens.

## Closed phases (rotated)

- **Phases A + B + C** (audit fix-ups, pre-release security tests, original P1 backlog) — closed 2026-04-30 → see [`history/progress-phase-a-c.md`](./history/progress-phase-a-c.md)
- **Phase C2** (Pro front-end surface bundle: P1.12–P1.15 + Layer 4b unification + bug-fix sweep) — closed 2026-05-02 → see [`history/progress-phase-c2.md`](./history/progress-phase-c2.md)
- **Phase E** (Pest test infrastructure — P2.5 scope-expanded; 18 commits; suite at 329 passing / 0 skipped / 634 assertions; T1.2 + TX.2 + T9.7 absorbed from manual register; HibpClient interface extracted) — closed 2026-05-02 → see [`history/progress-phase-e.md`](./history/progress-phase-e.md)
- **Phase D** (User index integration — P2.1 + P2.2 + half-built user-edit tab + P2.6 verification gate; 19 commits across D0–D4; suite at 513 / 1049; audit-context surface laid for Phase G's hash-chained audit log) — closed 2026-05-03 → see [`history/progress-phase-d.md`](./history/progress-phase-d.md)
- **Phase F + F2 + F3** (UI sweep, notifications activity surface P2.9, Phase G build plan P2.8) — closed 2026-05-06 → see [`history/progress-phase-f.md`](./history/progress-phase-f.md)
- **Phase G** (Enterprise build — G1–G12 + post-review remediation Steps 1–8; 17K+ lines + three record→element refactors; suite at 786 / 1875; schema 2.11.0) — closed 2026-05-14 → see [`history/progress-phase-g.md`](./history/progress-phase-g.md)
- **Phase H prep** (security audit polish bundles + Phase 2 edition realignment + comprehensive `docs/user/` rewrite; ~35 commits; suite at 802 / 1924; schema unchanged at 2.11.0) — closed 2026-05-15 → see [`history/progress-phase-h-prep.md`](./history/progress-phase-h-prep.md)

---

## Next Session

Phase H — release prep + full QA pass. Code-complete. All architectural decisions locked. Pest suite green. ECS + PHPStan clean.

The remaining work is the **full pre-tag QA pass**: a multi-hour focused user session running every block in `manual-tests.md` (Phases 0 through 25) end-to-end against the playground. New T-rows authored 2026-05-18 cover every Phase G surface, the Phase 2 edition realignment, and the security audit polish bundles.

`composer.json` stays at `5.2.0-alpha.1` per user direction.

**Read first (in order):**
1. `handover.md` — single-page handover with playground state + commands + Pest run instructions
2. `plan.md` — master plan, build order, gating
3. `manual-tests.md` — **start with the "Full pre-tag QA pass" active block at the top**; per-test PASS/PENDING/DEFERRED/COVERED-BY-PEST status

**Pest suite:** keep it green. Phase H is mostly QA work, but if any code touches happen (fix-forward from QA findings) they must clear `composer test` (ECS → PHPStan → Pest) before commit. Run via `cd /Users/michtio/dev/craft-plugin-playground/cms_v5 && ddev exec --dir /Users/Shared/dev/craft-plugins/v5/craft-password-policy composer test`.

**Memory store:** `~/.claude/projects/-Users-michtio-dev-craft-plugins-v5-craft-password-policy/memory/MEMORY.md` indexes 25 durable rules including release strategy, audit capture principle, foundation-first invariant, Craft 5 JSON content pattern, P2/P3 polish ships before tag.

After QA passes:
- Plugin Store listing rewrite (pre-v5.2.0 listing needs the new feature matrix + Enterprise positioning).
- Marketing copy — lead with NIS2 / NIST 800-63B Rev 4 / PCI-DSS / GDPR framework anchors.
- Tag 5.2.0. `composer.json` stays at `5.2.0-alpha.1`.

After 5.2.0 ships:
- 5.3 candidate bundle — auth-event audit (MFA / passkey / SSO lifecycle). See `ideas.md` "5.3.0 scope recommendation."

---

## Phase H smoke-test walk — findings log (in flight 2026-05-22 →)

User-driven walk-through against the playground per `docs/internal/smoke-tests.md`. Track findings as they surface. Each entry: scenario ID · status · one-line reproduction · disposition.

### Fixes landed during the walk

- **S1.3 FAIL → PASS** (commit `fc6f56a`, 2026-05-22) — HIBP lightswitch on Configuration silently reverted to OFF on every save. Root cause: legacy `pwned` / `pwnedFailMode` aliases leaked into `SettingsModel::getAttributes()` default-list output, then overwrote the canonical `hibp` key during `SettingsController::actionSave()`'s read-merge-write round-trip. Same vulnerability on `hibpFailMode` open↔closed. Fix: `getAttributes()` override filters the aliases from the default-list call; explicit `getAttributes(['pwned'])` still returns them for back-compat. 5 new Pest regression tests in `SettingsModelLegacyAliasTest` pin the contract. Suite now at 805 / 1927.

### Open findings — record, defer fix to a later pass

- **S1.4 — Strength indicator missing in custom modal** (2026-05-22) — On the playground's custom user-creation/edit modal, the password strength indicator does not render. The indicator works correctly on the user's own My Account → password change page. User flagged this as "modal needs more work overall" — deferring fix to a broader modal rework, not a one-off patch. Scope: surface the meter wherever `showStrengthIndicator` is enabled and a password input is present in any CP context, not just the My Account form. Likely root cause: the `PasswordPolicyAsset` registration only fires on `View::EVENT_BEFORE_RENDER_PAGE_TEMPLATE` (full page templates), not on dynamically-rendered modal templates. Modal templates render via a different View event or partial-render path that doesn't trigger the asset registration.
- **S1.4 — Strength indicator debounce feels laggy** (2026-05-22) — Visible input → meter update delay larger than expected ~250ms debounce. Not blocking; logged for perf review before tag. May be related to AJAX validate round-trip time rather than the debounce window itself.
- **Plugin log: `pwned` / `pwnedFailMode` deprecation spam every ~minute** (2026-05-22) — The 2026-05-22 plugin log is dominated by recurring `Password Policy config key 'pwned' is deprecated…` warnings firing in three distinct memory-address clusters (`1800480`, `1800672`, `1800888`) at ~50-60s intervals. Indicates **three callers** still writing the legacy key, every minute. Likely sources: a `config/password-policy.php` file with `pwned: true`, a cron / queue worker iterating settings, or a project-config consumer re-applying the legacy key. The 5.2.0 migration `m260429_224908_UpgradeTo520Schema::_renameProjectConfigKeys()` strips `pwned` from project config on upgrade — if the warning is still firing, the upgrade either didn't run, or another surface (file-based config, queue payload, cached settings) is reintroducing it. **Action**: triage source. If file-based config: surface a one-time admin notice and document the rename in upgrade-from-5.1.md. If queue/internal: track down the caller and fix. Either way, this noise drowns out actionable log entries and should be cleaned before tag.
- **S1.6 — force-change-on-first-login not flipping `passwordResetRequired`** (2026-05-22, in flight) — Manual flow: enable setting, create new user, sign in as user → no redirect. Diagnostics: project config persists `forceChangeOnFirstLogin = true`. "Require password reset" checkbox is NOT checked on the user after creation. No "Failed to set passwordResetRequired" log entries on the user-creation timestamp. Existing Pest at `tests/Integration/Services/PasswordHistoryAuditContextTest.php:281` covers this exact scenario via `Craft::$app->getElements()->saveElement($user, false)` and passes — so the listener logic is sound. Divergence must be CP-form-specific. Investigation pending — see active conversation for diagnostic Q's to user.

### Scope corrections to `smoke-tests.md` discovered during the walk

- **S1.4 path** — strength indicator toggle lives on **Configuration** subnav, not Validators. Doc corrected.
- **S1.4 surface scope** — strength meter appears on the user's own **My Account → password change**, NOT on Users → New user (admin creating a user). Doc clarified.

### Deferred to end-of-walk

- **S1.1** — Fresh `composer require` + plugin install on Lite. Destructive against current populated playground; run as the last step before §20 pre-tag sanity.
- **S1.2** — Upgrade from 5.1.x. Needs a separate 5.1.x baseline site; sandbox-only.
