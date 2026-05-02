# Progress Log

Session-level tracking of what was done, when, and what's next. Keeps `plan.md` clean as the master reference and `manual-tests.md` focused on test results.

**Current phase:** D — user index integration (not yet started).

When a phase closes, its session log rotates to `history/progress-phase-<id>.md` and this file becomes a small pointer until the next phase opens.

## Closed phases (rotated)

- **Phases A + B + C** (audit fix-ups, pre-release security tests, original P1 backlog) — closed 2026-04-30 → see [`history/progress-phase-a-c.md`](./history/progress-phase-a-c.md)
- **Phase C2** (Pro front-end surface bundle: P1.12–P1.15 + Layer 4b unification + bug-fix sweep) — closed 2026-05-02 → see [`history/progress-phase-c2.md`](./history/progress-phase-c2.md)
- **Phase E** (Pest test infrastructure — P2.5 scope-expanded; 18 commits; suite at 329 passing / 0 skipped / 634 assertions; T1.2 + TX.2 + T9.7 absorbed from manual register; HibpClient interface extracted) — closed 2026-05-02 → see [`history/progress-phase-e.md`](./history/progress-phase-e.md)

---

## Next Session

Phase A (audit fix-ups), Phase B (pre-release security tests), **Phase C (P1 backlog)**, Phase C2 (Pro front-end surface bundle), and **Phase E (Pest test infrastructure)** all closed. Build order swap (E before D, signed off 2026-05-02) means Phase D now lands on top of a 329-test regression net.

**Next: Phase D — user index integration.**

**Priority 1 (Phase D):**
- P2.1 — User index table attributes via `EVENT_REGISTER_TABLE_ATTRIBUTES` + `EVENT_SET_TABLE_ATTRIBUTE_HTML`. Columns: password status (badge), last change, expired, reset required. Lite edition.
- P2.2 — Admin password change action. Element action with elevated session + `changedByUserId` tracking. Storage: Option A (see `reference.md` §6.2). New permission `pp:change-user-passwords`. Migration: nullable `changedByUserId` column on `passwordpolicy_password_history`. **Author via `ddev craft migrate/create <Name> --plugin=password-policy`** — never hand-pick filenames or timestamps.

P2.6 absorbed as a Phase D quality gate: when adding new CP affordances, verify they respect `allowAdminChanges = false` read-only mode.

After Phase D → Phase F (P2.8 — draft Phase G build plan) → **Phase G (Enterprise — Phase 10/11/12)** → Phase H (release prep + tag 5.2.0).

**Read first (in order):**
1. `handover.md` — single-page handover with playground state + commands + Pest run instructions
2. `plan.md` — master plan, build order, gating
3. `progress.md` — this file, current-phase session log (older phases rotated to `history/`)
4. `manual-tests.md` — per-test PASS/PENDING/DEFERRED/COVERED-BY-PEST status

**Pest suite:** keep it green during Phase D. Run `cd /Users/michtio/dev/craft-plugin-playground/cms_v5 && ddev exec --dir /Users/Shared/dev/craft-plugins/v5/craft-password-policy composer test` after each commit. The chain is ECS → PHPStan → Pest (stops on first failure). Phase D will likely touch User element behavior + the password history table + CP routing — the regression net should catch incidental breakage before it lands.

**Memory store:** `~/.claude/projects/-Users-michtio-dev-craft-plugins-v5-craft-password-policy/memory/MEMORY.md` indexes all durable rules including release strategy (single 5.2.0 covers all editions; nothing tags until Enterprise done), the migration generator rule (`ddev craft migrate/create <Name> --plugin=password-policy`), the Craft 5 JSON content pattern, and 19 skill gaps (`feedback_skill_gaps.md` — gaps #15–19 are testing-specific, useful seed for any Pest setup in another plugin).
