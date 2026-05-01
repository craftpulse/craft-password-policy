# Progress Log

Session-level tracking of what was done, when, and what's next. Keeps `plan.md` clean as the master reference and `manual-tests.md` focused on test results.

**Current phase:** D — user index integration (not yet started).

When a phase closes, its session log rotates to `history/progress-phase-<id>.md` and this file becomes a small pointer until the next phase opens.

## Closed phases (rotated)

- **Phases A + B + C** (audit fix-ups, pre-release security tests, original P1 backlog) — closed 2026-04-30 → see [`history/progress-phase-a-c.md`](./history/progress-phase-a-c.md)
- **Phase C2** (Pro front-end surface bundle: P1.12–P1.15 + Layer 4b unification + bug-fix sweep) — closed 2026-05-02 → see [`history/progress-phase-c2.md`](./history/progress-phase-c2.md)

---

## Next Session

Phase A (audit fix-ups), Phase B (pre-release security tests), and **Phase C (P1 backlog)** all closed. Phase C2 (Pro front-end surface bundle) closed in full as of 2026-05-01. Next is Phase D — user index integration.

**Priority 1 (Phase D):**
- P2.1 — User index table attributes via `EVENT_REGISTER_TABLE_ATTRIBUTES` + `EVENT_SET_TABLE_ATTRIBUTE_HTML`. Columns: password status (badge), last change, expired, reset required. Lite edition.
- P2.2 — Admin password change action. Element action with elevated session + `changedByUserId` tracking. Storage: Option A (see `reference.md` §6.2). New permission `pp:change-user-passwords`. Migration: nullable column on password history table.

After Phase D → Phase E (P2.5 Pest tests, including the deferred T1.2 + TX.2 + T9.7 site propagation listener) → Phase F (P2.4/2.6 polish) → **Phase G (Enterprise — Phase 10/11/12)** → Phase H (release prep + tag 5.2.0).

**Read first (in order):**
1. `handover.md` — single-page handover with playground state + commands
2. `plan.md` — master plan, build order, gating
3. `progress.md` — this file, current-phase session log (older phases rotated to `history/`)
4. `manual-tests.md` — per-test PASS/PENDING/DEFERRED status

**Memory store:** `~/.claude/projects/-Users-michtio-dev-craft-plugins-v5-craft-password-policy/memory/MEMORY.md` indexes all durable rules including release strategy (single 5.2.0 covers all editions; nothing tags until Enterprise done), the migration generator rule (`ddev craft migrate/create <Name> --plugin=password-policy`), and the Craft 5 JSON content pattern.
