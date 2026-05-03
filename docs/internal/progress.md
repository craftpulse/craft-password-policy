# Progress Log

Session-level tracking of what was done, when, and what's next. Keeps `plan.md` clean as the master reference and `manual-tests.md` focused on test results.

**Current phase:** F — polish + draft Phase G build plan (P2.8). Not yet started.

When a phase closes, its session log rotates to `history/progress-phase-<id>.md` and this file becomes a small pointer until the next phase opens.

## Closed phases (rotated)

- **Phases A + B + C** (audit fix-ups, pre-release security tests, original P1 backlog) — closed 2026-04-30 → see [`history/progress-phase-a-c.md`](./history/progress-phase-a-c.md)
- **Phase C2** (Pro front-end surface bundle: P1.12–P1.15 + Layer 4b unification + bug-fix sweep) — closed 2026-05-02 → see [`history/progress-phase-c2.md`](./history/progress-phase-c2.md)
- **Phase E** (Pest test infrastructure — P2.5 scope-expanded; 18 commits; suite at 329 passing / 0 skipped / 634 assertions; T1.2 + TX.2 + T9.7 absorbed from manual register; HibpClient interface extracted) — closed 2026-05-02 → see [`history/progress-phase-e.md`](./history/progress-phase-e.md)
- **Phase D** (User index integration — P2.1 + P2.2 + half-built user-edit tab + P2.6 verification gate; 19 commits across D0–D4; suite at 513 passing / 0 skipped / 1049 assertions; audit-context surface laid as the foundation Phase G builds on) — closed 2026-05-03 → see [`history/progress-phase-d.md`](./history/progress-phase-d.md)

---

## Next Session

Phases A → D + E all closed. Phase D landed on top of Phase E's 329-test regression net per the build-order swap. The codebase now has the audit-context capture surface (D0/D1) that Phase G's hash-chained audit log will sit on top of, the user-index admin affordances (D2/D3) that Phase G's compliance dashboard will pivot off, and the user-edit "tab" pointer (D4) that closes the half-built Phase 6 template.

**Next: Phase F — polish + draft Phase G build plan (P2.8).**

P2.8 is the only Phase F deliverable. Use `internal/history/phase-c2-build-plan.md` as the structural template. Lock these architectural decisions before any Phase G code lands:

1. **Hash-chained audit row format.** Canonical JSON shape, `previousHash` column. Decision on whether `dateCreated` participates in canonicalisation (timezone normalisation matters).
2. **Independent verifier CLI.** `password-policy/audit/verify` chain-walk semantics, exit codes, output format, behavior on partial chains (retention-purged early rows).
3. **SIEM forwarders.** Protocols (syslog over TCP/UDP/TLS? HTTP webhook? both?), queue-driven via `\craft\queue\BaseBatchedJob`.
4. **Webhook HMAC scheme.** Signature header, payload canonicalisation rules, replay-attack window.
5. **`AlertCooldownService` scope.** Which event classes register cooldowns. Generalises P1.3's `notificationLogRetentionDays` dedup pattern per-event-class.
6. **Streaming audit-log export pattern.** `AuditController::actionExport` extension via `BaseBatchedJob`.

Re-evaluate at draft time whether any Phase G subset (e.g. SIEM webhooks, ApiTokenService) can defer to 5.3 if scope expands beyond one comfortable build cycle. The "no v5.3 deferral" rule loosens once P2.8 is drafted.

After Phase F → **Phase G (Enterprise — Phase 10/11/12)** → Phase H (release prep + tag 5.2.0).

**Read first (in order):**
1. `handover.md` — single-page handover with playground state + commands + Pest run instructions
2. `plan.md` — master plan, build order, gating
3. `progress.md` — this file, current-phase session log (older phases rotated to `history/`)
4. `manual-tests.md` — per-test PASS/PENDING/DEFERRED/COVERED-BY-PEST status

**Pest suite:** keep it green during Phase F. Phase F is mostly docs / planning work, but if any code touches happen they must clear `composer test` (ECS → PHPStan → Pest) before commit. Run via `cd /Users/michtio/dev/craft-plugin-playground/cms_v5 && ddev exec --dir /Users/Shared/dev/craft-plugins/v5/craft-password-policy composer test`.

**Memory store:** `~/.claude/projects/-Users-michtio-dev-craft-plugins-v5-craft-password-policy/memory/MEMORY.md` indexes 23 durable rules including release strategy, audit capture principle (Phase D codified this — Lite + Pro + Enterprise all populate audit columns; gate exposure not capture), Craft 5 JSON content pattern, the Craft CLI `migrate/create` rule, and 20 skill gaps. Entry #20 (the console-bootstrap CP-test trifecta) is the load-bearing gap for any Phase G CP controller tests.
