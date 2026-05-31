# Phase F + F2 + F3 — Polish, notifications activity, Phase G build plan (closed 2026-05-06)

Three sub-phases ran back-to-back on 2026-05-06 — all closed in a single session. F is the user-edit UI sweep; F2 is the notifications activity surface (P2.9); F3 is the Phase G build plan draft (P2.8). Pest suite went 513 → 551 passing / 0 skipped (1151 assertions). ECS clean, PHPStan clean.

Phase F unblocked Phase G — once the architectural decisions in the F3 build plan were locked, the Enterprise build had a deterministic spec to execute against. F2 also retroactively codified the **audit capture principle** (`project_audit_capture_principle.md`): capture runs on every edition; gate exposure not capture. That memory rule became load-bearing for every subsequent edition-tier decision, including the Phase 2 edition realignment that landed nine days later.

## Sub-phases

### F — User-edit UI sweep (single commit, 2026-05-06)

Commit `refactor(users): polish user-edit UI sweep — status pills, edit-screen event, action menu`. Targeted polish on the Phase D surface:

- **User-index renderers rewritten** with `Cp::statusLabelHtml()` + `Color` enum + empty-cell convention. Memory entry `feedback_skill_gaps.md` gained gap #22 (status pill helper).
- **Expiry-dependent columns + sort options gated on `expiryAmount` configured.** When expiry is disabled globally, the `daysUntilExpiry` / `expired` columns drop out of the renderable set and the sort options drop them too. Cleaner UX than rendering empty cells.
- **`_registerUserEditTab()` (sidebar pointer workaround) replaced** with a real `UsersController::EVENT_DEFINE_EDIT_SCREENS` registration. **Memory gap #21 corrected** — the event ships in Craft 5.0+, contrary to an earlier wrong-as-stated claim. The Phase D sidebar pointer was the workaround for a non-existent gap.
- **`Element::EVENT_DEFINE_ACTION_MENU_ITEMS`** listener appends Force Reset / Send Reset Email / Change Password… to the per-user edit screen "…" menu. Memory gap #23 captured the action-menu vs index-actions duality.
- **`ChangeUserPassword` dropped from index bulk-action menu** (same-password-on-N-users is a security anti-pattern). Class kept for the static modal helpers consumed by the action menu listener; dead `getTriggerHtml()` override removed.
- **Modal styling pinned** (480px + `fitted`) and wrapped in `Craft.elevatedSessionManager.requireElevatedSession()`.
- **`UserSecurityController` switched to `EditUserTrait`** so the left nav stays visible.

**Quiet correctness bug surfaced + fixed.** `UserQuery` selects neither `lastPasswordChangeDate` nor `passwordResetRequired` — the latter newly verified — so the "Password reset has been requested" banner never rendered and the Force Password Reset button always showed. Both columns now hydrate via direct scalar query in `UserSecurityController::actionIndex()`. Same pattern as memory gap #9 (the original `lastPasswordChangeDate` find).

### F2 — Notifications activity surface (single commit, 2026-05-06)

Commit `feat(notifications): activity surface — capture-on-failure + resend + per-user panel`. P2.9 closed.

`passwordpolicy_notification_log` schema rewritten into a real audit table:

- **New columns** — `status`, `recipientEmail`, `siteId`, rendered `subject` + `body`, `errorMessage`, `resentFromId`.
- **Idempotent migration** `m260506_174529_AddNotificationLogActivityColumns`. `Install.php` matched. `schemaVersion` 2.3.0 → 2.4.0.
- **`NotificationService` rewrites the row write OUT of the success try block** — both success and failure paths capture rows. `Throwable::getMessage()` on the failure path lands in `errorMessage`. `composeFromTemplate()` exposes a `&$rendered` out-param so the dispatch path captures rendered subject + body without a redundant second `View::renderString()` pass.
- **Dedup gate `_hasRecentNotification()`** now filters on `status = 'sent'` so failed-then-retried doesn't suppress.
- **New `NotificationService::resend(NotificationLogRecord)`** re-renders fresh from the current template (NOT snapshot replay), bypasses dedup, chains via `resentFromId`, rejects non-resendable mailer-key types.
- **New `NotificationActivityService`** (read-side), **`NotificationActivityController`**, URL rules, `Notifications → Activity` sibling subnav.
- **Per-user notifications panel** embedded on the Password Security screen.
- **New `NotificationStatus` backed enum** (Sent / Failed).
- **Notification-log GC pruner ungated from Pro** — architectural fix: capture runs on every edition per `project_audit_capture_principle.md`, so prune must too.

Three Pest test files added: `NotificationServiceCaptureTest`, `NotificationServiceResendTest`, `NotificationActivityServiceTest`. Suite at 551 / 1151.

Bounce ingestion (provider webhooks) deferred to `ideas.md`.

### F3 — Phase G build plan (P2.8) (2026-05-06)

Deliverable: [`internal/phase-g-build-plan.md`](../phase-g-build-plan.md) — 1238-line layered build plan covering G1 through G12. Locked architectural decisions:

1. **Hash-chained audit row format** — SHA-256 forward chain. Canonical JSON with alphabetical key order + UTC ISO 8601 timestamp. First-row sentinel `'0' × 64`. `dateCreated` participates in canonicalisation; timezone normalisation handled by formatting in UTC before canonicalisation.
2. **Independent verifier CLI** — `password-policy/audit/verify` chain-walk semantics. Exit codes: `0` = chain valid, `1` = first break (with row id), `2` = unreadable / schema drift. Output: machine-parseable for CI. Retention-purge-tolerant — partial chains exit `0` with a "purged early rows" notice rather than catastrophic.
3. **SIEM forwarders** — syslog-over-TLS via `\craft\queue\BaseBatchedJob`. UDP cut from scope entirely.
4. **Webhook HMAC scheme** — `X-PasswordPolicy-Signature: sha256=<hex>`. Replay window 5 min. Idempotency UUID header for replay protection.
5. **`AlertCooldownService`** — dedicated `passwordpolicy_alert_cooldowns` table generalising F2's notification-log dedup pattern. Per-event-class registration.
6. **Streaming audit-log export** — `AuditController::actionExport` extends via `BaseBatchedJob`. Presigned filesystem-backed download token.

**User-confirmed scope (2026-05-06):**

- Ships in 5.2.0 — G1 through G12 in full (G9 ships whole, not infra-only).
- Defers to 5.3 — Phase 12 § REST surface (ApiTokenService + ApiController) only.
- Cut from the matrix entirely — syslog UDP forwarder protocol.

Estimated 6-8 working days for the full set. Phase G unblocked.

## Cumulative metrics at Phase F3 close

- **Suite:** 551 passing / 0 skipped / 1151 assertions (+38 over Phase D close).
- **Schema:** 2.4.0 (F2 bumped 2.3.0 → 2.4.0).
- **ECS + PHPStan:** clean, 3-entry PHPStan baseline unchanged from E1.
- **Commits:** 3 single-commit phases. F + F2 + F3 each one commit on `5.x`.

## Memory deltas

- Memory gap #21 **corrected** — `UsersController::EVENT_DEFINE_EDIT_SCREENS` does ship in Craft 5.0+. Phase D's sidebar pointer was a workaround for a non-issue.
- Memory gap #22 added — `Cp::statusLabelHtml()` + `Color` enum is the canonical helper for index status pills.
- Memory gap #23 added — `Element::EVENT_DEFINE_ACTION_MENU_ITEMS` (per-row edit-screen menu) is a separate surface from element-index bulk actions; both register independently.
- `project_audit_capture_principle.md` codified — capture on every edition, gate exposure not capture. Load-bearing for Phase G and later for the Phase 2 edition realignment.

## What's next (post-F3)

Phase G — Enterprise build, driven by the F3 build plan. Six to eight working days estimated; in practice ran 2026-05-07 through 2026-05-14 with a post-review remediation pass also folded in.
