# Phase D — User index integration (closed 2026-05-03)

P2.1 + P2.2 + P2.6 (absorbed as a verification gate) + the half-built `_users/password-security.twig` user-edit tab. 19 commits across five sub-phases (D0–D4). Pest suite went from 329 → 513 passing / 0 skipped (1049 assertions). ECS clean, PHPStan clean (3-entry baseline unchanged).

Phase D landed on top of Phase E's regression net (P2.5 closed first per the build-order swap signed off 2026-05-02). Every new CP affordance has both a Pest pin AND respects `allowAdminChanges = false` (P2.6 verification gate). The audit-context surface introduced in D0–D1 is the load-bearing infrastructure for Phase G's hash-chained audit log — capturing on every edition (Lite + Pro + Enterprise) per the `project_audit_capture_principle.md` memory rule, so when Enterprise ships the verifier CLI the rows are already there.

## Sub-phases

### D0 — Audit context surface (2026-05-02)

Four commits: `ab1d456` (`ChangeReason` + `AuditContext`), `1c85466` (audit-shape migration), `e7c45dd` (`UserStateService` + `PasswordHistoryService` API), `e09e6d6` (audit-shape migration test + UserStateRecord test).

- **`ChangeReason` enum** (`src/enums/ChangeReason.php`) — string-backed, Craft 5 idiom. Cases cover every change pathway: `SelfService`, `Cli`, `AdminChange`, `AdminForceReset`, `BreachForced`, `ExpiryForced`, `FirstLoginForced`. Each case has a `label()` method for CP rendering.
- **`AuditContext` model** (`src/models/AuditContext.php`) — bag of ChangeReason + IP + user-agent + changedByUserId. Static factories: `selfService()`, `cli()`, `adminChange($adminId)`, `fromRequest(reason)`. Pulls IP/UA from `Craft::$app->getRequest()` defensively.
- **Audit-shape migration** (`m260502_214932_AddAuditShapeToPasswordHistory.php`) — adds nullable columns to `passwordpolicy_password_history`: `changeReason`, `changedByUserId` (FK to users), `changedFromIp`, `changedFromUserAgent`. Plus a new `passwordpolicy_user_state` table for pending-reset reason + breach-check timestamps. Idempotent guards on every column add.
- **`UserStateService`** (`src/services/UserStateService.php`) — manages the user_state table. Methods: `getStateForUser`, `setPendingReason`, `clearPendingReason`, `recordBreachCheck`. Plus the in-process explicit-context slot (`setExplicitContext`/`consumeExplicitContext`) for D3's `ChangeUserPassword` controller — single-use, not persisted, keyed by user id.
- **`PasswordHistoryService::savePasswordHash($userId, $hash, $context)`** — third arg added; persists the audit columns alongside the hash.
- **Audit-shape migration test** (`UpgradeTo520MigrationTest`) extended +14 tests — replays from 5.1.1 schema, asserts the new columns exist with the right shape, history-replay back-fills `changeReason = legacy_unknown` for old rows.

`Install.php` updated for fresh installs to ship the new shape day-one. `PasswordHistoryRecord` gains the new properties; `UserStateRecord` is new.

### D1 — Audit listener wiring (2026-05-02 → 03)

Three commits: `1739df9` (consume pending reason), `41aed57` (wire ForcePasswordReset + expiry triggers), `bf66716` (force-reset preload follow-up). One coverage commit `1290468`.

- **Central `EVENT_AFTER_SAVE` listener** at `PasswordPolicy::_resolveAuditContext()` — three-tier precedence:
  1. Explicit context (admin-direct change wins)
  2. Pending-reset reason on user_state
  3. Default — `SelfService` (web) or `Cli` (console)
- **`ForcePasswordReset` action** pins `pendingResetReason = AdminForceReset` after flipping `passwordResetRequired`. The user's NEXT password change consumes it and writes `changeReason = admin_force_reset` to history.
- **Expiry trigger** (`RetentionService::requirePasswordReset`) pins `pendingResetReason = ExpiryForced`. Same consume-on-next-save semantics.
- **HIBP-on-login** pins `pendingResetReason = BreachForced` (D0.3 already shipped this; D1.3 confirms via tests).
- **First-login force** (in the central listener for new users with `forceChangeOnFirstLogin = true`) pins `pendingResetReason = FirstLoginForced`. The next save (the user actually setting their password on first login) consumes it.

`bf66716` is a follow-up: `UserQuery::beforePrepare()` doesn't addSelect `passwordResetRequired` (memory gap #9 — same gotcha as `lastPasswordChangeDate`). The bulk action's "skip already-flagged users" short-circuit was reading the in-memory `false` regardless of DB state. Fix: pre-load the persisted column for queried user IDs via `_loadPasswordResetFlags()`.

`1290468` (D1.4) — coverage for audit context propagation through every change site: self-service, CLI, force-reset, HIBP-on-login, expiry. 14 tests across `PasswordHistoryAuditContextTest`, `ForcePasswordResetActionTest`, `HibpOnLoginUserStateTest`, `RetentionServicePendingReasonTest`, `UserStateServiceTest`.

### D2 — User index columns (P2.1) (2026-05-03)

Four commits: `6f1574d` (UserIndexService + Lite-tier columns), `beaf5b8` (Pro-tier coverage), `aa48b93` (condition rules for D2 columns), `e5486e0` (refactor cleanup).

- **`UserIndexService`** (`src/services/UserIndexService.php` — 1119 lines) — single source of truth for user-index columns. Per-request preload via `preloadForUsers()` keeps cell rendering out of N+1 territory. Cache shape: `lastChange`, `passwordResetRequired`, `lastHistoryReason`, `lastHistoryPolicy`, `lastBreachAt`, `currentPolicyId`, `appliedPolicies`. Uses direct DB queries to bypass `UserQuery::beforePrepare()`'s missing-column gotchas.
- **Composite status** — seven priority-ordered states: `breached` (recent), `expired`, `reset-required`, `policy-drift` (Pro + Team+), `expiring-soon`, `never-changed`, `ok`. Constants `BREACHED_RECENT_DAYS = 90` and `EXPIRING_SOON_DAYS = 7` are hardcoded for now (codified in `ideas.md` as customer-driven config candidates).
- **Lite-tier columns** (every Craft edition): `lastPasswordChange`, `daysUntilExpiry`, `expired`, `resetRequired`, `status`, `lastChangeReason`. Six baseline columns.
- **Pro-tier columns** (require `getIsPro()`): `breachedRecently` on every Craft edition; `policyDrift` + `appliedPolicies` only when Craft is Team or higher (Solo can't model multi-policy users — only one user, no groups).
- **Sort options** — only on cheap-to-sort columns (those backed by direct user-table columns). `appliedPolicies` and `policyDrift` deliberately have no sort mapping; they're aggregate-derived.
- **Condition rules** for the new column axes: `BreachedRecentlyConditionRule`, `LastChangeReasonConditionRule`, `PasswordExpiringWithinConditionRule`, `PasswordStatusConditionRule`, `PolicyDriftConditionRule`. Each one's `EVENT_REGISTER_CONDITION_RULES` registration is gated identically to the column it maps to.
- **`e5486e0` cleanup** — centralised expiry-interval parsing in `_getExpiryInterval()` to remove a duplicated `match` across `_getExpiryThreshold()` + the days-until-expiry cell + the priority lookup.

Coverage (8 test files in `tests/Integration/UserIndex/`): registration matrix (all four plugin × Craft cells), Lite cell rendering, Pro cell rendering, edition gating, sort options, status priority, policy drift, preload batching. **`PreloadBatchingTest` is the load-bearing query-count test** — asserts the preload runs at most N+M queries regardless of how many cells render, where N = users in batch, M = number of preload methods (currently 4 per batch).

### D3 — Admin element actions (P2.2) (2026-05-03)

Four commits: `e12de46` (skeletons + permission), `be569de` (ChangeUserPassword end-to-end + audit propagation), `c0f70f7` (SendPasswordResetEmail bulk + pending-reason setter coverage), `ec3382b` (policy-validation gate + UserStateService explicit-context coverage). One docblock fix `76cd0e0`.

- **`pp:change-user-passwords` permission** — registered in `UserPermissions::EVENT_REGISTER_PERMISSIONS` alongside the existing `pp:force-reset-passwords`. One permission gates both new actions.
- **`ChangeUserPassword` action** — single-user (`bulk: false`, `validateSelection: count === 1`). Bulk-change-with-same-password is a security anti-pattern. Opens a JS modal with new + confirm fields; modal posts to `actions/password-policy/user-password/change`.
- **`SendPasswordResetEmail` action** — bulk-friendly confirm dialog. Pins `pendingResetReason = AdminForceReset` BEFORE sending the mailer call so even SMTP failures record operator intent. Per-user soft-fail; final message reports sent + failed counts.
- **`UserPasswordController`** — new CP POST controller with `actionChange()` + `actionSendResetEmail()`. `beforeAction()` enforces CP request, POST, `pp:change-user-passwords`, AND elevated session. `actionChange()` rejects bulk-shaped POSTs, self-targets, mismatched confirms, and policy-validation failures.
- **`UserStateService::setExplicitContext()`** — controller pins the slot before `saveElement()`; the central history-write listener consumes it before falling back to pending-reason resolution. Three-tier precedence formalised. The slot is single-use to prevent stale carry-over to a follow-up save in the same request.
- **Read-only mode** — both action classes' `getTriggerHtml()` returns null when `allowAdminChanges = false`, so the triggers don't register on the index. Defense-in-depth: `UserPasswordController::beforeAction()` also enforces it (returns 403 on bypass). P2.6 verification gate satisfied.

Coverage: `UserPasswordControllerTest` (16 tests), `ChangeUserPasswordActionTest` (4 tests), `SendPasswordResetEmailActionTest` (8 tests), `UserStateServiceTest` (12 tests). Trifecta from memory gap #20 applied — `UserStub.idParam`, `WebRequestStub.stubIsCpRequest`, `assetManager.basePath` from `_craft/config/app.php`. Also extended `UserStub::stubHasElevatedSession` for the elevated-session gate test.

### D4 — User-edit tab (2026-05-03)

One commit: `b15c460`.

- **No native tab event in Craft 5.** Verified by reading `craft\elements\User`, `craft\controllers\ElementsController::actionEdit` (tabs come from `$form?->getTabMenu()` — field-layout driven), `craft\helpers\Cp` (no tab event), `craft\web\View` (no tab event), and the Twig hook surface (`cp.users.edit.prefs` is the only user-edit hook, scoped to the preferences panel). The brief's speculative `Cp::EVENT_REGISTER_USER_EDIT_FORM_TABS` doesn't exist; the historical `users/_edit.twig` template doesn't exist in 5.x either.
- **Closest idiomatic surface: `Element::EVENT_DEFINE_SIDEBAR_HTML`** on the User class. Appends a "Password Security" link block to the right-side meta-fields column. The link points at the standalone CP page registered at `password-policy/users/<userId>/security`.
- **`UserSecurityController::actionIndex(int $userId)`** — loads the user, hydrates `lastPasswordChangeDate` directly from the users table (memory gap #9 again), resolves the effective policy via `PolicyResolverService::resolveForUser()`, derives `isExpired` / `neverChanged` / `policySource`, and renders `password-policy/_users/password-security`.
- **Permission predicate**: either-or (`pp:force-reset-passwords` OR `pp:change-user-passwords`). Both permissions concern the same admin-on-user surface; splitting at the page-visibility level would surface a useless "see the page but every action greyed out" state. Single source of truth: `UserSecurityController::callerHasViewPermission()` — registration listener and `beforeAction()` both consult it.
- **Read-only mode (P2.6 verification gate)**: link still appears (read-only data is fine to view). Page template renders `readOnlyNotice()` at the top of the content block + `disabled` on the force-reset `<button>`. Existing POST target (`password-policy/retention/force-reset`) unchanged — D4 doesn't redesign template content, only registers + gates it.

Coverage (12 tests in `tests/Integration/UserEditTab/PasswordSecurityTabTest.php`): registration predicate (admin path + no-identity path + non-admin path), read-only mode (link still appears + notice renders + button disabled), controller wiring (happy path + 404 + permission 403), POST target alignment (force-reset URL still in template).

**Two new `WebRequestStub` pins** for CP-template rendering tests: `getPathInfo()` (Craft `Request::$_path` is uninitialised by default; the global sidebar template reads it unconditionally) and `getUrl()` (Yii `Request::getUrl()` throws when `$_SERVER['REQUEST_URI']` is absent; CP templates use `craft.app.request.url` for `redirectInput`). Tests render only the inner `{% block content %}` rather than the full `_layouts/cp` chain — the layout chain pulls in global sidebar + notifications + sessions which aren't D4's surface and the console-bootstrapped test process doesn't have.

## Skill gaps captured (this phase)

One new entry added to `feedback_skill_gaps.md` (#20 — landed in D3 build):

20. **Console-bootstrap CP-test trifecta** — testing CP controllers from a console-bootstrap Pest setup needs three orthogonal pins: `UserStub.idParam`, `WebRequestStub.getIsCpRequest()` + host info, `assetManager.basePath`. Each pin is one line; the discovery cost is the chase. Test-infrastructure cost belongs in support files, not in test files.

D4 incidentally exercised the same trifecta plus added two more CP-render-specific pins (`getPathInfo()` + `getUrl()` on the request stub). Worth folding into a future skill expansion as "CP-template-render trifecta" — the pins for CP-controller tests are necessary but not sufficient when the test renders templates that walk the full CP layout chain.

## Architectural decisions (locked during the phase)

1. **Audit capture on every edition.** Lite + Pro + Enterprise installs all populate `changeReason`, `changedByUserId`, `changedFromIp`, `changedFromUserAgent` on every history row. Edition gates `audit-log VIEW` (Enterprise dashboard) but NOT capture. Future Enterprise installs that didn't have audit logging enabled at install time still get a populated history once they upgrade. Memory rule `project_audit_capture_principle.md`.
2. **Three-tier audit context resolution.** Explicit > pending-reason > default. The explicit-slot (`UserStateService::setExplicitContext`) is the seam for admin-direct intent overriding any prior pending state.
3. **`ChangeReason` is a single enum, not split per edition.** Even reasons that only make sense in Pro+ contexts (`BreachForced` requires HIBP-on-login) live in the same enum. Lite installs simply never write those values; the column accepts any of them. Keeps the schema stable across editions.
4. **User-edit "tab" is a sidebar link, not a top-level tab.** Craft 5 doesn't expose a tab-injection event for the User edit screen. Going via `EVENT_DEFINE_SIDEBAR_HTML` keeps the surface discoverable without trying to hijack the field-layout-owned tab strip. If a future Craft release adds a tab-injection event, swap the registration listener — the controller + URL rule + template stay unchanged.
5. **Either-or permission predicate for the user-edit page.** `pp:force-reset-passwords` OR `pp:change-user-passwords` — both gate the same surface. Operator personas typically hold both; splitting the visibility predicate would make the matrix harder without gain.
6. **`UserIndexService::preloadForUsers()` is the bounded-query contract.** N users + M preload methods = N×M queries max. Tests pin this contract via `PreloadBatchingTest` so a future "while we're here, also fetch X per user" refactor surfaces as a query-count regression in CI.

## Reusable artifacts for Phase F + G

- `src/enums/ChangeReason.php` — every change pathway has a stable string identifier. Phase G's audit-log row format uses these directly.
- `src/models/AuditContext.php` — IP/UA capture pattern. Phase G extends with hash-chain `previousHash` field per `compliance-grade enhancements` design.
- `src/services/UserStateService.php` — the explicit-context slot is the seam Phase G's webhook verifier and `AlertCooldownService` will hook into for "what triggered this row" attribution.
- `src/services/UserIndexService.php` — the preload pattern (`preloadForUsers` → cache → cell rendering) is the template for Phase G's compliance dashboard aggregations.
- `tests/Support/UserStub.php` — extended with `stubHasElevatedSession`. Phase G's audit-export controller tests will use it.
- `tests/Support/WebRequestStub.php` — `getPathInfo()` + `getUrl()` stubs make CP-template rendering tests possible. Phase G's compliance dashboard utility tests will use them.

## Files touched (full Phase D)

```
src/PasswordPolicy.php (D0–D4 — listener registration, audit context resolver, sidebar pointer)
src/controllers/UserPasswordController.php (D3, new)
src/controllers/UserSecurityController.php (D4, new)
src/elements/actions/ChangeUserPassword.php (D3, new)
src/elements/actions/ForcePasswordReset.php (D1 update — explicit pending-reason)
src/elements/actions/SendPasswordResetEmail.php (D3, new)
src/elements/conditions/BreachedRecentlyConditionRule.php (D2.3, new)
src/elements/conditions/LastChangeReasonConditionRule.php (D2.3, new)
src/elements/conditions/PasswordExpiringWithinConditionRule.php (D2.3, new)
src/elements/conditions/PasswordStatusConditionRule.php (D2.3, new)
src/elements/conditions/PolicyDriftConditionRule.php (D2.3, new)
src/enums/ChangeReason.php (D0.1, new)
src/migrations/Install.php (D0.2 — fresh-install schema includes audit columns + user_state)
src/migrations/m260502_214932_AddAuditShapeToPasswordHistory.php (D0.2, new)
src/models/AuditContext.php (D0.1, new)
src/records/PasswordHistoryRecord.php (D0.2 — adds the four audit columns)
src/records/UserStateRecord.php (D0.2, new)
src/services/PasswordHistoryService.php (D0.3 — savePasswordHash gains $context arg)
src/services/RetentionService.php (D1 — pins ExpiryForced pending reason)
src/services/ServicesTrait.php (D0.3 + D2 — userState + userIndex getters)
src/services/UserIndexService.php (D2.1, new)
src/services/UserStateService.php (D0.3, new; D3 — explicit-context slot)
src/templates/_users/password-security.twig (D4 — readOnly handling + disabled button)
tests/_craft/config/app.php (D3 — assetManager.basePath pin)
tests/Pest.php (D2 + D4 — new sub-dirs registered)
tests/Support/Factories/UserFactory.php (D3 — UserFactory::nonAdmin())
tests/Support/MigrationTestCase.php (D0.4 — minor)
tests/Support/UserStub.php (D3 — stubHasElevatedSession + idParam)
tests/Support/WebRequestStub.php (D3 + D4 — stubIsCpRequest + getPathInfo + getUrl)
tests/Integration/ConditionRules/BreachedRecentlyConditionRuleTest.php (D2.3)
tests/Integration/ConditionRules/LastChangeReasonConditionRuleTest.php (D2.3)
tests/Integration/ConditionRules/PasswordExpiringWithinConditionRuleTest.php (D2.3)
tests/Integration/ConditionRules/PasswordStatusConditionRuleTest.php (D2.3)
tests/Integration/ConditionRules/PolicyDriftConditionRuleTest.php (D2.3)
tests/Integration/Controllers/UserPasswordControllerTest.php (D3.4)
tests/Integration/Migrations/UpgradeTo520MigrationTest.php (D0.4 — extended)
tests/Integration/Records/UserStateRecordTest.php (D0.4)
tests/Integration/Services/ChangeUserPasswordActionTest.php (D3.4)
tests/Integration/Services/ForcePasswordResetActionTest.php (D1.4)
tests/Integration/Services/HibpOnLoginUserStateTest.php (D1.4)
tests/Integration/Services/PasswordHistoryAuditContextTest.php (D1.4)
tests/Integration/Services/RetentionServicePendingReasonTest.php (D1.4)
tests/Integration/Services/SendPasswordResetEmailActionTest.php (D3.4)
tests/Integration/Services/UserStateServiceTest.php (D3.4)
tests/Integration/UserEditTab/PasswordSecurityTabTest.php (D4)
tests/Integration/UserIndex/AttributeRegistrationTest.php (D2.2)
tests/Integration/UserIndex/CellRenderingTest.php (D2.2)
tests/Integration/UserIndex/EditionGatingTest.php (D2.2)
tests/Integration/UserIndex/PolicyDriftStatusTest.php (D2.2)
tests/Integration/UserIndex/PreloadBatchingTest.php (D2.2)
tests/Integration/UserIndex/ProCellRenderingTest.php (D2.2)
tests/Integration/UserIndex/SortOptionsTest.php (D2.2)
tests/Integration/UserIndex/StatusBadgePriorityTest.php (D2.2)
docs/internal/ideas.md (D4 close — three follow-ups captured)
```

## What didn't get touched

- `5.1.x` branch — still parked, three backport commits unpushed and untagged.
- Phase F (P2.8 — Phase G build plan draft).
- Enterprise (Phase G — Phase 10/11/12).
- Release prep (Phase H — tag, Plugin Store, marketing copy, deployment docs).
- The 5.2.x cleanup candidates from `ideas.md` (validator Unicode awareness, broader log-level audit).
- The three D-cycle follow-ups newly captured in `ideas.md`: `PasswordExpiredConditionRule::matchElement()` UserQuery gotcha, hardcoded `BREACHED_RECENT_DAYS` / `EXPIRING_SOON_DAYS` constants, per-user resolver iteration in the Pro+Team+ preload.
- Email notification surfaces — explicitly parked per the user's call. Future phase, possibly post-5.2.0.
- Notification email per-action-type (e.g. "your password was changed by an admin") — same parking.
