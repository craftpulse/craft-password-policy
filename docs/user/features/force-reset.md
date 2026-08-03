# Force Password Reset

Force reset comes in two shapes, and which edition you need depends on which shape you want.

**Mass reset, on every edition.** The **Password Retention** utility's "Force Reset Passwords" action, and the matching console command, flag every account already past your configured expiry window. You point them at nothing, they find the expired accounts themselves. Admin accounts are skipped.

**Per-user reset, on Pro and Enterprise.** Three control-panel surfaces flag one named account, whether or not its password has expired:

- **Bulk**: the `ForcePasswordReset` element action on the Users index. Sets `passwordResetRequired = true` on every selected user; they must change their password the next time they sign in.
- **From the user edit screen**: the "Force password reset" item in the "…" action menu next to Save.
- **From the Password Security screen**: the "Force Password Reset" button in that screen's Actions pane.

Two related actions round out the set, both available on every edition:

- **Change password…** (`ChangeUserPassword`). Opens a modal where an admin sets a new password for one user directly. Single-user only, and it requires an elevated session.
- **Send reset email** (`SendPasswordResetEmail`). Sends Craft's standard "set your password" email. Bulk-friendly from the Users index.

> 📷 *Screenshot: Users index with three users selected, the bulk actions menu open, and the Password Policy actions highlighted (`Send reset email`, `Force password reset on next sign-in`).*

This page covers each action, its permission requirements, the underlying service API for programmatic use, and the audit-context propagation that distinguishes admin-initiated resets from user-initiated ones in the audit log.

## When to use which

| Action | Affects | When the user notices | Audit reason |
|---|---|---|---|
| **Force Reset Passwords** (Password Retention utility) | Every already-expired non-admin account | Next sign-in, redirected to a change-password screen | `ExpiryForced` |
| **Change password…** (`ChangeUserPassword`) | One user at a time | Immediately, admin sets the new password directly | `AdminChange` |
| **Send reset email** (`SendPasswordResetEmail`) | Bulk | User receives Craft's standard set-password email | `AdminForceReset` |
| **Force password reset on next sign-in** (`ForcePasswordReset`) | Bulk, named accounts | Next sign-in, redirected to a change-password screen | `AdminForceReset` |

**Don't use bulk Change-Password.** The single-user `ChangeUserPassword` modal requires an elevated session and is intentionally not bulk-available. Setting the same password on N users is a security anti-pattern; the bulk path is `SendPasswordResetEmail` or `ForcePasswordReset`.

## Permissions

| Permission | What it grants |
|---|---|
| `pp:force-reset-passwords` | The mass path: the Password Retention utility's "Force Reset Passwords" action and the `password-policy/retention/force-reset-passwords` console command. Registered on **every edition**. |
| `pp:user-force-reset` | The per-user path: the `ForcePasswordReset` bulk action, the "Force password reset" user-edit action-menu item, the Actions pane on the Password Security screen, and the `UserSecurityController::actionForceReset()` POST handler. **Pro+ only**: the handle isn't registered on Lite, and the POST handler answers 404 there. |
| `pp:change-user-passwords` | Single-user `ChangeUserPassword` action + the `UserPasswordController` POST handler. Registered on every edition. |
| Craft's `editUsers` permission | Prerequisite for reaching the Users index and the user-edit screen these actions live on. |

The two force-reset handles are separate because they gate different capabilities. Holding the mass grant buys the expired-only sweep and nothing else; it doesn't open the per-user endpoint.

`pp:change-user-passwords` is registered separately again because setting another user's password directly is a higher-privilege operation than triggering a reset email: the latter requires the user to authenticate via email, the former bypasses that step.

### A non-admin can never force a reset on an admin

`pp:user-force-reset` is grantable to non-admins, so this guard sits below the permission rather than relying on it. If the acting user is not an admin and the target is:

- the Password Security screen renders no Force Password Reset button,
- the bulk element action refuses the whole run rather than partially applying it and silently skipping the admin,
- and the POST handler answers 403.

An admin forcing a reset on another admin is allowed. The mass path never touches admin accounts at all, on any edition.

## Audit trail

Every force-reset action writes a row to `passwordpolicy_user_state` with a `pendingReason` enum value. When the user next changes their password, the history listener picks up the pending reason and emits it as the `changeReason` on the `password_history` row. This is how the audit log distinguishes a self-initiated password change from one that the admin forced.

| Action | `pendingReason` set | `changeReason` after user changes |
|---|---|---|
| Change Password (admin modal) | n/a (immediate) | `AdminChange` |
| Send Reset Email | `AdminForceReset` | `AdminForceReset` |
| Force on Next Login (per-user) | `AdminForceReset` | `AdminForceReset` |
| Force Reset Passwords (mass, expired accounts) | `ExpiryForced` | `ExpiryForced` |
| HIBP-on-login forced reset | `BreachForced` | `BreachForced` |
| User-initiated change | - | `SelfService` |

The mass and per-user paths pin different reasons on purpose. `ExpiryForced` says a retention sweep reached the account; `AdminForceReset` says an operator pointed at it. Both write a `password_reset_forced` audit event.

On Enterprise installs, both the `password_changed` and `password_reset_forced` audit events carry this reason in their `details` JSON. Filtering the audit log by reason produces a clean view of admin actions vs user actions.

## Programmatic API

For automation, integrations, and custom controllers: every action above is backed by service-layer methods that work on every edition. The Pro gate is on the CP surfaces, not the underlying capability.

### `UserPasswordController::actionChange()` (HTTP)

POST `password-policy/user-password/change` with `{userId, newPassword, newPasswordConfirm}`. Requires an elevated session (`Craft.elevatedSessionManager.requireElevatedSession()` in JS, or `requireElevatedSession()` in PHP). Permission: `pp:change-user-passwords`.

Validates the new password against the user's resolved policy (Pro: per-group; Lite: global), rejects matches against the password history, captures `changeReason = AdminChange` in the audit context, then saves through `Craft::$app->elements->saveElement()`.

### `RetentionService::canForceResetUser(User $target, ?User $actor): bool`

The peer-admin guard, and the single gate every per-user force-reset surface consults. Returns `false` when there is no acting user, or when the target is an admin and the actor isn't. Call it before `forceResetForUser()` in any custom path, and reject on `false`.

### `RetentionService::forceResetForUser(User $target): bool`

The per-user write. Sets `passwordResetRequired = true`, pins `pendingReason = AdminForceReset`, and writes a `password_reset_forced` audit event. Returns `false` when the user was already flagged, which is a no-op rather than a failure: re-pinning would overwrite an in-flight reason such as `BreachForced`.

Performs no authorization of its own, so admin targets stay reachable to admin actors. Clear `canForceResetUser()` first.

### `RetentionService::requirePasswordReset(User $user): void`

The mass write, behind the retention utility and the console command. Skips admin accounts and pins `pendingReason = ExpiryForced`. Use `forceResetForUser()` instead when an operator named the account.

### `RetentionService::resetPasswordsByGroup(int $groupId): int`

Sets `passwordResetRequired = true` on all non-admin users in a group. Pins `pendingReason = AdminForceReset` on each user's `user_state` row. Returns the count of affected users.

Works on every edition. Requires Craft Team or higher (Solo Craft has no user groups).

### `UserStateService::setPendingReason(User $user, ChangeReason $reason): void`

The lower-level seam. Pins a `pendingReason` enum value on the user's `user_state` row. The history-write listener consumes this on the next password save and emits it as the `changeReason`. Use this for custom force-reset paths that need to record a non-standard reason in the audit trail.

### Session invalidation

`PasswordService::destroyOtherSessions(int $userId, ?string $excludeToken = null): int` removes auth tokens from `Table::SESSIONS` for a user. Returns the count of destroyed sessions.

When called from a web context with `$excludeToken = Craft::$app->getRequest()->getCsrfToken()`, the current admin's session is preserved: the admin stays logged in even if they invalidate themselves. CLI commands have no web session, so all target sessions are removed.

Craft's `User::afterSave` already calls this on every password change in 5.9.21+; the front-end `PasswordChangeController` calls it again explicitly as belt-and-braces against any future Craft refactor.

## Console commands

```bash
# Force-reset every account already past the expiry window
./craft password-policy/retention/force-reset-passwords
```

Available on every edition. The command takes no target: it resolves the expired accounts itself and skips admins. It requires `retentionUtilities` to be enabled in settings, and it exits non-zero with a message if it isn't.

Default behaviour runs synchronously and reports each account with `--verbose`. Use `--queue` to push the work to a queue job instead, which is the better choice on a large user table.

There is no per-user console flag. Per-user force reset is a control-panel capability; for scripted per-user work, call `RetentionService::forceResetForUser()` directly.

## See also

- [User-index integration](./user-index.md): the status columns + condition rules that surface "force reset pending" + "password expired" on the Users index.
- [Audit logging](./audit-logging.md): how the audit trail records the reason for each reset.
- [Notifications](./notifications.md): the email-template surface for the breach-detected / new-device / admin-security alert flows.
- [Events](../reference/events.md): `PasswordChangedEvent` (every change), `BreachDetectedEvent` (HIBP-on-login matches).
