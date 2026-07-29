# Force Password Reset

The plugin surfaces three ways to force a password reset on existing users:

- **Single user**: `ChangeUserPassword` element action (Pro). Opens a modal in the control panel where an admin can set a new password for one user.
- **Bulk**: `SendPasswordResetEmail` element action (Pro). Sends Craft's standard "set your password" email to all selected non-admin users.
- **Force-on-next-login**: `ForcePasswordReset` element action (Pro). Sets `passwordResetRequired = true` on selected users; they must change their password the next time they sign in.

All three are bulk-friendly via the Users index. The single-user `ChangeUserPassword` action is also available from the per-user edit-screen action menu.

> 📷 *Screenshot: Users index with three users selected, the bulk actions menu open, and the three Password Policy actions highlighted (`Change password…`, `Send reset email`, `Force password reset on next sign-in`).*

This page covers the three actions, their permission requirements, the underlying service API for programmatic use, and the audit-context propagation that distinguishes admin-initiated resets from user-initiated ones in the audit log.

## When to use which

| Action | Affects | When the user notices | Audit reason |
|---|---|---|---|
| **Change password…** (`ChangeUserPassword`) | One user at a time | Immediately, admin sets the new password directly | `AdminChange` |
| **Send reset email** (`SendPasswordResetEmail`) | Bulk | User receives Craft's standard set-password email | `AdminForceReset` |
| **Force password reset on next sign-in** (`ForcePasswordReset`) | Bulk | Next time the user signs in, they're redirected to a change-password screen | `AdminForceReset` |

**Don't use bulk Change-Password.** The single-user `ChangeUserPassword` modal requires an elevated session and is intentionally not bulk-available. Setting the same password on N users is a security anti-pattern; the bulk path is `SendPasswordResetEmail` or `ForcePasswordReset`.

## Permissions

| Permission | What it grants |
|---|---|
| `pp:change-user-passwords` | Single-user `ChangeUserPassword` action + the `UserPasswordController` POST handler. |
| Craft's `editUsers` permission | `SendPasswordResetEmail` and `ForcePasswordReset` actions. |

`pp:change-user-passwords` is registered separately because setting another user's password directly is a higher-privilege operation than triggering a reset email: the latter requires the user to authenticate via email, the former bypasses that step.

## Audit trail

Every force-reset action writes a row to `passwordpolicy_user_state` with a `pendingReason` enum value. When the user next changes their password, the history listener picks up the pending reason and emits it as the `changeReason` on the `password_history` row. This is how the audit log distinguishes a self-initiated password change from one that the admin forced.

| Action | `pendingReason` set | `changeReason` after user changes |
|---|---|---|
| Change Password (admin modal) | n/a (immediate) | `AdminChange` |
| Send Reset Email | `AdminForceReset` | `AdminForceReset` |
| Force on Next Login | `AdminForceReset` | `AdminForceReset` |
| HIBP-on-login forced reset | `BreachDetectedForceReset` | `BreachDetectedForceReset` |
| Expiry forced reset | `ExpiryForceReset` | `ExpiryForceReset` |
| User-initiated change | - | `UserChange` |

On Enterprise installs, both the `password_changed` and `password_reset_forced` audit events carry this reason in their `details` JSON. Filtering the audit log by reason produces a clean view of admin actions vs user actions.

## Programmatic API

For automation, integrations, and custom controllers: every action above is backed by service-layer methods that work on every edition. The Pro gate is on the CP element-action surface, not the underlying capability.

### `UserPasswordController::actionSet()` (HTTP)

POST `password-policy/user-password/set` with `{userId, newPassword, confirmPassword}`. Requires an elevated session (`Craft.elevatedSessionManager.requireElevatedSession()` in JS, or `requireElevatedSession()` in PHP). Permission: `pp:change-user-passwords`.

Validates the new password against the user's resolved policy (Pro: per-group; Lite: global), rejects matches against the password history, captures `changeReason = AdminChange` in the audit context, then saves through `Craft::$app->elements->saveElement()`.

### `RetentionService::resetPasswordsByGroup(int $groupId): int`

Sets `passwordResetRequired = true` on all non-admin users in a group. Pins `pendingReason = AdminForceReset` on each user's `user_state` row. Returns the count of affected users.

Works on every edition. Requires Craft Team or higher (Solo Craft has no user groups).

### `UserStateService::setPendingReason(int $userId, PendingReason $reason): void`

The lower-level seam. Pins a `pendingReason` enum value on the user's `user_state` row. The history-write listener consumes this on the next password save and emits it as the `changeReason`. Use this for custom force-reset paths that need to record a non-standard reason in the audit trail.

### Session invalidation

`PasswordService::destroyOtherSessions(int $userId, ?string $excludeToken = null): int` removes auth tokens from `Table::SESSIONS` for a user. Returns the count of destroyed sessions.

When called from a web context with `$excludeToken = Craft::$app->getRequest()->getCsrfToken()`, the current admin's session is preserved: the admin stays logged in even if they invalidate themselves. CLI commands have no web session, so all target sessions are removed.

Craft's `User::afterSave` already calls this on every password change in 5.9.21+; the front-end `PasswordChangeController` calls it again explicitly as belt-and-braces against any future Craft refactor.

## Console commands

```bash
# Bulk force-reset all non-admin users in a group
./craft password-policy/retention/force-reset-passwords --group=editors
```

Default behaviour runs synchronously. Use `--queue` to push the work to a queue job for large user counts.

```bash
# Force-reset a single user by ID
./craft password-policy/retention/force-reset-passwords --user=42
```

## See also

- [User-index integration](./user-index.md): the status columns + condition rules that surface "force reset pending" + "password expired" on the Users index.
- [Audit logging](./audit-logging.md): how the audit trail records the reason for each reset.
- [Notifications](./notifications.md): the email-template surface for the breach-detected / new-device / admin-security alert flows.
- [Events](../reference/events.md): `PasswordChangedEvent` (every change), `BreachDetectedEvent` (HIBP-on-login matches).
