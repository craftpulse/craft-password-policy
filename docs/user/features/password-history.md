# Password History

Block reuse of the last N passwords. Every edition stores a hashed copy of every password change in `passwordpolicy_password_history`; when a user tries to change to a password they've used recently, the change is rejected with a clear error message.

Per-group history overrides (different `passwordHistoryCount` per user group via named policies) require the **Pro** edition. The global setting applies to every edition.

> 📷 *Screenshot: Front-end password change form showing the validation error "This password matches one you have used recently. Please choose a different password" rendered next to the new-password input, with the requirements list still highlighting the other rules in green.*

## Configuration

Open **Settings → Password Policy → History** in the control panel.

- **Password history count** — How many previous passwords to remember (default `0` = feature disabled, max `24`). Setting this to a positive value enables the validator.
- **Password history expiry days** — How many days to retain history rows before the GC prunes them (default `365`). The latest N rows are always retained regardless of age; this setting controls the cleanup of older rows that exceed the count.

> ::: tip Per-group history overrides (Pro)
> The global setting applies on every edition. On Pro, each named policy can set its own `passwordHistoryCount` for per-group enforcement — the resolver picks the highest value across the user's groups so a user in a Customers group (history=4) and an Admins group (history=12) is checked against the last 12. See [Per-Group Policies](./per-group-policies.md).
> :::

## How it works

When `passwordHistoryCount > 0`, every successful password save:

1. Hashes the new plaintext with bcrypt (the same algorithm Craft uses for the active password).
2. Inserts a row into `passwordpolicy_password_history` with the user ID, hash, timestamp, and audit-context fields.
3. Prunes older history rows beyond the configured count (the latest N are retained; the rest are deleted).

On subsequent password changes, the `PasswordHistoryValidator` compares the proposed new password against each stored history hash using **constant-time** comparison:

- No early break — every historical hash is checked, even after a match is found.
- The comparison loop is padded to the configured count via dummy `Craft::$app->getSecurity()->validatePassword()` calls when the user has fewer history rows than the count.

This prevents timing attacks from revealing which position in history matched (or that any position did).

The validator runs **after** content rules (length, complexity, blocklist) and before HIBP — content-failing passwords are rejected before the relatively expensive bcrypt-verify chain runs.

## Force change on first login

Independent of password history, the `forceChangeOnFirstLogin` setting (every edition) sets `passwordResetRequired = true` on every newly-created user. Next time they sign in, they're prompted to change their password.

The recursion guard in `PasswordPolicy::EVENT_AFTER_SAVE` prevents an infinite loop: setting `passwordResetRequired` triggers another `saveElement()` call, which fires `EVENT_AFTER_SAVE` again, which would re-enter the history-write path. A static `$_processing` flag short-circuits the recursive entry.

## Audit context propagation

Every history row carries the `changeReason` enum value that tells the audit log why the password was changed:

| `changeReason` | When |
|---|---|
| `UserChange` | The user changed their own password. |
| `AdminChange` | An admin used the **Change password…** action to set the user's password directly. |
| `AdminForceReset` | The user changed their password after an admin forced a reset (`SendPasswordResetEmail`, `ForcePasswordReset`, bulk `force-reset-passwords` command). |
| `BreachDetectedForceReset` | The user changed their password after HIBP-on-login detected a breach. |
| `ExpiryForceReset` | The user changed their password after the password expired. |

The reason is determined by the **pending reason** on `passwordpolicy_user_state` — when an admin or automation forces a reset, the pending reason is pinned in advance; when the user actually changes their password, the history listener picks up the pending reason and stamps it on the new history row.

On Enterprise installs, the audit log's `password_changed` event carries the same reason in its `details` JSON. Filtering the audit log by reason produces a clean "admin actions vs user actions" view.

## Privacy + security guarantees

### Plaintext never persists

The validator works against the bcrypt hashes only. The plaintext is captured briefly in a process-private static property between `EVENT_BEFORE_SAVE` (the only event that sees the plaintext) and `EVENT_AFTER_SAVE` (where the hash is written), then cleared. A request-end safety net (`Application::EVENT_AFTER_REQUEST`) unconditionally clears any cached plaintexts on every request — including those that bailed early via exception.

The cache key is `"{userId}:{spl_object_id}"`, which prevents cross-contamination between concurrent user saves in a single request (e.g. a controller saving two users back-to-back).

### `#[\SensitiveParameter]` on every plaintext argument

Every service method that accepts a plaintext password uses PHP 8.2's `#[\SensitiveParameter]` attribute. PHP omits the value from stack traces and `serialize()` output — useful for any unhandled exception that bubbles past the plugin code.

### `__debugInfo()` doesn't leak the cache

The `PasswordHistoryService::__debugInfo()` override returns only `['_pendingCount' => N]`, hiding the cached plaintexts from `var_dump`, Xdebug inspection, and any other debug-tool that uses PHP's standard introspection path.

### Routed through Craft's Security service

The plugin calls `Craft::$app->getSecurity()->validatePassword($plaintext, $hash)` for every comparison — not `password_verify()` directly. This keeps the history-check path consistent with Craft's active-password-check path: if you configure site-level peppered hashing, both paths apply the pepper uniformly.

## Current-password fallback

If a user's history table has fewer entries than the configured count, the service also checks the proposed new password against the user's currently-active password in `users.password`. This covers two cases:

- Users created after the plugin was installed who haven't changed their password yet.
- Users migrated from a pre-5.2.0 install where history wasn't enabled.

For both cases, the result is the same: the user can't reuse their current password as a "new" one.

## Retention

History rows are managed by the GC pruner. `password-policy/gc/run` deletes rows that:

- Exceed the configured count per user (oldest first), AND
- Are older than `passwordHistoryExpiryDays`.

The count is a floor — even if the user's oldest history rows are decades old, the latest N are retained. This prevents the edge case where TTL wipes a user's only history row and the validator silently re-allows password reuse.

```cron
# Run retention nightly at 02:00
0 2 * * * cd /path/to/project && ./craft password-policy/gc/run
```

See [GC and retention](../operations/gc-and-retention.md) for the production cron recipe.

## See also

- [Per-Group Policies](./per-group-policies.md) — set a different history count for different user groups.
- [Force reset](./force-reset.md) — the three admin actions that drive an `AdminForceReset` audit reason.
- [Audit logging](./audit-logging.md) — `password_changed` events with full `changeReason` propagation (Enterprise).
- [GC and retention](../operations/gc-and-retention.md) — retention configuration + cron recipe.
