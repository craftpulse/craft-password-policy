# Force Password Reset

The plugin ships three programmatic seams for forcing password resets and invalidating sessions. All three are available on every edition (Lite, Pro, Enterprise) — no service-layer Pro gate. The Pro upsell is in the CP element-action UX (`ForcePasswordReset`) and the audit context that propagates with it (`AdminForceReset` pending reason on `user_state`), not in the underlying service methods.

For the developer event catalog (`PasswordChangedEvent`, `PasswordValidationEvent`, `UserRegisteredEvent`, `BreachDetectedEvent`), see [events reference](../reference/events.md).

## Session Invalidation

### `RetentionService::invalidateUserSessions(int $userId, ?string $excludeToken = null): int`

**Edition:** All editions.

Deletes auth tokens from `Table::SESSIONS` for a user. Works with all PHP session backends (Redis, files, etc.) because Craft stores auth tokens in the database regardless of where session payloads live.

**Admin exclusion.** When called from a web context, the current admin's session token is preserved — the admin stays logged in even if they invalidate themselves. CLI commands have no web session, so all target sessions are deleted.

## Group-Based Force Reset

### `RetentionService::resetPasswordsByGroup(int $groupId): int`

**Edition:** All editions. Requires Craft Team or higher (Solo Craft has no user groups).

Sets `passwordResetRequired = true` for all non-admin users in a group. Returns the count of affected users. Pins an `AdminForceReset` pending reason on each user's `user_state` row so the next history-write picks up the right `changeReason`.

## Element Action: `ForcePasswordReset`

**Edition:** Pro.

The bulk-friendly `ForcePasswordReset` element action on the Users index. Selecting users + triggering the action calls `RetentionService::resetPasswordsByGroup()`-equivalent logic per selected user. The Pro gate registers the action; Lite installs see no trigger on the index. Custom code running on Lite can still call the service methods directly — the gate is on the index UX, not the underlying capability.
