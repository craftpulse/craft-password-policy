# Force Password Reset

Pro and Enterprise editions ship two ways to require users to set a new password on next login: invalidating their existing sessions, and bulk-resetting every member of a user group.

For the developer event catalog (`PasswordChangedEvent`, `PasswordValidationEvent`, `UserRegisteredEvent`, `BreachDetectedEvent`), see [events reference](../reference/events.md).

## Session Invalidation

### `RetentionService::invalidateUserSessions(int $userId, ?string $excludeToken = null): int`

Deletes auth tokens from `Table::SESSIONS` for a user. Works with all PHP session backends (Redis, files, etc.) because Craft stores auth tokens in the DB regardless.

**Admin exclusion:** When called from a web context, the current admin's session token is preserved — the admin stays logged in. CLI commands have no web session, so all target sessions are deleted.

## Group-Based Force Reset

### `RetentionService::resetPasswordsByGroup(int $groupId): int`

Sets `passwordResetRequired = true` for all non-admin users in a group. Returns the count of affected users. Audit logged per user.
