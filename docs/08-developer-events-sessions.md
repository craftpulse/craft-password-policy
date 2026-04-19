# Phase 8 — Developer Events, Session Invalidation, Enhanced Force Reset

## Overview

Phase 8 adds the developer event system (Lite — free for ecosystem), session invalidation on force reset (Pro), and group-based force reset (Pro).

## Developer Events

### PasswordChangedEvent (`EVENT_PASSWORD_CHANGED`)

Fired after a password has been successfully changed and history stored. By the time this event fires, `newPassword` is already null — the plaintext is gone.

**Properties:**
- `User $user` — The user whose password was changed
- `bool $isNew` — Whether this is a newly created user

**Available in:** All editions (Lite)

**Example — Slack notification on admin password change:**
```php
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\events\PasswordChangedEvent;

Event::on(
    PasswordPolicy::class,
    PasswordPolicy::EVENT_PASSWORD_CHANGED,
    function(PasswordChangedEvent $event) {
        if ($event->user->admin) {
            // Send webhook to Slack
        }
    }
);
```

### PasswordValidationEvent

Event class for future use in validation pipeline. Properties:
- `User $user` — The user being validated
- `array $errors` — Validation errors from built-in rules
- `bool $isValid` — Whether built-in validation passed

## Session Invalidation

### `RetentionService::invalidateUserSessions(int $userId, ?string $excludeToken = null): int`

Deletes auth tokens from `Table::SESSIONS` for a user. Works with all PHP session backends (Redis, files, etc.) because Craft stores auth tokens in the DB regardless.

**Admin exclusion:** When called from a web context, the current admin's session token is preserved — the admin stays logged in. CLI commands have no web session, so all target sessions are deleted.

## Group-Based Force Reset

### `RetentionService::resetPasswordsByGroup(int $groupId): int`

Sets `passwordResetRequired = true` for all non-admin users in a group. Returns the count of affected users. Audit logged per user.
