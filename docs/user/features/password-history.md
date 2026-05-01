# Phase 2 — Password History Service + Validator + Event Handlers

## Overview

Phase 2 implements password reuse prevention. When a user changes their password, the old hash is stored in history. Future password changes are checked against stored history using constant-time comparison.

## Password History Lifecycle

1. **EVENT_BEFORE_SAVE** — Plugin caches `$user->newPassword` in a process-private static property
2. **Craft saves the user** — Craft hashes with bcrypt and stores in `users.password`
3. **EVENT_AFTER_SAVE** — Plugin extracts-and-clears the cache, hashes the plaintext, stores in `passwordpolicy_password_history`
4. **APPLICATION::EVENT_AFTER_REQUEST** — Safety net: unconditionally clears all cached plaintexts

The plaintext never touches the database, logs, or external services.

## Security Measures

### Memory Protection

- **`#[SensitiveParameter]`** — All methods accepting plaintext use PHP 8.2's attribute to redact from stack traces
- **`__debugInfo()`** — Returns only `['_pendingCount' => N]`, hiding cached passwords from debug tools
- **Cache key** — `"{userId}:{spl_object_id}"` prevents cross-contamination between concurrent user saves

### Constant-Time Comparison

- No early exit — every historical hash is checked even after a match is found
- Padded iterations — if history has fewer entries than the configured limit, dummy `password_verify()` calls pad timing to consistent duration
- Prevents timing attacks from revealing which position in history matched

### Current Password Fallback

If the history table has fewer entries than the configured limit, the service also checks against the user's current password in `users.password`. This covers users created after migration who haven't changed their password yet.

## Force Change on First Login

When `forceChangeOnFirstLogin` is enabled, new users (`$event->isNew`) have `passwordResetRequired = true` set automatically in EVENT_AFTER_SAVE.

**Recursion guard:** Setting `passwordResetRequired` triggers another `saveElement()` call inside EVENT_AFTER_SAVE. A static `$_processing` guard prevents infinite recursion and double history entries.

## Edition Gating

- **History storage**: Pro+ only (`getIsPro() && passwordHistoryCount > 0`)
- **History validation**: Pro+ only (gated inside `PasswordHistoryValidator`)
- **Force change on first login**: All editions (Lite setting)
- **Request-end cleanup**: All editions (safety net always active)

## Files Added/Modified

- `src/services/PasswordHistoryService.php` — New service
- `src/validators/PasswordHistoryValidator.php` — New validator
- `src/services/ServicesTrait.php` — Register `passwordHistory` service
- `src/rules/UserRules.php` — Add `PasswordHistoryValidator` rule
- `src/PasswordPolicy.php` — Event listeners, recursion guard, request cleanup
