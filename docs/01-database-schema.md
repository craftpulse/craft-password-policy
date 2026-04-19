# Phase 1 — Database Schema + Migrations + Records

## Overview

Phase 1 creates the database tables that power password history, audit logging, and the common password blocklist. Tables are created regardless of edition — data structures exist even if the features are gated.

## Tables

### `passwordpolicy_password_history`

Stores bcrypt hashes of previous passwords for reuse prevention.

| Column | Type | Notes |
|--------|------|-------|
| `id` | PK | |
| `userId` | int, NOT NULL | FK to `users.id`, CASCADE on delete |
| `passwordHash` | string, NOT NULL | bcrypt hash (same format as Craft) |
| `dateCreated` | datetime, NOT NULL | |
| `uid` | string | |

**Indexes:** `(userId, dateCreated)` for efficient history lookup.

**GDPR:** CASCADE delete ensures password history is automatically removed when a user is deleted. No manual cleanup required.

### `passwordpolicy_audit_log`

Records security-relevant events without storing password data.

| Column | Type | Notes |
|--------|------|-------|
| `id` | PK | |
| `userId` | int, nullable | FK to `users.id`, SET NULL on delete |
| `changedByUserId` | int, nullable | FK to `users.id`, SET NULL on delete |
| `event` | string, NOT NULL | Event type (e.g., `password_changed`) |
| `outcome` | string, NOT NULL | `success`, `failure`, or `warning` |
| `source` | string, nullable | `self-service`, `admin`, `cli`, `queue` |
| `details` | JSON, nullable | Runtime-filtered via allowlist |
| `ipHash` | string, nullable | SHA-256 of IP (never raw) |
| `userIdentifier` | string, nullable | HMAC-SHA-256 of email |
| `dateCreated` | datetime, NOT NULL | |
| `uid` | string | |

**Indexes:** `(userId)`, `(event, dateCreated)`.

**GDPR:** SET NULL on user deletion preserves audit records anonymously. The `userIdentifier` uses HMAC-SHA-256 with a server key for post-deletion correlation (key can be destroyed).

### `passwordpolicy_blocklist`

Common and custom password blocklist for dictionary-based validation.

| Column | Type | Notes |
|--------|------|-------|
| `id` | PK | |
| `word` | string, NOT NULL | Stored lowercase, unique |
| `source` | string, NOT NULL | `common` or `custom` |
| `dateCreated` | datetime, NOT NULL | |

**Indexes:** `(word)` unique.

## Migrations

### Fresh Install (`Install.php`)

Creates all three tables. Guards each with `tableExists()` check for idempotency.

`safeDown()` drops all tables in reverse dependency order.

### Upgrade from 5.1.x (`m250419_000000_AddPasswordPolicyTables`)

1. Delegates table creation to `Install.php`
2. Seeds password history from existing user password hashes:
   - Copies current bcrypt hash from `users.password`
   - Includes all users with a non-null password
   - Temporarily disables Yii query logging to prevent hash exposure in debug mode
   - Uses batch insert for performance

## Records

- `PasswordHistoryRecord` — ActiveRecord for `passwordpolicy_password_history`
- `AuditLogRecord` — ActiveRecord for `passwordpolicy_audit_log`
- `BlocklistWordRecord` — ActiveRecord for `passwordpolicy_blocklist`

## Migration Notes

- Schema version `2.0.0` triggers this migration on upgrade from 5.1.x
- All tables are created regardless of edition
- Password history seeding runs once during upgrade
- Query logging is disabled during seed to prevent bcrypt hashes in log files
