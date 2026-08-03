# Database Schema

Every table the plugin creates, with columns, indexes, foreign keys, and the Craft 5 element-table relationships. Useful for direct SQL access, custom integrations, debugging, and DB-administrator handoff.

The schema is created by `Install.php` on fresh install and by dated migrations on upgrade. Both paths produce the same schema and are idempotent, re-running them on an existing schema is a no-op.

Current schema version: `2.18.0`.

## Element-backed tables

Three tables back Craft 5 element types. Their `id` columns are foreign keys to `craft_elements.id` with FK CASCADE on element delete, Craft's element delete handles the row removal.

### `passwordpolicy_audit_log` (Enterprise: capture is universal, index is gated)

Hash-chained audit rows.

| Column | Type | Notes |
|---|---|---|
| `id` | int PK | FK to `craft_elements.id`, CASCADE on element delete |
| `event` | varchar(64), NOT NULL | One of the captured event types (e.g. `password_changed`) |
| `userIdentifier` | varchar(64), NOT NULL | HMAC-SHA-256 hex of the subject's email, keyed by `CRAFT_AUDIT_PII_KEY`. Hashed into the chain (the FK `userId` is not) |
| `changedByIdentifier` | varchar(64), nullable | HMAC-SHA-256 hex of the acting admin's email, same keying. Hashed into the chain (the FK `changedByUserId` is not) |
| `userId` | int, nullable | FK to `craft_users.id`, `SET NULL` on user hard-delete. Excluded from the hash payload (mutable on delete) |
| `changedByUserId` | int, nullable | FK to the acting admin's `craft_users.id`, `SET NULL` on user hard-delete. Excluded from the hash payload |
| `ipHash` | varchar(64), nullable | SHA-256 hex of the request IP |
| `outcome` | enum, NOT NULL | `success`, `failure`, `denied`, `pending` |
| `details` | JSON, nullable | Per-event payload filtered against the PII allowlist |
| `previousHash` | char(64), NOT NULL | `rowHash` of the preceding row (genesis = `'0' × 64`) |
| `rowHash` | char(64), NOT NULL | SHA-256 of canonical JSON + previousHash |
| `forwardedAt` | datetime, nullable | SIEM forwarder watermark; NULL = unforwarded |
| `forwardAttempts` | int, default 0 | Retry counter for the SIEM forwarder |
| `dateCreated`, `dateUpdated`, `uid` | Craft standard | |

**Indexes:**

- `(userId, dateCreated)`: per-user timeline queries.
- `(event, dateCreated)`: per-event-type filters.
- `(forwardedAt)`: SIEM forwarder's unforwarded-rows scan.

**Element type:** `craftpulse\passwordpolicy\elements\AuditLogElement`. `canSave()` returns `false` after the initial insert: rows are append-only. Element delete is allowed (used by retention purge).

See [Audit logging](../features/audit-logging.md).

### `passwordpolicy_notification_log` (Pro+; capture is universal)

Activity log of every notification dispatch, success and failure.

| Column | Type | Notes |
|---|---|---|
| `id` | int PK | FK to `craft_elements.id`, CASCADE on element delete |
| `userId` | int, nullable | FK to `craft_users.id`, `SET NULL` on user hard-delete |
| `notificationType` | varchar(64), NOT NULL | `expiry_reminder`, `breach_detected`, `new_device`, `admin_alert_<event>` |
| `status` | enum, NOT NULL | `sent` or `failed` |
| `recipientEmail` | varchar(255), nullable | The address the notification was sent to |
| `siteId` | int, nullable | FK to `craft_sites.id` (which site's template was used) |
| `subject` | text, nullable | Rendered subject (captured for editable-template sends) |
| `body` | text, nullable | Rendered body (same caveat as subject) |
| `errorMessage` | text, nullable | Captured on `status = failed`; null on success |
| `resentFromId` | int, nullable | FK to a sibling row when this dispatch is a resend |
| `sentAt` | datetime, NOT NULL | When the dispatch attempt was made |
| `dateCreated`, `dateUpdated`, `uid` | Craft standard | |

**Indexes:**

- `(userId, sentAt)`: per-user timeline.
- `(notificationType, sentAt)`: per-type metrics.
- `(status, sentAt)`: failure investigations.

**Element type:** `craftpulse\passwordpolicy\elements\NotificationLogElement`.

See [Notifications](../features/notifications.md).

### `passwordpolicy_policies` (Pro)

Named per-group policies.

| Column | Type | Notes |
|---|---|---|
| `id` | int PK | FK to `craft_elements.id`, CASCADE on element delete |
| `name` | varchar(255), NOT NULL | Display name |
| `handle` | varchar(64), NOT NULL UNIQUE | Slug for programmatic access |
| `preset` | varchar(64), nullable | `nist_800_63b`, `owasp_asvs`, `pci_dss_v4`, `strict_enterprise`, or null for custom |
| `settings` | JSON, NOT NULL | The policy's effective values (tri-state booleans, integer overrides, expiry settings) |
| `sortOrder` | smallint | Display order in the policies index |
| `dateCreated`, `dateUpdated`, `uid` | Craft standard | |

**Element type:** `craftpulse\passwordpolicy\elements\PolicyElement`.

See [Per-Group Policies](../features/per-group-policies.md).

## Pure-record tables (no element backing)

### `passwordpolicy_policy_groups` (Pro)

Junction table linking named policies to Craft user groups.

| Column | Type | Notes |
|---|---|---|
| `id` | int PK | |
| `policyId` | int, NOT NULL | FK to `passwordpolicy_policies.id`, CASCADE on policy delete |
| `groupId` | int, NOT NULL | FK to `craft_usergroups.id`, CASCADE on group delete |
| `dateCreated`, `dateUpdated`, `uid` | Craft standard | |

**Unique index:** `(policyId, groupId)`.

The group-delete cascade is intentional, when a Craft user group is deleted, its policy assignments are automatically dropped. A pre-delete observability listener captures which policies lost an assignment for audit purposes.

### `passwordpolicy_password_history`

Stores bcrypt hashes of previous passwords for reuse prevention. Capture is universal across editions since 5.2.0; per-group `passwordHistoryCount` overrides remain Pro.

| Column | Type | Notes |
|---|---|---|
| `id` | int PK | |
| `userId` | int, NOT NULL | FK to `craft_users.id`, CASCADE on user delete |
| `passwordHash` | varchar(255), NOT NULL | bcrypt (same format as Craft's `users.password`) |
| `changeReason` | enum, nullable | `UserChange`, `AdminChange`, `AdminForceReset`, `BreachDetectedForceReset`, `ExpiryForceReset` |
| `changedByUserId` | int, nullable | FK to `craft_users.id`, `SET NULL`, who initiated the change |
| `changedFromIp` | varchar(45), nullable | The IP the change came from (full address, see privacy note below) |
| `changedFromUserAgent` | text, nullable | UA string at change time |
| `dateCreated`, `dateUpdated`, `uid` | Craft standard | |

**Indexes:**

- `(userId, dateCreated)`: per-user lookup with the latest-N retention contract.

**Privacy note:** `changedFromIp` stores the full IP because incident-response timelines need it. This is distinct from `passwordpolicy_audit_log.ipHash` which hashes the same value because the audit log is exported to SIEMs and shared with auditors. The password-history table is internal-only.

See [Password history](../features/password-history.md).

### `passwordpolicy_blocklist`

Common-password blocklist + custom dictionary.

| Column | Type | Notes |
|---|---|---|
| `id` | int PK | |
| `word` | varchar(191), NOT NULL | Lowercased + trimmed at insert time |
| `source` | enum, NOT NULL | `common` (bundled) or `custom` (admin-managed) |
| `policyId` | int, nullable | FK to `passwordpolicy_policies.id`, CASCADE on policy delete; NULL = global custom dictionary |
| `dateCreated`, `dateUpdated`, `uid` | Craft standard | |

**Indexes:**

- `(word, source)`: primary lookup path for validator queries.
- `(source)`: bulk operations grouped by source.
- `(policyId)`: per-policy scoping (Enterprise).

The 191-character `word` column matches MySQL's `utf8mb4` index limit. The bundled list contains ~10,000 entries from SecLists.

See [Blocklist](../features/blocklist.md).

### `passwordpolicy_notification_templates` (Pro+)

Per-(notification key, site) editable email templates.

| Column | Type | Notes |
|---|---|---|
| `id` | int PK | |
| `notificationKey` | varchar(64), NOT NULL | `expiry-reminder`, `breach-detected`, `new-device-alert`, `admin-security-alert` |
| `siteId` | int, NOT NULL | FK to `craft_sites.id`, CASCADE on site delete |
| `content` | JSON, NOT NULL | `{ subject, body, senderName, senderEmail, replyTo, templatePath }` |
| `dateCreated`, `dateUpdated`, `uid` | Craft standard | |

**Unique index:** `(notificationKey, siteId)`: one row per key per site.

The `content` column uses the Craft 5 elements-sites JSON-content idiom, race-free per-site editing without separate columns per field. `templatePath` is the G11 Enterprise custom-Twig-template-path key; it's nullable and ignored on non-Enterprise installs.

See [Notifications](../features/notifications.md).

### `passwordpolicy_user_state`

Per-user state: last breach check, breached-recently flag, pending change reason.

| Column | Type | Notes |
|---|---|---|
| `id` | int PK | |
| `userId` | int, NOT NULL UNIQUE | FK to `craft_users.id`, CASCADE on user delete |
| `lastBreachDetectedAt` | datetime, nullable | Last HIBP-on-login match timestamp (Pro+) |
| `lastBreachCheckAt` | datetime, nullable | Last successful HIBP-on-login query (Pro+, regardless of outcome) |
| `pendingChangeReason` | enum, nullable | Pinned by force-reset actions; consumed by the next history-write |
| `dateCreated`, `dateUpdated`, `uid` | Craft standard | |

Captured on every edition (per the audit-capture principle). Pro/Enterprise expose more of it through the user-index columns; Lite writes the same rows but doesn't surface them in the CP.

### `passwordpolicy_alert_cooldowns`

Per-(eventClass, cooldownKey) dedup substrate for the AlertCooldownService.

| Column | Type | Notes |
|---|---|---|
| `id` | int PK | |
| `eventClass` | varchar(128), NOT NULL | Alert key (e.g. `admin_security_alert:breach_detected`) |
| `cooldownKey` | varchar(191), NOT NULL | Scope discriminator (e.g. `user:42`, `event:breach_detected`, `forwarder:3:password_changed`) |
| `firedAt` | datetime, NOT NULL | When the cooldown was recorded |
| `dateCreated`, `dateUpdated`, `uid` | Craft standard | |

**Indexes:**

- `(eventClass)`, `(cooldownKey)`, `(firedAt)`, individual indexes for ad-hoc queries.
- `(eventClass, cooldownKey, firedAt)`: composite covering the dedup hot path.

See [Alert cooldowns](../features/alert-cooldowns.md).

### `passwordpolicy_siem_forwarders` (Enterprise)

Configured SIEM endpoints.

| Column | Type | Notes |
|---|---|---|
| `id` | int PK | |
| `name` | varchar(255), NOT NULL | Display name |
| `enabled` | tinyint(1), NOT NULL DEFAULT 1 | Soft toggle |
| `protocol` | enum, NOT NULL | `syslog-tls` or `http` |
| `host` | varchar(255), nullable | For syslog-tls |
| `port` | smallint, nullable | For syslog-tls |
| `url` | varchar(2048), nullable | For http |
| `headers` | JSON, nullable | Custom headers for http (e.g. `{"Authorization": "Splunk <token>"}`) |
| `tlsCaBundlePath` | varchar(1024), nullable | Override path for syslog-tls CA bundle |
| `consecutiveFailures` | int, NOT NULL DEFAULT 0 | Circuit-breaker state |
| `circuitOpenAt` | datetime, nullable | When the breaker opened |
| `lastDeliveryAt` | datetime, nullable | Most recent delivery attempt |
| `dateCreated`, `dateUpdated`, `uid` | Craft standard | |

See [SIEM forwarders](../features/siem-forwarders.md).

### `passwordpolicy_webhook_endpoints` (Enterprise)

Configured webhook delivery endpoints.

| Column | Type | Notes |
|---|---|---|
| `id` | int PK | |
| `name` | varchar(255), NOT NULL | Display name |
| `enabled` | tinyint(1), NOT NULL DEFAULT 1 | Soft toggle |
| `url` | varchar(2048), NOT NULL | HTTPS destination |
| `signingSecret` | varchar(255), NOT NULL | HMAC key (encrypted at rest via Craft's `Security::encryptByKey()`) |
| `previousSigningSecret` | varchar(255), nullable | Old key during the rotation grace window |
| `secretRotatedAt` | datetime, nullable | When the rotation happened |
| `eventFilter` | JSON, nullable | Optional list of event names to scope deliveries |
| `lastDeliveredRowId` | int, NOT NULL DEFAULT 0 | Per-endpoint audit-row watermark |
| `consecutiveFailures` | int, NOT NULL DEFAULT 0 | Circuit-breaker state |
| `circuitOpenAt` | datetime, nullable | When the breaker opened |
| `dateCreated`, `dateUpdated`, `uid` | Craft standard | |

See [Webhooks](../features/webhooks.md).

## Tables read by the plugin (not modified)

The plugin reads from Craft core tables without adding columns:

- `craft_users`: `lastPasswordChangeDate`, `passwordResetRequired`, `lastLoginAttemptIp`, `invalidLoginCount`, `lockoutDate`, `admin`, and standard element columns.
- `craft_sessions`: auth tokens for the `destroyOtherSessions` path.
- `craft_usergroups`: referenced by `passwordpolicy_policy_groups` and the user-index condition rules.
- `craft_sites`: referenced by `passwordpolicy_notification_templates` and the per-site template propagation.

## Foreign-key drop order

When uninstalling the plugin or dropping tables manually, drop in reverse FK-dependency order:

1. `passwordpolicy_policy_groups` (FK to `passwordpolicy_policies` and `craft_usergroups`)
2. `passwordpolicy_blocklist` (FK to `passwordpolicy_policies`)
3. `passwordpolicy_password_history` (FK to `craft_users`)
4. `passwordpolicy_user_state` (FK to `craft_users`)
5. `passwordpolicy_notification_log` (FK to `craft_elements`, `craft_users`, `craft_sites`)
6. `passwordpolicy_notification_templates` (FK to `craft_sites`)
7. `passwordpolicy_audit_log` (FK to `craft_elements`, `craft_users`)
8. `passwordpolicy_alert_cooldowns` (no FKs)
9. `passwordpolicy_siem_forwarders` (no FKs)
10. `passwordpolicy_webhook_endpoints` (no FKs)
11. `passwordpolicy_policies` (FK to `craft_elements`)

`./craft plugin/uninstall password-policy` handles the order automatically.

## Schema-version tracking

`PasswordPolicy::$schemaVersion` is the source of truth, `2.18.0` as of release. Increment on every structural change (column add, table add, index change). Used by Craft to determine "needs craft up" state.

## Migration filenames

Fresh installs run `Install.php` directly and don't apply the dated migrations. Upgraders apply the dated migrations in timestamp order:

- `m260429_224908_UpgradeTo520Schema`: single consolidated migration for the 5.1.x → 5.2.0 baseline.
- `m26050*` and `m26051*`, Phase G dated migrations (hash chain recompute, element conversions, FK dedup, G12 notification seeds, etc.).

## See also

- [Audit logging](../features/audit-logging.md): semantic detail on `passwordpolicy_audit_log`.
- [Notifications](../features/notifications.md): semantic detail on the notification tables.
- [Per-Group Policies](../features/per-group-policies.md): semantic detail on the policies tables.
- [Blocklist](../features/blocklist.md): semantic detail on the blocklist table.
- [Events](./events.md): events that fire on writes to these tables.
- [Upgrade Guide](../operations/upgrade-from-5.1.md): what changes in the schema on 5.1.x → 5.2.0.
