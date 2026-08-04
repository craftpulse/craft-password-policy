# Database Schema

Every table the plugin creates, with columns, indexes, foreign keys, and the Craft 5 element-table relationships. Useful for direct SQL access, custom integrations, debugging, and DB-administrator handoff.

The schema is created by `Install.php` on fresh install and by dated migrations on upgrade. Both paths produce the same schema and are idempotent, re-running them on an existing schema is a no-op.

Current schema version: `2.19.0`. Fourteen tables.

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
| `changeReason` | enum, nullable | `SelfService`, `AdminChange`, `AdminForceReset`, `FirstLoginForced`, `ExpiryForced`, `BreachForced`, `Cli`, `MigrationSeed` |
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
| `cooldownKey` | varchar(191), NOT NULL | Scope discriminator (e.g. `user:42`, `event:breach_detected`, `group:3:hibp_breach_detected`) |
| `firedAt` | datetime, NOT NULL | When the cooldown was recorded |
| `dateCreated`, `dateUpdated`, `uid` | Craft standard | |

**Indexes:**

- `(eventClass)`, `(cooldownKey)`, `(firedAt)`, individual indexes for ad-hoc queries.
- `(eventClass, cooldownKey, firedAt)`: composite covering the dedup hot path.

See [Alert cooldowns](../features/alert-cooldowns.md).

### `passwordpolicy_siem_forwarders` (Enterprise)

Configured SIEM destinations. `protocol` decides which half of the row is in use, which is why the three address columns are all nullable.

| Column | Type | Notes |
|---|---|---|
| `id` | int PK | |
| `name` | varchar(255), nullable | Display name. The index falls back to the destination (`host:port` or the URL) when it's null |
| `enabled` | tinyint(1), NOT NULL DEFAULT 1 | Soft toggle |
| `protocol` | varchar(32), NOT NULL DEFAULT `'syslog-tls'` | `syslog-tls` or `http` |
| `host` | varchar(255), nullable | Receiver hostname or IP. Required on `syslog-tls`, null on `http` |
| `port` | int, nullable | Receiver port. Required on `syslog-tls`, null on `http`. The new-forwarder form prefills 6514 |
| `framing` | varchar(32), NOT NULL DEFAULT `'octet-counted'` | Syslog message delimiting: `octet-counted` (RFC 5425) or `newline`. Ignored on `http` |
| `url` | varchar(2048), nullable | HTTPS collector URL. Required on `http`, null on `syslog-tls`. Accepts an env var reference, resolved at forward time |
| `authType` | varchar(32), NOT NULL DEFAULT `'none'` | `none`, `bearer`, or `basic`. Ignored on `syslog-tls` |
| `authToken` | text, nullable | HTTP credential, encrypted at rest via Craft's `Security::encryptByKey()`. Null when `authType` is `none` |
| `headers` | JSON, nullable | Extra request headers as a name to value map, for example `{"DD-API-KEY": "$PP_DATADOG_KEY"}`. Values accept env var references. Null on `syslog-tls` |
| `tlsCertVerify` | tinyint(1), NOT NULL DEFAULT 1 | Verify the receiver's certificate chain and hostname. Applies to `syslog-tls` only: an `http` forwarder always verifies |
| `tlsCaBundlePath` | varchar(255), nullable | PEM CA bundle path. Accepts an env var reference, resolved at use. Honoured by both transports |
| `eventClasses` | JSON, nullable | Per-forwarder event-class allowlist override. Null or empty falls back to `siemForwardEventClasses` |
| `consecutiveFailures` | int, NOT NULL DEFAULT 0 | Circuit-breaker state |
| `circuitOpenAt` | datetime, nullable | When the breaker opened |
| `dateCreated`, `dateUpdated`, `uid` | Craft standard | |

**Indexes:**

- `(enabled)`, `(circuitOpenAt)`: the `getActiveForwarders()` predicate.

See [SIEM forwarders](../features/siem-forwarders.md).

### `passwordpolicy_webhook_endpoints` (Enterprise)

Configured webhook delivery endpoints.

| Column | Type | Notes |
|---|---|---|
| `id` | int PK | |
| `name` | varchar(255), nullable | Display name. The index falls back to the URL when it's null |
| `enabled` | tinyint(1), NOT NULL DEFAULT 1 | Soft toggle |
| `url` | varchar(2048), NOT NULL | HTTPS destination. Accepts an env var reference, resolved at dispatch |
| `secretCurrent` | text, NOT NULL | Active HMAC key, encrypted at rest via Craft's `Security::encryptByKey()` |
| `secretPrevious` | text, nullable | Previous key, retained through the rotation grace window |
| `secretRotatedAt` | datetime, nullable | When the rotation happened |
| `eventClasses` | JSON, nullable | Per-endpoint event-class allowlist override. Null or empty falls back to `webhookForwardEventClasses` |
| `lastDeliveredRowId` | bigint, nullable | Per-endpoint audit-row watermark. Set to the newest audit row id when the endpoint is created, so a new endpoint never replays history |
| `consecutiveFailures` | int, NOT NULL DEFAULT 0 | Circuit-breaker state |
| `circuitOpenAt` | datetime, nullable | When the breaker opened |
| `dateCreated`, `dateUpdated`, `uid` | Craft standard | |

**Indexes:**

- `(enabled)`, `(circuitOpenAt)`: the `getActiveEndpoints()` predicate.
- `(lastDeliveredRowId)`: the per-endpoint watermark scan.

See [Webhooks](../features/webhooks.md).

### `passwordpolicy_known_devices`

One row per (user, device) pair. Capture is universal across editions; the new-device alert email that reads it is Enterprise.

| Column | Type | Notes |
|---|---|---|
| `id` | int PK | |
| `userId` | int, NOT NULL | FK to `craft_users.id`, CASCADE on user delete |
| `fingerprint` | char(64), NOT NULL | SHA-256 of `"{userAgent}|{maskedIp}"`. The raw user agent and raw IP are never stored |
| `deviceLabel` | varchar(255), nullable | Coarse label, e.g. `Chrome on macOS`, or `Unknown device` |
| `maskedIp` | varchar(45), nullable | IPv4 masked to a `/24`, IPv6 to a `/64` |
| `siteId` | int, nullable | FK to `craft_sites.id`, `SET NULL` on site delete. Null for a control panel sign-in |
| `firstSeenAt` | datetime, NOT NULL | First sign-in from this device |
| `lastSeenAt` | datetime, NOT NULL | Most recent sign-in from this device |
| `dateCreated`, `dateUpdated`, `uid` | Craft standard | |

**Indexes:**

- `(userId, fingerprint)` **unique**: the upsert key. A device is new exactly when no row matches this pair.
- `(fingerprint)`: lookup by fingerprint.
- `(lastSeenAt)`: the retention purge's scan.

Retention-managed against `deviceRetentionDays` (default 180) by `gc/run`.

See [Device tracking](../features/device-tracking.md).

### `passwordpolicy_group_alert_subscriptions`

One row per (group, event, recipient) alert-routing rule. Storage is edition-independent; the dispatch that reads these rows is Pro.

| Column | Type | Notes |
|---|---|---|
| `id` | int PK | |
| `groupId` | int, NOT NULL | FK to `craft_usergroups.id`, CASCADE on group delete |
| `eventType` | varchar(255), NOT NULL | `breach_detected` or `new_device` |
| `recipientEmail` | varchar(255), NOT NULL | The address that receives the routed copy |
| `enabled` | tinyint(1), NOT NULL DEFAULT 1 | Off keeps the row without routing |
| `dateCreated`, `dateUpdated`, `uid` | Craft standard | |

**Indexes:**

- `(groupId, eventType)`: the resolution path, matching the affected user's groups against subscribed events.

The group-delete cascade is intentional: deleting a Craft user group drops its routing rules rather than leaving alerts addressed on behalf of a group that no longer exists.

See [Group alerts](../features/group-alerts.md).

### `passwordpolicy_api_tokens` (Enterprise)

Registry of hashed Bearer tokens for the read-only REST API.

| Column | Type | Notes |
|---|---|---|
| `id` | int PK | |
| `name` | varchar(255), NOT NULL | Operator-supplied display name |
| `tokenHash` | char(64), NOT NULL UNIQUE | SHA-256 of the token. The plaintext is never persisted and is not recoverable |
| `tokenPrefix` | varchar(16), NOT NULL | First 8 characters, for identifying the row in the control panel |
| `scopes` | JSON, nullable | Reserved for future per-token scoping; not consumed in 5.2.0 |
| `lastUsedAt` | datetime, nullable | Most recent authenticated request |
| `expiresAt` | datetime, nullable | Null means no expiry. `findByToken()` rejects rows whose value is in the past |
| `createdByUserId` | int, nullable | FK to `craft_users.id`, `SET NULL`. A token outlives the admin who issued it |
| `dateCreated`, `dateUpdated`, `uid` | Craft standard | |

**Indexes:**

- `(tokenHash)` **unique**: the lookup key, and the guarantee that two tokens cannot share a digest.
- `(expiresAt)`: the expired-token purge's scan.

Unlike the audit tables, nothing writes here below Enterprise: the only writer is the Enterprise-gated token manager, so the table sits empty on Lite and Pro. Expired rows are purged by `gc/run`.

See [REST API](./rest-api.md).

## Tables read by the plugin (not modified)

The plugin reads from Craft core tables without adding columns:

- `craft_users`: `lastPasswordChangeDate`, `passwordResetRequired`, `lastLoginAttemptIp`, `invalidLoginCount`, `lockoutDate`, `admin`, and standard element columns.
- `craft_sessions`: auth tokens for the `destroyOtherSessions` path.
- `craft_usergroups`: referenced by `passwordpolicy_policy_groups`, `passwordpolicy_group_alert_subscriptions`, and the user-index condition rules.
- `craft_sites`: referenced by `passwordpolicy_notification_templates`, `passwordpolicy_known_devices`, and the per-site template propagation.

## Foreign-key drop order

When uninstalling the plugin or dropping tables manually, drop in reverse FK-dependency order. This is the order `Install.php`'s own teardown uses:

1. `passwordpolicy_api_tokens` (FK to `craft_users`)
2. `passwordpolicy_group_alert_subscriptions` (FK to `craft_usergroups`)
3. `passwordpolicy_known_devices` (FK to `craft_users`, `craft_sites`)
4. `passwordpolicy_webhook_endpoints` (no FKs)
5. `passwordpolicy_siem_forwarders` (no FKs)
6. `passwordpolicy_alert_cooldowns` (no FKs)
7. `passwordpolicy_user_state` (FK to `craft_users`)
8. `passwordpolicy_notification_templates` (FK to `craft_sites`)
9. `passwordpolicy_blocklist` (FK to `passwordpolicy_policies`)
10. `passwordpolicy_policy_groups` (FK to `passwordpolicy_policies` and `craft_usergroups`)
11. `passwordpolicy_policies` (FK to `craft_elements`)
12. `passwordpolicy_notification_log` (FK to `craft_elements`, `craft_users`, `craft_sites`)
13. `passwordpolicy_audit_log` (FK to `craft_elements`, `craft_users`)
14. `passwordpolicy_password_history` (FK to `craft_users`)

`./craft plugin/uninstall password-policy` handles the order automatically.

## Schema-version tracking

`PasswordPolicy::$schemaVersion` is the source of truth, `2.19.0` as of release. Increment on every structural change (column add, table add, index change). Used by Craft to determine "needs craft up" state.

## Migration filenames

Fresh installs run `Install.php` directly and don't apply the dated migrations. Upgraders apply the dated migrations in timestamp order. There are 24 of them:

- `m260429_224908_UpgradeTo520Schema` establishes the 5.1.x to 5.2.0 baseline: it renames the legacy `pwned` settings key to `hibp` and seeds the tables that 5.1.x did not have.
- The remainder land the individual 5.2.0 features on top: hash-chain columns and the chain recompute, element conversions for the audit log, notification log and policies, a foreign-key deduplication pass, the alert-cooldown, SIEM, webhook, known-device, group-alert-subscription and API-token tables, the geo columns, the notification-default seeds, the kebab-case permission rename, and the audit-kit module adoption.

Every migration is idempotent, so re-running one against a schema that already has its changes is a no-op.

## See also

- [Audit logging](../features/audit-logging.md): semantic detail on `passwordpolicy_audit_log`.
- [Notifications](../features/notifications.md): semantic detail on the notification tables.
- [Per-Group Policies](../features/per-group-policies.md): semantic detail on the policies tables.
- [Blocklist](../features/blocklist.md): semantic detail on the blocklist table.
- [Device tracking](../features/device-tracking.md): semantic detail on the known-devices table.
- [Group alerts](../features/group-alerts.md): semantic detail on the subscriptions table.
- [REST API](./rest-api.md): semantic detail on the API tokens table.
- [Events](./events.md): events that fire on writes to these tables.
- [GC and retention](../operations/gc-and-retention.md): which of these tables are retention-managed.
- [Upgrade Guide](../operations/upgrade-from-5.1.md): what changes in the schema on 5.1.x → 5.2.0.
