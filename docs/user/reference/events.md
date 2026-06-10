# Events

The Password Policy plugin fires a small set of events for consumers building integrations — analytics dashboards, audit-trail mirroring, SIEM forwarding, custom notifications. Subscribe to whichever events match your use case; the plugin's own behavior never depends on a listener being attached, so a missing handler is never a fatal error.

This page documents every event the plugin fires today. New events are added in the same commit as the feature that fires them — events drift from documentation otherwise.

> **Privacy note.** Events that fire near password handling never include the plaintext, full SHA-1 hash, or full prefix-and-suffix bucket in their payload. The framework is designed so consumer listeners cannot accidentally leak secrets. Where relevant, each event documents what is and isn't included.

---

## `PasswordChangedEvent`

**FQ class:** `craftpulse\passwordpolicy\events\PasswordChangedEvent`
**Edition:** Lite (free for the ecosystem)
**Triggered by:** `PasswordPolicy::EVENT_PASSWORD_CHANGED`
**When:** After a password has been successfully changed and the new bcrypt hash has been recorded in the password history table. Fires inside the User element's `EVENT_AFTER_SAVE` listener once history persistence completes.

### Payload

| Property | Type | Description |
|----------|------|-------------|
| `$user` | `craft\elements\User` | The user whose password changed. By the time this event fires, `$user->newPassword` is already null. |
| `$isNew` | `bool` | Whether this is a newly created user (first password) vs an existing user changing their password. |

### Example listener

```php
use yii\base\Event;
use craftpulse\passwordpolicy\events\PasswordChangedEvent;
use craftpulse\passwordpolicy\PasswordPolicy;

Event::on(
    PasswordPolicy::class,
    PasswordPolicy::EVENT_PASSWORD_CHANGED,
    function(PasswordChangedEvent $event) {
        if ($event->isNew) {
            // First-time setup hook — welcome flow, etc.
            return;
        }

        // Mirror to your analytics / audit system here.
        Craft::info(
            "User {$event->user->id} changed their password.",
            'my-module',
        );
    },
);
```

---

## `UserRegisteredEvent`

**FQ class:** `craftpulse\passwordpolicy\events\UserRegisteredEvent`
**Edition:** Lite
**Triggered by:** `RegistrationService::EVENT_USER_REGISTERED`
**When:** After `RegistrationService::register()` successfully creates a user, assigns groups, and (optionally) sends Craft's activation email. Distinguished from a direct `Craft::$app->elements->saveElement($user)` call so listeners can choose to act only on registrations that flowed through the plugin's service entry point.

### Payload

| Property | Type | Description |
|----------|------|-------------|
| `$user` | `craft\elements\User` | The persisted user element |
| `$groups` | `string[]` | The group handles assigned at registration time |
| `$viaService` | `bool` | Always `true` when fired by the service. Reserved for future use. |

### Example listener

```php
use yii\base\Event;
use craftpulse\passwordpolicy\events\UserRegisteredEvent;
use craftpulse\passwordpolicy\services\RegistrationService;

Event::on(
    RegistrationService::class,
    RegistrationService::EVENT_USER_REGISTERED,
    function(UserRegisteredEvent $event) {
        // Welcome email, CRM sync, analytics ping, etc.
        $primaryGroup = $event->groups[0] ?? 'no-group';
        Craft::info(
            "User {$event->user->email} registered as {$primaryGroup}.",
            'my-module',
        );
    },
);
```

---

## `BreachDetectedEvent`

**FQ class:** `craftpulse\passwordpolicy\events\BreachDetectedEvent`
**Edition:** Pro
**Triggered by:** `PasswordPolicy::EVENT_BREACH_DETECTED`
**When:** During a successful HIBP-on-login k-anonymity check, when the user's plaintext password matches an entry in the Pwned Passwords database. Fires after the plugin sets `$user->passwordResetRequired = true`, sends the `breach-detected` notification email, and (on Enterprise) writes an audit-log entry — so listeners can rely on those side effects having already run.

### Payload

| Property | Type | Description |
|----------|------|-------------|
| `$user` | `craft\elements\User` | The user whose password was found in the breach database |
| `$sha1Prefix` | `string` | The 5-character SHA-1 prefix submitted to HIBP (uppercase). K-anonymity safe — an attacker cannot reverse the prefix to a unique password. |
| `$detectedAt` | `\DateTime` | Server time when the match was detected |

> The plaintext, full SHA-1 hash, and bucket suffix are intentionally NOT in the payload. Listeners that need to forward this event to a SIEM or external audit log can do so with confidence that no password material leaks.

### Example listener

```php
use yii\base\Event;
use craftpulse\passwordpolicy\events\BreachDetectedEvent;
use craftpulse\passwordpolicy\PasswordPolicy;

Event::on(
    PasswordPolicy::class,
    PasswordPolicy::EVENT_BREACH_DETECTED,
    function(BreachDetectedEvent $event) {
        // Forward to your SIEM. Only the prefix is exposed; safe to log.
        Craft::warning(
            sprintf(
                'Breach detected for user %d at %s (prefix %s)',
                $event->user->id,
                $event->detectedAt->format(DATE_ATOM),
                $event->sha1Prefix,
            ),
            'my-siem',
        );
    },
);
```

---

## `NewDeviceDetectedEvent`

**FQ class:** `craftpulse\passwordpolicy\events\NewDeviceDetectedEvent`
**Edition:** all (free ecosystem hook — device capture is universal)
**Triggered by:** `PasswordPolicy::EVENT_NEW_DEVICE_DETECTED`
**When:** After a successful login (`yii\web\User::EVENT_AFTER_LOGIN`, which also covers passkey + remember-me) from a device fingerprint that has no prior row for the user. Fires after the `passwordpolicy_known_devices` row is written, on every edition — independent of whether the Enterprise-gated new-device alert email is sent. On Enterprise the audit row (if `enableAuditLog`) and the cooldown-throttled alert email (if `enableNewDeviceAlerts`) have already run when the event fires.

### Payload

| Property | Type | Description |
|----------|------|-------------|
| `$user` | `craft\elements\User` | The user who logged in from the new device |
| `$deviceLabel` | `string` | Human-readable label (e.g. "Chrome on macOS"). Never the raw user-agent. |
| `$maskedIp` | `string` | Source IP with the last IPv4 octet zeroed / IPv6 truncated to /64. Never the raw IP. |
| `$siteId` | `int\|null` | The site the login happened on, or null |

> The raw user-agent, raw IP, and the SHA-256 device fingerprint are intentionally NOT in the payload. Persisting the fingerprint alongside the user recreates a linkable device ledger; the masked label is the safe display surface.

### Example listener

```php
use yii\base\Event;
use craftpulse\passwordpolicy\events\NewDeviceDetectedEvent;
use craftpulse\passwordpolicy\PasswordPolicy;

Event::on(
    PasswordPolicy::class,
    PasswordPolicy::EVENT_NEW_DEVICE_DETECTED,
    function(NewDeviceDetectedEvent $event) {
        // E.g. trigger an MFA step-up, or forward to your SIEM.
        Craft::info(
            sprintf(
                'New device for user %d: %s (%s)',
                $event->user->id,
                $event->deviceLabel,
                $event->maskedIp,
            ),
            'my-integration',
        );
    },
);
```

---

## `GroupAlertDispatchedEvent`

**FQ class:** `craftpulse\passwordpolicy\events\GroupAlertDispatchedEvent`
**Edition:** Pro (per-group alerts are a Pro surface)
**Triggered by:** `PasswordPolicy::EVENT_GROUP_ALERT_DISPATCHED`
**When:** After a COPY of a `breach_detected` / `new_device` alert is routed to a group-designated security contact — once per recipient that cleared the per-group cooldown (`group:{groupId}:{eventType}`). Recipients are resolved from the affected user's RESOLVED group membership (`User::getGroups()`), never a global setting. Does NOT fire for the end-user's own alert, nor for recipients suppressed by the cooldown.

### Payload

| Property | Type | Description |
|----------|------|-------------|
| `$user` | `craft\elements\User` | The user who triggered the originating alert |
| `$groupId` | `int` | The user group whose subscription resolved this recipient |
| `$eventType` | `string` | `breach_detected` or `new_device` |
| `$recipientEmail` | `string` | The security-contact email the copy was routed to |

> The payload carries no password material. The contact's email itself carries only the event type and a minimal user identifier (username or email) — the same convention the admin-security-alert surface uses.

### Example listener

```php
use yii\base\Event;
use craftpulse\passwordpolicy\events\GroupAlertDispatchedEvent;
use craftpulse\passwordpolicy\PasswordPolicy;

Event::on(
    PasswordPolicy::class,
    PasswordPolicy::EVENT_GROUP_ALERT_DISPATCHED,
    function(GroupAlertDispatchedEvent $event) {
        // E.g. mirror the routed alert into an incident-queue integration.
        Craft::info(
            sprintf(
                'Group %d security contact %s notified of %s for user %d',
                $event->groupId,
                $event->recipientEmail,
                $event->eventType,
                $event->user->id,
            ),
            'my-integration',
        );
    },
);
```

---

## `AccountInactiveEvent`

**FQ class:** `craftpulse\passwordpolicy\events\AccountInactiveEvent`
**Edition:** Pro (the inactive-account scan is a Pro surface)
**Triggered by:** `PasswordPolicy::EVENT_ACCOUNT_INACTIVE`
**When:** After the Feature 5 inactive-account scan actions a dormant account — once per actioned user, regardless of action mode. Fires AFTER the action takes effect (the `inactive-account` email was dispatched, or the user was suspended), so listeners observe a settled state. "Inactive" is measured against `users.lastLoginDate`, falling back to `users.dateCreated` for never-logged-in accounts.

### Payload

| Property | Type | Description |
|----------|------|-------------|
| `$user` | `craft\elements\User` | The dormant user the scan actioned |
| `$action` | `string` | The action taken: `report`, `notify`, or `suspend` |

> The payload carries no password material. On Enterprise installs, the scan additionally writes an `account_inactive` audit row carrying only the action + a constant source string (`inactive_scan`) — never PII.

### Example listener

```php
use yii\base\Event;
use craftpulse\passwordpolicy\events\AccountInactiveEvent;
use craftpulse\passwordpolicy\PasswordPolicy;

Event::on(
    PasswordPolicy::class,
    PasswordPolicy::EVENT_ACCOUNT_INACTIVE,
    function(AccountInactiveEvent $event) {
        // E.g. open a deprovisioning ticket when an account is suspended.
        if ($event->action === 'suspend') {
            Craft::info(
                sprintf('Inactive account suspended: user %d', $event->user->id),
                'my-integration',
            );
        }
    },
);
```

---

## `PasswordValidationEvent`

**FQ class:** `craftpulse\passwordpolicy\events\PasswordValidationEvent`
**Edition:** Lite (free for the ecosystem)
**Triggered by:** `PasswordPolicy::EVENT_PASSWORD_VALIDATION`
**When:** After Yii's `Model::validate()` finishes running every rule (including the plugin's password rules) on a User element. Fires from the plugin's own `User::EVENT_AFTER_VALIDATE` listener, which packages the password-attribute errors into the event payload before triggering. The plaintext password and any derived hash material are intentionally NOT in the payload.

### Payload

| Property | Type | Description |
|----------|------|-------------|
| `$user` | `craft\elements\User` | The user whose password is being validated. Listeners can call `$event->user->addError('newPassword', '…')` to push their own error onto the user-facing form response. |
| `$errors` | `string[]` | Validation error messages collected from `password` + `newPassword` attribute errors. Snapshot of the plugin's rule outcome at firing time. |
| `$isValid` | `bool` | `true` when no password-attribute errors were collected, otherwise `false`. |

> The event does NOT fire when neither `password` nor `newPassword` is in scope on the User — that filters out validate() calls triggered by unrelated edits (a name-only update, etc.).

### Example listener

```php
use yii\base\Event;
use craftpulse\passwordpolicy\events\PasswordValidationEvent;
use craftpulse\passwordpolicy\PasswordPolicy;

Event::on(
    PasswordPolicy::class,
    PasswordPolicy::EVENT_PASSWORD_VALIDATION,
    function(PasswordValidationEvent $event) {
        // Custom rule: forbid passwords that contain the user's last name.
        $lastName = $event->user->getFieldValue('lastName');
        $newPassword = $event->user->newPassword ?? '';

        if ($lastName && $newPassword !== '' && stripos($newPassword, $lastName) !== false) {
            $message = 'Password must not contain your last name.';
            $event->errors[] = $message;
            $event->isValid = false;

            // Surface the error in the form response too — `$event->errors`
            // alone is observability-only; addError() pushes the error to
            // the user-facing validation output.
            $event->user->addError('newPassword', $message);
        }
    },
);
```

---

## `AuditChainRotatedEvent`

**FQ class:** `craftpulse\passwordpolicy\events\AuditChainRotatedEvent`
**Edition:** Enterprise
**Triggered by:** `AuditLogService::EVENT_AUDIT_CHAIN_ROTATED`
**When:** After `AuditLogService::purgeOldEntries()` deletes one or more audit-log rows AND at least one row remains. The plugin's hash-chained audit log walks SHA-256 forward — when the retention prune drops rows from the head, the new first surviving row's `previousHash` legitimately references a now-deleted row, and consumers (verifier, SIEM forwarder, off-site archive) need a hook to record the rotation boundary. Skipped entirely when the prune deleted zero rows OR emptied the table.

### Payload

| Property | Type | Description |
|----------|------|-------------|
| `$startId` | `int` | The `id` of the new first surviving row. Verifiers walking the chain after this rotation must begin at this id. |
| `$startRowHash` | `string` | The `rowHash` (hex SHA-256) of the new first surviving row. Pair with `$startId` for the verifier-facing anchor. |
| `$endId` | `int` | The highest `id` deleted in this prune. Pair with `$endRowHash` to anchor an off-site archive of the rows that just left the database. |
| `$endRowHash` | `string` | The `rowHash` of the LAST surviving row at prune time — the chain head that the new first row's `previousHash` references when both still exist. When the prune left exactly one row, `$endRowHash === $startRowHash`. |
| `$rotatedAt` | `\DateTime` | Server-UTC timestamp of the rotation. |

### Example listener

```php
use yii\base\Event;
use craftpulse\passwordpolicy\events\AuditChainRotatedEvent;
use craftpulse\passwordpolicy\services\AuditLogService;

Event::on(
    AuditLogService::class,
    AuditLogService::EVENT_AUDIT_CHAIN_ROTATED,
    function(AuditChainRotatedEvent $event) {
        // Pin the rotation in your compliance dashboard. Auditors
        // walking the chain after this point start at $event->startId
        // with $event->startRowHash as the verified anchor.
        Craft::info(
            "Audit chain rotated: deleted up to id {$event->endId}, "
            . "new head id {$event->startId} (rowHash {$event->startRowHash}).",
            'compliance-mirror',
        );
    },
);
```

---

## `AlertCooldownEvent`

**FQ class:** `craftpulse\passwordpolicy\events\AlertCooldownEvent`
**Edition:** every (capture surface)
**Triggered by:** `AlertCooldownService::EVENT_ALERT_COOLDOWN_FIRED`
**When:** After `AlertCooldownService::recordFire()` writes a row to `passwordpolicy_alert_cooldowns`. The fire decision has already been made by the time this event triggers — listeners observe the fact, they don't gate it. Capture is universal across editions because cooldowns themselves capture on every edition; the event fires on Lite, Pro, and Enterprise alike. Edition gates apply to read surfaces (the SIEM forwarder, compliance dashboard) — they don't gate the event.

### Payload

| Property | Type | Description |
|----------|------|-------------|
| `$eventClass` | `string` | The logical alert type the cooldown was recorded against — e.g. `expiry_reminder`, `admin_security_alert:hibp_breach_detected`, `hibp_login_burst`. Stable identifier consumers can match on. |
| `$cooldownKey` | `string` | The cooldown's dedup key. Shape varies by event class: `user:<id>` for per-user windows, `event:<event>` for per-event-name windows, `prefix:<5char-sha1>` for HIBP bucket-level windows. |
| `$firedAt` | `\DateTime` | UTC timestamp recorded on the `passwordpolicy_alert_cooldowns.firedAt` column. Authoritative for "when the alert fired" — listeners that need to correlate against external systems should use this rather than the listener's own clock read. |

### Example listener — mirror suppression record to a SIEM

```php
use yii\base\Event;
use craftpulse\passwordpolicy\events\AlertCooldownEvent;
use craftpulse\passwordpolicy\services\AlertCooldownService;

Event::on(
    AlertCooldownService::class,
    AlertCooldownService::EVENT_ALERT_COOLDOWN_FIRED,
    function(AlertCooldownEvent $event) {
        // Off-site evidence: an auditor walking the cooldowns history
        // wants the same row visible in both places. Forwarding here
        // means the suppression record outlives a local DB rotation.
        Craft::info(
            sprintf(
                'Alert cooldown fired: %s/%s at %s',
                $event->eventClass,
                $event->cooldownKey,
                $event->firedAt->format(DATE_ATOM),
            ),
            'compliance-mirror',
        );
    },
);
```

---

## `PolicySaveEvent`

**FQ class:** `craftpulse\passwordpolicy\events\PolicySaveEvent`
**Edition:** Lite (free for the ecosystem)
**Triggered by:** `PolicyService::EVENT_BEFORE_SAVE_POLICY` and `PolicyService::EVENT_AFTER_SAVE_POLICY`
**When:** Around the policy-save lifecycle in `PolicyService::savePolicy()`. The same event class is shared between the two phases — listeners distinguish by which constant they subscribed to and (where it matters) by `$isNew`.

- **`EVENT_BEFORE_SAVE_POLICY`** fires after the policy validates but BEFORE the element pipeline runs. Listeners may amend `$event->policy` (the amended model is what gets persisted) or flip `$event->isValid = false` to abort the save. When a listener vetoes, `savePolicy()` returns `false` and no row is written.
- **`EVENT_AFTER_SAVE_POLICY`** fires after `Craft::$app->getElements()->saveElement()` returns successfully. By this point: the `craft_elements` row is on disk, the paired `PolicyRecord` is upserted, the junction-table sync is done, and (on UPDATEs) the `policy_changed` audit row has been written by `PolicyElement::afterSave()`. The save is final at this point — listeners cannot abort, the `$isValid` flag is inherited from `\yii\base\ModelEvent` but meaningless after-the-fact. Does NOT fire on validation failure, on a BEFORE-veto, or when `saveElement()` returned `false`.

### Payload

| Property | Type | Description |
|----------|------|-------------|
| `$policy` | `craftpulse\passwordpolicy\models\PolicyModel` | The policy being saved. Mutable on BEFORE — a listener may amend fields and the amended model is what `savePolicy()` will persist. On AFTER, the model reflects the just-committed state (`id` and `uid` populated for INSERTs from the paired `craft_elements` row). |
| `$groupIds` | `int[]` | The user-group IDs the caller passed in. Mutable on BEFORE; mutation has no downstream effect on AFTER (the junction-table sync has already run). |
| `$isNew` | `bool` | `true` when the save is an INSERT, `false` when it's an UPDATE. The flag reflects the pre-save shape of the policy and stays stable across BEFORE and AFTER for a single save call — even though `policy->id` will be populated by AFTER for INSERTs, `$isNew` still reads `true`. |
| `$isValid` | `bool` | Inherited from `\yii\base\ModelEvent`, defaults to `true`. On BEFORE, a listener flips it to `false` to abort the save. On AFTER, the flag is inherited but meaningless — the save is already committed. |

### Example listener — veto saves below an org-wide minimum

A hypothetical compliance plugin enforcing "no policy on this site may set `minLength` below 12":

```php
use yii\base\Event;
use craftpulse\passwordpolicy\events\PolicySaveEvent;
use craftpulse\passwordpolicy\services\PolicyService;

Event::on(
    PolicyService::class,
    PolicyService::EVENT_BEFORE_SAVE_POLICY,
    function(PolicySaveEvent $event) {
        if ($event->policy->minLength !== null && (int)$event->policy->minLength < 12) {
            $event->policy->addError(
                'minLength',
                'Policy minLength must be at least 12 (org-wide compliance rule).',
            );
            $event->isValid = false;
        }
    },
);
```

### Example listener — mirror saves to a custom audit channel

```php
use yii\base\Event;
use craftpulse\passwordpolicy\events\PolicySaveEvent;
use craftpulse\passwordpolicy\services\PolicyService;

Event::on(
    PolicyService::class,
    PolicyService::EVENT_AFTER_SAVE_POLICY,
    function(PolicySaveEvent $event) {
        $verb = $event->isNew ? 'created' : 'updated';
        Craft::info(
            "Policy {$verb}: {$event->policy->handle} (id {$event->policy->id})",
            'compliance-mirror',
        );
    },
);
```

---

## Subscribing to events

All examples above use Yii's standard `Event::on(class, name, callback)` pattern. Listeners are typically registered in your module's `init()` method:

```php
public function init(): void
{
    parent::init();

    Event::on(
        PasswordPolicy::class,
        PasswordPolicy::EVENT_PASSWORD_CHANGED,
        [$this, 'onPasswordChanged'],
    );
}
```

For one-shot integrations or testing, a closure works equally well. Listeners that throw exceptions break the firing flow — wrap your handler in `try/catch` if your integration target may be unavailable (third-party API down, etc.). The plugin's own internal listeners follow this defense-in-depth pattern.

---

## `WebhookDeliveryAttemptEvent`

**FQ class:** `craftpulse\passwordpolicy\events\WebhookDeliveryAttemptEvent`
**Edition:** every (capture surface)
**Triggered by:** `WebhookService::EVENT_WEBHOOK_DELIVERY_ATTEMPT`
**When:** After every dispatch attempt by `WebhookService::dispatch()` — success or failure. The webhook delivery itself is Enterprise-only (the queue job is gated, the CP UI is gated), but the event class fires regardless of edition because a non-Enterprise install can still synthesise a dispatch in tests or via custom code.

### Payload

| Property | Type | Description |
|----------|------|-------------|
| `$endpointId` | `int` | The webhook endpoint id the dispatch targeted. |
| `$auditRowId` | `int` | The audit-log row id this dispatch attempted to deliver. Stable correlation key — listeners can join against `passwordpolicy_audit_log` on this id to recover the full payload. |
| `$statusCode` | `?int` | HTTP status code returned by the endpoint, or `null` when the dispatch failed before a response (connect refusal, DNS failure, timeout). |
| `$duration` | `int` | Duration of the dispatch in milliseconds, measured around the Guzzle call. Includes connect, TLS handshake, send, receive. |
| `$success` | `bool` | Whether the dispatch was treated as a success by the service. Success = 2xx HTTP response. 4xx, 5xx, transport failure, and timeouts all map to `false`. |
| `$errorMessage` | `?string` | Human-readable error message on dispatch failure. Null on success. Never includes the request body or signature material. |

> The HMAC signature, plaintext secret, and full request body are intentionally NOT in the event payload. Listeners that need the body can join against the audit log row via `auditRowId`. The signature and secret material are cryptographic identifiers that downstream listeners have no legitimate reason to receive.

### Example listener — feed delivery outcomes into a metrics dashboard

```php
use yii\base\Event;
use craftpulse\passwordpolicy\events\WebhookDeliveryAttemptEvent;
use craftpulse\passwordpolicy\services\WebhookService;

Event::on(
    WebhookService::class,
    WebhookService::EVENT_WEBHOOK_DELIVERY_ATTEMPT,
    function(WebhookDeliveryAttemptEvent $event) {
        Craft::info(
            sprintf(
                'Webhook %d → audit row %d: %s (%dms, status=%s)',
                $event->endpointId,
                $event->auditRowId,
                $event->success ? 'OK' : 'FAIL',
                $event->duration,
                $event->statusCode ?? 'transport-error',
            ),
            'webhook-metrics',
        );
    },
);
```

---

## `AuditExportCompleteEvent`

**FQ class:** `craftpulse\passwordpolicy\events\AuditExportCompleteEvent`
**Edition:** Enterprise
**Triggered by:** `AuditExportJob::EVENT_AUDIT_EXPORT_COMPLETE`
**When:** After `AuditExportJob` finishes writing every batch and the file is fully materialised. Listeners observe the completion — the export decision was made earlier (operator triggered the utility or `password-policy/audit/export --queue` console command); by the time this fires, the file already exists, the one-time-use download token is cached, and the email notification is on its way to the requesting admin.

### Payload

| Property | Type | Description |
|----------|------|-------------|
| `$token` | `string` | The 64-char URL-safe random token. Doubles as the filename and the cache-key suffix. |
| `$filePath` | `string` | Absolute filesystem path (local fallback) or filesystem-relative path (when a custom FsInterface handle is configured). |
| `$format` | `string` | Output format — `csv` or `jsonl`. |
| `$rowCount` | `int` | The number of rows written to the export. Includes every row in the configured date window. |
| `$requestedById` | `int` | The userId of the admin who requested the export. |
| `$expiresAt` | `\DateTime` | UTC timestamp when the one-time-use download token expires. After this point the download URL returns 404. |

> The event payload intentionally does NOT include the file contents. Listeners that want the rows themselves dispatch their own filesystem read against `$filePath` — that decision is theirs, and keeping the bytes out of the event keeps the path narrow for listeners that only need the operational signal (off-site mirroring, compliance dashboards, audit-trail-of-exports tracking).

### Example listener — mirror export operations to a SIEM

```php
use yii\base\Event;
use craftpulse\passwordpolicy\events\AuditExportCompleteEvent;
use craftpulse\passwordpolicy\jobs\AuditExportJob;

Event::on(
    AuditExportJob::class,
    AuditExportJob::EVENT_AUDIT_EXPORT_COMPLETE,
    function(AuditExportCompleteEvent $event) {
        Craft::info(
            sprintf(
                'Audit export %s by user %d: %d rows in %s, expires %s',
                $event->token,
                $event->requestedById,
                $event->rowCount,
                $event->format,
                $event->expiresAt->format('c'),
            ),
            'audit-export-mirror',
        );
    },
);
```

---

## Future events

These are scheduled for v5.3 / Phase G but documented here so you can plan around them:

- **`PolicyValidatedEvent`** — fires after a password validation cycle completes (success or failure). Payload includes the resolved policy, which rules ran, which passed/failed.
- **`PasswordExpiredEvent`** — fires when a password's age crosses the expiry threshold. Triggered by the queue-driven expiry-reminder job and the Force Reset element action.
- **`LockoutThresholdReachedEvent`** — Enterprise. Fires when a user's failed-login count reaches the lockout threshold. Payload includes the failed attempt history (anonymized) for SIEM forwarding.
