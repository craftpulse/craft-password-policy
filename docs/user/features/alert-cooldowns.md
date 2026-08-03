# Alert Cooldowns

The plugin's `AlertCooldownService` is a per-(event class, scope) dedup substrate that prevents alert spam: operators don't get 47 identical "password breach detected" emails when 47 users on the same compromised password sign in within a minute. It's used internally by the notifications layer + the audit + the SIEM/webhook forwarders; you typically don't interact with it directly unless you're building custom alerting on top.

This page covers what the service does, how the dedup windows are configured, and how to register a custom alert with cooldown semantics.

## What it does

Every alert in the plugin (notification emails, SIEM forwards, webhook deliveries, future plugin extensions) goes through `AlertCooldownService::shouldFire()` before dispatch:

```php
$cooldown = PasswordPolicy::$plugin->getAlertCooldown();
$alertKey = 'admin_security_alert:breach_detected';
$scope = 'event:breach_detected';
$windowSeconds = 300;

if ($cooldown->shouldFire($alertKey, $scope, $windowSeconds)) {
    // Send the alert: the service has already recorded the fire.
    sendAdminEmail(...);
} else {
    // Within the cooldown window. Skip silently.
}
```

The service:

1. Looks up the most-recent fire of `(alertKey, scope)` in `passwordpolicy_alert_cooldowns`.
2. If the fire is within `windowSeconds` of now, returns `false` (skip).
3. Otherwise records the new fire + returns `true` (fire).

The record happens **on the `true` return**: the caller doesn't need a separate `markSent()` call. This is the auto-record contract: a successful `shouldFire()` is the side-effect of recording the cooldown.

## How dedup windows are configured

Each call to `shouldFire()` specifies its own window. The plugin's built-in alert types use these defaults:

| Alert | Window | Scope shape | Why |
|---|---|---|---|
| `expiry_reminder` | `expiryReminderDays` × 86400 sec (default 14 days) | per user | Don't email the same user about the same expiry twice. |
| `breach_detected` | 24 hours | per user | Don't email the same user about the same HIBP match more than once a day. |
| `new_device_alert` | (caller-handled, typically the HIBP-on-login 24h cache) | per user | Defer to caller. |
| `admin_security_alert` | 5 minutes | per event class | Operators get one digest of "breach detected" per 5 minutes, not one email per user. |
| `siem_forward_retry` | exponential backoff (1, 5, 25, 125, 625 sec) | per forwarder + event class | Don't hammer a down SIEM. |
| `webhook_delivery_retry` | exponential backoff | per endpoint + event class | Same. |

`AlertCooldownService::DEFAULT_COOLDOWN_*` constants are the canonical source; see the service source for the current defaults.

### Scope semantics

The `scope` parameter is a free-form discriminator. Common shapes:

- **Per-user**: `"user:{userId}"`. Different users have independent cooldowns; the same user is rate-limited.
- **Per-event-class**: `"event:{eventName}"`. All users get one alert per window for a given event type. Useful for `admin_security_alert` where the operator wants a digest, not per-user emails.
- **Global**: `"global"`. One alert per window across the whole site. Rare: most alerts have a more specific scope.
- **Composite**: `"forwarder:{forwarderId}:{eventName}"`. Per-forwarder, per-event-class state. Used by the SIEM forwarder retry logic.

The discriminator is a `VARCHAR(191)` column with a composite index on `(eventClass, cooldownKey, firedAt)`, fast `WHERE eventClass = ? AND cooldownKey = ? AND firedAt >= ?` queries even with millions of rows.

## Retention

The `passwordpolicy_alert_cooldowns` table is retention-managed by `password-policy/gc/run`:

```
DELETE FROM passwordpolicy_alert_cooldowns
WHERE firedAt < NOW() - INTERVAL <window> SECOND
```

There is no retention setting for this table. The window is derived: the longer of your longest configured cooldown and a 7-day floor. Deriving it is what keeps the purge from deleting a row that a still-open cooldown depends on, so a table you cannot misconfigure is the point.

Older rows don't affect correctness: the `shouldFire()` query only looks at the most-recent fire within the window. Retention is purely a table-size guard.

## Registering a custom alert

If you're extending the plugin with a custom alert type, plug into the service like any built-in:

```php
use craftpulse\passwordpolicy\PasswordPolicy;

final class MyCustomAlertService
{
    public function maybeFireMyAlert(int $userId, string $reason): void
    {
        $cooldown = PasswordPolicy::$plugin->getAlertCooldown();

        if (!$cooldown->shouldFire(
            alertClass: 'my_custom_alert',
            scope: "user:{$userId}",
            cooldownSeconds: 3600,  // 1 hour
        )) {
            return;
        }

        // Send the alert. shouldFire() has already recorded the cooldown.
        $this->sendIt($userId, $reason);
    }
}
```

The service is registered in `ServicesTrait` as `alertCooldown`. PHPDoc return type ensures IDE autocomplete works.

### When to use it

Yes:

- You're sending an email, push notification, SMS, Slack message, or any user-facing alert that could spam under load.
- You're retrying a flaky external call and want exponential backoff.
- You want per-resource dedup of any kind.

No:

- You're writing audit-log rows. Audit captures every event; cooldowns are for delivery-side dedup. Capture and delivery are separate concerns.
- You're rate-limiting an inbound request. Use Craft's request-level throttling (e.g. `requireElevatedSession`) for that.

## Inspecting cooldown state

The compliance dashboard's **Activity in last 24h** section surfaces cooldown fires grouped by event class; see [Compliance Dashboard](./compliance-dashboard.md).

There is no console command for cooldown state. For ad-hoc inspection, query the table directly:

```sql
SELECT eventClass, cooldownKey, firedAt
FROM passwordpolicy_alert_cooldowns
WHERE firedAt > NOW() - INTERVAL 24 HOUR
ORDER BY firedAt DESC;
```

The `(eventClass, cooldownKey, firedAt)` composite index covers this shape, so it stays fast even on a table with a long retention window.

## Events

The `EVENT_ALERT_COOLDOWN_FIRED` event fires every time `shouldFire()` returns `true` and records a new cooldown row. Listen to it for custom monitoring:

```php
use craftpulse\passwordpolicy\events\AlertCooldownEvent;
use craftpulse\passwordpolicy\services\AlertCooldownService;
use yii\base\Event;

Event::on(
    AlertCooldownService::class,
    AlertCooldownService::EVENT_ALERT_COOLDOWN_FIRED,
    function(AlertCooldownEvent $event) {
        // $event->alertClass, $event->scope, $event->firedAt
        // Useful for forwarding cooldown fires to a metrics system (StatsD, Datadog metrics, etc.)
    }
);
```

The event captures every fire (`shouldFire() === true`); cooldown skips (`shouldFire() === false`) don't fire an event: the absence of a fire is the signal.

## See also

- [Notifications](./notifications.md): the primary consumer of cooldowns for email dedup.
- [SIEM forwarders](./siem-forwarders.md): uses cooldowns for retry backoff.
- [Webhooks](./webhooks.md): uses cooldowns for retry backoff.
- [Compliance Dashboard](./compliance-dashboard.md): surfaces cooldown activity for operators.
- [Events](../reference/events.md): `EVENT_ALERT_COOLDOWN_FIRED` payload and example listeners.
