# Group Alerts

Routes a copy of a security alert to a designated contact whenever a member of a given user group triggers it. Requires the Pro edition.

The use case is a security contact per team: the SOC address wants breach detections for the staff group, the client's own IT manager wants them for the client-users group, and neither should receive the other's.

## How recipients are resolved

**From the affected user's actual group membership, at the moment the alert fires.** Not from a global recipient setting.

That distinction is the whole feature. A subscription is a rule saying "when someone in group A triggers event E, also tell contact C". When a user triggers the event, the plugin reads that user's resolved groups and collects the subscriptions matching them. A user in no groups produces no group alerts.

A contact subscribed through two groups the user belongs to is alerted **once**: the recipient set is de-duplicated by email address.

This is separate from, and additional to, the alert the affected user receives themselves. Group alerts never replace the user's own notification.

## Configuring subscriptions

**Password Policy → Notifications → Group alerts** (Pro, `pp:notification-templates-manage`).

The screen is an editable table. Each row is one routing rule:

| Column | Description |
|---|---|
| Group | The Craft user group the rule watches. |
| Event | The event to route: `breach_detected` or `new_device`. |
| Recipient | The email address that receives the copy. |
| Enabled | Off keeps the row without routing anything. |

The permission is the same one that gates the notification template editor, on the grounds that deciding who receives which alert is a notification-management decision rather than a separate kind of authority.

Deleting a Craft user group deletes its subscriptions, by foreign-key cascade. No orphan rules, and no alerts routed on behalf of a group that no longer exists.

Subscriptions are stored on every edition, so they survive a downgrade and start working again on upgrade. Only the dispatch that reads them is Pro-gated.

## The two events

### `breach_detected`

Fires when HIBP finds a user's password in a breach corpus during sign-in. Requires Pro, which the feature does anyway.

### `new_device`

Fires when a user signs in from a device the plugin has not seen before.

This one is worth noting: it is **independent of `enableNewDeviceAlerts`**. That setting is Enterprise and controls the email to the end user. A Pro install with no end-user device emails at all can still route new-device notices to a group's security contact, which is often what a security team actually wants: tell us, do not alarm the users. See [Device tracking](./device-tracking.md).

## Throttling

Each recipient is throttled per group and event, on a key of `group:{groupId}:{eventType}`, with a default window of **one hour**.

The key is the group, not the recipient and not the affected user. That is deliberate: if a breach corpus update matches thirty accounts in one group inside a minute, the contact gets one message about that group rather than thirty. A burst against one group does not suppress alerts about a different group, because the key differs.

See [Alert cooldowns](./alert-cooldowns.md).

## What the contact receives

The alert goes out through the admin security alert template, with the recipient overridden to the subscribed address.

It names the event type and a single user identifier: the username, falling back to the email address. Nothing more. A group contact never receives more about a user than that user's own alert would disclose, which keeps a per-team security contact from becoming a way to read another team's account details.

Delivery is defensive per recipient. If one address fails, the failure is logged and the remaining recipients still get their copies, and neither the sign-in nor the user's own alert is affected. The log line is deliberately opaque: it records the event type and the user id, never the recipient address or the user identifier.

## Observing dispatches

`EVENT_GROUP_ALERT_DISPATCHED` fires once per recipient that actually received a copy. It does not fire for the user's own alert, and it does not fire for a recipient the cooldown suppressed, so it is a record of messages sent rather than of alerts considered.

```php
use craftpulse\passwordpolicy\events\GroupAlertDispatchedEvent;
use craftpulse\passwordpolicy\PasswordPolicy;
use yii\base\Event;

Event::on(
    PasswordPolicy::class,
    PasswordPolicy::EVENT_GROUP_ALERT_DISPATCHED,
    function(GroupAlertDispatchedEvent $event) {
        $user = $event->user;
        $groupId = $event->groupId;
        $eventType = $event->eventType;
        $recipientEmail = $event->recipientEmail;
        // ...
    },
);
```

`groupId` is the group that resolved the recipient, which is also the group half of the cooldown key. When two of the user's groups subscribe the same contact, this is the first one matched.

See [Events](../reference/events.md#groupalertdispatchedevent).

## Working with subscriptions in code

```php
use craftpulse\passwordpolicy\PasswordPolicy;

// Every subscription, ordered by group, then event, then recipient.
$subscriptions = PasswordPolicy::$plugin->getGroupAlerts()->getAllSubscriptions();

// The de-duplicated recipients for one user and event, keyed by email,
// valued by the resolving group id.
$recipients = PasswordPolicy::$plugin->getGroupAlerts()
    ->recipientsForUser($user, 'breach_detected');
```

`recipientsForUser()` is the method to call if you are building your own routing on top of this. Resolve from the user, as it does, rather than reading a global list: a global read is how a per-group feature silently stops being per-group.

## See also

- [Notifications](./notifications.md): the templates these alerts render.
- [Device tracking](./device-tracking.md): the source of `new_device`.
- [Alert cooldowns](./alert-cooldowns.md): the throttle.
- [Per-group policies](./per-group-policies.md): the other per-group surface.
- [Database schema](../reference/database-schema.md): the `passwordpolicy_group_alert_subscriptions` table.
