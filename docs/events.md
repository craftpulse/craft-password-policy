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

## `PasswordValidationEvent`

**FQ class:** `craftpulse\passwordpolicy\events\PasswordValidationEvent`
**Edition:** Lite
**When:** After all built-in validators have run. Allows third-party modules to add their own validation logic by inspecting `$event->errors` and pushing additional messages onto the array. This event was introduced in 5.2.0 alongside the validator pipeline refactor.

### Payload

| Property | Type | Description |
|----------|------|-------------|
| `$user` | `craft\elements\User` | The user whose password is being validated |
| `$errors` | `string[]` | Validation error messages from built-in rules (third parties may push additional ones) |
| `$isValid` | `bool` | Whether the password passed all built-in validation |

### Example listener

```php
use yii\base\Event;
use craftpulse\passwordpolicy\events\PasswordValidationEvent;
use craftpulse\passwordpolicy\PasswordPolicy;

Event::on(
    PasswordPolicy::class,
    'passwordValidation',
    function(PasswordValidationEvent $event) {
        // Custom rule: forbid passwords that contain the user's last name
        $lastName = $event->user->getFieldValue('lastName');
        if ($lastName && stripos($event->user->newPassword ?? '', $lastName) !== false) {
            $event->errors[] = 'Password must not contain your last name.';
            $event->isValid = false;
        }
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

## Future events

These are scheduled for v5.3 / Phase G but documented here so you can plan around them:

- **`PolicyValidatedEvent`** — fires after a password validation cycle completes (success or failure). Payload includes the resolved policy, which rules ran, which passed/failed.
- **`PasswordExpiredEvent`** — fires when a password's age crosses the expiry threshold. Triggered by the queue-driven expiry-reminder job and the Force Reset element action.
- **`LockoutThresholdReachedEvent`** — Enterprise. Fires when a user's failed-login count reaches the lockout threshold. Payload includes the failed attempt history (anonymized) for SIEM forwarding.
