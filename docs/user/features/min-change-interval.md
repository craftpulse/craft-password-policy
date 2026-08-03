# Minimum Change Interval

Stops a user changing their password again within N hours of their last change. Requires the Pro edition.

Disabled by default (`minChangeIntervalHours = 0`).

## What it is for

This closes a specific hole in password history. If you block reuse of the last 5 passwords, a user who wants their old password back can change it 5 times in a row and then set it a sixth time, flushing the history and landing exactly where they started. History alone cannot stop that, because each individual change is legitimate.

An interval makes the attack take days instead of a minute. With history at 5 and an interval of 24 hours, getting the old password back costs almost a week of deliberate effort, which is enough to make it not worth doing.

The two settings are meant to be used together. History without an interval is bypassable; an interval without history stops nothing, since a user can just set the same password again.

## Configuring it

The global value has no control panel field. Set it in `config/password-policy.php`:

```php
return [
    'minChangeIntervalHours' => 24,
];
```

`0` disables the check. Any positive value is the number of hours that must elapse between two changes for the same account.

Per-policy overrides **do** have a field, on the policy edit screen at **Password Policy → Policies → [policy]**, labelled **Minimum change interval (hours)**. Leave it empty to inherit the global value.

Resolution is per user, and the resolved value wins. A group policy setting 24 hours enforces 24 hours even when the global value is `0`, so you can run the interval for one group without imposing it site-wide. See [Per-group policies](./per-group-policies.md).

## Which changes are exempt

**A change the system forced is never blocked.** The plugin cannot tell a user "you changed your password too recently" when the plugin is the reason they are changing it.

Four forced-reset reasons are exempt:

| Reason | When it applies |
|---|---|
| `AdminForceReset` | An admin forced a reset on the account. |
| `FirstLoginForced` | `forceChangeOnFirstLogin` is on and this is the first sign-in. |
| `ExpiryForced` | The password passed its expiry window. |
| `BreachForced` | HIBP found the password in a breach corpus. |

The exemption is read from the pending reset reason on the account, the same source the history writer uses, so the two always agree about why a change happened.

Everything else is subject to the interval, and that includes two cases worth being explicit about:

- **An ordinary self-service change.** This is the case the feature exists for.
- **An admin setting a password by hand**, without having forced a reset first. Only an actual force-reset is exempt, not any change an admin happens to make. If you are an admin resetting a password for a user who just changed theirs, force the reset rather than typing a new password directly.

An account that has never changed its password is not blocked either: there is no previous change to measure from.

## What the user sees

On a blocked change, the password field gets a validation error naming the time the change becomes possible:

> You changed your password too recently; you can change it again after 3 Aug 2026, 09:31.

The time is formatted in the user's own locale and timezone. The check runs on save, so it applies wherever a password is set: the control panel, the front-end change-password form, and the AJAX validation endpoint.

The comparison reads Craft's own `lastPasswordChangeDate` column rather than the plugin's history table, so the interval is enforced correctly even with password history switched off entirely.

## When not to use it

Do not set this on a site whose users mostly arrive through password reset emails. A user who resets, mistypes their intent, and immediately wants to reset again will hit the interval and file a support ticket. The forced-reset exemptions cover the reset-email path itself, but not a user changing their password twice in a row of their own accord.

Long intervals are worse than they look. At 168 hours (a week), a user who suspects their password is compromised cannot change it, and they have to reach you instead. If you want protection against history-flushing, 24 hours is enough; going higher trades real security for a theoretical improvement.

## See also

- [Password history](./password-history.md): the feature this protects.
- [Per-group policies](./per-group-policies.md): per-group overrides and how resolution works.
- [Validators](./validators.md): the other checks that run on save.
- [REST API](../reference/rest-api.md): `policy/resolve` returns the resolved interval.
