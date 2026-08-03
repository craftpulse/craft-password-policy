# Device Tracking

Records which devices an account signs in from, so an unfamiliar one can be recognised as new.

**Capture runs on every edition.** The alert email that tells a user about a new device requires the Enterprise edition, but the recording underneath it does not. A Lite install builds device history from day one, so an install that later upgrades to Enterprise starts with a populated history rather than treating every existing device as new and emailing everybody at once.

## What a device is

On each successful sign-in the plugin derives a fingerprint and looks for a matching row for that account. No match means a new device.

The fingerprint is a SHA-256 hash of the user agent joined to the **masked** IP. Masking happens before hashing, and that ordering is the interesting part: it means a user whose address moves within the same network keeps the same device identity. Without it, every DHCP lease renewal would look like a new laptop.

Masking is:

| Address | Masked to |
|---|---|
| IPv4 | Final octet zeroed, so a `/24`. `203.0.113.47` becomes `203.0.113.0`. |
| IPv6 | Truncated to a `/64`. |
| Anything unparseable | The literal `Unknown`. |

## What is stored, and what is not

**The raw user agent and the raw IP are never persisted.** They exist in request scope for the duration of the sign-in and are used to derive three things, all of which are stored instead of the originals:

| Column | Contents |
|---|---|
| `fingerprint` | The SHA-256 hash. Not reversible, and never written to the log. |
| `deviceLabel` | A coarse human-readable label, for example `Chrome on macOS`. Falls back to `Unknown device` when neither the browser nor the OS is recognised. |
| `maskedIp` | The masked address, for example `203.0.113.0`. |

Alongside those, the row keeps the user id, the site the sign-in happened on (null for a control panel sign-in), and first-seen and last-seen timestamps.

The label is deliberately coarse. It carries enough for a user to recognise their own device in an email, and not enough to be a browser fingerprint. There is no screen resolution, no font list, no plugin enumeration, and no version string.

Rows are pruned by `gc/run` against `deviceRetentionDays`, default 180 days. The purge runs on every edition, since capture does.

## What happens on a new device

On a match, the plugin bumps `lastSeenAt` and stops. On a miss it inserts the row, then does the following in order:

1. **Always**, on every edition: fires `EVENT_NEW_DEVICE_DETECTED` with the user, the device label, the masked IP, and the site id. This is the hook to use if you want new-device behaviour on an edition below Enterprise. See [Events](../reference/events.md#newdevicedetectedevent).
2. **On Enterprise with `enableAuditLog`**: writes a `new_device` audit row. The row's details carry `source: login` and the device label, and nothing else: the allowlist would drop a raw user agent or IP even if something tried to pass one.
3. **On Enterprise with `enableNewDeviceAlerts`**: emails the user, subject to a cooldown of one alert per user per 24 hours.
4. **On Pro, if any group alert subscribes to `new_device`**: routes a copy to that group's security contact. This is independent of `enableNewDeviceAlerts`, so a Pro install can notify a security contact about new devices without emailing end users at all. See [Group alerts](./group-alerts.md).

## The alert email

Enterprise. No control panel field: set it in `config/password-policy.php`:

```php
return [
    'enableNewDeviceAlerts' => true,
    'deviceRetentionDays' => 180,
];
```

The email names the device label and the masked IP. With [IP geolocation](./geoip.md) on, the label gains a country: `Chrome on macOS, BE`. The country is resolved at send time, only after the cooldown has cleared, so a suppressed alert costs no lookup.

The template is editable per site at **Password Policy → Notifications**, under the `new-device-alert` key.

The 24-hour cooldown matters more than it looks. Without it, a user browsing from a train, whose carrier address moves between networks, would receive an alert per network. See [Alert cooldowns](./alert-cooldowns.md).

## Reading it honestly

A "new device" here means a new (user agent, masked network) pair. That is a useful signal and a weak one, and it is worth knowing which failures you are buying:

- **A browser update can look like a new device**, because a version string change alters the user agent.
- **A private browsing window usually does not**, because the user agent and network are unchanged.
- **A genuinely stolen session need not**, if the attacker is on the same network and the same browser.

So treat an alert as "worth a glance from the account owner", which is exactly what the email asks for. It is not authentication, and nothing in the plugin blocks a sign-in on the strength of it.

## See also

- [Group alerts](./group-alerts.md): routing new-device notices to a security contact.
- [Alert cooldowns](./alert-cooldowns.md): how the per-user throttle works.
- [IP geolocation](./geoip.md): adding a country to the device label.
- [Audit logging](./audit-logging.md): the `new_device` audit row.
- [Database schema](../reference/database-schema.md): the `passwordpolicy_known_devices` table.
