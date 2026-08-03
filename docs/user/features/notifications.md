# Notifications

The plugin ships a complete notification surface for password-related emails (expiry reminders, breach alerts, new-device alerts, admin security alerts) across all three editions, with different levels of operator control.

- **Lite** dispatches the seeded `expiry-reminder` template via the cron / queue path and writes a capture row to the notification log. No CP template editor, no activity screen, no resend, and no breach / new-device / admin-alert emails.
- **Pro** adds the CP template editor (per-site overrides), token-picker UX, AJAX test-send, the activity log screen, the resend action, plus the `breach-detected` and `new-device-alert` email types that depend on the Pro HIBP-on-login listener.
- **Enterprise** adds the `admin-security-alert` email type, cooldown-gated against the audit log's alert cooldowns table, plus the option to override the DB-stored body with a site Twig template.

> 📷 *Screenshot: Notifications → Templates index showing four editable templates (Expiry Reminder, Breach Detected, New Device Alert, Admin Security Alert) with their per-site overrides.*

This page covers configuring the templates, sending notifications programmatically, the activity log, and (on Enterprise) overriding the DB-stored body with a site Twig template.

## What's in the box

Four editable email templates ship at install time, seeded per site:

| Template key | When it fires | Edition | Tokens |
|---|---|---|---|
| `expiry-reminder` | A user's password approaches the configured expiry window | Lite (stock seeded template, no editor) / Pro (editable) / Enterprise | `{{ user }}`, `{{ daysUntilExpiry }}`, `{{ siteName }}` |
| `breach-detected` | HIBP-on-login matches a user's password against the breach database | Pro | `{{ user }}`, `{{ detectedAt }}`, `{{ siteName }}` |
| `new-device-alert` | A user signs in from a device the plugin hasn't seen before | Pro | `{{ user }}`, `{{ deviceLabel }}`, `{{ maskedIp }}`, `{{ siteName }}` |
| `admin-security-alert` | A security event matching the configured `adminAlertEvents` list fires | Enterprise | `{{ event }}`, `{{ context }}`, `{{ siteName }}` |

Plus one system-mailer-registered key for the audit-export-ready email:

| Template key | When it fires | Where to edit |
|---|---|---|
| `password-policy:audit-export-ready` | An audit export job completes; this email contains the one-time download link | **Settings → Email → System messages** (Craft Pro+) |

## Editing templates

Open **Password Policy → Notifications → Templates** in the control panel.

> 📷 *Screenshot: Edit template screen for "Expiry Reminder" with the General tab visible, subject field, body textarea, click-to-copy token chips ({{ user }}, {{ daysUntilExpiry }}, {{ siteName }}), and the Advanced tab tab in the secondary nav.*

Each template has three tabs:

- **General**: Subject + body (plaintext). Both fields are Twig sources; tokens render at send time with per-user context.
- **Advanced**: Sender name, sender email, reply-to. Empty fields fall back to Craft's system mailer defaults.
- **Test**: Test-send the current draft to the signed-in admin's email. The rendered subject and a body excerpt are returned in-page so you can verify token substitution without leaving the screen.

> ::: tip Token chips
> Click a token chip below the body textarea to insert it at the cursor in whichever field (subject or body) was last focused. Token chips list the variables available for this template's render context, try clicking `{{ user.friendlyName ?? user.username }}` to insert a name-with-fallback expression.
> :::

> ::: tip Env-var-aware sender fields
> Sender Email and Reply-To accept env-var indirection. Type `$EXPIRY_REMINDER_FROM` to read from your `.env` instead of hardcoding the address in project config.
> :::

Save the template. Subsequent notification sends use the new content.

### Per-site templates

The plugin keeps one row per `(notificationKey, siteId)` tuple. Multi-site installs can edit each template independently per site, which is useful for translation, different brand voice, or per-site sender overrides.

The site switcher at the top of the edit screen jumps between sites. When a new site is added to the install, the plugin automatically copies the primary-site template rows into the new site so you don't see a missing-template state on first edit. The propagation listener attaches to `Sites::EVENT_AFTER_SAVE_SITE` and runs defensively, if the propagation fails, the site save itself is never blocked.

## Permissions

| Permission | What it grants |
|---|---|
| `pp:notification-templates-manage` | The Templates index + edit screen + test-send action. |
| `pp:notification-log-view` | The Activity index + per-user notification panel on the user-edit screen. Nested separately so a log auditor doesn't need template-write rights. |

## Programmatic API

For automation, listener-driven sends, and custom integrations.

```php
use craftpulse\passwordpolicy\PasswordPolicy;

PasswordPolicy::$plugin->getNotifications()->sendPasswordExpiryReminder(
    user: $user,
    daysRemaining: 7,
);

PasswordPolicy::$plugin->getNotifications()->sendBreachDetected(
    user: $user,
    detectedAt: new \DateTime('now'),
);

PasswordPolicy::$plugin->getNotifications()->sendNewDeviceAlert(
    user: $user,
    deviceLabel: 'Chrome on macOS',
    maskedIp: '192.168.x.x',
);

PasswordPolicy::$plugin->getNotifications()->sendAdminSecurityAlert(
    event: 'breach_detected',
    context: ['userId' => $user->id, 'email' => $user->email],
);
```

All methods are Pro-gated (or Enterprise for `sendAdminSecurityAlert`) and throw `RuntimeException` when called on a sub-edition. Callers in plugin code already gate on the edition; the service-level guard is defense-in-depth.

### Dedup

Each notification type has a per-user dedup window backed by the `AlertCooldownService` table. The default windows are:

| Type | Window | Scope |
|---|---|---|
| `expiry_reminder` | `expiryReminderDays` × 86400 seconds | per user |
| `breach_detected` | 24 hours | per user |
| `new_device` | (caller is responsible, typically the HIBP-on-login 24h cache) | per user |
| `admin_security_alert` | 5 minutes | per event class |

A subsequent call inside the window short-circuits silently: no email sent, no log row written. The `resend()` admin action explicitly bypasses the dedup gate.

## Activity log

Every dispatch attempt (success and failure) writes a `NotificationLogElement` row capturing the rendered subject, rendered body, recipient email, error message (on failure), and a link back to the user if applicable.

Open **Password Policy → Notifications → Activity** to see the chronological log.

> 📷 *Screenshot: Activity index with status pills (Sent / Failed) and a detail-panel view showing the rendered subject + body for a selected row.*

| Column | What it shows |
|---|---|
| Status | `Sent` (green pill) or `Failed` (red pill) |
| Recipient | The email address the notification was addressed to |
| Type | Notification type (e.g. `expiry_reminder`, `breach_detected`) |
| User | Link to the user element (where applicable) |
| Sent at | UTC timestamp |
| Error | Truncated error message on failed rows |

Click any row to see the rendered subject, the full body, the error (if any), and a **Resend** button that re-renders the template fresh from current state and sends again.

### Resend

The Resend button re-renders the template **from the current state**, not a snapshot replay. If you've edited the template since the original send, the resend reflects your edits. The original row's `notificationType`, `userId`, and `recipientEmail` are reused; everything else is regenerated.

`new-device-alert` and `admin-security-alert` are not resendable in 5.2.0: these types require their original event payload (`deviceLabel`, `maskedIp`, `event`, `context`) to re-render, and the plugin doesn't snapshot those inputs. Clicking Resend on a row of either type returns a no-op.

### Retention

The notification log is retention-managed. Configure the window in **Settings → Password Policy → Retention → Notification log retention days** (default `30`). The `password-policy/gc/run` console command hard-deletes rows older than the configured window.

```cron
# Run retention nightly at 02:00
0 2 * * * cd /path/to/project && ./craft password-policy/gc/run
```

See [GC and retention](../operations/gc-and-retention.md) for the production cron recipe and per-table retention policy.

## Per-user notifications panel

Every user's edit screen has a **Password Security** tab with a Notifications panel embedded near the bottom. The panel lists the user's recent notification activity (last 10 by default, filterable to `Sent` / `Failed`) with the same Resend action available from the Activity index.

> 📷 *Screenshot: User edit screen → Password Security tab → Notifications panel listing four entries (one failed, three sent) with a Resend button on the failed row.*

Permission required: `pp:notification-log-view`.

## Custom Twig email template paths (Enterprise)

Enterprise installs can override the DB-stored body with a site Twig template, which is useful for whitelabel branding, full HTML emails with `<img>` includes, or dev-managed templates that live in version control alongside the rest of the site.

> 📷 *Screenshot: Edit template screen on Enterprise with the "Custom Twig template" field visible (autosuggest, with a placeholder of `_emails/expiry-reminder.twig`).*

On the **Edit template** screen:

1. Set the **Custom Twig template** field to a path resolvable under Craft's `View::TEMPLATE_MODE_SITE` (e.g. `_emails/expiry-reminder.twig`).
2. Save.

When the notification fires:

- **Subject** still renders from the DB-stored field. Admins want to edit subject without touching a Twig file.
- **Body** renders from the site template via `Craft::$app->getView()->renderTemplate($templatePath, $vars)` instead of the DB body. The DB body becomes a fallback (more on that below).

The template receives the same render context as the DB body: `user`, `daysUntilExpiry`, `siteName`, etc. The view runs under site mode, so all of Craft's standard site-template helpers (`include`, `extends`, asset URLs) are available.

### Field validation

The plugin validates the template path at save time: `Craft::$app->getView()->resolveTemplate($templatePath, View::TEMPLATE_MODE_SITE)` must return a real file. Saving a path that doesn't resolve produces a clear "Twig template not found" error on the field rather than a silent runtime failure on the next send.

### Edition-strip on save

The CP edit screen omits the templatePath field entirely on Pro and Lite editions (it only renders on Enterprise). The save and test-send actions also strip the field server-side if a crafted POST tries to bypass the UI, defense in depth.

### Downgrade behaviour

If you downgrade an Enterprise install to Pro, existing template rows retain their `templatePath` value in the JSON content column, but the renderer falls back to the DB body. The Pro edit screen omits the field entirely. Upgrade back to Enterprise and the path resumes working.

The renderer gate is enforced at the `composeFromTemplate()` call site. When the plugin is no longer Enterprise, the templatePath is ignored regardless of what's in the JSON.

## Console commands

```bash
# Send expiry reminders for every user with passwords approaching expiry
./craft password-policy/notification/send-expiry-reminders

# Send the expiry reminder for one specific user (useful for testing)
./craft password-policy/notification/send-expiry-reminders --user=42
```

The command enqueues `SendPasswordExpiryRemindersJob`: a `BaseBatchedJob` that recomputes its recipient set per batch for natural retry idempotency. Runs on every edition since 5.2.0.

For production, run nightly via cron:

```cron
# Send expiry reminders every morning at 06:00 local time
0 6 * * * cd /path/to/project && ./craft password-policy/notification/send-expiry-reminders
```

## Default templates

Default subject + body for each template ship via `EmailDefaults::all()` (`src/data/EmailDefaults.php`). On fresh install they seed per site. On upgrade from 5.1.x or earlier, dated seed migrations add the new keys idempotently, existing custom edits are preserved.

To restore the default content for a single template:

1. Delete the row in `passwordpolicy_notification_templates` for the affected `(notificationKey, siteId)`.
2. The next send will trigger `propagateToSite()` which re-seeds from `EmailDefaults`.

There's no "Reset to defaults" button in the CP; restoring is a deliberate dev action.

## See also

- [GC and retention](../operations/gc-and-retention.md): notification log retention configuration + cron recipe.
- [Events](../reference/events.md): `BreachDetectedEvent`, `PasswordChangedEvent`, etc. Listen to these for custom side effects beyond the email path.
- [Audit logging](./audit-logging.md): every notification dispatch attempt produces an audit row on Enterprise installs.
- [Front-end Twig builders](./frontend-twig.md): the consumer-side surface for change-password and reset-password forms.
