# Getting Started

This guide walks you from a fresh `composer require` to a working policy that enforces a minimum password length, checks new passwords against the Have I Been Pwned breach database, and shows a strength indicator in the control panel.

If you're upgrading from 5.1.x, read [Upgrading from 5.1.x](./operations/upgrade-from-5.1.md) instead.

## Step 1 — Install

In your Craft project root:

```bash
composer require craftpulse/craft-password-policy
./craft plugin/install password-policy
```

Or install through the Plugin Store: **Settings → Plugins → Search "Password Policy" → Install**.

> 📷 *Screenshot: Plugin Store listing with the Install button highlighted.*

The plugin installs in the **Lite** edition by default. Lite is free and covers global password rules, HIBP breach checking at password change, strength meter, retention/expiry, and force-change-on-first-login. See the [Edition Matrix](./editions.md) for what each tier ships.

## Step 2 — Configure a global policy

Open **Settings → Password Policy** in the control panel.

> 📷 *Screenshot: Settings → Password Policy sidebar showing the Policy / Validation / Monitoring sections.*

The settings page is grouped into three sections:

- **Policy** — length, complexity, expiry, retention.
- **Validation** — HIBP, strength meter, content security policy nonce.
- **Monitoring** — notification log retention, expiry reminder cadence.

Start with the **Configuration** screen under Policy. The defaults are reasonable for most sites, but at minimum we recommend:

1. Set **Minimum length** to `12` (or `15` to match NIST 800-63B Rev. 4 single-factor requirements).
2. Enable **Have I Been Pwned** to check new passwords against the breach database via k-anonymity.
3. Leave **HIBP Fail Mode** on `Open` for most production sites — a transient API outage won't block a password change. Switch to `Closed` only if you can tolerate the rare false reject during HIBP outages.

> ::: tip
> The HIBP check uses k-anonymity: the plugin sends only the first 5 characters of the SHA-1 of the password to the HIBP API. The full hash and the password itself never leave your server.
> :::

Save the page. Your policy is now active on every new user save and password change.

## Step 3 — Test it

Open **Users → New user** in the control panel and try setting a weak password:

> 📷 *Screenshot: New user form rejecting "Password123" with the strength meter at red and the rule list showing failures.*

You should see:
- Per-rule pass/fail next to the password field.
- A strength meter colored by zxcvbn-php's analysis.
- If you typed a password from the bundled common-password list or a known breach, a clear rejection message.

## Step 4 — (Optional) Enable the strength indicator everywhere

Under **Settings → Password Policy → Validation**, toggle **Show strength indicator**. The strength meter will now render on:

- The control panel's New User and password change screens.
- Any front-end form using `craft.passwordPolicy.passwordField()` or `passwordWidget()` (see [Front-end Twig builders](./features/frontend-twig.md)).
- The installer and set-password screens.

## Step 5 — (Optional) Set up password expiry

If your compliance framework requires periodic password changes, configure expiry under **Settings → Password Policy → Policy → Retention**:

- **Expiry amount** + **Expiry period**: how long a password is valid (e.g. `90 days`). Set to `null` to disable.
- **Expiry reminder days** (Pro): when to email users before expiry.

> ::: warning NIST 800-63B Rev. 4 caveat
> NIST 800-63B Rev. 4 explicitly forbids periodic rotation (`SHALL NOT require subscribers to change passwords periodically`). PCI DSS v4.0.1 §8.3.9 still requires 90-day rotation. Pick the framework that matches your audit and use the matching preset on the [Per-group policies](./features/per-group-policies.md) screen.
> :::

Then set up the GC cron so expired passwords actually trigger reset prompts:

```cron
# Run nightly at 02:00 local time
0 2 * * * cd /path/to/project && ./craft password-policy/gc/run
```

See [Cron setup](./operations/cron-setup.md) for the recommended production schedule.

## Next steps by edition

### Lite (where you are now)

You're done — the Lite edition is a single global policy. Visit [Validators](./features/validators.md) to fine-tune which checks run on every password.

### Pro

Upgrade to Pro to unlock:

- **[Per-group named policies](./features/per-group-policies.md)** — different rules for different user groups, with four bundled compliance presets (NIST 800-63B, OWASP ASVS L1, PCI-DSS v4.0.1, Strict Enterprise).
- **[HIBP-on-login](./features/audit-logging.md#hibp-on-login)** — re-check every user's password against the breach database on every sign-in, not just at change time.
- **[Password history](./features/password-history.md)** — block reuse of the last N passwords.
- **[Front-end Twig builders](./features/frontend-twig.md)** — `loginForm()`, `passwordChangeForm()`, `passwordResetForm()` for consumer-site forms with AJAX validation and a11y baked in.
- **[Email notifications](./features/notifications.md)** — per-site editable templates with token chips and a test-send button.

Set the edition in `config/project/project.yaml`:

```yaml
plugins:
  password-policy:
    edition: pro
```

Then run `./craft up` to apply.

### Enterprise

Upgrade to Enterprise on top of Pro to unlock the audit + integration surface:

- **[Hash-chained audit log](./features/audit-logging.md)** — tamper-evident from the row level up, with a [bundled verifier CLI](./features/audit-verifier.md) auditors can run from a fresh checkout.
- **[Compliance dashboard](./features/compliance-dashboard.md)** — Enterprise CP utility with aggregates over the audit infrastructure, plus HTML and CSV report exports.
- **[SIEM forwarders](./features/siem-forwarders.md)** — Syslog-over-TLS to Splunk HEC, Datadog Logs, or any RFC 5424 receiver.
- **[Webhook delivery](./features/webhooks.md)** — HMAC-signed delivery with replay-window protection and idempotency UUIDs.
- **[Audit export](./features/audit-export.md)** — Streaming CSV/JSONL to any Craft filesystem.
- **[Per-policy custom blocklist](./features/blocklist.md#per-policy-blocklist-enterprise)** — Scope custom blocked words to specific named policies (e.g. customer names for sales reps, project codenames for engineering).

Enterprise also adds a dedicated audit-PII HMAC key — see [Provisioning `CRAFT_AUDIT_PII_KEY`](./operations/upgrade-from-5.1.md#provisioning-craft_audit_pii_key) for the one-shot setup command.

## Troubleshooting

### "Plugin not found" after `composer require`

Make sure you ran `./craft plugin/install password-policy` after the Composer install. The plugin needs both Composer registration and Craft's plugin install action.

### Strength meter doesn't appear on the New User screen

Check **Settings → Password Policy → Validation → Show strength indicator**. The toggle is off by default to avoid surprising existing installs on upgrade.

### HIBP requests fail with TLS errors

The plugin forces `verify => true` on the HIBP request regardless of your site-level `config/guzzle.php`. If your network blocks TLS verification entirely (corporate proxy with self-signed certs), set the HIBP fail mode to `Open` — the plugin will fail gracefully and log a warning rather than blocking the password change.

### Migrations fail with foreign-key errors

Run `./craft up` to ensure schema migrations have applied. If you're upgrading from 5.1.x, see the dedicated [Upgrade Guide](./operations/upgrade-from-5.1.md).

## Where to next

- [Edition Matrix](./editions.md) — what each tier ships, with framework anchors.
- [All features](../README.md#documentation) — feature-by-feature documentation index.
- [Events reference](./reference/events.md) — hook into password and audit events for analytics, alerting, or SIEM mirroring.
