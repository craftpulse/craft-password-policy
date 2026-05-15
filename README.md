# Password Policy for Craft CMS

[![Craft 5](https://img.shields.io/badge/Craft%20CMS-5.0+-CE3262)](https://plugins.craftcms.com/password-policy)
[![Edition: Lite • Pro • Enterprise](https://img.shields.io/badge/Edition-Lite%20%E2%80%A2%20Pro%20%E2%80%A2%20Enterprise-3D8FFF)](./docs/user/editions.md)
[![License](https://img.shields.io/badge/License-craft-9A6DEF)](./LICENSE.md)

Enforce strong password rules across your Craft site — and prove it. From a simple length requirement on a single-site install to a compliance-grade audit trail with tamper-evident hash chains, breach detection on every login, per-group policy presets, and SIEM forwarding, Password Policy is the combined surface that handles all of it in one plugin.

> 📷 *Screenshot: Plugin Store hero with the Compliance Dashboard utility, a policy edit screen showing tri-state rule overrides, and the front-end strength meter.*

## What you get

| | Lite (free) | Pro | Enterprise |
|---|---|---|---|
| Password rules (length, complexity, blocklist) | ✅ | ✅ | ✅ |
| Password expiry + retention | ✅ | ✅ | ✅ |
| Have I Been Pwned (HIBP) at password change | ✅ | ✅ | ✅ |
| Strength meter (CP + front-end) | ✅ | ✅ | ✅ |
| Force change on first login | ✅ | ✅ | ✅ |
| Per-group named policies + presets (NIST, OWASP, PCI-DSS, Strict) | — | ✅ | ✅ |
| Password history (block reuse of last N) | — | ✅ | ✅ |
| HIBP-on-login (re-check on every sign-in) | — | ✅ | ✅ |
| Front-end Twig render builders (login / register / change / reset) | — | ✅ | ✅ |
| Custom blocklist editor | — | ✅ | ✅ |
| Email notifications (per-site editable templates) | — | ✅ | ✅ |
| Tamper-evident hash-chained audit log | — | — | ✅ |
| Independent verifier CLI (auditor-runnable) | — | — | ✅ |
| Compliance dashboard + HTML/CSV reports | — | — | ✅ |
| Syslog-over-TLS forwarder (Splunk HEC, Datadog, generic) | — | — | ✅ |
| HMAC-signed webhook delivery (replay-window protected) | — | — | ✅ |
| Streaming audit-log export (any Craft filesystem) | — | — | ✅ |
| Per-policy custom blocklist | — | — | ✅ |
| Custom Twig email template paths | — | — | ✅ |

[See the full feature matrix →](./docs/user/editions.md)

## Why this plugin

**Compliance-ready, not just compliance-adjacent.** Pro and Enterprise tiers map directly to specific clauses in NIST 800-63B Rev. 4, NIS2 Article 21, PCI DSS v4.0.1, ISO 27001:2022, SOC 2, and GDPR. The four bundled policy presets — NIST 800-63B, OWASP ASVS L1, PCI-DSS v4.0.1, Strict Enterprise — translate framework requirements into one-click configurations. The audit log is hash-chained from the row level up and verifiable end-to-end via a console command auditors can run from a fresh checkout.

**Privacy by design.** The audit log stores SHA-256 IP hashes, never raw IPs. The userIdentifier column is HMAC-SHA-256 of email, keyed by a dedicated `CRAFT_AUDIT_PII_KEY` env var that's independent of Craft's `securityKey` — rotate it to destroy historical correlation without breaking sessions, CSRF tokens, or asset URLs. The per-event PII allowlist fails closed: an event type not in the registry is dropped rather than silently leaking unintended fields.

**Built on Craft's grain.** Lockout delegates to Craft core (`maxInvalidLogins`); we don't reinvent it. Audit rows are real Craft elements with sources, sort options, and condition rules. Notification logs are elements too — the activity index uses the native element-index renderer. Permissions follow Craft's view-vs-manage nesting convention. CP forms use Craft macros throughout. Front-end Twig builders are policy-aware and a11y-baked.

**Front-end first.** A Pro install ships fluent Twig render builders for login, registration, change-password, and reset-password forms — each one policy-aware, AJAX-validated, and accessible by default (live regions, `aria-describedby`, `aria-invalid`, progressbar role on the strength meter, flipping `aria-label` on the show/hide eye toggle). The vanilla-JS client is ~5 KB, framework-free, no build step required on the consumer site.

## Requirements

- Craft CMS 5.0 or newer
- PHP 8.2+
- MySQL 8.0+, MariaDB 10.4+, or PostgreSQL 13+

## Install

In your Craft project root:

```bash
composer require craftpulse/craft-password-policy
./craft plugin/install password-policy
```

Or install through the Plugin Store: **Settings → Plugins → Search "Password Policy"**.

Then open the plugin Settings to configure your global policy. [Getting Started →](./docs/user/getting-started.md)

## Upgrading from 5.1.x

The 5.2.0 upgrade ships a single consolidated migration that renames the legacy `pwned` settings key to `hibp` (project config + DB) and seeds the new tables. Your existing 5.1.x configuration is preserved.

```bash
composer update craftpulse/craft-password-policy
./craft up
```

For the full migration walkthrough — including the new `CRAFT_AUDIT_PII_KEY` env var for Enterprise installs — see [Upgrade Guide →](./docs/user/operations/upgrade-from-5.1.md).

## Documentation

| | |
|---|---|
| 🚀 [Getting Started](./docs/user/getting-started.md) | Install, configure, and ship your first policy. |
| 📚 [Documentation Index](./docs/README.md) | All user-facing docs in one place. |
| 💎 [Edition Matrix](./docs/user/editions.md) | What ships at each tier, with framework anchors. |
| 🔐 [Audit Logging](./docs/user/features/audit-logging.md) | Hash-chained audit log, verifier CLI, retention. |
| 📊 [Compliance Dashboard](./docs/user/features/compliance-dashboard.md) | Enterprise utility + HTML/CSV reports. |
| 🚦 [SIEM Forwarders](./docs/user/features/siem-forwarders.md) | Syslog-over-TLS to Splunk HEC, Datadog, and friends. |
| 🪝 [Webhooks](./docs/user/features/webhooks.md) | HMAC-signed delivery with replay-window protection. |
| 🎨 [Front-End Twig](./docs/user/features/frontend-twig.md) | Render builders for consumer-site forms. |
| 🎟️ [Events](./docs/user/reference/events.md) | Hook into password and audit events. |

## Quick examples

### Read password status in a Twig template

```twig
{% set status = craft.passwordPolicy.passwordStatus() %}
{% if status == 'expiring' %}
    <p>Your password expires in {{ craft.passwordPolicy.daysUntilExpiry() }} days.</p>
{% elseif status == 'expired' %}
    <p>Your password has expired. Please update it.</p>
{% endif %}
```

Both `craft.passwordPolicy` (camelCase) and `craft.passwordpolicy` (lowercase) work — new code should prefer the camelCase form.

### Render a policy-aware change-password form

```twig
{{ craft.passwordPolicy.passwordChangeForm({
    liveValidation: true,
    toggleVisibility: true,
    submitGate: '#submit',
}).render() }}
```

The builder resolves the user's effective policy (global on Lite; per-group on Pro), wires AJAX validation, renders requirements with `aria-describedby`, and gates the submit button on validation state. [See the full builder API →](./docs/user/features/frontend-twig.md)

### Listen for breach detection

```php
use craftpulse\passwordpolicy\events\BreachDetectedEvent;
use craftpulse\passwordpolicy\services\PasswordService;
use yii\base\Event;

Event::on(
    PasswordService::class,
    PasswordService::EVENT_BREACH_DETECTED,
    function(BreachDetectedEvent $event) {
        // $event->user, $event->sha1Prefix (k-anonymity safe), $event->detectedAt
        // Plaintext, full SHA-1, and bucket suffix are intentionally absent.
    }
);
```

[Full event catalog →](./docs/user/reference/events.md)

### Verify the audit chain (Enterprise)

```bash
./craft password-policy/audit/verify --from=2026-01-01
# Exits 0 on clean pass; 1 on chain break; 2 on unreadable row.
# Designed to be auditor-runnable from a fresh checkout.
```

[Audit log + verifier →](./docs/user/features/audit-logging.md)

## License

This plugin requires a commercial license through the Craft Plugin Store. See [LICENSE.md](./LICENSE.md).

## Support

- **Plugin Store**: [plugins.craftcms.com/password-policy](https://plugins.craftcms.com/password-policy)
- **Bugs and feature requests**: [github.com/craftpulse/craft-password-policy/issues](https://github.com/craftpulse/craft-password-policy/issues)
- **Email**: hello@craft-pulse.com

Brought to you by [CraftPulse](https://craft-pulse.com/).
