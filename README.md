# Password Policy

[![Craft 5](https://img.shields.io/badge/Craft%20CMS-5.9.15+-CE3262)](https://plugins.craftcms.com/password-policy)
[![Edition: Lite • Pro • Enterprise](https://img.shields.io/badge/Edition-Lite%20%E2%80%A2%20Pro%20%E2%80%A2%20Enterprise-3D8FFF)](./docs/user/editions.md)
[![License](https://img.shields.io/badge/License-craft-9A6DEF)](./LICENSE.md)

Password Policy enforces password rules on a Craft install, from a length requirement on a single site to per-group compliance presets, breach detection on every login, and a tamper-evident audit trail.

## Features

- Length, complexity, and expiry rules, with per-group overrides.
- Have I Been Pwned checks at password change, and on every login.
- Password history to block reuse of previous passwords.
- Common-password blocklist, plus an admin-managed custom deny list.
- Strength meter on control panel and consumer-facing password fields.
- Compliance presets for NIST 800-63B, OWASP ASVS L1, PCI DSS v4.0.1, CIS Controls v8, and a strict enterprise baseline.
- Front-end Twig builders for login, registration, change-password, and reset-password forms.
- Expiry reminder, breach detection, and new-device notification emails, editable per site.
- Dormant-account detection, with report, notify, or suspend handling.
- Hash-chained audit log with an independently runnable verifier.
- SIEM forwarding over syslog-TLS, HMAC-signed webhooks, and streaming audit export.
- Read-only REST API for password status and resolved policy.
- Deep support for Craft features: multi-site, customizable permissions, editions, and events.

Features are split across three editions. See [Editions](./docs/user/editions.md).

## Requirements

### Craft CMS

Password Policy requires Craft CMS 5.9.15 or greater.

### PHP

Password Policy requires PHP 8.2 or greater.

### Database

Password Policy requires MySQL 8.0 or greater, MariaDB 10.4 or greater, or PostgreSQL 13 or greater.

## Installation

You can install Password Policy via the Plugin Store, or through Composer.

### Craft Plugin Store

To install **Password Policy**, navigate to the _Plugin Store_ section of your Craft control panel, search for `Password Policy`, and click the _Try_ button.

### Composer

You can also add the package to your project using Composer and the command line.

1. Open your terminal and go to your Craft project:

```shell
cd /path/to/project
```

2. Tell Composer to require the plugin:

```shell
composer require craftpulse/craft-password-policy
```

3. Install the plugin:

```shell
php craft plugin/install password-policy
```

### DDEV

If your project runs in DDEV, run the same commands through DDEV from the project root:

```shell
ddev composer require craftpulse/craft-password-policy
ddev craft plugin/install password-policy
```

## Next steps

Password Policy enforces nothing beyond Craft's own defaults when first installed. To start enforcing a policy:

- Set your rules under **Settings → Password Policy**.
- Schedule the retention and reminder commands. See [Cron setup](./docs/user/operations/cron-setup.md).
- Decide whether existing users must change their passwords. See [Force reset](./docs/user/features/force-reset.md).

See [Getting started](./docs/user/getting-started.md) for the walkthrough.

## Documentation

Full documentation lives in [`docs/`](./docs/README.md).

| | |
|---|---|
| [Getting started](./docs/user/getting-started.md) | Install, configure, and ship your first policy. |
| [Documentation index](./docs/README.md) | Every user-facing page in one place. |
| [Editions](./docs/user/editions.md) | What ships at each edition, and every setting. |
| [Upgrade from 5.1](./docs/user/operations/upgrade-from-5.1.md) | What changes on the 5.1.x to 5.2.0 upgrade. |
| [Console commands](./docs/user/reference/console-commands.md) | Every command, with its options. |
| [Events](./docs/user/reference/events.md) | Hooking into password and audit events. |

## Licensing

You can try Password Policy in a development environment for as long as you like. Once your site goes live, you are required to purchase a license for the plugin.

For more information, see [Craft's Commercial Plugin Licensing](https://craftcms.com/docs/5.x/extend/plugin-store.html#commercial-plugins).

## Support

- **Plugin Store**: [plugins.craftcms.com/password-policy](https://plugins.craftcms.com/password-policy)
- **Bugs and feature requests**: [github.com/craftpulse/craft-password-policy/issues](https://github.com/craftpulse/craft-password-policy/issues)
- **Email**: hello@craft-pulse.com

## Credits

Password Policy bundles the **DB-IP IP-to-Country Lite** database for the optional IP geolocation feature, licensed under [Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/):

> IP Geolocation by DB-IP (https://db-ip.com)

If you enable geolocation, this attribution must remain visible. See [IP geolocation](./docs/user/features/geoip.md).

Password strength estimation uses [bjeavons/zxcvbn-php](https://github.com/bjeavons/zxcvbn-php). The bundled common-password list is derived from [SecLists](https://github.com/danielmiessler/SecLists).

Brought to you by [CraftPulse](https://craft-pulse.com/).
