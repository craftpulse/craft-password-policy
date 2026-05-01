# Password Policy plugin for Craft CMS 5.x

The Password Policy plugin is a powerful tool for enforcing secure password policies within your Craft CMS 5 installation.
It helps administrators define and manage password rules for users, enhancing security and compliance in multi-user environments.

![Screenshot](./resources/img/password-policy.jpg)

## Requirements

This plugin requires Craft CMS 5.0.0 or later.

## Installation

To install Password Policy, follow these steps:

1. Open your terminal and go to your Craft project:

        cd /path/to/project

2. Then tell Composer to load the plugin:

        composer require craftpulse/craft-password-policy

3. Install the plugin via `./craft install/plugin password-policy` via the CLI, or in the Control Panel, go to Settings → Plugins and click the “Install” button for Password Policy.

You can also install Password Policy via the **Plugin Store** in the Craft Control Panel.

Password Policy works on Craft 5.x.

## Configuration options

### Minimum Password Length
Define the minimum number of characters a password must contain.
Default: `8`

### Complexity Requirements
The following requirements can be enabled in the plugin settings:

- At least one uppercase and lowercase letter
- At least one number
- At least one special character (e.g., !@#$%)

### Password Strength Indicator
A password strength indicator can be enabled to aid your users into choosing a stronger password

### Content Security Policy (CSP) Nonce Support
For sites with strict Content Security Policy requirements, the plugin supports CSP nonces for the password indicator script. This is useful for CSP policies that require nonces for all external scripts instead of allowing `'self'`. **The plugin does NOT set CSP headers** - you must configure these yourself.

**Note:** Most users don't need this feature. Only enable if you have strict CSP policies that require nonces for external scripts. This should only be activated if it's available on the front-end.

### Have I been pwned?
Enhance your security by ensuring users can not select any leaked password. This employs the k-Anonymity method to validate passwords against the Pwned Passwords API without compromising user privacy by revealing passwords to an external service.

### Password Retention Features
#### Password Expiration Method
You can determine the period in days,weeks,months or years when a password should expire. If you want to make use of this functionality, you can find this under Utilities → Password Retention → Force Reset Passwords.
Or if you want to use this utility through the CLI for e.g. a cronjob you can use `craft password-policy/retention/force-reset-passwords`.

## Editions

Password Policy ships in three editions:

- **Lite** (default) — global password rules, HIBP breach checking, password strength indicator, retention/expiry, force-reset on first login. Free.
- **Pro** — adds password history (block reuse), advanced validators (sequential / repeated / contextual / common-password blocklist), and **per-group named policies** with tri-state overrides. Paid.
- **Enterprise** — adds privacy-preserving audit logging, device tracking, compliance dashboard, SIEM forwarding, and webhooks. Paid.

The edition is set in `project.yaml`:

```yaml
plugins:
  password-policy:
    edition: pro  # lite | pro | enterprise
```

## Pro Features

### Named Policies (Per-Group Overrides)

Pro adds a Policies manager at **Password Policy → Policies** for creating named policies and assigning them to one or more user groups. Each policy can override individual rules without affecting global settings.

#### Tri-state rule overrides

Every boolean rule on a policy has three states:

- **Off** (red X) — explicitly disabled for assigned groups, even if globally on
- **Global** (hollow circle) — inherits the global setting (default)
- **On** (green check) — explicitly enabled for assigned groups, even if globally off

When a user belongs to multiple groups, the resolver applies "most-restrictive wins" semantics: any explicit `On` wins over any `Off`; an explicit `Off` is honored only when no other group's policy says `On`.

#### Presets

Apply a security standard as a starting template, then customize:

- **NIST 800-63B** — passphrase-friendly, breach-checking, no complexity, no expiration
- **OWASP ASVS L1** — 12+ characters, max 128, breach-checking
- **PCI-DSS v4.0** — 12+ chars, mixed case + numbers, history of 4, common-password blocklist, 90-day expiry
- **Strict Enterprise** — 12+ chars, all complexity, all advanced checks, history of 5, 90-day expiry, fail-closed HIBP

A **"Restore preset defaults"** button re-applies the preset values after customization. A **"Reset all to global"** button clears every override on the policy in one click.

The policies index shows divergence at a glance: a small blue dot next to policy names that differ from their preset, plus a "Changes" column with the divergence count.

### Password History

Block reuse of the last N passwords. Configurable count (default 5) and retention period.

### Advanced Validators

Beyond basic length and complexity, Pro adds:

- **Sequential characters** — rejects sequences like `abc`, `123`, `qwerty` (covers ASCII runs and keyboard patterns)
- **Repeated characters** — rejects runs like `aaaa`
- **Contextual data** — rejects passwords containing the user's name, username, or email
- **Common passwords** — rejects passwords found in a seeded blocklist (extendable via custom dictionary)

The blocklist auto-seeds via a queue job when the toggle is enabled and the table is empty.

## Twig Variables

Front-end and CP templates can read password status via the `craft.passwordpolicy` variable:

```twig
{{ craft.passwordpolicy.passwordStatus() }}    {# 'current' | 'expiring' | 'expired' | 'never' #}
{{ craft.passwordpolicy.daysUntilExpiry() }}   {# integer or null #}
{{ craft.passwordpolicy.isExpiring(7) }}       {# bool — within N days? #}
{{ craft.passwordpolicy.activeSessionCount() }}
```

## AJAX Validation Endpoint

`POST /admin/password-policy/validate` with `{ password: '...' }` returns per-rule pass/fail JSON for live feedback. CSRF is required for CP requests; use `Craft.csrfTokenValue` in the request body.

## Front-End Templates (Pro)

The plugin ships fluent render builders on `craft.passwordpolicy.*` for building user-facing login, registration, password-change, and password-reset pages. Each builder is policy-aware (Pro resolves per-group; Lite applies global), comes with full a11y wiring (live region, `aria-describedby`, `aria-invalid`, `aria-busy`, `role="progressbar"`, flipping `aria-label` on the show/hide toggle), and auto-registers a vanilla-JS client asset that drives debounced AJAX validation, requirement-list state classes, strength-meter labels, and submit-button gating.

```twig
{{ craft.passwordpolicy.passwordWidget({
    name: 'password',
    liveValidation: true,
    submitGate: '#submit',
    showHint: true,
}).render() }}
```

See [`docs/user/features/frontend-twig.md`](./docs/user/features/frontend-twig.md) for the complete API reference.

## Events

Hook into password-policy events for analytics, audit-trail mirroring, SIEM forwarding, or custom side effects. The plugin fires events for password changes, registrations (via `RegistrationService`), and HIBP-on-login breach detection (Pro). Every event near password handling guarantees no plaintext or hash material in its payload — listeners can forward them anywhere without leaking secrets.

See [`docs/user/reference/events.md`](./docs/user/reference/events.md) for the catalog and example listeners.

Brought to you by [CraftPulse](https://craft-pulse.com/)
