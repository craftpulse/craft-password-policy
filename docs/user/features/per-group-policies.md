# Per-Group Policies (Pro)

Different teams need different password rules. Customer-facing front-end accounts may need a friendlier policy than admin staff; vendors and external contractors may need a stricter floor. Per-group policies let you create **named policies** in the control panel, apply one of five compliance presets (or build from scratch), and assign each policy to one or more Craft user groups.

> [!TIP]
> **Compliance presets (Pro)**
>
> The **Compliance Presets** page at **Settings → Password Policy → Compliance Presets** lets a Pro install overwrite the global policy with NIST 800-63B, OWASP ASVS L1, PCI-DSS v4.0, CIS Controls v8, or Strict Enterprise values in one click. The page is gated to Pro, applying a preset is a framework-named conformance commitment, and the Pro tier is where the named-policy + per-group infrastructure lives. Lite installs can hand-configure the same field values manually via the regular settings pages.
>
> Per-group named-policy CRUD (the rest of this page) is the deeper Pro feature: applying *different* presets to *different* groups, divergence indicators, conflict UX, merge resolution.

This page covers the policies CRUD workflow, the five bundled presets, tri-state rule overrides, how merging works when a user belongs to multiple groups, and how to use the resolver from your own code.

## How it works

Each named policy carries the same fields as the global settings: length, complexity, validators, expiry, history. For each field, the policy either:

- **Overrides** the global value (e.g. `minLength = 12` on a Customers policy when global is `8`), or
- **Inherits** the global value (leave the field empty).

Boolean fields (`cases`, `numbers`, `symbols`, `hibp`, `checkSequentialChars`, `checkRepeatedChars`, `checkContextual`, `checkCommonPasswords`) have a **three-state** override per policy: explicit On, explicit Off, or Inherit Global. The merge logic when a user belongs to multiple groups is "most-restrictive wins" with one exception for explicit Offs, see [Merging](#merging) below.

A policy applies to a user when the user belongs to any of the policy's assigned groups. A user belonging to zero groups gets the global policy. A user belonging to multiple groups gets the merged result.

## Enabling per-group policies

Open **Settings → Password Policy → Per-Group Policies** and toggle **Enable per-group policies**. The **Policies** subnav appears between Blocklist and Settings.

> [!TIP]
> **Solo Craft installs**
>
> Per-group policies require Craft Team or higher (Solo Craft doesn't have user groups). The Pro edition itself is available on every Craft license, but the per-group surface needs groups to apply policies to. On Solo, this toggle is hidden and the global policy applies to all users.

## Creating a policy

Open **Password Policy → Policies → New policy** in the control panel.

The edit screen has three tabs:

### General

- **Name**: Display name shown in the policies index and in user-edit screens. Pick something readable for your team (e.g. "Customers (NIST)", "Admins (Strict)").
- **Handle**: Auto-generated from the name; you can override it. Used for `craft.passwordPolicy.requirements({ groups: ['editors'] })` calls in templates.
- **Preset**: Apply one of the five bundled compliance presets as a starting template. See [Presets](#presets) below. Leave blank for a fully custom policy.
- **Assigned groups**: Multi-select. The policy applies to users in any of the selected groups.

### Rules

- **Min/max length**: Numeric fields with override warnings showing the global value.
- **HIBP fail mode**: `Open` (accept on API failure) or `Closed` (reject). Inherits global if left blank.
- **Tri-state rule overrides**: A compact table of the eight boolean rules with three buttons each:

| Button | Value | Meaning |
|---|---|---|
| ❌ Red X | `Off` | Explicit override: this rule does NOT apply to assigned groups, even if globally enabled. |
| ⚪ Hollow circle | `Global` | Inherit the global setting. |
| ✓ Green check | `On` | Explicit override: this rule applies to assigned groups, even if globally disabled. |

The keyboard navigation on the rule overrides table follows the WAI-ARIA radiogroup pattern: Tab into the table, then arrow keys move between options. Home/End jump to the first/last rule.

### Lifecycle

- **Expiry amount + period**: How long passwords are valid (e.g. `90 days`). Leave blank to inherit global expiry, or set to disable (override on a policy that should never expire).

### Saving

Click **Save**. The policy is immediately active for users in the assigned groups. They'll see the new rules on their next password change.

## Presets

Five bundled compliance presets let you start from a known-good policy and customise from there. Presets are a Pro feature, because applying one is a framework-named commitment, and the Pro tier is where the named-policy + per-group infrastructure lives. Lite installs can still hand-configure any preset's underlying field set; what's gated is the one-click apply.

> [!WARNING]
> **Picking a preset is a framework commitment**
>
> Each preset maps to a specific compliance framework. NIST 800-63B Rev. 4 forbids composition rules and periodic rotation; PCI DSS v4.0.1 requires both. CIS Controls v8 requires annual rotation. Don't mix-and-match, pick the preset that matches your audit and customise within its constraints. See [Compliance frameworks](../operations/compliance-frameworks.md) for the clause-by-clause mapping.

### NIST 800-63B Rev. 4

```
minLength: 15
hibp: true
checkCommonPasswords: true
cases: false (composition rules forbidden)
numbers: false
symbols: false
expiryAmount: null (rotation forbidden)
```

NIST 800-63B Rev. 4 (finalised 31 July 2025) sets a 15-character minimum for single-factor authentication, requires a blocklist of compromised + commonly-used passwords (HIBP + `checkCommonPasswords` together), and explicitly forbids composition rules + periodic rotation. The §3.2.2 rate-limiting requirement (≤100 consecutive failed attempts) is delegated to Craft core (`maxInvalidLogins`).

### OWASP ASVS L1

```
minLength: 12
maxLength: 128
hibp: true
cases: false (no composition mandates)
expiryAmount: null
```

OWASP ASVS Level 1 baseline: passphrase-friendly, breach-checking, no composition rules. Suitable for general consumer accounts where you want a defensible policy without picking a side on the composition-rules debate.

### PCI DSS v4.0.1

```
minLength: 12
cases: true (numeric AND alphabetic)
numbers: true
hibp: true
checkCommonPasswords: true
passwordHistoryCount: 4
expiryAmount: 90 days
```

PCI DSS v4.0.1 §8.3.6 to §8.3.9 compliance: 12-char min (or 8 for legacy), numeric + alphabetic mix, last-4 history, 90-day rotation. **The 90-day rotation conflicts with NIST 800-63B Rev. 4's SHALL NOT rotate.** This is the right preset only if you're under PCI scope.

### CIS Controls v8

```
minLength: 14
maxLength: 128
hibp: true
checkCommonPasswords: true
cases: false (length over complexity)
numbers: false
symbols: false
passwordHistoryCount: 5
expiryAmount: 365 days
```

CIS Controls v8 Safeguard 5.2 sets the length floor at 14 chars for password-only accounts (8 for MFA-enabled). The plugin defaults to 14 because MFA presence can't be reliably detected at preset-apply time. The CIS Password Policy Guide companion adds last-5 history, continuous breach checking, common-password blocklist, and one-year expiration. **The 365-day rotation conflicts with NIST 800-63B Rev. 4's SHALL NOT rotate**, pick CIS only if you're under CIS scope (US federal contractors, CIS Benchmark shops).

### Strict Enterprise

```
minLength: 12
cases: true
numbers: true
symbols: true
hibp: true (fail-closed)
checkCommonPasswords: true
checkSequentialChars: true
checkRepeatedChars: true
checkContextual: true
passwordHistoryCount: 5
expiryAmount: 90 days
```

Maximum enforcement for privileged users: admins, finance staff, security operators. Fails closed on HIBP outages (reject when the API is unreachable). 90-day rotation. Use this for groups where the convenience trade-off is worth the friction. Sets `checkSequentialChars`, `checkRepeatedChars`, and `checkContextual`, Pro-only validators.

### Customising a preset

After picking a preset, you can override individual fields. The policy edit screen shows:

- **Divergence indicators**: Fields that differ from the preset get a blue left-border. The policies index shows a "Changes" column with the divergence count + a blue dot next to the policy name.
- **Override warnings**: Numeric fields and the HIBP fail mode select show a small "This setting overrides the policy preset" warning when you've changed them.
- **Restore preset defaults** button: top-right of the edit screen when divergence > 0. One click reverts every field to the preset's value.
- **Reset all to global** button: One click clears every override on the policy, making it a no-op clone of the global settings. Useful for starting fresh.

## Merging

When a user belongs to multiple groups, each of which has a different policy applied, the resolver merges them into a single effective policy.

The rules:

### Numeric fields

| Field | Rule | Example |
|---|---|---|
| `minLength`, `passwordHistoryCount`, `minimumCharacterTypes` | Highest value wins | 8 + 12 → 12 |
| `maxLength` | Lowest non-zero wins; 0 = no limit | 128 + 0 → 128 |

### Enum fields

| Field | Rule | Example |
|---|---|---|
| `hibpFailMode` | `closed` wins over `open` | mixed → `closed` |
| `complexityMode` | `individual` wins over `minimum` | mixed → `individual` |

### Expiry

Shortest period wins. A user in a 90-day-rotation group AND a 180-day-rotation group ends up on the 90-day window.

### Boolean fields (tri-state semantics)

For each boolean field across all matching policies:

1. Any policy says **On** → resolved = `true` (most-restrictive wins).
2. Otherwise, any policy says **Off** → resolved = `false` (a single group's explicit exemption is honoured).
3. Otherwise (all policies inherit) → resolved = the global setting.

This lets you exempt a single group from an otherwise-global rule. Example: a legacy "External vendors" group with `checkSequentialChars = Off` will let external vendors use sequential-character passwords even if the global setting requires the check, useful when migrating accounts that pre-date the rule.

If any other group's policy says `On` for that field, the explicit On wins and the exemption doesn't apply for users in both groups.

## Conflict notice

If you save a policy whose `minLength` exceeds the global `maxLength`, the plugin surfaces a conflict notice on the edit screen and on the policies index:

> ⚠️ **Conflict:** This policy's minLength (`14`) is higher than your global maxLength (`12`). Users in assigned groups cannot satisfy both. Raise the global maxLength or lower this policy's minLength.

The notice is informational; saving still works. The resolver handles the conflict by clamping the effective maxLength to the resolved minLength + logging a warning.

## Reading the resolved policy from your code

### From Twig

```twig
{# Resolved policy for the current user #}
{% set rules = craft.passwordPolicy.requirements() %}
<p>Your password must be at least {{ rules.minLength }} characters.</p>

{# Resolved policy for a hypothetical group assignment (registration preview) #}
{% set rules = craft.passwordPolicy.requirements({ groups: ['customers'] }) %}
```

The `groups` parameter accepts group handles. Useful on registration pages where you want to show the user what policy they'll be subject to before they pick their group / role.

### From PHP

```php
use craftpulse\passwordpolicy\PasswordPolicy;

$resolved = PasswordPolicy::$plugin->getPolicyResolver()->resolveForUser($user);
// $resolved is a SettingsModel with all fields merged
```

For a fully decoupled call site, use the service's `resolveForUserGroupHandles(array $handles)` variant to skip the User object lookup.

## Inspecting the resolved policy

There is no console command for this. Two surfaces answer "what rules actually apply to this user":

- **The user's Password Security screen** in the control panel, and the **Group policies** column on the Users index, both show which named policies apply to an account.
- **The REST API's `policy/resolve` endpoint** (Enterprise) returns the resolved rule set as JSON for a given user UID. See [REST API](../reference/rest-api.md#get-policyresolve).

From your own code, call the resolver directly, as shown above.

## See also

- [Validators](./validators.md): the eight individual rules + the composite minimum-character-types mode.
- [Password history](./password-history.md): block reuse of the last N passwords (per-group `passwordHistoryCount` overrides require Pro).
- [Compliance frameworks](../operations/compliance-frameworks.md): clause-by-clause mapping for evidence packages.
- [Audit logging](./audit-logging.md): `policy_changed` audit events capture field-level diffs on every save (Enterprise).
- [Front-end Twig builders](./frontend-twig.md): render builders that consume the resolved policy automatically.
