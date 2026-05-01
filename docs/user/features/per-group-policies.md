# Phase 5 — Per-Group Named Policies + Presets + Policy Resolver

## Overview

Pro feature. Admins create **named policies** in the CP, each with a tri-state override per rule (Off / Global / On) and an optional preset starting template. Policies are assigned to one or more user groups via a junction table. The PolicyResolverService merges all policies applying to a user using two-phase resolution.

## Architecture

| Component | Purpose |
|---|---|
| `passwordpolicy_policies` table | Stores named policies with JSON settings |
| `passwordpolicy_policy_groups` junction table | Links policies to user groups |
| `PolicyModel` | The named policy entity (name, handle, preset, settings, sortOrder) |
| `PolicyService` | CRUD operations + group assignment sync |
| `PolicyResolverService` | Merges policies for a user into a resolved `SettingsModel` |
| `PolicyController` | `index`, `edit`, `save`, `delete`, `reorder` actions |
| `GroupPolicyModel` | Internal merge target — exposes `mergeWithGlobal()` for non-bool fields and `booleanOverrideFields()` for the resolver's bool pre-pass |
| `PolicyPreset` enum | NIST_800_63B, OWASP_ASVS, PCI_DSS_V4, STRICT_ENTERPRISE — each has a `toGroupPolicy()` method that returns the canonical preset values |
| Migration `m260426_000000_AddPoliciesTables` | Creates tables, migrates legacy `groupPolicies` settings array into named policies, renames `pwned`→`hibp` |

## CP UI

### Settings → Group Policies

A toggle (`enablePerGroupPolicies`) plus a "Manage Policies" button linking to the policies index. When enabled, the "Policies" subnav item appears (above "Settings").

### Policies index (`/admin/password-policy/policies`)

VueAdminTable with columns:
- **Name** — link to the policy edit screen
- **Groups** — comma-separated assigned group names
- **Preset** — preset label or "Custom"
- **Changes** — divergence count vs the preset (or `—`)

A small **blue dot icon** appears next to policy names whose values diverge from their preset. Clicking such a policy navigates directly to the Rules tab via `#rules` deep-link.

### Policy edit screen

`asCpScreen()` with three tabs:

- **General** — name, handle, preset selector, "Restore preset defaults" button (when preset diverged), assigned groups
- **Rules** — min/max length, password history count, HIBP fail mode, then a compact `<table class="data">` of tri-state boolean overrides
- **Lifecycle** — expiry amount + period

Toolbar (next to Save): **"Reset all to global"** button — clears every override on the form.

### Tri-state rule overrides

For each boolean rule (cases, numbers, symbols, hibp, sequential, repeated, contextual, common):

| Button | Value | Meaning |
|---|---|---|
| ❌ Red X | `0` (false) | Override OFF — explicit "this rule does not apply to assigned groups" |
| ⚪ Hollow grey circle | `''` (null) | Inherit global setting |
| ✓ Green check | `1` (true) | Override ON — explicit "this rule applies" |

Markup mirrors the `craftcms/webhooks` event filter pattern: `<div class="btngroup"><div class="btn">…</div></div>` with Craft's icon font (`data-icon="remove"` / `"checkmark"`) and `<div class="status inactive">` for the hollow circle. Active state uses `var(--bg-enabled)` / `var(--bg-disabled)` for accessibility-tested colors.

### Override warnings

Numeric fields and the HIBP fail mode select use Craft's native `warning:` parameter (mirrors the Blitz config-override pattern):

- Numeric fields show a warning when the explicit value **differs** from global (e.g. *"This setting overrides the global value of `8`."*)
- HIBP fail mode shows informational text when set to "Inherit global" (revealing the global value), and a warning when explicitly overridden

Implemented via two macros in `_policies/_macros.twig`:

```twig
{% macro overrideWarning(globalValue) -%}
    {{ 'This setting overrides the global value of `{value}`.'|t('password-policy', { value: globalValue })|markdown(inlineOnly=true) }}
{%- endmacro %}

{% macro inheritsGlobal(globalValue) -%}
    {{ 'Currently using the global setting: `{value}`.'|t('password-policy', { value: globalValue })|markdown(inlineOnly=true) }}
{%- endmacro %}
```

### Divergence-from-preset indicator

Fields whose value differs from the policy's preset get a **blue left border** (`.pp-divergent`). Computed server-side via `PolicyModel::getDivergentFields()`. Works on numeric fields, the HIBP fail mode select, the bool rule rows, and the lifecycle expiry field.

## PolicyResolverService

### `resolveForUser(User $user): SettingsModel`

Resolution logic:

1. If not Pro, or `enablePerGroupPolicies` is false → return global settings unchanged
2. Get user's groups; if none → return global
3. Query named policies via `PolicyService::getPoliciesForGroupIds()`
4. **Two-phase merge:**
   - **Bool pre-pass** — for each boolean field, check all policies: any explicit `true` wins; otherwise any explicit `false` wins; otherwise keep global
   - **Non-bool sequential merge** — apply each policy's `mergeWithGlobal()` (handles ints, selects, expiry)
5. Post-merge validation: if `maxLength < minLength`, log warning and use minLength as effective maxLength

### Merge rules (non-bool fields)

| Setting | Rule | Example |
|---|---|---|
| Integer minimum (`minLength`, `passwordHistoryCount`, `minimumCharacterTypes`) | Highest value wins | 8 + 12 → 12 |
| Integer maximum (`maxLength`) | Lowest non-zero wins; 0 = no limit | 128 + 0 → 128 |
| `hibpFailMode` | `closed` wins over `open` | mixed → closed |
| `complexityMode` | `individual` wins over `minimum` | mixed → individual |
| Expiration | Shortest period wins | 90d vs 180d → 90d |

### Boolean resolution semantics

For each boolean field across all matching policies:
- Any policy says `true` → resolved = `true` (most restrictive)
- Else any policy says `false` → resolved = `false` (single-group exemption honored)
- Else (all `null`) → resolved = global value

This lets a single group's explicit Off override global On for that group's users (e.g. exempt a legacy/external group from sequential-char checks), while still ensuring multi-group users get the most-restrictive resolution when groups conflict.

## Presets

Each preset is defined in `PolicyPreset::toGroupPolicy()`. The same values are duplicated in the edit template's preset auto-fill JS for client-side previewing — both should stay in sync.

### NIST 800-63B
- minLength: 8
- All complexity off (passphrase-friendly)
- No expiration
- HIBP: on

### OWASP ASVS L1
- minLength: 12
- maxLength: 128 (V2.1.2)
- All complexity off
- No expiration
- HIBP: on

### PCI-DSS v4.0
- minLength: 12
- cases: on, numbers: on, symbols: off (per spec)
- HIBP: on
- History: 4
- Common passwords: on
- Expiry: 90 day(s) (Req 8.3.9)

> Note: 90-day rotation conflicts with NIST 800-63B SHOULD-NOT guidance on periodic password changes.

### Strict Enterprise
- minLength: 12
- All complexity on (cases, numbers, symbols)
- HIBP: on, fail mode: closed
- History: 5
- All advanced validators on
- Expiry: 90 day(s)

## Divergence helpers

`PolicyModel::getOverrideFields(): array<string>` — returns names of fields with explicit (non-null) values.

`PolicyModel::getDivergentFields(): array<string>` — returns names of fields where the policy differs from its preset. If no preset is set, returns the same as `getOverrideFields()`.

Used by:
- The policies index to compute the "Changes" column count
- The edit screen to apply `.pp-divergent` blue-border CSS class to divergent fields/rows

## Controller details

### `_normalizeSettings()` tri-state handling

POST values arrive as strings. The normalizer maps:

| POST value | Normalized | Stored in JSON? |
|---|---|---|
| missing or `''` | (skipped) | No — null = inherit |
| `'0'` | `false` | Yes |
| `'1'` | `true` | Yes |

Numeric fields: `''` is treated as "not set" (inherit). Empty strings are dropped.

`expiryPeriod` is only meaningful with an `expiryAmount` — orphaned `expiryPeriod` is stripped.

### `PolicyModel::setSettingsFromArray()`

Resets every override field to `null` first, then applies the values from the array. The array is treated as the **complete** representation of overrides — anything missing means inherit. This makes "Reset all to global" work correctly: form submits empty settings → all fields cleared.
