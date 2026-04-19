# Phase 5 — Per-Group Policies + Presets + Policy Resolver

## Overview

Phase 5 enables per-group password policies with "most restrictive wins" merge logic and pre-configured compliance presets.

## PolicyResolverService

### `resolveForUser(User $user): SettingsModel`

Resolution logic:
1. If not Pro, or `enablePerGroupPolicies` is false, return global settings
2. Get user's groups
3. For each group with a configured policy, create a `GroupPolicyModel`
4. Merge all group policies with global using "most restrictive wins"
5. Post-merge validation: if `maxLength < minLength`, warn and correct

### Merge Rules

| Setting Type | Rule | Example |
|-------------|------|---------|
| Integer minimum (minLength, passwordHistoryCount) | Highest value wins | Groups with 8 and 12 → 12 |
| Integer maximum (maxLength) | Lowest non-zero wins; 0 = no limit | Groups with 128 and 0 → 128 |
| Boolean enablers (cases, numbers, etc.) | `true` wins | One group has cases=true → true |
| Complexity mode | `individual` wins over `minimum` | Mixed → individual |
| Expiration | Shortest period wins | 90 days vs 180 days → 90 days |

## GroupPolicyModel

Mirrors policy fields from SettingsModel. `null` = inherit from global. The `mergeWithGlobal()` method applies merge rules to produce a complete SettingsModel.

## PolicyPreset Enum

Three pre-configured templates:

### NIST 800-63B
- minLength: 8
- No complexity toggles
- No expiration
- HIBP: enabled
- Passphrase-friendly (existing regex accepts spaces and Unicode)

### OWASP ASVS Level 1
- minLength: 12
- maxLength: 128 (V2.1.2)
- No complexity toggles
- No expiration
- HIBP: enabled

### Strict Enterprise
- minLength: 12
- All complexity on (cases, numbers, symbols)
- History: 5
- All advanced validators on
- 90-day expiration
- HIBP: enabled

## Usage

```php
// Apply NIST preset to a group
$preset = PolicyPreset::NIST_800_63B;
$groupPolicy = $preset->toGroupPolicy();
```

## Post-Merge Validation

If group A sets minLength=16 and group B sets maxLength=12, the merged result would be invalid (min > max). The resolver logs a warning and uses minLength as the effective maxLength.
