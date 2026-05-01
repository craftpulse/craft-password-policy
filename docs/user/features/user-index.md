# Phase 6 — User Index & Profile Integration

## Overview

Phase 6 integrates password policy data into Craft's Users index and user edit screen. Condition rules enable filtering, the bulk action enables mass force-reset, and the user tab shows password security details.

## Condition Rules

Three condition rules registered on `UserCondition::EVENT_REGISTER_CONDITION_RULES`:

### PasswordExpiredConditionRule
- Filters users whose `lastPasswordChangeDate` is older than the expiry threshold
- Computes threshold from `expiryAmount`/`expiryPeriod` settings
- Lightswitchable: toggle between expired and not-expired

### PasswordResetRequiredConditionRule
- Filters users where `passwordResetRequired = true`
- Simple boolean condition

### PasswordNeverChangedConditionRule
- Filters users where `lastPasswordChangeDate IS NULL`
- Users who have never changed their password since account creation

## Bulk Action: ForcePasswordReset

Registered on `User::EVENT_REGISTER_ACTIONS` (Pro only).

- Sets `passwordResetRequired = true` on selected users
- Skips users already flagged
- Returns count of affected users
- Confirmation dialog before execution

## User Edit Tab: Password Security

Template at `_users/password-security.twig`:
- Current password status (color-coded: green/red/orange)
- Which policy applies and why
- Force Reset button (gated by `pp:force-reset-passwords` permission)

## Edition Gating

- Condition rules: All editions
- Bulk action: Pro+
- User edit tab: Pro+ (when registered via URL rules)
