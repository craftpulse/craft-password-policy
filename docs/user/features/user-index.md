# User Index Integration

Password Policy threads its data into Craft's native Users element index (table columns, sort options, condition-builder rules, and bulk element actions) rather than building a parallel "Password Policy" CP section. Operators work where they already are; the plugin surfaces what they need to see, filter on, and act on, all from `/admin/users`.

> 📷 *Screenshot: Users index showing the Password Policy columns enabled (Last password change, Days until expiry, Status (composite seven-state pill), Last change reason) with a few rows displaying mixed states (current, expired, reset-required, breached).*

## Table attributes

Nine attributes register on `RegisterElementTableAttributesEvent` for `craft\elements\User`. `UserIndexService::preloadForUsers()` runs once per request to keep cell rendering at O(1) per cell. The full preload issues at most five bounded queries regardless of visible-row count.

| Attribute | Edition | Notes |
|-----------|---------|-------|
| `passwordpolicy_lastChange` | Lite | Date of the last password change. `-` for never-changed. |
| `passwordpolicy_daysUntilExpiry` | Lite | Days remaining until expiry, computed against the resolved policy. Negative for already-expired. |
| `passwordpolicy_expired` | Lite | Boolean badge: red dot for expired, green for not. |
| `passwordpolicy_resetRequired` | Lite | `users.passwordResetRequired` value, surfaced as a badge. |
| `passwordpolicy_status` | Lite | Composite seven-state badge; see "Status priority" below. |
| `passwordpolicy_lastChangeReason` | Lite | Most recent history row's `changeReason` (label-formatted). |
| `passwordpolicy_breached` | Pro | Whether the user has a `lastBreachDetectedAt` value at all. Independent of the recent-window gate on the status badge. |
| `passwordpolicy_policyDrift` | Pro + Craft Team or higher | Whether the most-recent history row's `policySnapshot` differs from what the resolver returns now. |
| `passwordpolicy_groupPolicies` | Pro + Craft Team or higher | Comma-separated list of named policies applying to the user. |

The two `policy*` columns require Craft Team-or-better because Solo Craft installs cannot have user groups (and per-group policy resolution is the whole point of those columns). The `breached` column requires Pro because HIBP-on-login (the only path that populates `lastBreachDetectedAt`) is a Pro feature.

### Status priority

When multiple states apply, the composite `passwordpolicy_status` badge shows the most severe, in this order:

1. **breached** (red), within 90 days of `user_state.lastBreachDetectedAt`
2. **expired** (red), past the resolved expiry window
3. **reset_required** (orange), `users.passwordResetRequired = true`
4. **policy_drift** (yellow, Pro + Team+ only): most-recent history row's `policySnapshot` differs from current resolver output
5. **expiring** (yellow), within 7 days of expiry
6. **never_changed** (gray): no history row exists for the user
7. **ok** (green): none of the above

The 90-day breached window and 7-day expiring window are hardcoded for 5.2.0; promotion to plugin settings is captured in `docs/internal/ideas.md` for a 5.2.x follow-up.

## Sort options

A subset of the table attributes register `RegisterElementSortOptionsEvent` entries; only attributes that map cleanly to a single SQL column qualify. `passwordpolicy_lastChange`, `passwordpolicy_daysUntilExpiry`, `passwordpolicy_expired`, and `passwordpolicy_resetRequired` are sortable; the composite-status and policy-drift columns are not (they're computed across multiple tables).

## Condition rules

Eight condition rules register on `UserCondition::EVENT_REGISTER_CONDITION_RULES`. They appear in the condition builder under the "Password" heading on the Users index toolbar.

| Rule | Edition | Notes |
|------|---------|-------|
| `PasswordExpiredConditionRule` | Lite | Lightswitchable: filter expired vs. not-expired. |
| `PasswordResetRequiredConditionRule` | Lite | Boolean filter on `users.passwordResetRequired`. |
| `PasswordNeverChangedConditionRule` | Lite | Filter users whose `lastPasswordChangeDate IS NULL`. |
| `PasswordExpiringWithinConditionRule` | Lite | Parameterised: "expires within N days". Complements `PasswordExpiredConditionRule` (yes/no) with a window. |
| `LastChangeReasonConditionRule` | Lite | Multi-select on the `ChangeReason` enum (self-service, admin change, force-reset, breach-forced, etc.). |
| `PasswordStatusConditionRule` | Lite | Multi-select on the seven-state composite status. |
| `BreachedRecentlyConditionRule` | Pro | Filter users whose `user_state.lastBreachDetectedAt` is within the last 90 days. |
| `PolicyDriftConditionRule` | Pro + Craft Team or higher | Filter users whose stored policy snapshot diverges from the current resolver output, flagging users who haven't re-validated since a policy change. |

`PasswordExpiredConditionRule` and `PasswordExpiringWithinConditionRule` deliberately overlap. Operators want the lightswitch ergonomics for "show me expired users" plus the parameterised rule for "show me users expiring within a custom window." Both are kept; querying either rules path through the same `expiryAmount` resolver.

## Element actions

Three plugin-owned actions register on `User::EVENT_REGISTER_ACTIONS`. All three respect `allowAdminChanges = false`: `getTriggerHtml()` returns null in read-only mode so the trigger never registers on the index.

| Action | Edition | Notes |
|--------|---------|-------|
| `ForcePasswordReset` | Pro | Sets `passwordResetRequired = true` on selected users. Pins an `AdminForceReset` pending reason on `user_state` so the next history row records why. Bulk-friendly. |
| `ChangeUserPassword` | All editions | Single-user modal: the admin types a new password, the action validates it against the resolved policy, then writes the new hash. The audit context propagates as `AdminChange` with `changedByUserId` set to the operator. Bulk-change-with-same-password is a security anti-pattern; the modal is single-user only. |
| `SendPasswordResetEmail` | All editions | Pins an `AdminForceReset` pending reason on `user_state` and sends Craft's standard reset email. Bulk-friendly. |

`ChangeUserPassword` and `SendPasswordResetEmail` are NOT Pro-gated. The decision is intentional: every operator running Craft has this capability already (via `users/set-password` console command, or the user edit screen's password field). Wiring them as element actions is convenience UX, not a Pro-tier upsell. Pro's actual upsell here is `ForcePasswordReset`: the `AdminForceReset` pending reason that propagates to the audit row is what Pro/Enterprise customers pay for.

## User edit screen: Password Security tab

The User edit screen ships a **Password Security** tab via `UsersController::EVENT_DEFINE_EDIT_SCREENS`. The tab is gated on either `pp:force-reset-passwords` or `pp:change-user-passwords` permission and is visible on every edition (gating is permission-based, not edition-based).

> 📷 *Screenshot: User edit screen with the Password Security tab selected, showing the resolved policy panel, status indicators (last change date, days until expiry, force-reset state), and three action buttons (Change password…, Send reset email, Force password reset on next sign-in).*

The tab renders:

- **Current status**: colour-coded status pills via `Cp::statusLabelHtml()`: green for current, red for expired or breached recently, orange for reset-required, yellow for expiring soon, grey for never-changed.
- **Resolved policy**: the effective rules for this user with the source attribution (which named policies contributed, or "global settings").
- **Per-user action buttons**: Change password… (opens the `ChangeUserPassword` modal with elevated-session protection), Send reset email, Force password reset on next sign-in.
- **Notification activity panel**: the user's last 10 notification log entries with Resend buttons (Pro+, requires `pp:notification-log-view`).
- **Force-reset history**: last 5 history rows with `changeReason` labels.

Read-only mode (`allowAdminChanges = false`) keeps the tab visible but disables every action button; status + resolved policy + activity log are read-only data and remain visible.

## Permissions

| Handle | Notes |
|--------|-------|
| `pp:force-reset-passwords` | Required to use the `ForcePasswordReset` action and the force-reset button on the user-edit Password Security page. |
| `pp:change-user-passwords` | Required to use `ChangeUserPassword` and `SendPasswordResetEmail` actions. |

Either permission also unlocks the Password Security sidebar link on the user edit screen. Defense-in-depth: the permission predicate runs both at sidebar render time AND in `UserSecurityController::beforeAction()`.
