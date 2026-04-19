# Manual Testing Scenarios

Test each scenario after installing the plugin on a fresh Craft CMS 5 site. Start from `5.2.0-alpha.1` and work forward — each branch builds on the previous.

---

## Phase 0 — Edition Infrastructure (alpha.1)

### T0.1 — Edition helpers return correct values
1. Install plugin in Lite edition
2. In a Twig template: `{{ dump(craft.app.plugins.getPlugin('password-policy').getIsLite()) }}` → `true`
3. `getIsPro()` → `false`, `getIsEnterprise()` → `false`
4. Switch to Pro: `getIsPro()` → `true`, `getIsEnterprise()` → `false`
5. Switch to Enterprise: all three → `true`

### T0.2 — Settings model accepts all new attributes
1. Open plugin settings in CP
2. Save without changes → no errors
3. All existing settings preserved (minLength, maxLength, cases, numbers, symbols, etc.)
4. New settings default to off/0 — zero behavior change

### T0.3 — HIBP TLS fix
1. Enable HIBP in settings
2. Set a password known to be breached (e.g., "password123")
3. Should be rejected with breach message
4. Check that `config/guzzle.php` with `'verify' => false` does NOT disable HIBP TLS (the plugin overrides it)

### T0.4 — Log sensitive key stripping
1. Trigger a password-policy log event
2. Check `storage/logs/password-policy-*.log`
3. Confirm no `password`, `newPassword`, `plaintext`, `hash`, or `passwordHash` keys appear

---

## Phase 1 — Database Schema (alpha.2)

### T1.1 — Fresh install creates tables
1. Uninstall and reinstall the plugin
2. Check database: `passwordpolicy_password_history`, `passwordpolicy_audit_log`, `passwordpolicy_blocklist`, `passwordpolicy_notification_log` exist
3. All indexes and foreign keys present

### T1.2 — Upgrade migration seeds history
1. Install plugin at 5.1.1 (before v5.2.0 schema)
2. Create 3 users with passwords
3. Upgrade to 5.2.0 (`ddev craft up`)
4. Check `passwordpolicy_password_history` — one row per user with a password
5. Hashes match `users.password` column

### T1.3 — Seeding disables query logging
1. Enable debug mode (`devMode: true`)
2. Run the upgrade migration
3. Check debug logs — no bcrypt hashes visible

### T1.4 — Uninstall drops all tables
1. Uninstall the plugin
2. All `passwordpolicy_*` tables are gone

---

## Phase 2 — Password History (alpha.3)

### T2.1 — Password change stores history (Pro)
1. Enable Pro edition, set `passwordHistoryCount: 5`
2. Change a user's password to "NewPassword1!"
3. Check `passwordpolicy_password_history` — new row with bcrypt hash
4. Old entries pruned to count limit

### T2.2 — Password reuse rejected (Pro)
1. Set password to "TestPassword1!"
2. Change password to "AnotherPassword2@"
3. Try to change back to "TestPassword1!" → **rejected** with "used recently" message

### T2.3 — History check disabled on Lite
1. Switch to Lite edition
2. Repeat T2.2 — password reuse should be **accepted**

### T2.4 — Force change on first login
1. Enable `forceChangeOnFirstLogin`
2. Create a new user
3. Check user: `passwordResetRequired` = `true`
4. Existing users unaffected

### T2.5 — Recursion guard
1. Enable `forceChangeOnFirstLogin`
2. Create a new user — should succeed without infinite loop
3. Check that only ONE history entry is created (not duplicated)

### T2.6 — Request-end cleanup
1. Set a breakpoint or log after `EVENT_AFTER_REQUEST`
2. Confirm `$_pendingPasswords` is empty after every request

---

## Phase 3 — Advanced Validators (alpha.4)

### T3.1 — Sequential characters rejected (Pro)
1. Enable `checkSequentialChars`
2. Try passwords: `abc12345!` → rejected, `qwerty123!` → rejected
3. `Hx9$mK2p` → accepted (no sequences)

### T3.2 — Repeated characters rejected (Pro)
1. Enable `checkRepeatedChars`
2. `aaa12345!` → rejected, `111abcDE!` → rejected
3. `Hx9$mK2p` → accepted

### T3.3 — Contextual check (Pro)
1. Enable `checkContextual`, user: username=`johndoe`, email=`johndoe@example.com`
2. `johndoe123!` → rejected (contains username)
3. `example123!` → rejected (contains email domain — wait, checks local part, not domain)
4. `johndoe` in password → rejected
5. System name in password → rejected

### T3.4 — Common password blocklist (Pro)
1. Enable `checkCommonPasswords`
2. Run `ddev craft password-policy/blocklist/update` (or install migration seeds)
3. `password` → rejected, `123456` → rejected
4. `Hx9$mK2pQr!` → accepted

### T3.5 — Minimum character types mode (Pro)
1. Set `complexityMode: 'minimum'`, `minimumCharacterTypes: 3`
2. `abcdefgh` (1 type) → rejected
3. `Abcdefgh` (2 types) → rejected
4. `Abcdefg1` (3 types) → accepted
5. `Abcde1!` (4 types) → accepted

### T3.6 — Blocklist CLI commands
1. `ddev craft password-policy/blocklist/stats` → shows counts
2. `ddev craft password-policy/blocklist/update` → re-seeds common list
3. Create `custom-words.txt` with test words, run `ddev craft password-policy/blocklist/import --file=custom-words.txt`
4. Verify custom words are blocked

---

## Phase 4 — Audit Logging (alpha.5)

### T4.1 — Password change logged (Enterprise)
1. Enable Enterprise + `enableAuditLog`
2. Change a user's password
3. Check `passwordpolicy_audit_log` — row with `event=password_changed`, `outcome=success`
4. `ipHash` is a SHA-256 hash (not raw IP)
5. `userIdentifier` is an HMAC hash (not email)

### T4.2 — Audit log silent on Lite/Pro
1. Switch to Pro, repeat password change
2. `passwordpolicy_audit_log` — **no new rows**

### T4.3 — HIBP breach detection logged
1. Enterprise + audit enabled
2. Set password to a known breached password (e.g., "password")
3. Password rejected AND `hibp_breach_detected` entry in audit log

### T4.4 — HIBP fail-closed mode
1. Set `pwnedFailMode: 'closed'`
2. Block HIBP API (e.g., via hosts file or firewall)
3. Try to change password → **rejected** with "Unable to verify" message
4. `hibp_check_failed` in audit log with `failMode: closed`

### T4.5 — Account lockout logged
1. Enterprise + audit
2. Attempt 5+ failed logins to trigger Craft lockout
3. `account_locked` entry in audit log

### T4.6 — Audit CLI
1. `ddev craft password-policy/audit/export --format=csv --days=30` → CSV to stdout
2. `ddev craft password-policy/audit/export --format=json` → JSON to stdout
3. `ddev craft password-policy/audit/purge --days=0` → purges all entries

---

## Phase 5 — Per-Group Policies (beta.1)

### T5.1 — Global policy when no groups
1. Craft Solo (no groups) → `PolicyResolverService::resolveForUser()` returns global settings
2. User with no group assignments → global settings

### T5.2 — Single group policy merge
1. Create group "Editors" with policy: `minLength: 12`
2. Enable `enablePerGroupPolicies`, assign policy to group
3. User in Editors → resolved `minLength` is 12 (overrides global 6)

### T5.3 — Multi-group "most restrictive wins"
1. Group A: `minLength: 8`, Group B: `minLength: 12`
2. User in both → resolved `minLength` is 12 (highest wins)
3. Group A: `cases: true`, Group B: `cases: false`
4. Resolved → `cases: true` (true wins)

### T5.4 — Invalid merge state
1. Group A: `minLength: 16`, Group B: `maxLength: 12`
2. Resolved → warning logged, `maxLength` corrected to 16

### T5.5 — Presets
1. Apply NIST preset to a group: verify `minLength: 8`, `pwned: true`, complexity off
2. Apply OWASP preset: verify `minLength: 12`, `maxLength: 128`
3. Apply Strict Enterprise: verify all toggles on, history 5, 90-day expiry

---

## Phase 6 — User Index Integration (beta.2)

### T6.1 — Condition rules
1. Go to Users index → click condition builder
2. "Password Expired" rule available → toggle on → filters correctly
3. "Password Reset Required" rule → filters `passwordResetRequired = true` users
4. "Password Never Changed" rule → filters `lastPasswordChangeDate IS NULL` users

### T6.2 — Bulk force reset action (Pro)
1. Select multiple users in Users index
2. "Force Password Reset" action available
3. Execute → confirmation dialog → users flagged with `passwordResetRequired = true`
4. On Lite → action not available

---

## Phase 8 — Developer Events (beta.3)

### T8.1 — PasswordChangedEvent fires
1. Register an event listener in a test module:
   ```php
   Event::on(PasswordPolicy::class, PasswordPolicy::EVENT_PASSWORD_CHANGED, function($event) {
       Craft::warning("Password changed for user {$event->user->id}, isNew: " . ($event->isNew ? 'yes' : 'no'));
   });
   ```
2. Change a user's password → warning logged
3. Verify `$event->user->newPassword` is `null` (plaintext already gone)

### T8.2 — Session invalidation
1. Log in as User A on two different browsers
2. Force reset User A from admin panel
3. Browser 1 (admin) stays logged in
4. Browser 2 (User A) is logged out on next request

### T8.3 — Group force reset
1. Create group with 3 users
2. `RetentionService::resetPasswordsByGroup($groupId)` → returns 3
3. All 3 users have `passwordResetRequired = true`
4. Admin users in the group are skipped

---

## Phase 9 — Notifications + GC + Validation (beta.4)

### T9.1 — Twig variables
1. In a template: `{{ craft.passwordpolicy.passwordStatus() }}` → `current`/`expiring`/`expired`/etc.
2. `{{ craft.passwordpolicy.daysUntilExpiry() }}` → number or null
3. `{{ craft.passwordpolicy.isExpiring(7) }}` → true/false
4. `{{ craft.passwordpolicy.activeSessionCount() }}` → number
5. Not logged in → safe defaults (null, false, 'unknown', 0)

### T9.2 — AJAX validation endpoint
1. `POST /password-policy/validate` with body `{ "password": "abc" }`
2. Response: JSON with per-rule `pass: true/false/null` results
3. HIBP rule returns `null` if still checking
4. Works without CSRF for anonymous requests
5. Works with CSRF for CP requests

### T9.3 — GC auto-purge
1. Set `notificationLogRetentionDays: 0` (purge everything)
2. Trigger Craft GC: `ddev craft gc`
3. `passwordpolicy_notification_log` is empty
4. Repeat for `passwordHistoryExpiryDays` and `auditLogRetentionDays`

### T9.4 — Notification dedup
1. Call `sendPasswordExpiryReminder()` twice for same user
2. Only one email sent (dedup within reminder window)
3. Only one `notification_log` entry

---

## Phase 7 — Settings UI (beta.5)

### T7.1 — All tabs render
1. Open plugin settings
2. 7 tabs: Configuration, Password Rules, Password Retention, Password History, Advanced Validators, Group Policies, Audit Logging
3. Each tab renders without errors

### T7.2 — Edition gating in UI
1. Lite edition: Password History, Advanced Validators, Group Policies show "Pro edition required"
2. Audit Logging shows "Enterprise edition required"
3. Pro: all except Audit Logging accessible
4. Enterprise: all tabs accessible

### T7.3 — Edition stripping on save
1. Lite edition: manually POST Pro settings via browser dev tools
2. Save → Pro settings are **stripped** (not saved)
3. Database/project config unchanged for gated settings

### T7.4 — Complexity mode toggle
1. Pro: select "Minimum character types" → individual toggles hidden
2. Select "Individual toggles" → minimum selector hidden
3. Save and reload → selection persists

### T7.5 — HIBP fail-mode warning
1. Set fail-mode to "closed"
2. Warning appears about blocking password changes during outages

---

## Cross-Cutting Concerns

### TX.1 — PHPStan + ECS pass on every branch
1. `composer check-cs` → no errors
2. `composer phpstan` → no errors

### TX.2 — Zero behavior change on upgrade from 5.1.1
1. Install 5.1.1, configure settings, create users
2. Upgrade to 5.2.0
3. All existing behavior identical — no new validation, no new UI elements
4. New settings all default to off/0

### TX.3 — Sensitive data never logged
1. Enable debug mode
2. Perform password operations
3. Grep all log files for password-like strings — none found
4. Check `passwordpolicy_audit_log.details` — no `password`, `hash`, `userAgent`, or `ip` keys
