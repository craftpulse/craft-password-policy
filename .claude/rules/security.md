<!-- craftcms-claude-skills -->
# Security — craftpulse/craft-password-policy

This is a security plugin. Holding a higher standard for itself than for typical Craft plugins is the point. The conventions below are non-negotiable.

## Sensitive data — never log

`PasswordPolicy::log()` strips `SENSITIVE_LOG_KEYS` (`password`, `newPassword`, `plaintext`, `hash`, `passwordHash`) from `$params` before encoding. Defense-in-depth for any consumer or future code that calls log() with a payload containing these keys.

`#[\SensitiveParameter]` on every plaintext password argument. PHP 8.2+ omits the value from stack traces and `serialize()` output. Forgetting this on a public method is a finding in code review.

## HIBP — privacy guards

Listener at `User::EVENT_BEFORE_AUTHENTICATE` (only Craft 5 hook with synchronous plaintext-in-scope access during login).

**Never log:**
- The plaintext password.
- The full SHA-1 hash.
- The full prefix-and-suffix bucket.

**OK to log:**
- "match found, user X notified" booleans.
- The 5-char SHA-1 prefix is k-anonymity safe — it's intentionally what we send to HIBP — but don't log it just because it's safe; log only what's operationally useful.

**Privacy comment required** at the listener so a future reader doesn't accidentally relax the rule.

## HIBP — failure modes

- **API down / non-2xx (not 429)** — fail-open. Log at `Logger::LEVEL_WARNING` (not ERROR — every transient outage shouldn't page someone). Return `null` so callers can distinguish "unable to check" from "not breached."
- **429 rate limit** — site-wide backoff cache key (`pp:hibp-429-backoff`, value `'1'`, TTL = `Retry-After` header or `HIBP_DEFAULT_BACKOFF_SECONDS`). Every caller short-circuits via `isHibpBackoffActive()` before hitting the API. Per-user dedup is downstream of this.
- **TLS** — `'verify' => true` on the Guzzle client at the request site. Overrides any site-level `config/guzzle.php` `verify => false`.

## Edition strip on save

`SettingsController::actionSave` unconditionally `unset()`s edition-gated keys before `savePluginSettings()`. Even crafted POST payloads carrying Pro/Enterprise keys can't survive on a sub-edition install. Defense-in-depth — UI doesn't render the gated fields, but the strip is the second line.

When adding a new Pro or Enterprise setting key, **add it to the strip block in the same commit**. Forgetting means a Lite user can write to Pro keys via curl.

## Front-end validation endpoint (`password-policy/validation/validate`)

- Anonymous-allowed (used by AJAX validators on registration / reset pages).
- For anonymous requests, ignore `username` / `email` POST params for zxcvbn context — accepting attacker-controlled context lets the response leak signal about a known-username password's strength model. For authenticated requests, take values from `Craft::$app->getUser()->getIdentity()`.
- Truncate context strings to a sane length defensively (254 chars).

## Migrations + bcrypt seed loops

When a migration seeds password history (or any flow that batch-inserts bcrypt hashes), **toggle `enableLogging` and `enableProfiling` off** before the loop, restore in `finally`. Yii's debug logger would otherwise capture the hashes at SQL bind time.

## Project config writes

Wrap in `$projectConfig->muteEvents = true` try/finally. Prevents internal subscribers from re-entering during plugin-managed key renames (e.g. `pwned` → `hibp` rename in `m260429_224908_UpgradeTo520Schema`).

## CSRF + CSP

- All POST controllers enforce CSRF (Craft default; never disable).
- Plugin's CP indicator script supports CSP nonces via the `cspNonce` setting — when on, `Craft::$app->getSecurity()->getNonce()` is passed through asset registration.
- Front-end builders' inline JS (if any — try to keep zero) uses the same nonce path.

## Password change flows

Front-end `PasswordChangeController` invalidates other sessions for the user after successful save. Belt-and-braces: Craft's `User::afterSave` already does this in 5.9.21+, but the explicit wiring documents the security contract.
