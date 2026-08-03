# Validators

The plugin ships eight password validators, each toggleable via plugin settings (Lite + Pro) or per-policy override (Pro). This page documents what each validator does, when it runs, and how to extend it.

## What's available

| Validator | Default | Edition | What it rejects |
|---|---|---|---|
| **Min/max length** | Min 6, Max 0 (unlimited) | Lite | Passwords shorter than min or longer than max. |
| **Complexity (individual)** | Off | Lite | Passwords missing the required character types (`cases`, `numbers`, `symbols`). |
| **Complexity (minimum)** | Off | Pro | Passwords matching fewer than `minimumCharacterTypes` of the four types. |
| **HIBP** | Off (Lite) / On (Pro) | Lite | Passwords found in the Have I Been Pwned breach database. |
| **Common passwords** | Off | Lite | Passwords matching the bundled blocklist (10,000 SecLists common credentials) plus admin-managed custom words. |
| **Sequential characters** | Off | Pro | Passwords containing 3+ sequential ASCII characters or keyboard-row runs (`abc`, `xyz`, `321`, `qwerty`, `asdf`). |
| **Repeated characters** | Off | Pro | Passwords containing 3+ repeated characters (`aaa`, `111`, `!!!`). Unicode-aware. |
| **Contextual data** | Off | Pro | Passwords containing the user's username, email local-part, first/last name, system name, or primary site domain. |

Some validators (HIBP, Common passwords, Contextual data) need external context to make a decision: the user's email, a cache of blocked words, an API connection. The plugin gates them off by default to keep the Lite install cheap; flip the toggle on when the cost is worth it.

## Validation order

Validators run in a deliberate sequence so the cheapest checks reject obviously-bad passwords before expensive checks fire:

1. **Length**: single string operation, sub-microsecond.
2. **Complexity**: single regex per character type, sub-microsecond.
3. **Common passwords**: O(1) cached hash-map lookup.
4. **Sequential / Repeated / Contextual**: string scans, microsecond.
5. **HIBP**: HTTP request to the Pwned Passwords API (k-anonymity), 50-500ms typical.
6. **Password history**: bcrypt-verify chain × N (constant-time padded), 100-300ms × N.

A weak password gets rejected at step 1 or 2; the expensive HIBP + history checks only run on passwords that pass the cheap rules. This is also why the bundled common-password blocklist runs before HIBP: a `password123` rejection saves the HIBP API call.

## Length

**Setting:** `minLength` (default `6`) + `maxLength` (default `0` = unlimited).

The hard floor is **6** characters: Craft itself enforces this even with the plugin uninstalled. Most compliance frameworks require higher minimums:

- NIST 800-63B Rev. 4 (single-factor): **15**
- NIST 800-63B Rev. 4 (MFA component): **8**
- PCI DSS v4.0.1 §8.3.6: **12** (or 8 for legacy systems)
- OWASP ASVS L1: **12**

Set `maxLength` only if you genuinely need an upper bound (e.g. a downstream system that truncates beyond N chars). Most installs leave it at `0`.

## Complexity

The plugin supports two complexity modes via the `complexityMode` setting:

### Individual toggles (default)

Each character class is a separate setting:

- `cases`: require at least one uppercase AND at least one lowercase letter.
- `numbers`: require at least one digit.
- `symbols`: require at least one non-alphanumeric character (any Unicode non-letter, non-digit, non-whitespace).

All enabled toggles must be satisfied independently. A password missing any required class is rejected with a clear per-class error message.

> [!WARNING]
> **NIST 800-63B Rev. 4 forbids composition rules**
>
> Rev. 4 §3.1.1.2 explicitly forbids requiring composition (`SHALL NOT impose other composition rules`). The composition fields remain available because PCI DSS v4.0.1 §8.3.6 still requires numeric + alphabetic mix. Pick the preset that matches your audit. See [Compliance frameworks](../operations/compliance-frameworks.md).

### Minimum types mode (Pro)

Set `complexityMode = 'minimum'` and `minimumCharacterTypes = N` (where N is between 1 and 4). The validator counts how many of `uppercase, lowercase, digit, symbol` are present and rejects passwords with fewer than N.

This is the OWASP-favoured shape: rather than mandate every class, mandate any-3-of-4 (or any-2-of-4). It's a softer compliance posture than individual toggles, often preferable for consumer accounts where you want a baseline of complexity without prescribing the exact mix.

The two modes are mutually exclusive: switching to `minimum` mode ignores the individual `cases` / `numbers` / `symbols` toggles.

## HIBP (Have I Been Pwned)

**Setting:** `hibp`, universal across editions, default off. Applying any of the Pro compliance presets (NIST, OWASP, PCI-DSS, CIS, Strict Enterprise) turns it on. Pair with `hibpFailMode` (default `open`).

When enabled, the validator sends the **first 5 characters of `SHA-1(password)`** to the Pwned Passwords API and compares the returned bucket against the rest of the SHA-1. The full hash and the password itself never leave your server: the bucket contains ~500-800 candidate passwords and the API returns counts per suffix, never the suffix in plaintext.

### Fail modes

- **`open`** (default): on API failure, accept the password. Recommended for most production sites. A transient HIBP outage won't block a password change.
- **`closed`**: On API failure, reject the password. Recommended for high-security installs. The user sees a friendly retry-later message.

### Rate limiting

If HIBP returns `429 Too Many Requests`, the plugin sets a site-wide backoff cache key. Every subsequent caller (change-time + login) short-circuits until the backoff expires. TTL is parsed from the `Retry-After` header; defaults to 60s if absent. The privacy guard: the backoff sentinel is the literal `'1'`, never user-derived.

### TLS verification

HIBP requests force `verify => true` on the Guzzle client at the request site. This overrides any site-level `config/guzzle.php` that disables TLS verification globally. If your network blocks TLS verification entirely (corporate proxy with self-signed certs), set `hibpFailMode = open`: the plugin will fail gracefully and log a warning rather than blocking password changes.

### HIBP-on-login (Pro)

In addition to checking at password-change time, Pro adds **HIBP-on-login**, re-checking every signing-in user's password against the breach database on every authentication attempt. See [Audit logging → HIBP-on-login](./audit-logging.md#hibp-on-login).

## Common passwords (blocklist)

**Setting:** `checkCommonPasswords`, universal across editions. Default off; the four compliance presets that include it (NIST, PCI-DSS, CIS Controls v8, Strict Enterprise) all turn it on.

The validator rejects passwords matching the `passwordpolicy_blocklist` table: a combined list of:

- **Bundled common passwords** (`source = 'common'`), 10,000 entries from the SecLists Common-Credentials list, seeded at install.
- **Custom words** (`source = 'custom'`), admin-managed via the Blocklist editor at **Password Policy → Blocklist**.

The validator emits source-aware error messages:

- Bundled match: `"This password is too common. Choose a more unique password."`
- Custom match: `"This password has been blocked. Choose a different password."`

Lookups go through a cached hash-map in `Craft::$app->getCache()`, O(1) at runtime. The cache is invalidated automatically on any add, remove, or seed operation.

See [Blocklist](./blocklist.md) for the editor UX and per-policy blocklist (Enterprise).

## Sequential characters

**Setting:** `checkSequentialChars` (default off; on in `STRICT_ENTERPRISE` preset).

Rejects passwords containing 3+ sequential characters in either direction:

- **ASCII sequences**: letters and digits in standard order: `abc`, `xyz`, `321`, `mno`. Both ascending and descending.
- **Keyboard rows**: top row (`qwerty`, `qwertz`, `azerty` variants), home row (`asdf`), bottom row (`zxcv`), number row (`1234`). All in both directions.

The validator is ASCII-only by design, Unicode sequence detection is a different problem (collations, scripts, joining behaviour) and would produce false positives on non-Latin scripts.

## Repeated characters

**Setting:** `checkRepeatedChars` (default off; on in `STRICT_ENTERPRISE` preset).

Rejects passwords containing 3+ consecutive repeated characters: `aaa`, `111`, `!!!`. The validator is Unicode-aware, `あああ` rejects too, as does `🔒🔒🔒`. The regex grapheme matching uses PHP's `\X` pattern when available.

## Contextual data

**Setting:** `checkContextual` (default off; on in `STRICT_ENTERPRISE` preset).

Rejects passwords containing case-insensitive substrings of the user's own context (minimum 3-char matches):

- **Username**: exact value of `user.username`.
- **Email local-part**: text before `@` in the email.
- **First name and last name**: separately checked.
- **System name**: `Craft::$app->getSystemName()`, split into individual words (so `Acme Web Corp` rejects `acme`, `web`, and `corp` individually).
- **Primary site domain**: the hostname portion of the primary site URL.

The 3-char minimum prevents over-rejecting common short substrings (`a`, `co`, `mr`).

> [!TIP]
> **Why contextual checks matter**
>
> Compliance frameworks generally treat user-contextual passwords as a form of insufficient entropy. NIST 800-63B Rev. 4 §3.1.1.2 explicitly recommends rejecting "context-specific words, such as the name of the service, the username, and derivatives thereof."

## Hooking into validation

The `PasswordValidationEvent` fires once per password validation attempt, after every validator has run. Listen to it for analytics, custom side effects, or to push additional errors onto the response.

```php
use craftpulse\passwordpolicy\events\PasswordValidationEvent;
use craftpulse\passwordpolicy\services\PasswordService;
use yii\base\Event;

Event::on(
    PasswordService::class,
    PasswordService::EVENT_PASSWORD_VALIDATION,
    function(PasswordValidationEvent $event) {
        // $event->user, $event->isValid, $event->errors
        // Push a custom error onto the response:
        if (!$event->isValid && my_custom_rule($event)) {
            $event->errors[] = 'Custom error message.';
        }
    }
);
```

See [Events reference](../reference/events.md) for the full event catalog with payload tables.

## See also

- [Per-Group Policies](./per-group-policies.md): apply different validator combinations to different user groups.
- [Blocklist](./blocklist.md): manage the bundled common-password list and the custom dictionary editor.
- [HIBP-on-login + audit log](./audit-logging.md#hibp-on-login): Pro: re-check on every sign-in, audit on Enterprise.
- [Front-end Twig builders](./frontend-twig.md): render validator state on consumer-site forms with live AJAX feedback.
- [AJAX validation endpoint](../reference/ajax-validate.md): the `/password-policy/validate` endpoint for custom front-end integrations.
