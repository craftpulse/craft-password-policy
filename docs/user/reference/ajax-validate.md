# AJAX Validation Endpoint

`POST password-policy/validation/validate` returns per-rule pass/fail JSON plus a strength analysis block, suitable for live front-end validation feedback or partner-built registration flows. The endpoint runs every applicable validator individually so consumers get rule-by-rule feedback (not just an opaque boolean).

This is the same endpoint the plugin's own front-end Twig render builders use, see [Front-end Twig builders](../features/frontend-twig.md). The vanilla-JS client at `src/web/assets/passwordpolicyclient/password-policy.js` is the reference implementation if you want to mimic its behaviour from your own front-end stack.

## Request

```
POST <site-url>/actions/password-policy/validation/validate
Content-Type: application/x-www-form-urlencoded
X-Requested-With: XMLHttpRequest
```

| Param | Required | Notes |
|---|---|---|
| `password` | yes | Plaintext to validate. Never logged or persisted by the endpoint. |
| `username` | no | Optional contextual input, feeds the contextual validator + zxcvbn's user-input dictionary. **Ignored on anonymous requests** (see [Security notes](#security-notes) below). |
| `email` | no | Same as `username`. Ignored on anonymous requests. |
| `groups[]` | no | Array of group **handles** for anonymous group-preview validation. Useful on a "Sign up as Editor" form where the resolved criteria should reflect the Editors-group policy. |

The endpoint is `$allowAnonymous = ['validate']`, anonymous users (registration forms, password-reset flows) can hit it without a CSRF-issued session. Authenticated CP/site requests still go through Craft's standard CSRF check.

### Example request (vanilla JS)

```js
const formData = new FormData();
formData.append('password', userInput);
formData.append('groups[]', 'editors');

const response = await fetch('/actions/password-policy/validation/validate', {
    method: 'POST',
    headers: { 'X-Requested-With': 'XMLHttpRequest' },
    body: formData,
});

const result = await response.json();
console.log(result.isValid, result.rules, result.strength);
```

## Response

```json
{
  "isValid": false,
  "errors": [
    "Password must contain mixed case.",
    "Password must contain at least one digit."
  ],
  "errorsByKey": {
    "cases": "Password must contain mixed case.",
    "numbers": "Password must contain at least one digit."
  },
  "rules": [
    { "key": "minLength", "pass": true,  "message": "At least 12 characters" },
    { "key": "cases",     "pass": false, "message": "Upper and lowercase letters" },
    { "key": "numbers",   "pass": false, "message": "At least one digit" },
    { "key": "symbols",   "pass": true,  "message": "At least one symbol" },
    { "key": "hibp",      "pass": true,  "message": "Not found in breach database" }
  ],
  "strength": {
    "engine": "zxcvbn-php",
    "label": "fair",
    "score": 2,
    "crackTime": "3 hours",
    "suggestions": [
      "Add another word or two. Uncommon words are better."
    ],
    "warning": null
  }
}
```

### Top-level fields

| Field | Type | Meaning |
|---|---|---|
| `isValid` | `bool` | `true` only when every applicable rule passed. |
| `errors` | `string[]` | Flat list of failure messages (suitable for a generic error display). |
| `errorsByKey` | `object<string,string>` | Failure messages keyed by rule key (suitable for placing errors next to specific form fields). |
| `rules` | `Rule[]` | Per-rule pass/fail with localised messages. |
| `strength` | `Strength` | Strength analysis from the zxcvbn-php engine. |

### `Rule` shape

| Field | Type | Meaning |
|---|---|---|
| `key` | `string` | Stable identifier, `minLength`, `maxLength`, `cases`, `numbers`, `symbols`, `hibp`, `blocklist`, `sequential`, `repeated`, `contextual`, `characterTypes`, `historyMatch`. |
| `pass` | `bool` or `null` | `true` = passed; `false` = failed; `null` = check is in progress (HIBP uses this when the API request is still resolving). |
| `message` | `string` | Localised, human-readable description of the rule. Suitable to render directly. |

The `key` value `hibp` replaces the legacy `pwned` key from 5.1.x. The `pwned` key is **no longer emitted** in 5.2.0 responses; consumers parsing the response should reference `hibp`. If you're maintaining a 5.1.x-compatible parser, accept both.

### `Strength` shape

| Field | Type | Meaning |
|---|---|---|
| `engine` | `string` | Always `zxcvbn-php` in 5.2.0. |
| `label` | `string` | One of `weak`, `fair`, `strong`, `excellent`. |
| `score` | `int` | 0-4 (zxcvbn's native score). |
| `crackTime` | `string` | Localised crack-time estimate (e.g. `"3 hours"`, `"centuries"`). |
| `suggestions` | `string[]` | Localised improvement suggestions (may be empty). |
| `warning` | `string` or `null` | Localised warning if zxcvbn detected a specific weakness pattern. |

A blocklist hit forces `label = "weak"` + `score = 0` regardless of zxcvbn's natural reading, without this override a long+complex blocklisted password would read as "excellent" while the back-end correctly rejects it.

## Error responses

| Status | Body | When |
|---|---|---|
| `400 Bad Request` | `{ "error": "Password is required" }` | `password` field missing or empty. |
| `429 Too Many Requests` | `{ "error": "Rate limited" }` | Site-wide HIBP backoff is active. The validator returns immediately without hitting the HIBP API. |
| `500 Internal Server Error` | `{ "error": "Validation failed" }` | Unexpected exception. Full detail logged server-side via `$plugin->log()`; never exposed to the client. |

## Security notes

- **The endpoint never echoes back the submitted password**: neither in the response nor in server-side logs.
- **Anonymous requests have `username` and `email` discarded.** Accepting attacker-controlled context values would let an unauthenticated client probe "how does the strength score change when I claim my username is X?": a small but real signal-leak surface. Anonymous requests pass empty strings to the validators.
- **Authenticated requests pull `username` and `email` from the session identity**: `Craft::$app->getUser()->getIdentity()`. POST-supplied values are ignored.
- **Context strings are length-truncated** to 254 characters defensively, even when pulled from the session.
- **Front-end behaviour is intentionally non-blocking.** AJAX failures freeze the indicator at last-known state. The server-side validator on save remains the authoritative gate, never trust the AJAX result as the only check.
- **CSRF is required for authenticated requests** but waived for anonymous (the endpoint is anonymous-allowed because registration and reset flows need it).

## Performance

The endpoint runs the validators in cost-ascending order, same as the save-time path:

1. Length, complexity, blocklist (sub-millisecond each).
2. Sequential, repeated, contextual (microseconds).
3. HIBP (50-500ms: the network call).
4. zxcvbn strength analysis (typically 50-200ms, CPU-bound).

For typical UX (250ms-debounced live validation on every keystroke after the user pauses), the response time is dominated by HIBP + zxcvbn. The client-side JS displays "in-progress" state with `aria-busy="true"` while the request resolves.

## See also

- [Validators](../features/validators.md): what each rule key checks.
- [Front-end Twig builders](../features/frontend-twig.md): render builders that use this endpoint automatically.
- [Per-Group Policies](../features/per-group-policies.md): how the `groups[]` parameter resolves the effective policy.
