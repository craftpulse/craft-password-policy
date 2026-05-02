# AJAX Validation Endpoint

`POST password-policy/validation/validate` returns per-rule pass/fail JSON, suitable for live front-end validation feedback or partner-built registration flows. The endpoint runs every applicable validator individually so consumers get rule-by-rule feedback (not just an opaque boolean).

This is the same endpoint the plugin's own front-end Twig render builders use — see [`features/frontend-twig.md`](../features/frontend-twig.md).

## Request

```
POST <site-url>/actions/password-policy/validation/validate
Content-Type: application/x-www-form-urlencoded
X-Requested-With: XMLHttpRequest
```

| Param      | Required | Notes |
|------------|----------|-------|
| `password` | yes      | Plaintext to validate. Never logged or persisted by the endpoint. |
| `username` | no       | Optional contextual input — feeds the contextual validator + zxcvbn user-input dictionary. Authenticated requests pull this from the session identity, anonymous requests send empty strings server-side. |
| `email`    | no       | Same as `username`. |

The endpoint is `$allowAnonymous = ['validate']` — anonymous users (registration forms, password-reset flows) can hit it without a CSRF-issued session.

## Response

```json
{
  "isValid": false,
  "rules": [
    { "key": "minLength", "pass": true,  "message": "At least 8 characters" },
    { "key": "cases",     "pass": false, "message": "Upper and lowercase letters" },
    { "key": "pwned",     "pass": null,  "message": "Not found in breach database" }
  ]
}
```

| Field                | Type             | Meaning |
|----------------------|------------------|---------|
| `isValid`            | `bool`           | `true` only when every rule passed (or returned `null`). |
| `rules[i].key`       | `string`         | Stable identifier for the rule (`minLength`, `cases`, `pwned`, `historyMatch`, `blocklist`, `sequential`, `repeated`, `contextual`, `characterTypes`). |
| `rules[i].pass`      | `bool` or `null` | `true` = passed, `false` = failed. `null` = check is in progress (HIBP currently uses this when the upstream request is still resolving). |
| `rules[i].message`   | `string`         | Localised, human-readable description of the rule. Suitable to render directly in the form. |

## Error responses

The endpoint returns `400 Bad Request` with `{ "error": "Password is required" }` when `password` is missing. All other unexpected errors return `500` with a generic message — full exception detail is logged server-side via `$plugin->log()` and never exposed to the client.

## Security notes

- The endpoint **never echoes back the submitted password** — neither in the response nor in server-side logs.
- For authenticated requests, `username` and `email` are pulled from the session identity. POST-supplied values for these fields are ignored to close a small but real signal-leak surface (an unauthenticated attacker submitting a known username and observing how the strength score changes for guessed passwords).
- Anonymous requests send empty strings for `username`/`email` server-side regardless of POST input.
- Front-end behavior is intentionally non-blocking: AJAX failures freeze the indicator at last-known state. The server-side validator on save remains the authoritative gate.
