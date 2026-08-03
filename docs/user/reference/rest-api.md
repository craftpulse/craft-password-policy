# REST API

A read-only HTTP API over three endpoints, for machine clients that need password-policy state without a control panel session. Requires the Enterprise edition.

The API is **off by default**. Nothing is reachable until you turn on `apiEnabled` and issue at least one token.

Everything the API exposes is readable. There is no write surface: no endpoint changes a policy, resets a password, or issues a token. Provisioning stays in the control panel on purpose, so a leaked token cannot escalate into a configuration change.

## Turning it on

`apiEnabled` has no control panel field. Set it in `config/password-policy.php`:

```php
return [
    'apiEnabled' => true,
];
```

Then go to **Password Policy → API tokens** and issue a token. Copy it: it is shown once.

Keeping the switch out of the control panel is deliberate. Exposing password state over HTTP is a deployment decision, so it belongs in the file your deploy reviews, not behind a lightswitch someone can flip while looking for something else.

## Authentication

Bearer token in the `Authorization` header:

```shell
curl -H "Authorization: Bearer <token>" \
  https://example.com/password-policy/api/v1/policy/resolve?userUid=<uid>
```

Every endpoint is a GET, so there is no CSRF token to send.

A missing header, a malformed header, an unknown token, and an expired token all return the **same** 401 body:

```json
{ "error": "Unauthorized." }
```

That is deliberate. A distinct "token expired" response would tell an attacker which of their guesses was once a real token.

## When the API is not available

Below Enterprise, or with `apiEnabled` off, every endpoint returns an identical 404:

```json
{ "error": "Not found." }
```

The two cases are byte-identical and neither names an edition. From outside, an install without the API is indistinguishable from an install that never had the routes, which is the same hide-rather-than-badge behaviour the control panel follows.

## Rate limit

**60 requests per token per minute**, counted in a fixed window.

Over the limit, the API returns 429 with a `Retry-After` header giving the seconds until the window resets:

```
HTTP/1.1 429 Too Many Requests
Retry-After: 60
```

The counter increments under a per-token mutex, so concurrent requests cannot both read the same count and slip past the cap. If the mutex cannot be acquired within 2 seconds the request is treated as rate-limited rather than allowed through: the limit fails closed.

The limit is per token, not per IP. Issue a separate token per consumer so one noisy integration cannot exhaust another's budget, and so you can revoke one without disrupting the rest.

## Endpoints

### `GET /users/<uid>/password-status`

Password state for one user, identified by element **UID** rather than id.

```shell
curl -H "Authorization: Bearer <token>" \
  https://example.com/password-policy/api/v1/users/e1f0c2a4-1234-4abc-9def-0123456789ab/password-status
```

```json
{
  "userUid": "e1f0c2a4-1234-4abc-9def-0123456789ab",
  "userId": 42,
  "status": "expiring",
  "expired": false,
  "expiringSoon": true,
  "breached": false,
  "resetRequired": false,
  "neverChanged": false,
  "lastChange": "2026-05-14T09:31:07+00:00",
  "daysUntilExpiry": 5
}
```

`status` is the same summary value the Users index column shows: `ok`, `expiring`, `expired`, `breached`, `reset_required`, `policy_drift`, or `never_changed`. The booleans beside it are the individual flags that fed into it, so a consumer can act on one condition without parsing the summary.

An unknown UID returns 404 with `{"error": "User not found."}`. Note that this is a *different* body from the API-unavailable 404 above, so a consumer can tell "no such user" from "no such API".

### `GET /policy/resolve`

The rule set that actually applies to one user, after per-group resolution.

```shell
curl -H "Authorization: Bearer <token>" \
  "https://example.com/password-policy/api/v1/policy/resolve?userUid=e1f0c2a4-1234-4abc-9def-0123456789ab"
```

| Param | Description |
|---|---|
| `userUid` | The user's element UID. Required; omitting it returns 400. |

```json
{
  "userUid": "e1f0c2a4-1234-4abc-9def-0123456789ab",
  "userId": 42,
  "policy": {
    "minLength": 15,
    "maxLength": 0,
    "requireMixedCase": false,
    "requireNumbers": false,
    "requireSymbols": false,
    "checkCommonPasswords": true,
    "hibp": true,
    "passwordHistoryCount": 5,
    "minChangeIntervalHours": 24,
    "expiryAmount": null,
    "expiryPeriod": "day"
  }
}
```

The `policy` object is an explicit allowlist of password rules. SIEM credentials, webhook secrets, the audit PII key, and every other infrastructure setting are absent by construction rather than by filtering, so a new Enterprise setting cannot leak here by being forgotten.

This is the endpoint to use when a separate application (a mobile app, a partner registration flow) needs to enforce the same rules client-side that Craft will enforce on save.

### `GET /audit`

A paginated slice of the audit log, redacted.

```shell
curl -H "Authorization: Bearer <token>" \
  "https://example.com/password-policy/api/v1/audit?from=2026-07-01&to=2026-08-01&limit=100"
```

| Param | Description |
|---|---|
| `from` | Only rows created at or after this datetime. Parsed as UTC. |
| `to` | Only rows created at or before this datetime. Parsed as UTC. |
| `limit` | Rows per page. Defaults to 50, capped at 200. |
| `offset` | Rows to skip. Defaults to 0. |

Unlike the `audit/verify` console command, `from` and `to` here really are dates.

```json
{
  "total": 3184,
  "limit": 100,
  "offset": 0,
  "rows": [
    {
      "id": 3184,
      "userId": 42,
      "event": "password_changed",
      "outcome": "success",
      "source": "cp",
      "details": { "reason": "SelfService" },
      "geoCountry": "BE",
      "geoRegion": null,
      "dateCreated": "2026-08-02 14:22:51",
      "uid": "..."
    }
  ]
}
```

Rows are newest first. `total` is the count for the whole filtered range, not the page, so a consumer can page without a second request to discover the end.

The columns are a fixed subset. The hash-chain columns (`rowHash`, `previousHash`) and the HMAC identifier columns (`userIdentifier`, `changedByIdentifier`) are **not** exposed. Chain verification is the [verifier command's](../features/audit-verifier.md) job, over the database, and an API consumer holding row hashes would gain nothing it could act on.

`details` is decoded into a real JSON object rather than a JSON string inside JSON. It contains only keys on that event's allowlist; run [`audit/schema`](./console-commands.md#auditschema) to see the whole registry.

## API tokens

**Password Policy → API tokens** (Enterprise, `pp:api-manage`) is the token registry.

### Issuing

Give the token a name, optionally set an expiry in days, and issue it. The plaintext appears **once**, immediately after issuing.

Only a SHA-256 hash of the token is stored, plus its first 8 characters so the screen has something to identify the row by. The plaintext is not recoverable from the database. If you lose it, revoke the token and issue another.

A token with no expiry never expires. Set one unless you have a reason not to: `gc/run` purges expired tokens automatically, so an expiry is also how the registry stays tidy.

### Revoking

Revoking deletes the row. The next request presenting that token gets the standard 401, indistinguishable from a token that never existed.

A token outlives the admin who issued it. Deleting that admin's Craft account nulls the `createdByUserId` reference and leaves the token working, because revocation should be a decision someone makes rather than a side effect of offboarding.

## See also

- [Console commands](./console-commands.md): the CLI equivalents, where they exist.
- [Audit logging](../features/audit-logging.md): what the audit log captures and why.
- [Per-group policies](../features/per-group-policies.md): how the resolved policy in `policy/resolve` is derived.
- [Editions](../editions.md): what each edition includes.
