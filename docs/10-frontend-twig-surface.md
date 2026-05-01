# Front-End Twig Surface (Pro)

Reference for the `craft.passwordpolicy.*` render builders that ship with v5.2.0. Use these to build login, registration, password-change, and password-reset pages on consumer-facing site templates without re-implementing the policy criteria, AJAX validation, strength meter, show/hide toggle, or a11y wiring yourself.

The builders work on every edition. On Lite, they emit markup against the global policy. On Pro, the resolved per-group policy applies automatically when the user (or anonymous group-preview hint) has groups assigned.

> **Twig errors propagate naturally.** Builders throw `\InvalidArgumentException` on misuse — missing required fields, unknown options, contradictory config. Twig surfaces the exception in dev mode; production renders the friendly error template. Don't wrap calls in `try/catch`.

---

## Quick start

A complete password-change form for a logged-in user, with live AJAX validation, strength meter, requirement checklist, and submit gating:

```twig
{{ craft.passwordpolicy.passwordChangeForm()
    .submitLabel('Update password'|t)
    .successRedirect('/account')
    .render() }}
```

A custom registration form composed of the field-renderer primitives:

```twig
<form method="post">
    {{ csrfInput() }}
    <input type="hidden" name="action" value="users/save-user">

    <label>Email <input type="email" name="email" required></label>

    <label>Password</label>
    {{ craft.passwordpolicy.passwordWidget({
        name: 'password',
        liveValidation: true,
        submitGate: '#submit',
        showHint: true,
    }).render() }}

    <button id="submit" type="submit">Sign up</button>
</form>
```

---

## Data accessors

### `requirements(params = [])`

Returns the resolved policy as a flat associative array.

```twig
{% set rules = craft.passwordpolicy.requirements() %}
<p>Your password must be at least {{ rules.minLength }} characters.</p>
{% if rules.requireSymbols %}
    <p>It must include a special character.</p>
{% endif %}
```

Keys: `minLength`, `maxLength`, `requireUppercase`, `requireLowercase`, `requireNumbers`, `requireSymbols`, `blocklistEnabled`, `historyCount`, `hibpEnabled`, `complexityMode`, `minimumCharacterTypes`, `sequentialCharsCheck`, `repeatedCharsCheck`, `contextualCheck`.

Optional `params.groups`: array of group **handles** for anonymous group preview. Use this on a "Sign up as Editor" form so the resolved criteria reflect the Editors-group policy:

```twig
{% set rules = craft.passwordpolicy.requirements({groups: ['editors']}) %}
```

### `requirementsText(params = [])`

Returns a single human-readable sentence summarizing the resolved policy. Useful as static helper text under a password input.

```twig
<p class="hint">{{ craft.passwordpolicy.requirementsText() }}</p>
{# → "Password must contain: at least 12 characters, mixed case, a number." #}
```

### `requirementRules(params = [])`

Returns a list of `{key, label, met}` rows. `met` is always `null` server-side; the client JS toggles a corresponding state class on `<li data-pp-requirement="<key>">` elements.

```twig
<ul>
    {% for rule in craft.passwordpolicy.requirementRules() %}
        <li data-pp-requirement="{{ rule.key }}">{{ rule.label }}</li>
    {% endfor %}
</ul>
```

---

## Field renderers

All field renderers accept either a chained-setter style or an equivalent config-array.

### `passwordField()`

A single `<input type="password">` with optional show/hide toggle, AJAX live validation, submit-gating, and a11y wiring.

| Setter | Type | Default | Notes |
|--------|------|---------|-------|
| `name(string)` | required | — | Input `name` attribute |
| `id(string)` | optional | auto-generated | Input `id` |
| `value(string)` | optional | empty | Never prefilled in production |
| `autocomplete(string)` | optional | `new-password` | |
| `inputAttrs(array)` | optional | `[]` | Merged into the `<input>` |
| `wrapperAttrs(array)` | optional | `[]` | Merged into the wrapping `<div>` |
| `toggleVisibility(bool)` | optional | `true` | Show/hide eye button |
| `toggleAttrs(array)` | optional | `[]` | Merged into the toggle button |
| `liveValidation(bool)` | optional | `false` | Auto-registers the JS asset |
| `submitGate(string)` | optional | — | CSS selector for submit button to enable/disable |
| `groups(array)` | optional | `[]` | Group handles for anonymous group-preview validation |

```twig
{{ craft.passwordpolicy.passwordField()
    .name('password')
    .id('register-password')
    .liveValidation(true)
    .submitGate('#register-button')
    .render() }}
```

### `requirementList()`

A `<ul>` of requirement rows tied to the resolved policy. Each `<li>` has `data-pp-requirement="<key>"` so the client JS can toggle pass/fail classes.

| Setter | Type | Default |
|--------|------|---------|
| `listAttrs(array)` | optional | `[]` |
| `itemAttrs(array)` | optional | `[]` |
| `groups(array)` | optional | `[]` |

### `strengthMeter()`

Animated bar with strength label. Class state (`pp-strength-weak/fair/strong/excellent`) toggled by JS.

| Setter | Type | Default |
|--------|------|---------|
| `wrapperAttrs(array)` | optional | `[]` |
| `barAttrs(array)` | optional | `[]` |

### `requirementsHint()`

A `<p>` with the human-readable summary returned by `requirementsText()`.

### `passwordWidget()`

Composite — wraps `passwordField` + `strengthMeter` + `requirementList` (+ optional `requirementsHint`) in a single `<div class="pp-widget">`.

| Setter | Type | Default |
|--------|------|---------|
| `name(string)` | required | — |
| `id(string)` | optional | auto |
| `inputAttrs(array)` | optional | `[]` |
| `wrapperAttrs(array)` | optional | `[]` |
| `toggleVisibility(bool)` | optional | `true` |
| `liveValidation(bool)` | optional | `true` |
| `submitGate(string)` | optional | — |
| `showStrength(bool)` | optional | `true` |
| `showRequirements(bool)` | optional | `true` |
| `showHint(bool)` | optional | `false` |
| `groups(array)` | optional | `[]` |

---

## Form renderers

Complete `<form>` elements including hidden CSRF, hashed redirect, and the appropriate password fields.

### `loginForm()`

POSTs to Craft's `users/login` action.

```twig
{{ craft.passwordpolicy.loginForm()
    .successRedirect('/account')
    .submitLabel('Sign in'|t)
    .render() }}
```

| Setter | Default |
|--------|---------|
| `formAttrs(array)` | `[]` |
| `loginNameAttrs(array)` | `[]` |
| `passwordAttrs(array)` | `[]` |
| `submitButtonAttrs(array)` | `[]` |
| `submitLabel(string)` | "Login" |
| `successRedirect(string)` | — |
| `rememberMe(bool)` | `true` |

### `passwordChangeForm()`

POSTs to `password-policy/front/password-change/save` (the plugin's own `Front\PasswordChangeController`). Three password fields: current, new (validated), confirm. The new-password field gets `liveValidation(true)` and submit-gating.

| Setter | Default |
|--------|---------|
| `formAttrs(array)` | `[]` |
| `submitButtonAttrs(array)` | `[]` |
| `submitLabel(string)` | "Update password" |
| `successRedirect(string)` | — |

### `passwordResetForm({code, userUid})`

POSTs to Craft's `users/set-password` action. Token-based reset flow — Craft validates the `code` + `userUid` from the reset email link, the plugin's `User::EVENT_DEFINE_RULES` listener validates the new password against the policy.

```twig
{{ craft.passwordpolicy.passwordResetForm({
    code: craft.app.request.queryParam('code'),
    userUid: craft.app.request.queryParam('id'),
}).render() }}
```

`code` and `userUid` are **required** — the builder throws `\InvalidArgumentException` if either is missing so consumers learn about the wiring mistake at render time.

---

## Strength engine

The validate AJAX endpoint returns a `strength` block alongside the per-rule `errorsByKey`:

```json
{
  "passed": true,
  "errorsByKey": {},
  "errors": [],
  "rules": [...],
  "strength": {
    "engine": "baseline",
    "label": "fair",
    "ruleCount": 3,
    "lengthTier": 1
  }
}
```

### Engine A (baseline)

Always available. Rule-counting × length tier produces a label:

| Length | 0 rule types | 1 | 2 | 3 | 4 |
|--------|--------------|---|---|---|---|
| `<8`   | weak | weak | weak | weak | weak |
| `8-11` | weak | weak | fair | fair | fair |
| `12-15`| weak | fair | fair | strong | strong |
| `16+`  | weak | strong | strong | excellent | excellent |

Blocklist hit forces `weak` regardless of length.

### Engine B (zxcvbn-php, Pro opt-in)

Enable via the `useZxcvbnStrength` setting on the Settings → Configuration page (Pro). Replaces the strength block with `{engine: 'zxcvbn', label, score, crackTime, suggestions, warning}`. Same `label` vocabulary so CSS classes are stable across engines.

---

## a11y notes

Every builder ships with full a11y wiring:

- **Live region** — auto-injected `<span class="pp-live-region" aria-live="polite" aria-atomic="true">` linked to the input via `aria-describedby`. Screen readers announce state changes ("Password meets all requirements." / "At least 12 characters") as the AJAX response cycles.
- **`aria-invalid`** — toggled on the input based on the `passed` flag in the validate response.
- **`aria-busy`** — set to `true` while the JS is debouncing / awaiting the AJAX response.
- **Strength meter** — `<div role="progressbar" aria-valuemin="0" aria-valuemax="4" aria-valuenow="...">` so the meter is announced as a progress bar with the current score.
- **Show/hide toggle** — `<button>` with flipping `aria-label="Show password"` ↔ `"Hide password"` and an inner SVG with two stacked paths (open eye + eye-slash) toggled via `style="display:none"`.

VoiceOver (macOS) and NVDA (Windows) have been targeted; the user is expected to verify SR behavior end-to-end on their own browser before publishing.

---

## Lite degradation

Builders work on every edition. On Lite installs:

- `requirements()` returns the global policy (no per-group resolution).
- The CP gates Pro features (Policies/Blocklist/Notifications subnavs); the front-end builders never throw.
- The `groups` parameter is silently ignored on Lite — the global policy applies regardless.

This is intentional. Consumer site templates should never need an edition check around a `passwordField()` call.

---

## Programmatic registration helper

For consumer-built registration controllers, `RegistrationService::register()` provides a Lite+Pro entry point that pre-validates the password against the resolved policy. See `docs/events.md` for the `UserRegisteredEvent` shape.

```php
use craftpulse\passwordpolicy\PasswordPolicy;

$user = PasswordPolicy::$plugin->getRegistration()->register([
    'email' => $email,
    'password' => $password,
    'username' => $username, // defaults to email
    'groups' => ['editors'], // group handles, not IDs
    'fields' => ['favoriteColor' => 'blue'],
    'sendActivationEmail' => null, // null = follow Craft's requireEmailVerification
]);
```

Validation failure throws `\InvalidArgumentException` with a flattened error message containing all attribute-prefixed errors.
