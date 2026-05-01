---
title: Phase C2 Build Plan — Pro Front-End Surface Bundle
version: 5.2.0
phase: C2
features: [P1.12, P1.13, P1.14, P1.15]
build_order: [P1.14, P1.13, P1.12, P1.15]
estimated_effort: ~3-4 working days
last_updated: 2026-05-01
---

# Phase C2 — Pro Front-End Surface Bundle

Layered build plan for the four P1 items added on 2026-05-01: P1.12 (Pro front-end Twig surface), P1.13 (HIBP-on-login Pro), P1.14 (Registration helper service), P1.15 (events catalog + documentation).

This is the build brief for whoever runs Phase C2 (likely `craft-feature-builder`). Read it whole before starting. Do not relitigate locked architecture — push back on me, not the spec.

---

## Context

- Plugin: `/Users/michtio/dev/craft-plugins/v5/craft-password-policy`
- Playground: `/Users/michtio/dev/craft-plugin-playground/cms_v5` (URL `https://plugin-playground-v5.ddev.site/admin`, login `development@craftpulse.com` / `Letmein-Craftpulse1!`)
- Branch: `5.x` (currently 24 commits ahead of `origin/5.x`, working tree clean)
- Plugin edition: Pro
- Mailpit: `ddev describe` shows the URL (`:8025` typical)

Memory store: `~/.claude/projects/-Users-michtio-dev-craft-plugins-v5-craft-password-policy/memory/MEMORY.md` — 20+ durable rules. Read first.

Read these handover docs in order before starting:
1. `docs/NEXT-SESSION.md`
2. `docs/PLAN.md` sections 1, 3 (esp. P1.12-P1.15 rows), 4
3. `docs/PROGRESS.md` (tail — 2026-04-30 → 2026-05-01 sessions)
4. `docs/TESTING.md` (T9.x rows for the existing notification surface — same patterns to mimic)

---

## Locked architecture (do not relitigate)

### Renderer model (image-optimize style)

Every renderer is a **fluent builder** with `.render()` terminator. Builders accept either chained setters OR equivalent config-object on construction. Mirrors `nystudio107/image-optimize`'s `imgTag()` / `pictureTag()` pattern.

```twig
{# Chained #}
{{ craft.passwordPolicy.passwordField()
    .name('password')
    .id('register-password')
    .inputAttrs({ class: 'form-control', placeholder: 'Choose a password'|t })
    .toggleVisibility(true)
    .liveValidation(true)
    .submitGate('#register-button')
    .render() }}

{# Equivalent config-object #}
{{ craft.passwordPolicy.passwordField({
    name: 'password',
    id: 'register-password',
    inputAttrs: { class: 'form-control' },
    toggleVisibility: true,
    liveValidation: true,
    submitGate: '#register-button',
}).render() }}
```

`*Attrs()` setters per element (`inputAttrs`, `wrapperAttrs`, `toggleAttrs`, `formAttrs`, `submitButtonAttrs`, etc.) merge into the rendered markup; empty values omitted.

### a11y is non-negotiable (plugin's responsibility)

- Live region for state announcements
- `aria-describedby` linking input to requirements list
- `aria-invalid` toggled on validation state
- `aria-busy` during HIBP-pending
- Screen-reader announcements for pass/fail transitions
- Show/hide toggle button has flipping `aria-label` ("Show password" / "Hide password")

a11y is not optional and not deferrable. Test with VoiceOver / NVDA.

### Twig errors propagate naturally

Don't wrap methods in defensive null returns or try/catch. Throw `\InvalidArgumentException` with clear messages for misuse. Twig surfaces it in dev mode; production renders the error template. Lean on Yii.

### Strength engine — A baseline + B Pro opt-in

- **A** (always on, ships with plugin): rule-counting × length-tier label (`weak/fair/strong/excellent`). Blocklist hit forces `weak`. No client-side or server-side dependencies. Returned in the validate response payload as `{strength: {label, ruleCount, lengthTier}}`.
- **B** (opt-in via Pro setting `useZxcvbnStrength: true`, default off): adds `bjeavons/zxcvbn-php` composer dep (~200KB minus dictionaries, MIT, **approved 2026-05-01**). Server-side. Augments the validate response with `{strength: {score: 0..4, label, suggestions: [], crackTime: '...'}}`. JS just renders.

CP-side strength meter (Craft's native zxcvbn-js) stays as-is — out of scope.

### Distribution — Twig helper, no Vite dependency on consumer

- Pre-built JS lives in `src/web/assets/dist/password-policy.js`. Vanilla, framework-free, ~5KB minified, **plugin's** build artifact (committed to repo).
- `PasswordPolicyClientAsset extends \craft\web\AssetBundle` declares it.
- Auto-registered by any builder when called with `liveValidation: true`. Consumers don't manually register.
- Consumer site doesn't need Vite, doesn't need a build step.

### Edition gating — graceful degradation, not throwing

- Builders work on Lite — they emit markup against global policy resolution.
- `requirements()` returns global on Lite, per-group on Pro.
- No silent no-ops. No 403s on the front-end. The CP gates Pro features (subnav, settings tabs); the front-end always works.
- HIBP-on-login is the one exception: Pro-only listener registration. Lite installs simply don't fire it.

### Show/hide toggle

- Default ON. Per-builder opt-out via `.toggleVisibility(false)`.
- FA-style eye / eye-slash inline SVG (MIT path data, no asset dep).
- Standard toggle: `type="password"` ↔ `type="text"`. Plain JS, no library.
- iCloud-style last-character-visible: NOT shipping (breaks password managers, marginal benefit).

---

## Build order rationale

Foundations first, then HIBP infra, then the large front-end surface, then docs synthesizing all events.

| Order | Item | Why |
|---|---|---|
| 1 | **P1.14 — RegistrationService** | Smallest, isolated, defines `UserRegisteredEvent` shape. Establishes service patterns the others reuse. |
| 2 | **P1.13 — HIBP-on-login** | Adds `breach-detected` notification key + login event listener + `BreachDetectedEvent`. Self-contained, builds on existing notification template infrastructure. |
| 3 | **P1.12 — Front-end Twig surface** | Largest. Builds on stable foundations. Field renderers + form renderers + JS asset + strength engine. |
| 4 | **P1.15 — Events catalog** | Docs synthesizing all event classes added in 1-3. `docs/events.md` + README cross-link. |

---

# Feature 1: P1.14 — RegistrationService (Lite + Pro per-group validation)

Smallest of the four. Foundational — defines the event class, registers the service, sets the pattern.

## Layer 1 — Event class

**Build**
- New `src/events/UserRegisteredEvent.php`. Extends `craft\events\ModelEvent` or `yii\base\Event`. Properties (typed):
  - `User $user` — the persisted user
  - `array $groups` — group handles assigned (resolved at register time)
  - `bool $viaService = true` — distinguishes service-driven registration from direct Craft user-save
- Full PHPDoc with `@author CraftPulse`, `@since 5.2.0`, `@event` markup.
- Section header with `=========`.

**Verify**
- `php -l` clean.
- Class loads via `composer dumpautoload` — `ddev composer dumpautoload`, then `ddev craft` lists plugin commands without fatal.

## Layer 2 — Service

**Build**
- New `src/services/RegistrationService.php`. Public method `register(array $params): User`.
- Param shape: `email` (required), `password` (required), `username` (optional, defaults to email), `groups` (array of handles), `fields` (custom field values keyed by handle), `sendActivationEmail` (default depending on Craft's `requireEmailVerification` setting).
- Resolve groups via `Craft::$app->userGroups->getGroupByHandle($handle)`. Throw `\InvalidArgumentException` if any handle is unknown — explicit failure.
- Pre-validate password against the resolved policy (Lite = global; Pro = `PolicyResolverService::resolveForGroups($groupIds)` against the assigned groups).
- Create user via `Craft::$app->elements->saveElement()`. Assign groups via `Craft::$app->users->assignUserToGroups()`. Set custom field values via `$user->setFieldValues()`.
- Optionally send activation email via `Craft::$app->users->sendActivationEmail()`.
- Fire `UserRegisteredEvent` AFTER successful save + group assignment.
- On validation failure: throw `\craft\errors\ElementValidationException` (or a custom `RegistrationValidationException` extending it) with `getValidationErrors()` exposing per-field errors.
- Register service in `src/services/ServicesTrait.php` as `registration`. Add `getRegistration()` getter with PHPDoc return type.

**Verify**
- `php -l` clean.
- One-shot console verification — run a registration via REPL or a temporary action:
  ```bash
  ddev craft password-policy/dev/register-test-user  # if you wire a temp dev command
  ```
  OR via Twig in a CP page (preferred — uses real request lifecycle).
- Confirm: user created, groups assigned by handle, custom field values set, event fired (add a temporary listener to verify), activation email sent (visible in Mailpit if applicable).

## Layer 3 — Edition gating

**Build**
- No edition gate on the service entry point — it works on Lite (with global validation).
- The Pro-only behavior is the per-group resolution. Add a Pro check inside `register()` before calling `PolicyResolverService::resolveForGroups()`. On Lite, fall back to global validation via the existing UserRules path.

**Verify**
- Switch playground to Lite via `project.yaml` + `ddev craft up`. Run a registration with `groups: ['editors']`. Confirm: registration succeeds (group assignment is Craft's responsibility, not edition-gated), password validates against global policy only.
- Switch back to Pro. Same registration. Confirm: password validates against the Editors policy if one exists.

## Layer 4 — Tests + Docs

**Build**
- TESTING.md additions: T11.1 (basic registration), T11.2 (group assignment by handle), T11.3 (Pro per-group password validation), T11.4 (validation failure → exception with field errors), T11.5 (UserRegisteredEvent fires).
- CHANGELOG entry under `[5.2.0] - Unreleased`.

**Verify all 5 tests on the playground.**

## Commit

Single commit at end of layer 4: `feat(registration): RegistrationService + UserRegisteredEvent + Pro per-group validation (P1.14)`. Extensive body covering: service shape, edition split, group-handle resolution, validation flow, event payload.

---

# Feature 2: P1.13 — HIBP-on-login (Pro)

Self-contained. Builds on existing notification template infrastructure (P1.3) + audit log (existing).

## Layer 1 — Event class + notification key

**Build**
- New `src/events/BreachDetectedEvent.php`. Properties: `User $user`, `string $sha1Prefix` (the 5-char k-anonymity prefix, never the full hash), `\DateTime $detectedAt`. PHPDoc + `@event`.
- New notification key `breach-detected` in `src/data/EmailDefaults.php`. Static method `breachDetected(): array` returning subject + body defaults. Tokens: `{{ user.friendlyName }}`, `{{ siteName }}`, `{{ detectedAt|datetime }}`.
- Migration: generate via `ddev craft migrate/create AddBreachDetectedNotificationDefaults --plugin=password-policy`. Migration body: for each enabled site, insert a row in `passwordpolicy_notification_templates` for `breach-detected` key with default content from `EmailDefaults::breachDetected()`. Idempotent guard.

**Verify**
- `ddev craft up` applies cleanly. Inspect `passwordpolicy_notification_templates` — new rows for `breach-detected` key, one per site.
- Visit `/admin/password-policy/notifications` — `breach-detected` appears in the index alongside `expiry-reminder`. Edit screen renders.

## Layer 2 — Settings + Pro guard

**Build**
- Add `enableHibpOnLogin: bool` to `SettingsModel` (default `true`). PHPDoc, `@since 5.2.0`.
- Add UI on the Settings → Validators page (or wherever HIBP at change time lives). Pro-strip in `SettingsController::actionSave` for Lite.
- Add ProductionSetting note: cron not required (it's a synchronous-on-login thing), but document the API rate limits.

**Verify**
- Field appears on the settings page. Toggling persists. Lite users don't see it (Pro-strip works).

## Layer 3 — Login listener + HIBP service

**Build**
- New private method `_registerLoginListeners()` in `src/PasswordPolicy::init()`. Registered only when `getIsPro()`.
- Listener on `craft\elements\User::EVENT_AFTER_LOGIN` (verify exact event name in `vendor/craftcms/cms/src/elements/User.php`). Receives the User element. Plaintext password is NOT in scope by this point.
- **Critical**: HIBP-on-login can't get the plaintext after login. The plaintext is only available **during** the login flow — at `Users::EVENT_AFTER_VALIDATE_PASSWORD` or via `\craft\controllers\UsersController` interception. We need to verify what event Craft fires that gives us the plaintext momentarily, OR we need to listen to the password-validate hook.
  - **Action**: research before building. Check `Users::EVENT_AFTER_VALIDATE_PASSWORD` (if exists), or `\craft\elements\User::authenticate()` overrides. Document findings in PROGRESS.md before writing code.
  - If plaintext-during-login isn't accessible via event, fall back to: store the SHA-1 prefix at password-change time (k-anonymity safe), background re-check via cron (deferred; this is Watchtower-mode in IDEAS.md). For 5.2.0, we want synchronous on-login if technically feasible.
- Hash plaintext to SHA-1, take 5-char prefix, hit `https://api.pwnedpasswords.com/range/<prefix>`. Async via `Craft::$app->queue` if needed for performance.
- 24h dedup cache via `Craft::$app->cache->getOrSet("pp:hibp-login:{$user->id}:{$prefix}", function () {...}, 86400)`.
- On detection (HIBP returns the SHA-1 suffix in the bucket):
  1. Set `$user->passwordResetRequired = true` and save (use `muteEvents` to avoid recursion).
  2. Send `breach-detected` email via `NotificationService::sendBreachDetected($user)` (new public method, uses `NotificationTemplateService::getTemplate('breach-detected', $siteId)`).
  3. Log to audit log via `AuditLogService->logEvent('breach_detected', ['userId' => $user->id])`. Audit log is Enterprise — gate this call inside `if ($plugin->getIsEnterprise())`.
  4. Fire `BreachDetectedEvent`.
- **Privacy**: never log the plaintext, full hash, or full prefix-and-suffix bucket. Log only "match found, user X notified."
- **Failure modes**: HIBP API down → `try/catch (\Throwable)`, log warning, return early. Rate-limited (429) → respect `retry-after` header, skip this login's check. Never block the login itself.

**Verify**
- Log in with a known-breached password (use `Password123!` which is in HIBP's database). Confirm:
  - Login succeeds (not blocked).
  - `passwordResetRequired = true` on the user.
  - `breach-detected` email lands in Mailpit.
  - Audit log entry exists (Enterprise; if not on Enterprise, skip this verification).
  - `BreachDetectedEvent` fires (add a temporary listener).
- Log in again immediately with the same password. Confirm: dedup cache hit, no second email, no second audit entry.
- Disable HIBP API access (block in DDEV's `/etc/hosts` or similar). Log in. Confirm: login still succeeds, warning logged, no exception bubbled.
- Switch to Lite. Confirm: listener doesn't register. Log in with a breached password — no detection, no email, no audit entry.

## Layer 4 — Tests + Docs

**Build**
- TESTING.md additions: T12.1 (breach detection on login), T12.2 (dedup cache 24h), T12.3 (HIBP API down — silent fail), T12.4 (Lite — listener doesn't register), T12.5 (BreachDetectedEvent fires), T12.6 (Enterprise audit entry).
- CHANGELOG entry.
- Update `docs/04-validators.md` (or wherever HIBP-at-change-time is documented) with the new HIBP-on-login section. Reference the audit log for Enterprise customers.

**Verify all 6 tests on the playground (Pro + Enterprise toggle as needed).**

## Commit

Single commit: `feat(hibp): HIBP-on-login Pro listener + breach-detected notification + BreachDetectedEvent (P1.13)`. Extensive body covering: event-source decision (synchronous-on-login vs Watchtower), privacy stance, failure modes, dedup cache, audit-log Enterprise gating.

---

# Feature 3: P1.12 — Front-end Twig surface (Pro)

The big one. Multi-layer, multi-component. Estimated 1.5–2 days alone.

## Layer 1 — Data accessors + group-preview

**Build**
- Add to `src/variables/PasswordPolicyVariable.php`:
  - `requirements(array $params = []): array` — accepts optional `groups: ['editor']` for anonymous group preview. Returns flat typed array: `{ minLength, maxLength, requireUppercase, requireLowercase, requireNumbers, requireSymbols, blocklistEnabled, historyCount, ... }`. Lite returns global; Pro resolves per-group via `PolicyResolverService` (when `groups` provided OR current user has groups).
  - `requirementsText(array $params = []): string` — single human-readable summary string. Same `groups` param. Goes through `Craft::t('password-policy', '...')` for i18n.
  - `requirementRules(array $params = []): array` — returns `[{key: 'length', label: 'Must be 12+ chars', met: false}, ...]`. `met` is `null` until the user starts typing (filled by JS via AJAX validate response).
- Type safety via dedicated PHPDoc; no class wrapping needed (flat array is fine per discussion).

**Verify**
- Twig template: `{{ craft.passwordPolicy.requirements({groups: ['editor']})|json_encode|raw }}`. Inspect output — looks like the resolved policy.
- Try without groups param when logged in as a user with groups. Confirm: returns the user's resolved policy (not global).
- Lite + same call. Confirm: returns global only.

## Layer 2 — Tag classes (fluent builders)

**Build directory** `src/web/twig/tags/` (or `src/twig/tags/` — match existing project conventions; check `src/twig/` if it exists).

For each builder, write a Tag class with:
- Chainable setters returning `$this`
- Constructor accepts optional config array
- `render(): string` final method
- Internal `_validate()` called at top of `render()` — throws `\InvalidArgumentException` for required-but-missing or contradictory config
- Auto-registers `PasswordPolicyClientAsset` if `$liveValidation === true`

Tag classes:
- `PasswordFieldTag` — `<input type="password">` with `data-pp-*` attributes. Supports: `name` (required), `id`, `value` (NOT prefilled in production — security), `autocomplete` (default `new-password`), `inputAttrs`, `wrapperAttrs`, `toggleVisibility` (default true), `toggleAttrs`, `liveValidation` (default false), `submitGate` (CSS selector for the submit button to enable/disable).
- `RequirementListTag` — `<ul>` of `<li data-pp-requirement="<key>">` items. Supports: `listAttrs`, `itemAttrs`, `groups` (for anonymous group preview).
- `StrengthMeterTag` — `<div data-pp-strength>` wrapper with `<div class="bar">` inside. Supports: `barAttrs`, `wrapperAttrs`. Class state toggled by JS.
- `RequirementsHintTag` — `<p>` with the human-readable summary. Supports: `wrapperAttrs`, `groups`.
- `PasswordWidgetTag` — composite. Internally instantiates `PasswordFieldTag` + `StrengthMeterTag` + `RequirementListTag` + `RequirementsHintTag`. Toggles via `showStrength`, `showRequirements`, `showHint`. Supports `wrapperAttrs` for the outer `<div>`.

For form renderers (a separate set):
- `LoginFormTag` — full `<form>` POSTing to Craft's `users/login`. Renders username/email input + password input + remember-me checkbox + submit button + redirect input + CSRF + flash error rendering.
- `PasswordChangeFormTag` — full `<form>` for logged-in user. Three password fields (current, new, confirm) + submit. POSTs to a new `Front\PasswordChangeController::actionSave`.
- `PasswordResetFormTag` — token-based reset form. POSTs to a new `Front\PasswordResetController::actionSave`.

Each form Tag accepts: `formAttrs`, `submitButtonAttrs`, `submitLabel`, `successRedirect`, individual field-attrs slots.

Naming convention: namespace `craftpulse\passwordpolicy\twig\tags\` (or similar). Each Tag in its own file.

**Verify**
- `php -l` clean for every Tag class.
- For each Tag, write a temporary Twig template that exercises it, render it via `php -r` or a CP one-shot route, and inspect the markup. Confirm: `data-pp-*` attributes present where expected, `*Attrs()` merging works, empty values omitted.

## Layer 3 — Variable wiring

**Build**
- Add methods on `PasswordPolicyVariable` that return Tag instances:
  - `passwordField(array $params = []): PasswordFieldTag`
  - `requirementList(array $params = []): RequirementListTag`
  - `strengthMeter(array $params = []): StrengthMeterTag`
  - `requirementsHint(array $params = []): RequirementsHintTag`
  - `passwordWidget(array $params = []): PasswordWidgetTag`
  - `loginForm(array $params = []): LoginFormTag`
  - `passwordChangeForm(array $params = []): PasswordChangeFormTag`
  - `passwordResetForm(array $params = []): PasswordResetFormTag`
- Each method just `return new XxxTag($params)`. No business logic in the variable.

**Verify**
- Twig `{{ craft.passwordPolicy.passwordField({name: 'pwd'}).render() }}` produces the expected `<input>`. Same for every other builder.

## Layer 4 — JS asset + AJAX wiring

**Build**
- New `src/web/assets/dist/` directory. Add `password-policy.js` (vanilla, ~5KB minified). Build with whatever bundler we use during plugin dev (esbuild / rollup / Vite — whatever's quickest to wire). Commit the **built artifact** to the repo.
- Behavior:
  - On DOMContentLoaded, find every `[data-pp-validate]`.
  - Attach `input` listener (debounced 250ms): POST to `password-policy/validation/validate` with `password` + any `data-pp-context-*` attributes mapped to corresponding form fields (e.g., `data-pp-context-username` → `username` body param).
  - Read response: `{rules: [...], strength: {label, score?, suggestions?}, hibp: 'pending'|'pass'|'fail'}`.
  - Toggle classes on consumer-marked slots:
    - `[data-pp-requirement="length"]` gets `pp-pass` / `pp-fail` / `pp-pending` based on response
    - `[data-pp-strength]` gets `pp-strength-weak` / `-fair` / `-strong` / `-excellent` based on label
    - `[data-pp-submit-gate]` (closest selector matching `submitGate` config from the input) gets `disabled` toggled
    - `[data-pp-live-region]` (closest, or auto-injected hidden `<span>` for a11y) gets the announcement text
  - HIBP UX: non-blocking. If response says HIBP is pending, treat synchronous rules' result for submit gate; if HIBP comes back as `fail`, retroactively flip to disabled. State announced via live region.
  - Show/hide toggle: bind click on `[data-pp-toggle-visibility]`, toggle input `type` between `password` and `text`, flip `aria-label` and inner SVG.
- Asset bundle: `src/assetbundles/passwordpolicyclient/PasswordPolicyClientAsset.php` extending `\craft\web\AssetBundle`. `$sourcePath = '@craftpulse/passwordpolicy/web/assets/dist'`. `$js = ['password-policy.js']`.

**Verify**
- Build a registration template at `templates/test-registration.twig` (in the playground): one form using `passwordField()` + `requirementList()` + `strengthMeter()` + `requirementsHint()` + a submit button.
- Visit the page, type a password slowly. Confirm:
  - Requirement list items toggle pass/fail/pending in real time.
  - Strength meter label updates.
  - Submit gate disables/enables.
  - HIBP-pending state appears for ~200-500ms after typing stops, then resolves.
  - VoiceOver reads state changes from the live region.
  - Show/hide toggle works.

## Layer 5 — Strength engine A baseline

**Build**
- Update `ValidationController::actionValidate` to compute and return the strength block:
  - Count rules passed (length, char-type, etc.).
  - Length tier: <8 = 0, 8-11 = 1, 12-15 = 2, 16+ = 3.
  - Label: `weak` / `fair` / `strong` / `excellent` derived from a small matrix of `(ruleCount, lengthTier)`.
  - Blocklist hit forces `weak`.
- Add `strength: {label, ruleCount, lengthTier}` to the JSON response.

**Verify**
- POST to validate with various passwords; inspect strength block. Confirm: blocklist passwords → `weak` regardless of length, long random passwords → `excellent`, etc.

## Layer 6 — Strength engine B Pro opt-in (zxcvbn-php)

**Build**
- Add `useZxcvbnStrength: bool` to `SettingsModel` (default `false`). UI on Settings → Validators page (Pro block).
- Composer dep: `ddev composer require bjeavons/zxcvbn-php`. Update `composer.json` + `composer.lock`.
- New `src/services/StrengthService.php` with two methods:
  - `analyzeBaseline(string $password, array $context = []): array` — the rule-counting + length-tier label.
  - `analyzeZxcvbn(string $password, array $context = []): array` — uses `\ZxcvbnPhp\Zxcvbn`. Pass user's `username`, `email`, etc. as the user-input dictionary. Returns score 0-4, crack-time string, suggestions array, label.
- Update `ValidationController::actionValidate` to call `analyzeZxcvbn` when `useZxcvbnStrength === true` AND `getIsPro()`. Otherwise call `analyzeBaseline`.
- Service registered in `ServicesTrait` as `strength`.

**Verify**
- Toggle setting on. POST to validate with `Password1!`. Confirm: zxcvbn returns score 0-1 with suggestions like "Capitalization doesn't help very much". Without the toggle, baseline returns `weak` only on blocklist hit (it would otherwise pass 4 rules and return `strong`).
- Toggle off. Same password. Confirm: baseline path runs, no zxcvbn call.

## Layer 7 — Form controllers

**Build**
- New `src/controllers/Front/PasswordChangeController.php` (note `Front\` namespace to distinguish from CP controllers). `$allowAnonymous = false` — must be logged in. `actionSave()` validates current password + new password against resolved policy + writes new password + invalidates other sessions (existing infrastructure).
- New `src/controllers/Front/PasswordResetController.php`. `$allowAnonymous = ['save']` — token-based. `actionSave()` validates token, validates new password, writes, redirects.
- URL rules in `PasswordPolicy::init()` URL rules registration:
  - `password-policy/front/password-change/save` (POST) → `front-password-change/save`
  - `password-policy/front/password-reset/save` (POST) → `front-password-reset/save`

**Verify**
- Build two test pages in the playground: `/account/change-password` and `/auth/reset?token=xxx`. Use `passwordChangeForm()` and `passwordResetForm()` builders. Confirm: POST flow works, validation surfaces errors, success redirects.

## Layer 8 — Tests + Docs

**Build**
- TESTING.md additions: T13.1–T13.12 covering each builder + AJAX flow + show/hide toggle + a11y + multi-site + HIBP-pending UX + form renderers.
- New doc `docs/10-frontend-twig-surface.md` with the full API reference.
- README updates: new "Front-End Templates" section linking to the doc.
- CHANGELOG entry.

**Verify all 12 manual tests on the playground.**

## Commits (one per layer)

Layer 1 → `feat(variables): requirements/requirementsText/requirementRules accessors with group preview (P1.12 layer 1)`
Layer 2 → `feat(twig-tags): fluent Tag classes for field + form renderers (P1.12 layer 2)`
Layer 3 → `feat(variables): wire Tag classes to craft.passwordPolicy.* methods (P1.12 layer 3)`
Layer 4 → `feat(client): JS asset + AJAX validation + a11y live region (P1.12 layer 4)`
Layer 5 → `feat(strength): rule-counting + length-tier baseline strength engine (P1.12 layer 5)`
Layer 6 → `feat(strength): zxcvbn-php Pro opt-in strength engine (P1.12 layer 6)`
Layer 7 → `feat(controllers): Front\PasswordChangeController + PasswordResetController (P1.12 layer 7)`
Layer 8 → `docs(frontend): manual tests + frontend twig surface reference + README cross-link (P1.12 layer 8)`

---

# Feature 4: P1.15 — Events catalog

Documentation deliverable. After P1.13 + P1.14 ship, all event classes exist; we document them.

## Layer 1 — Audit existing event classes

**Build**
- Scan `src/events/` for all event classes. As of P1.14 + P1.13 completion: `PasswordChangedEvent`, `UserRegisteredEvent`, `BreachDetectedEvent`. (Confirm by listing the directory.)
- For each, verify the class has `@author`, `@since`, `@event` PHPDoc + section header `=========`.

**Verify**
- `ddev craft password-policy/dev/list-events` (if you build a temp dev command) OR just `ls src/events/`. Confirm three classes.

## Layer 2 — Write `docs/events.md`

**Build**
- New `docs/events.md`. Structure:
  - Intro paragraph: "All events the plugin fires, for consumers building integrations."
  - One H2 per event. For each: name + FQ class, when fires, payload table (property, type, description), edition tier, example listener with imports.
  - Closing section: "Subscribing to events" — generic Craft pattern reminder.
- Future events placeholder: list `PolicyValidatedEvent`, `PasswordExpiredEvent`, `LockoutThresholdReachedEvent` as "planned" (with target version 5.3 or Phase G).

**Verify**
- File exists, renders cleanly in a Markdown preview. Listener examples are syntactically valid PHP.

## Layer 3 — README cross-link

**Build**
- Add an "Events" section to `README.md` linking to `docs/events.md`. Brief one-paragraph teaser ("Hook into password-policy events for analytics, audit, SIEM forwarding").
- Reference under the Pro/Enterprise positioning copy.

**Verify**
- Link works locally.

## Commit

Single commit: `docs(events): catalog of plugin events with example listeners (P1.15)`. Body explains the cross-cutting rule: every new feature ships with its event class + docs/events.md row in the same commit.

---

# Hard guards (read MEMORY.md for the durable list)

- **Always** generate migrations via `ddev craft migrate/create <Name> --plugin=password-policy`. Never hand-pick filenames or timestamps.
- **Use ddev shorthand commands.** Never `php`, `composer`, or `npm` on the host.
- **No `@deprecated` markers on code added in this same unreleased version** — delete dead code instead.
- **Don't say "pruned automatically"** in user-facing copy. `password-policy/gc/run` cron is the recommended production setup.
- **Default to native Craft components.** `forms.editableTableField` for admin lists, `<blockquote class="note tip|warning">` for callouts, `|datetime`/`|time` for locale-aware timestamps.
- **PHPDocs on everything.** `@author CraftPulse` + `@since 5.2.0` on classes and public methods. Section headers with `=========` separators on every class. Non-negotiable.
- **No commit AI attribution.** No `Co-Authored-By` trailers. No "Claude" / "Claude Code" / "AI" mentions in commit messages, code comments, or doc updates. Per CLAUDE.md.
- **Use ddev craft commands** (not `ddev mysql`) for inspecting Craft state.
- **Don't blindly trust audit subagent reports.** Verify before applying.
- **Twig errors propagate naturally.** Don't wrap methods in defensive null returns or try/catch. Throw `\InvalidArgumentException` for bad inputs.
- **a11y is non-negotiable.** Every front-end builder ships with full a11y wiring. Test with VoiceOver / NVDA before marking the feature done.
- **Privacy on HIBP-on-login.** Never log the plaintext, full hash, or full prefix-and-suffix bucket. Document this rule in code comments at the listener.
- **Edition gating is graceful, not throwing**, for the front-end Twig surface. Lite degrades to global-only resolution. The CP gates Pro features (subnav, settings tabs); the front-end always works.

---

# Commit protocol

- Commit at the end of each verified layer. Roughly 14 commits total for Phase C2 (3 + 4 + 8 + 1, with some layers possibly tiny enough to fold).
- Conventional commit prefixes: `feat`, `refactor`, `test`, `docs`, `chore`. Match the existing log style.
- Commit messages: imperative mood, extensive body covering *why* + *what* + *how to undo if needed* + any subtle implementation gotchas. Match the depth of `7b9d7b7` (the recent UX polish squash) and `04178bf` (the P1.4 batched job).
- DO NOT push. Local commits only — user pushes on their own cadence.
- HEREDOC commit messages for proper formatting.

---

# Final deliverables

When Phase C2 is complete:

- **Files created:** ~25-30 new files across events, services, records (none new — no schema beyond the migration), controllers, twig tags, asset bundles, JS bundle, templates, docs.
- **Files modified:** `src/PasswordPolicy.php`, `src/services/ServicesTrait.php`, `src/services/NotificationService.php`, `src/services/AuditLogService.php`, `src/variables/PasswordPolicyVariable.php`, `src/controllers/ValidationController.php`, `src/data/EmailDefaults.php`, `src/models/SettingsModel.php`, `src/templates/_settings/validators.twig`, `composer.json` + `composer.lock`.
- **TESTING.md:** ~20 new manual test rows across T11 (P1.14), T12 (P1.13), T13 (P1.12).
- **PLAN.md:** strike P1.12, P1.13, P1.14, P1.15. Mark Phase C2 done. Phase D becomes next.
- **PROGRESS.md:** comprehensive session note covering: architecture decisions made along the way, bugs caught during verification, drifts from the spec (with rationale), what was learned that's worth flagging for future skill updates.
- **NEXT-SESSION.md:** refresh handover for Phase D start (P2.1 user index + P2.2 admin password change).
- **CHANGELOG.md:** entries for all four features under `[5.2.0] - Unreleased`.
- **`docs/events.md`:** new file. **`docs/10-frontend-twig-surface.md`:** new file.
- **Working tree clean** after Phase C2 completion.

---

# Reporting

When complete, report:
- Files created (count + grouped by feature)
- Files modified (count + list)
- Commits made (count + one-liner each)
- Any verify steps that revealed issues + how they were resolved
- Any architectural assumptions made that weren't explicit in the plan (with rationale)
- Whether anything is left for the user to verify manually (e.g. browser-only UX, multi-site fixtures we don't have on the playground)
- Skill gaps surfaced during the build (every Craft API gotcha, every "how does X work in Craft 5" question that took >10 minutes to answer)

If a verify step fails and you can't recover, STOP and report. Don't push past failures. Surface the issue with file path + line number + what you expected vs what you got.
