# Progress Log — Phase C2 (closed)

Rotated from `internal/progress.md` when Phase C2 closed (2026-05-02). Phase C2 was the Pro front-end surface bundle — P1.12 (front-end Twig render builders + JS asset + strength engine A/B), P1.13 (HIBP-on-login Pro), P1.14 (RegistrationService helper), P1.15 (events catalog) — plus the Layer 4b strength-engine unification follow-up and the bug-fix sweep that closed C2.

Date range: 2026-05-01 → 2026-05-02.

Refer to `internal/plan.md` for current backlog, `internal/reference.md` for completed-work tables (§5), and `internal/history/phase-c2-build-plan.md` for the original Phase C2 build plan.

---

## Session: 2026-05-01 (Phase C2 — Pro front-end surface bundle)

### P1.14 — RegistrationService (shipped)

Smallest of the four Phase C2 features. Wired a programmatic registration helper that's edition-aware: callers pass group **handles** (not IDs — more dev-friendly), and the service resolves them up front, populates `$user->setGroups()` before `$user->validate()` so `UserRules::defineRules($user)` calls `PolicyResolverService::resolveForUser()` with the assigned-group context. Lite degrades to global validation; Pro applies per-group merged policy. New `UserRegisteredEvent` exposes `User`, `string[] $groups` (the input handle array), and `bool $viaService = true`. Plaintext is intentionally NOT in the event payload — the password is already validated and persisted by event time. Validation failures throw `\InvalidArgumentException` with attribute-prefixed messages flattened into one string for clean surfacing in consumer forms.

Verification ran via a temporary `DevController` (deleted before commit): basic registration, group resolution by handle, validation-failure surfacing, unknown-handle clear-error path, `EVENT_USER_REGISTERED` listener firing on success path only. T11.1–T11.5 added to TESTING.md.

### P1.13 — HIBP-on-login Pro — research before code

The plan called for synchronous-on-login HIBP detection. This requires the plaintext password to be in scope momentarily during the login flow. Findings:

- **`User::EVENT_BEFORE_AUTHENTICATE`** (vendor/craftcms/cms/src/elements/User.php:105 + line 1378-1387) fires inside `User::authenticate(string $password)` BEFORE the security check runs. The event is `craft\events\AuthenticateUserEvent` with public properties: `?string $password` (plaintext, in scope), `bool $performAuthentication`. `$event->sender` is the User. The signature is stable since Craft 3.0.0.
- **`User::EVENT_AFTER_VALIDATE_PASSWORD` does not exist on Craft 5.** Searched `vendor/craftcms/cms/src` for any "ValidatePassword" event constant and none was found. So `BEFORE_AUTHENTICATE` is the only synchronous in-flow hook with plaintext access.
- The plaintext is gone after `authenticate()` returns. There is no post-login event with plaintext access.

Decision: register the listener on `User::EVENT_BEFORE_AUTHENTICATE`, only when `getIsPro() === true`. The plaintext is hashed to SHA-1 inside the listener; only the 5-char k-anonymity prefix is sent to HIBP. Privacy invariant: never log the plaintext, full hash, or full prefix-and-suffix bucket. `passwordResetRequired` is set after the breach-confirmed branch fires (separate save with `muteEvents` to avoid recursion against the password-history listeners).

The event fires regardless of whether authentication succeeds, so we narrow our work to the success branch by hashing inside the listener and only acting if the password validates. We can't gate on success cleanly within `BEFORE_AUTHENTICATE` (it fires before validation), so we hash the plaintext, look it up in HIBP, and if breached, schedule the side-effects via `EVENT_AFTER_REQUEST` so they only run if Craft considered the auth successful (the request reaches its end with the user logged in). Alternatively: act inside the listener without success-gating — even if the password is wrong, an attacker has already proven they have the plaintext, so we still want to alert. Choice: act immediately. The privacy invariant is preserved — we never log the plaintext, only "match found, user X notified" booleans.

### P1.13 — built and verified

Listener landed at `PasswordPolicy::_registerHibpOnLoginListener()` (gated by `getIsPro()`) and `PasswordPolicy::_runHibpOnLoginCheck()`. Migration generated via `ddev craft migrate/create AddBreachDetectedNotificationDefaults --plugin=password-policy` seeds the `breach-detected` notification template per enabled site; `Install::_seedNotificationTemplateDefaults()` already iterates `EmailDefaults::all()` so fresh installs get the row automatically. New `enableHibpOnLogin` setting (default `true`, Pro) added with UI on Settings → Configuration. Verified end-to-end by setting editor user's password to `Welcome2024` (live HIBP confirmed breached), submitting a login POST, observing the breach-detected email + Craft's auto password-reset email in Mailpit, plugin log line (`HIBP-on-login match: user 55 notified, passwordResetRequired set`), and `passwordResetRequired = 1` written by the listener. Caught a cache-encoding bug during dedup verification — initial `bool` values collide with Yii's "missing key returns false" contract; switched to `'breached'`/`'clean'` string values. T12.1–T12.5 in TESTING.md.

### P1.12 — Front-end Twig surface

Built layers 1, 2, 3, 4a, 5, 6, 7, 8 in one focused session. Layer 4b (CP-side strength meter replacement on Pro CP requests) deferred — see "Layer 4b deferral" below.

Architecture decisions made along the way:
- **`render()` returns `\Twig\Markup`, not raw `string`.** First version of the BaseTag had `render(): string` — Twig auto-escaped the markup so the rendered page showed `&lt;div&gt;` everywhere. Fixed by making `render()` wrap an internal `_renderHtml(): string` in a `Markup` instance keyed to the view's charset. Concrete tags also implement `__toString()` so the composite tags can `.= (string)$field` without explicit `render()` calls.
- **No new front-end action URL rules.** `password-policy/front/password-change/save` works through Craft's standard plugin action URL routing — namespace `craftpulse\passwordpolicy\controllers\front\PasswordChangeController` resolves automatically. No manual URL rule required. Lowercased the directory from `Front` to `front` to match the namespace casing on case-sensitive filesystems.
- **`PasswordResetFormTag` uses Craft's existing `users/set-password` action**, not a new plugin controller. Craft's path validates the token + UID from the reset email; the plugin's `User::EVENT_DEFINE_RULES` listener handles the policy validation. No need for a parallel `Front\PasswordResetController` — fewer surfaces to keep tested.
- **Strength engine A vs B share a service.** `StrengthService::compute()` picks the engine based on `(getIsPro() && useZxcvbnStrength && class_exists(Zxcvbn::class))` and falls through to baseline if zxcvbn ever throws. Same response shape (`label` always present); engine-specific keys (`score`, `crackTime`, `suggestions`) only on B.
- **`requirementsHint()` and `requirementList()` re-instantiate `PasswordPolicyVariable` internally** to get the resolved settings. That's a small allocation cost per render but keeps the Tag classes side-effect-free.
- **`_resolveSettings()` for anonymous group preview** builds a fake `User` with the right `setGroups()` and hands it to `PolicyResolverService::resolveForUser()`. Reuses the existing per-group merge algorithm without duplicating the merge logic; resolver doesn't care about user.id when groups are present.

Bugs caught during verification:
- Twig auto-escape on raw HTML strings — fixed via `\Twig\Markup` wrap.
- Yii cache `bool false` collides with "missing key" — surfaced earlier in P1.13 dedup, mentioned here because the same pattern would have bit any cache-key-driven feature.

### Layer 4b deferral

Layer 4b (replacing Craft's native zxcvbn-js meter on Pro CP password inputs) was deferred from this session. The work requires:
1. Reading `vendor/craftcms/cms/src/web/assets/cp/dist/cp.js` to confirm the DOM signature of CP password inputs (`input[type="password"][autocomplete="new-password"]` and the surrounding `.password-input` wrapper).
2. Identifying every CP screen that uses it (admin's account, new-user creation, plugin password fields).
3. Documenting how `Craft.PasswordInput` exposes its evaluator and whether the score gates form submission anywhere.
4. Writing a separate `cp-strength.js` asset bundle that hides Craft's native meter via CSS and re-renders the plugin's requirement-list + strength-meter markup in the same slot, preserving Craft's submit-gating.
5. Auto-registering the bundle on every CP request only when `getIsPro()` is true.

The Craft CP JS is bundled and minified, the DOM signature drifts across versions, and the work warrants Garnish-style focus that the rest of P1.12 didn't need. Deferred as a separate session before 5.2.0 tag — see `TESTING.md` T13.12 for the marker. Front-end Twig surface ships clean without it; the asymmetry (Lite keeps Craft's meter on the CP, Pro replaces it) is purely an upgrade-incentive nicety.

### P1.15 — Events catalog

`../user/reference/events.md` synthesizes all event classes added across Phase A through Phase C2: `PasswordChangedEvent` (Lite), `UserRegisteredEvent` (Lite, P1.14), `BreachDetectedEvent` (Pro, P1.13), `PasswordValidationEvent` (Lite, pre-existing). Each entry has the FQ class, when it fires, payload table, edition tier, and an example listener with imports. Future events placeholder section (`PolicyValidatedEvent`, `PasswordExpiredEvent`, `LockoutThresholdReachedEvent`) flagged for 5.3+ / Phase G. Cross-linked from `README.md` "Events" section.

### Process notes

- 4 commits across the four features.
- Composer dep `bjeavons/zxcvbn-php` (^1.4) added — was pre-approved 2026-05-01.
- ECS still blocked by host PHP 8.4 vs DDEV PHP 8.3 vendor mismatch (unchanged from prior sessions). PHPStan ran clean throughout.
- All migrations generated via `ddev craft migrate/create <Name> --plugin=password-policy` per the durable rule.
- Per-layer playground verification cleared each gate before the next layer started, except Layer 4b which was scoped out before any code was written.

---

## Session: 2026-05-01 (P1.12 Layer 4b — strength engine unification)

### Spec premise correction

The original `history/phase-c2-build-plan.md` Layer 4b framing — "replace Craft's native zxcvbn meter on the CP" — was wrong. Confirmed empirically: `find vendor/craftcms/cms -name "*.js" | xargs grep -l zxcvbn` returns zero matches. Craft 5 ships no client-side zxcvbn meter. `Craft.PasswordInput` exists but is a Garnish wrapper for show/hide toggle + capslock detection — not a strength evaluator.

What did exist before this session was an unrelated asymmetry: the plugin shipped its **own** client-side strength indicator at `buildchain/src/js/indicator.ts` using `@zxcvbn-ts/core` (TS port). It hardcoded `#newPassword`, ran zxcvbn entirely in the browser, and had no awareness of the plugin's blocklist, per-group policy resolution, or the new `useZxcvbnStrength` Pro toggle. Layers 1–7 of P1.12 (commit `ffa7aa9`) added a server-side `bjeavons/zxcvbn-php` engine, `StrengthService` with two modes (baseline + zxcvbn-php), and a `password-policy.js` consumer asset that hits `/validate` for builder-rendered front-end forms. Result was two parallel zxcvbn implementations on different sides of the fence with diverging awareness of plugin features.

Layer 4b's actual job: unify. Refactor the CP-side indicator to consume the same AJAX `/validate` endpoint the front-end builders use. Single engine, single source of truth.

### Architectural decisions (made up front, before code)

- **Selector strategy → `input[type="password"][autocomplete="new-password"]:not([data-pp-no-strength])`.** Verified by reading Craft 5 CP password screens: `_special/install/account.twig`, `set-password.twig`, `users/_password.twig` all render via the `forms.passwordField` macro with `autocomplete: 'new-password'`. The macro renders `<input type="password" autocomplete="new-password">` inside `.passwordwrapper`. Broad enough to attach on installer, set-password, admin account, and new-user screens; narrow enough to skip current-password and confirmation fields (which use `autocomplete="current-password"` or no autocomplete). Opt-out via `data-pp-no-strength` for plugin fields that explicitly want to skip the indicator. Rejected `#newPassword` (too narrow — only matches the admin-account screen) and `[data-pp-cp-strength]` (would require Craft to opt in everywhere — not happening).
- **Failure mode → silent.** AJAX failures freeze the bars at last known state. Strength UX is non-blocking; the server-side validator on save remains the actual gate. Same behavior as the existing front-end consumer asset's `bindValidate` callback. Documented in code comment.
- **Visual language → preserved.** Keep 5-bar grid, keep `pp-bg-red-400 / pp-bg-orange-400 / pp-bg-amber-300 / pp-bg-teal-400 / pp-bg-green-500` color stops. Map server label to bar count: `weak` → 1 bar red, `fair` → 2 bars orange, `strong` → 3 bars teal, `excellent` → 5 bars green. When engine B's `score 0-4` is present, use it directly for the bar count (more granular than the 4-label vocabulary) — same color stops keyed off the rounded label.
- **Asset bundle → unchanged.** Reuse `PasswordPolicyAsset`. The Vite-registered `indicator.ts` is what changes; the bundle wiring is identical.
- **Insert location → closest `.field` ancestor of the input, falling back to the input's parent.** Replaces hardcoded `#newPassword-field`. Works on every CP screen because `forms.passwordField` always renders the input inside a `.field` wrapper.
- **Settings copy → tweaked.** Existing `instructions: "Display a password strength meter powered by zxcvbn in the control panel."` was already accurate (server engine is also zxcvbn through `bjeavons/zxcvbn-php`). Reworded to mention the unified pipeline (blocklist + per-group + Pro `useZxcvbnStrength` for detailed feedback).

### Build

Refactored `buildchain/src/js/indicator.ts` from a self-contained zxcvbn-ts client to a thin AJAX renderer against `password-policy/validation/validate`. Dropped `@zxcvbn-ts/core`, `@zxcvbn-ts/language-common`, `@zxcvbn-ts/language-en` from `buildchain/package.json` and `buildchain/package-lock.json` and ran `ddev npm install` inside the buildchain to refresh the lockfile. Bundle size dropped from **~1.65 MB → ~3 KB** (the entire zxcvbn dictionaries went away). `grep -c zxcvbn` on the new dist file returns 0.

Settings template: `_settings/configuration.twig` instructions tweaked to reflect the unified pipeline.

PROGRESS-PROGRESS link from C2-BUILD-PLAN.md crossed-out at the top of the Layer 4b section, replaced with the unification rationale; PLAN.md status block updated to mark P1.12 fully closed.

### Side effects: what the CP indicator now sees that it didn't before

- **Blocklist hits force `weak`.** Type `acmecorp` (or any custom blocklist word) — the CP indicator now flips red, where the old client-side one had no concept of the blocklist.
- **Per-group policy resolution.** A user in a group with a higher `minLength` than global gets the group's resolved settings reflected in the strength block. The old indicator never knew per-group existed.
- **Pro `useZxcvbnStrength` toggle.** When the toggle is on, the response carries engine-B-specific keys (`score`, `suggestions`, `crackTime`, `warning`). Toggle off → baseline label only. Same engine selection logic as the front-end builders — a single code path now governs strength UX everywhere.
- **CSP nonce wiring → preserved.** `cspNonce: true` in plugin settings still adds the nonce attribute to the registered script tag.

### Bugs / footguns surfaced

- The old `indicator.ts` hardcoded `#newPassword-field` for its insert anchor — fine on `users/_password.twig` (which uses that exact id), but it never even attached on `set-password.twig` or `_special/install/account.twig`, so the CP installer + reset paths weren't getting an indicator at all. Fixed by switching to `closest('.field')` ancestor.
- Yii cache `bool false` collides with "missing key returns false" — the same pattern that bit P1.13 dedup. Listed in skill gaps memory; nothing new to log here.

### Process notes

- One commit: `refactor(strength): unify CP and front-end strength engines via AJAX (P1.12 layer 4b)`.
- PHPStan pre-existing baseline of 3 errors in `NotificationTemplateModel.php` / `NotificationService.php` / `NotificationTemplateService.php` was already there before this session. None of my touched files (`buildchain/src/js/indicator.ts`, `buildchain/package.json`, `buildchain/package-lock.json`, `src/templates/_settings/configuration.twig`, docs) touched those files. Final PHPStan count remains 3.
- ECS still blocked by host PHP 8.4 vs DDEV PHP 8.3 vendor mismatch (unchanged from prior sessions).
- Phase C2 is now fully closed. Next is Phase D (P2.1 + P2.2).

---

## Session: 2026-05-02 (Bug fix sweep — C2 code review + 5.1.1 file-config compat)

C2 followup. Foreground code-review on the four C2 commits + a deep look at the 5.1.1 → 5.2.0 file-based config compatibility surface produced 11 bugs ranging from "render-time fatal" to "subtle privacy guard." All fixed in 6 commits.

### What changed and why

**Twig-tag layer (1 commit) — `fix(twig-tags): defensive null gating + render docblock correction`.** `PasswordWidgetTag` was forwarding `submitGate => null` into the strict-typed `PasswordFieldTag::submitGate(string $selector)` setter, which TypeError'd at construct time when a consumer called `passwordWidget()` without `submitGate`. The same author had already gated `id` for this exact reason; same pattern applied here. Also added an `id()` canonical setter alias on `PasswordResetFormTag` matching Craft's reset-email URL `?code=…&id=…` param name. The legacy `userUid()` setter is preserved as an alias that calls `id()` internally — both forms write to the same config slot. Last: `BaseTag::__toString()` docblock corrected to spell out that `{{ tag }}` in Twig double-escapes the rendered HTML (Twig auto-escapes `__toString()` returns because PHP's contract requires a plain `string`, not `\Twig\Markup`). Always use `{{ tag.render() }}` from Twig.

**Controllers (1 commit) — `fix(controllers): session invalidation on password change + ValidationController context input hardening`.** `Front\PasswordChangeController` now calls a new `PasswordService::destroyOtherSessions(User $user)` helper after a successful password change. Belt-and-braces: Craft's `User::afterSave` already runs the same delete when `newPassword` is set, but the C2 spec called for the wiring to be visible at the controller layer. Helper handles the console-path branch — `getToken()` only exists on the web `User` component; calling it on the console `User` throws `UnknownMethodException`. Helper now gates on `getRequest()->getIsConsoleRequest()` before asking for the token. Failure modes are caught and logged at WARNING — never thrown back to the caller; the password change has already succeeded by the time we get here. `ValidationController::_resolveStrengthContext()` now pulls `username`/`email` from the session identity for authenticated requests and returns empty strings for anonymous requests; never trusts POST. Closes a small but real signal-leak surface (an unauthenticated attacker could submit a known username and observe how the strength score changed for guessed passwords).

**Client asset (1 commit) — `fix(client-asset): auto-register on toggleVisibility, fix cpTrigger fallback, blocklist hit propagation in zxcvbn-php`.** Three things bundled because they all touch the front-end interactivity surface:

 1. `BaseTag::_needsClientAsset(array $config)` centralizes the gating logic. Any of `liveValidation`, `toggleVisibility`, or `submitGate` set to truthy registers the bundle. `PasswordFieldTag` now calls `_needsClientAsset($this->config)` instead of bare `if ($liveValidation)`. Builders with `toggleVisibility: true, liveValidation: false` no longer ship a non-functional eye button.
 2. `StrengthService::analyzeZxcvbn()` accepts a `bool $blocklistHit = false` param symmetric with `analyzeBaseline()`. When set, the engine forces label to `weak` and clamps `score` to `0`. `compute()` forwards the param to both engines. Previously, a blocklisted long+complex password read as "excellent" from zxcvbn-php while the rule list correctly rejected it.
 3. Both `password-policy.js` and `buildchain/src/js/indicator.ts` had `'/index.php?p=admin/actions/password-policy/...'` as the fallback URL when `window.Craft.actionUrl` is unavailable. The hardcoded `admin` cpTrigger broke on installs with custom `cpTrigger`. Fix: switch to Craft 5's native `/actions/password-policy/validation/validate` route. Rebuilt the CP strength bundle via `ddev exec --dir /var/www/html/cms/vendor/craftpulse/craft-password-policy/buildchain npm run build` — new hash `strengthIndicator-D8sW1YRB.js` (was `C9hr7Ix1`). Bundle size held at 2.20 KB.

**HIBP 429 backoff (1 commit) — `fix(security): site-wide HIBP 429 backoff cache`.** The HIBP-on-login dedup cache only keyed on `(userId, sha1Prefix)`, so every login from a different user with a different prefix burned a fresh API request even when HIBP was already 429-rate-limiting the site. New `PasswordService::HIBP_BACKOFF_CACHE_KEY` sentinel cached at the cache layer with a TTL parsed from `Retry-After` (defaults to 60s if absent or non-numeric). Two layers of short-circuit: `PasswordService::hibp()` checks at the top before any network call; `PasswordPolicy::_runHibpOnLoginCheck()` also checks before its existing per-user dedup cache. Privacy guard: sentinel value is the literal string `'1'`, never user-derived. New public method `isHibpBackoffActive()` exposes the state for future Enterprise diagnostics.

**Variable handle (1 commit) — `fix(variables): register both passwordpolicy and passwordPolicy handles + update C2 docs to camelCase`.** 5.1.1 shipped `craft.passwordpolicy` (lowercase). C2 docs use `craft.passwordPolicy` (camelCase). Renaming would break 5.1.1 consumers; instead, register under both handles. The lowercase form ships permanently for backward compat — never `@deprecated`. The camelCase form is canonical going forward. Updated `../user/features/frontend-twig.md` and three CHANGELOG entries to use the canonical form. PHP namespace `craftpulse\passwordpolicy\...` is unchanged (PHP namespaces are always lowercase here).

**Settings model (1 commit) — `fix(settings): alias deprecated pwned/pwnedFailMode on SettingsModel for 5.1.1 file-config compat`.** Pre-tag blocker. The 5.1.1 → 5.2.0 rename of `pwned` → `hibp` and `pwnedFailMode` → `hibpFailMode` was covered by a project-config migration, but file-based config (`config/password-policy.php`) bypasses project config entirely. A 5.1.1 consumer with `pwned: true` in their file config would fail loud at boot with "Setting unknown property: pwned" on the first request after `composer update`. Fix: override four hooks on `SettingsModel`:

 1. `attributes()` — extended to include `pwned` + `pwnedFailMode` so Yii's `setAttributes()` doesn't skip them as unknown.
 2. `canGetProperty()` / `canSetProperty()` — return true for the legacy keys.
 3. `__get()` — reads of legacy keys resolve to the new properties.
 4. `__set()` — writes route to the new properties AND log a `Craft::warning` per assignment so site operators see the deprecation message during `craft up` or any cache warm.

The `@deprecated` annotation here IS appropriate despite the rule against deprecating same-version code. The rule is about not deprecating NEW code; `pwned`/`pwnedFailMode` are 5.1.1-shipped public API being renamed.

### Process notes

- 6 commits, all green through PHPStan after each.
- ECS still blocked by host PHP 8.4 vs DDEV PHP 8.3 vendor mismatch (unchanged).
- PHPStan baseline holding at 0 errors throughout (the prior 3 errors mentioned in the previous session's notes appear to have been resolved before this session — current run is clean).
- Each bug verified individually via a short PHP script run inside DDEV before moving to the next bug. The `Bug 11` verification went one step further with an actual `config/password-policy.php` fixture in the playground that loaded cleanly through `getSettings()` with deprecation warnings flowing into the `password-policy` log channel.
- No new skill gaps surfaced beyond the existing memory-store entries.

### Bugs left out of scope

The Bug 11 conversation surfaced a related concern: there's no migration that runs against existing 5.1.1 file-based configs to suggest the rename. The deprecation warning fires on every cache warm, which is good observability but doesn't actively prompt the operator to migrate. Documenting the rename in the 5.2.0 migration guide (Phase H) is the right home for the prompt — the file-based config alias keeps things working until the operator gets to that doc.

### Phase status

Phase C2 closed-closed. Next is Phase D (P2.1 + P2.2 user index integration).

---
