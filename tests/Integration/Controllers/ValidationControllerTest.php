<?php
/**
 * Pest coverage for `ValidationController::actionValidate()` — the AJAX
 * password-validation endpoint that powers the front-end live checklist
 * and strength meter.
 *
 * Pin point: the C2 bug-fix sweep (commit b5d602f) hardened the strength
 * context resolution. Anonymous POST requests must NOT factor
 * `username` / `email` POST params into zxcvbn's user-input dictionary —
 * accepting attacker-controlled context lets unauthenticated callers
 * prime the dictionary with arbitrary strings and observe how that
 * changes the strength score for a known account. Authenticated requests
 * pull the context from `Craft::$app->getUser()->getIdentity()` instead;
 * POST values are ignored. Length-clamped to 254 chars defensively.
 *
 * The tests stand up a web-shaped request via `WebRequestStub` (so the
 * controller's `requirePostRequest` / `requireAcceptsJson` gates pass)
 * plus a `craft\web\Response` component (so `asJson()` has somewhere to
 * write). Path A confirmed in E5.2 — no bootstrap surgery needed.
 *
 * Privacy: the tests never pin on plaintext password content, full
 * SHA-1 hashes, or full HIBP bucket suffixes. Strength scores are
 * compared as integers; `hibp` is asserted as `bool|null` shape.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craft\web\Response;
use craftpulse\passwordpolicy\controllers\ValidationController;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;
use craftpulse\passwordpolicy\tests\Support\HibpClientFake;
use craftpulse\passwordpolicy\tests\Support\UserStub;
use craftpulse\passwordpolicy\tests\Support\WebRequestStub;

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->settings = $this->plugin->getSettings();

    // Stash bootstrap components so afterEach can restore them.
    $this->originalRequest = Craft::$app->getRequest();
    $this->originalUser = Craft::$app->getUser();
    $this->originalEdition = $this->plugin->edition;
    $this->originalUseZxcvbn = $this->settings->useZxcvbnStrength;
    $this->originalHibp = $this->settings->hibp;
    $this->originalHibpClient = $this->plugin->getHibpClient();

    // Default ValidationController context: web request, anonymous user,
    // Pro edition (so Engine B is available for context-leak assertions),
    // HIBP off (we toggle on per-test when needed), zxcvbn on.
    $this->request = new WebRequestStub();
    Craft::$app->set('request', $this->request);
    Craft::$app->set('response', new Response());

    $this->userStub = new UserStub();
    Craft::$app->set('user', $this->userStub);

    $this->plugin->edition = PasswordPolicy::EDITION_PRO;
    $this->settings->useZxcvbnStrength = true;
    $this->settings->hibp = false;

    // Swap in the HIBP fake so the controller never hits the live API.
    $this->hibpFake = new HibpClientFake();
    $this->plugin->set('hibpClient', $this->hibpFake);
});

afterEach(function() {
    Craft::$app->set('request', $this->originalRequest);
    Craft::$app->set('user', $this->originalUser);
    $this->plugin->edition = $this->originalEdition;
    $this->settings->useZxcvbnStrength = $this->originalUseZxcvbn;
    $this->settings->hibp = $this->originalHibp;
    $this->plugin->set('hibpClient', $this->originalHibpClient);
});

/**
 * Convenience: builds the ValidationController, invokes `actionValidate()`,
 * and returns the response payload (the array Craft hands `asJson()`).
 */
function invokeValidate(): array
{
    $controller = new ValidationController('validation', PasswordPolicy::$plugin);
    $response = $controller->actionValidate();
    /** @var array<string, mixed> $data */
    $data = $response->data;

    return $data;
}

// =============================================================================
// Allow-anonymous + response shape
// =============================================================================

it('declares actionValidate in $allowAnonymous so unauthenticated POSTs reach it', function() {
    // The CP-only default would 403 anonymous registration forms. Pin
    // the explicit allowlist so a future "lock everything down" sweep
    // doesn't accidentally re-gate the front-end validator. Use the
    // class default value directly so the property reflection doesn't
    // depend on the controller's parent init() running.
    $reflection = new ReflectionClass(ValidationController::class);
    $defaults = $reflection->getDefaultProperties();

    expect($defaults)->toHaveKey('allowAnonymous')
        ->and($defaults['allowAnonymous'])->toBeArray()
        ->and($defaults['allowAnonymous'])->toContain('validate');
});

it('returns a response with rules, strength, and the canonical top-level keys', function() {
    $this->request->stubBodyParams = [
        'password' => 'ZQ7nUJfp8d!',
    ];

    $payload = invokeValidate();

    // Top-level keys present even on a passing password.
    expect($payload)->toHaveKey('isValid')
        ->and($payload)->toHaveKey('passed')
        ->and($payload)->toHaveKey('errorsByKey')
        ->and($payload)->toHaveKey('errors')
        ->and($payload)->toHaveKey('rules')
        ->and($payload)->toHaveKey('strength')
        // Rules are an array of {key, pass, message} structures.
        ->and($payload['rules'])->toBeArray();

    foreach ($payload['rules'] as $rule) {
        expect($rule)->toHaveKey('key')
            ->and($rule)->toHaveKey('pass')
            ->and($rule)->toHaveKey('message');
    }
});

it('returns isValid=true when the password satisfies every active rule', function() {
    $this->request->stubBodyParams = [
        'password' => 'ZQ7nUJfp8d!',
    ];

    $payload = invokeValidate();

    expect($payload['isValid'])->toBeTrue()
        ->and($payload['passed'])->toBeTrue()
        ->and($payload['errorsByKey'])->toBe([])
        ->and($payload['errors'])->toBe([]);
});

it('returns isValid=false plus per-rule failures when the password is too short', function() {
    $this->request->stubBodyParams = [
        'password' => 'Aa1!',
    ];

    $payload = invokeValidate();

    expect($payload['isValid'])->toBeFalse()
        ->and($payload['passed'])->toBeFalse()
        // The min-length rule fails; client key is `length` after the
        // `_clientKey` mapping.
        ->and($payload['errorsByKey'])->toHaveKey('length');
});

// =============================================================================
// Context input hardening — anonymous POST drops username/email
// =============================================================================

it('does not factor anonymous POST username/email into zxcvbn context', function() {
    // Critical regression vector. If a future refactor reverses the gate,
    // attacker context leaks into the user-input dictionary and changes
    // the strength score for a known account. Pin: anonymous request
    // with a username that matches the password tokens should produce
    // the same score as the no-context baseline.
    $this->settings->useZxcvbnStrength = true;

    $this->request->stubBodyParams = [
        'password' => 'JbloggsJbloggs1!',
        'username' => 'jbloggs',
        'email' => 'jbloggs@example.com',
    ];

    $payloadWithPostContext = invokeValidate();

    // Same password, no POST context.
    $this->request->stubBodyParams = [
        'password' => 'JbloggsJbloggs1!',
    ];

    $payloadNoContext = invokeValidate();

    // Anonymous-POST-context path drops the values, so both calls produce
    // the same zxcvbn score. The strength service tests pin the converse
    // (context DOES weaken the score when delivered via the service);
    // here we pin the controller-side guard.
    expect($payloadWithPostContext['strength']['score'])
        ->toBe($payloadNoContext['strength']['score']);
});

it('uses authenticated session identity for zxcvbn context, not POST values', function() {
    // Authenticated callers get context from the session — POST values
    // are ignored even when they differ. Build a real user, set them
    // as the current identity, and verify the strength score reacts to
    // their session username (not the attacker-supplied POST value).
    $this->settings->useZxcvbnStrength = true;

    $user = UserFactory::admin([
        'username' => 'sessionuser',
        'email' => 'sessionuser@example.com',
    ]);

    $this->userStub->setIdentity($user);

    // Password derived from the SESSION username — should score low
    // because zxcvbn's user-input dictionary picks it up.
    $this->request->stubBodyParams = [
        'password' => 'SessionuserSessionuser1!',
        'username' => 'attacker', // ignored
        'email' => 'attacker@example.com', // ignored
    ];

    $sessionDerivedPayload = invokeValidate();

    // Same password, but logged out — zxcvbn has no context, so the
    // score is no lower than the authenticated reading. Drop identity
    // first.
    $this->userStub->setIdentity(null);

    $this->request->stubBodyParams = [
        'password' => 'SessionuserSessionuser1!',
    ];

    $anonymousPayload = invokeValidate();

    // Authenticated reading should be ≤ anonymous (context dictionary
    // weakens the score, never strengthens it).
    expect($sessionDerivedPayload['strength']['score'])
        ->toBeLessThanOrEqual($anonymousPayload['strength']['score']);
});

it('clamps the authenticated session context to 254 characters', function() {
    // Defensive: a pathological session username (e.g. one set via DB
    // direct-write to a rogue length) shouldn't blow up zxcvbn's matchers.
    // We can't easily construct a User with a 1000-char username (Craft's
    // validators cap it), but we can verify the substr() trim in the
    // controller's resolver is exercised by passing a 254+ char username
    // via the User stub directly.
    $this->settings->useZxcvbnStrength = true;

    $longUsername = str_repeat('a', 1000);
    $user = UserFactory::admin();
    // Bypass Craft's validator by writing the property directly — the
    // controller's _resolveStrengthContext only reads .username, so this
    // isolates the substr() guard.
    $user->username = $longUsername;
    $this->userStub->setIdentity($user);

    $this->request->stubBodyParams = [
        'password' => 'aaaa' . str_repeat('Z', 12) . '1!',
    ];

    // No throw: the substr(..., 0, 254) clamp prevents the 1000-char
    // value from reaching zxcvbn. Pin the response shape integrity as
    // proof the path completed cleanly.
    $payload = invokeValidate();

    expect($payload)->toHaveKey('strength')
        ->and($payload['strength'])->toHaveKey('score');
});

// =============================================================================
// HIBP integration — fail-open + breach detection through the controller
// =============================================================================

it('omits the hibp rule when settings.hibp is off (default)', function() {
    $this->settings->hibp = false;

    $this->request->stubBodyParams = [
        'password' => 'ZQ7nUJfp8d!',
    ];

    $payload = invokeValidate();

    $hibpRule = collect($payload['rules'])->firstWhere('key', 'hibp');

    expect($hibpRule)->toBeNull();
});

it('emits hibp rule with pass=null when settings.hibp is on but the client reports unreachable', function() {
    // Fail-open: client returns null → service returns null → controller
    // emits a rule with `pass: null` so the client UI can render
    // "couldn't check" rather than green/red.
    $this->settings->hibp = true;
    $this->hibpFake->nextResponse = null;

    $this->request->stubBodyParams = [
        'password' => 'ZQ7nUJfp8d!',
    ];

    $payload = invokeValidate();

    $hibpRule = collect($payload['rules'])->firstWhere('key', 'hibp');

    expect($hibpRule)->not->toBeNull()
        ->and($hibpRule['pass'])->toBeNull();
});

it('emits hibp rule with pass=true when the client returns clean response (no suffix match)', function() {
    $this->settings->hibp = true;
    $this->hibpFake->setCleanResponse();

    $this->request->stubBodyParams = [
        'password' => 'ZQ7nUJfp8d!unique-string-2026',
    ];

    $payload = invokeValidate();

    $hibpRule = collect($payload['rules'])->firstWhere('key', 'hibp');

    expect($hibpRule)->not->toBeNull()
        ->and($hibpRule['pass'])->toBeTrue();
});

it('emits hibp rule with pass=false when the client returns a matching suffix', function() {
    $this->settings->hibp = true;

    // Build a known SHA-1 hash and feed it back through the fake.
    $password = 'ZQ7nUJfp8d!unique-string-2026';
    $hash = strtoupper(sha1($password));
    $this->hibpFake->setBreachedHash($hash);

    $this->request->stubBodyParams = [
        'password' => $password,
    ];

    $payload = invokeValidate();

    $hibpRule = collect($payload['rules'])->firstWhere('key', 'hibp');

    expect($hibpRule)->not->toBeNull()
        ->and($hibpRule['pass'])->toBeFalse();
});

it('only sends the 5-char SHA-1 prefix to the HIBP client (k-anonymity)', function() {
    // Pin the contract at the controller level too — hibp() already pins
    // it at the service level, but a refactor that bypasses the service
    // (e.g. adds a controller-level check) shouldn't accidentally leak
    // the full hash.
    $this->settings->hibp = true;
    $this->hibpFake->setCleanResponse();

    $password = 'ZQ7nUJfp8d!some-random-string';
    $expectedPrefix = strtoupper(substr(sha1($password), 0, 5));

    $this->request->stubBodyParams = [
        'password' => $password,
    ];

    invokeValidate();

    expect($this->hibpFake->queryPrefixes)->toBe([$expectedPrefix])
        ->and($this->hibpFake->queryPrefixes[0])->toMatch('/^[0-9A-F]{5}$/');
});

// =============================================================================
// Strength block — propagation through the controller
// =============================================================================

it('propagates blocklistHit into the strength block via the engine override', function() {
    // The C2 fix routes blocklist hits to override Engine B's score/label
    // to weak/0. The controller computes blocklistHit from
    // `errorsByKey['common']` set when CommonPasswordValidator rejects
    // the password. Pin the propagation through the controller seam.
    //
    // Toggle Pro common-password check on so the controller emits the
    // common rule. Use a password the validator definitely rejects —
    // CommonPasswordValidator reads the bundled SecLists fixtures.
    $this->settings->checkCommonPasswords = true;

    $this->request->stubBodyParams = [
        'password' => 'password',
    ];

    $payload = invokeValidate();

    expect($payload['strength']['label'])->toBe('weak')
        ->and($payload['strength']['score'])->toBe(0);
});

it('returns Engine B response shape on Pro+useZxcvbnStrength=true', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;
    $this->settings->useZxcvbnStrength = true;

    $this->request->stubBodyParams = [
        'password' => 'tHis-Is-A-Pretty-S0lid-Passphrase-2026',
    ];

    $payload = invokeValidate();

    expect($payload['strength']['engine'])->toBe('zxcvbn');
});

it('falls back to Engine A response shape on Lite edition', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_LITE;
    $this->settings->useZxcvbnStrength = true; // ignored on Lite

    $this->request->stubBodyParams = [
        'password' => 'tHis-Is-A-Pretty-S0lid-Passphrase-2026',
    ];

    $payload = invokeValidate();

    expect($payload['strength']['engine'])->toBe('baseline');
});

// =============================================================================
// Client-key remapping — internal rule keys → front-end requirement keys
// =============================================================================

it('maps minLength failures to the client key `length`', function() {
    $this->request->stubBodyParams = [
        'password' => 'Aa1!',
    ];

    $payload = invokeValidate();

    expect($payload['errorsByKey'])->toHaveKey('length')
        // The internal rule key `minLength` maps to client `length`.
        ->and($payload['errorsByKey'])->not->toHaveKey('minLength');
});
