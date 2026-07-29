<?php
/**
 * Pest coverage for `ContextualValidator` — codifies the validator's
 * behavior across user-derived terms (username, email local part, first
 * name, last name) plus the environment-derived ones (system name, primary
 * site domain). Tests run against whatever `db_test` actually contains for
 * primary site + system name; the env-derived assertions discover those
 * values at runtime via `Craft::$app` rather than pinning to a string,
 * which would brittle the suite across different bootstrapping paths
 * (fresh `Install` migration vs. an existing fixture DB).
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craft\elements\User;
use craftpulse\passwordpolicy\validators\ContextualValidator;

// =============================================================================
// Constants
// =============================================================================

/**
 * Password that contains none of the bootstrap's environment terms
 * (system name parts or primary site domain). Lowercase form
 * `zr8#qvnlm2!` — no `password`, `policy`, `test`, `site`, or `craftcms`
 * substring.
 */
const NEUTRAL_PASSWORD = 'Zr8#qVnLm2!';

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->validator = new ContextualValidator();
});

// =============================================================================
// Helpers
// =============================================================================

/**
 * Builds a User with the given attributes plus a target `password` ready
 * for `validateAttribute()` to read.
 */
function contextualUser(array $attrs, string $password): User
{
    $user = new User($attrs);
    $user->password = $password;

    return $user;
}

// =============================================================================
// Happy path
// =============================================================================

it('accepts a password with no overlapping context', function() {
    $user = contextualUser([
        'username' => 'johndoe',
        'email' => 'john@example.com',
        'firstName' => 'John',
        'lastName' => 'Doe',
    ], NEUTRAL_PASSWORD);

    $this->validator->validateAttribute($user, 'password');

    expect($user->getErrors('password'))->toBe([]);
});

it('returns early on an empty password without inspecting context', function() {
    // The early-return guard means `username = 'usr'` (≥ 3 chars) doesn't
    // matter — validation simply skips.
    $user = contextualUser(['username' => 'usr'], '');

    $this->validator->validateAttribute($user, 'password');

    expect($user->getErrors('password'))->toBe([]);
});

// =============================================================================
// User-derived terms
// =============================================================================

it('rejects a password containing the username', function() {
    $user = contextualUser(['username' => 'johndoe'], 'johndoe' . NEUTRAL_PASSWORD);

    $this->validator->validateAttribute($user, 'password');

    expect($user->getErrors('password'))->not->toBe([]);
});

it('rejects a password containing the email local part', function() {
    $user = contextualUser(['email' => 'jane@example.com'], 'xJaneX' . NEUTRAL_PASSWORD);

    $this->validator->validateAttribute($user, 'password');

    expect($user->getErrors('password'))->not->toBe([]);
});

it('rejects a password containing the first name', function() {
    $user = contextualUser(['firstName' => 'Robert'], 'Robert' . NEUTRAL_PASSWORD);

    $this->validator->validateAttribute($user, 'password');

    expect($user->getErrors('password'))->not->toBe([]);
});

it('rejects a password containing the last name', function() {
    $user = contextualUser(['lastName' => 'Smith'], 'xxxSmithxxx' . NEUTRAL_PASSWORD);

    $this->validator->validateAttribute($user, 'password');

    expect($user->getErrors('password'))->not->toBe([]);
});

// =============================================================================
// Length thresholds + case folding
// =============================================================================

it('accepts a password when every user term is under the 3-char minimum', function() {
    // `ab` is 2 chars — skipped before the str_contains check.
    $user = contextualUser([
        'username' => 'ab',
        'firstName' => 'Jo',
        'lastName' => 'Li',
    ], NEUTRAL_PASSWORD);

    $this->validator->validateAttribute($user, 'password');

    expect($user->getErrors('password'))->toBe([]);
});

it('rejects when the user term is exactly the 3-char minimum', function() {
    $user = contextualUser(['firstName' => 'Joe'], 'JoexxNeutralx9!');

    $this->validator->validateAttribute($user, 'password');

    expect($user->getErrors('password'))->not->toBe([]);
});

it('matches case-insensitively against user terms', function() {
    // Username stored mixed-case, password contains lowercase form.
    $user = contextualUser(['username' => 'JohnDoe'], 'johndoe' . NEUTRAL_PASSWORD);

    $this->validator->validateAttribute($user, 'password');

    expect($user->getErrors('password'))->not->toBe([]);
});

// =============================================================================
// Email parsing edge cases
// =============================================================================

it('uses the email local part: not the domain', function() {
    // Local part is `a` (1 char), short-circuited by the MIN_CONTEXT_LENGTH
    // gate. The domain `example.com` is NEVER added as a term, so the
    // password can embed the full domain and still pass.
    $user = contextualUser(['email' => 'a@example.com'], 'example.com' . NEUTRAL_PASSWORD);

    $this->validator->validateAttribute($user, 'password');

    expect($user->getErrors('password'))->toBe([]);
});

it('rejects when the email local part embeds in the password', function() {
    $user = contextualUser(['email' => 'mariana@somewhere.org'], 'xMariana9' . NEUTRAL_PASSWORD);

    $this->validator->validateAttribute($user, 'password');

    expect($user->getErrors('password'))->not->toBe([]);
});

// =============================================================================
// Non-User models
// =============================================================================

it('skips user-term gathering when the model is not a User instance', function() {
    // `_gatherContextTerms()` only reads username/email/firstName/lastName
    // when `$model instanceof User` — anything else falls through to the
    // environment terms (system name + site domain). A POPO with a
    // `password` attribute and no Craft\elements\User pedigree should
    // therefore validate solely against system+domain.
    $bag = new class() {
        public ?string $password = null;

        public ?string $username = 'shouldBeIgnored';

        public function getErrors($attribute): array
        {
            return $this->errors[$attribute] ?? [];
        }

        public function addError($attribute, $error = ''): void
        {
            $this->errors[$attribute][] = $error;
        }

        /** @var array<string,string[]> */
        public array $errors = [];
    };

    $bag->password = 'shouldBeIgnored' . NEUTRAL_PASSWORD;
    $this->validator->validateAttribute($bag, 'password');

    expect($bag->getErrors('password'))->toBe([]);
});

// =============================================================================
// Environment-derived terms (system name + primary site domain)
// =============================================================================

it('rejects a password containing a system-name word', function() {
    // The validator splits the system name on whitespace/-/_ and adds
    // every ≥ 3-char word as a term. Discover the first such word at
    // runtime so the assertion stays valid whether the bootstrap installed
    // a fresh fixture or reused an existing `db_test` schema.
    $systemName = Craft::$app->getSystemName();
    $words = preg_split('/[\s\-_]+/', $systemName) ?: [];
    $word = null;

    foreach ($words as $candidate) {
        if (strlen($candidate) >= 3) {
            $word = $candidate;
            break;
        }
    }

    expect($word)
        ->not->toBeNull('System name has no ≥ 3-char word — this fixture cannot exercise the system-name branch.');

    $user = contextualUser([], $word . NEUTRAL_PASSWORD);

    $this->validator->validateAttribute($user, 'password');

    expect($user->getErrors('password'))->not->toBe([]);
});

it('rejects a password containing the primary site domain stem', function() {
    // The validator takes the first dotted segment of the primary site's
    // host as a term (e.g. `mycompany` from `mycompany.com`). Discover at
    // runtime — same rationale as the system-name test above.
    $baseUrl = Craft::$app->getSites()->getPrimarySite()->getBaseUrl();
    $host = $baseUrl !== null ? parse_url($baseUrl, PHP_URL_HOST) : null;

    expect($host)->not->toBeEmpty('Primary site has no resolvable host.');

    $stem = explode('.', (string)$host)[0];

    expect(strlen($stem))->toBeGreaterThanOrEqual(3, 'Domain stem is too short to exercise the rule.');

    $user = contextualUser([], $stem . NEUTRAL_PASSWORD);

    $this->validator->validateAttribute($user, 'password');

    expect($user->getErrors('password'))->not->toBe([]);
});

it('rejects a password containing a single-label host with no TLD to strip', function() {
    // Regression: a primary site configured with a bare hostname (e.g.
    // `localhost`, an internal/intranet name) has no dot to split on.
    // `explode('.', $host)` then returns a single element, and the term
    // was previously dropped entirely rather than checked as-is. This
    // pins the fix deterministically rather than relying on the
    // playground's ambient primary site happening to be single-label.
    $site = Craft::$app->getSites()->getPrimarySite();
    $originalBaseUrl = $site->getBaseUrl(false);

    $site->setBaseUrl('http://internalhost/');

    try {
        $user = contextualUser([], 'internalhost' . NEUTRAL_PASSWORD);

        $this->validator->validateAttribute($user, 'password');

        expect($user->getErrors('password'))->not->toBe([]);
    } finally {
        $site->setBaseUrl($originalBaseUrl);
    }
});
