<?php
/**
 * Pest coverage for the HIBP-on-login listener's `UserStateService`
 * wiring (Phase D1.2). The listener at `User::EVENT_BEFORE_AUTHENTICATE`
 * must:
 *
 *  - Call `recordBreachCheck()` on every non-null result so
 *    `lastBreachCheckAt` updates regardless of breach outcome.
 *  - Call `setPendingReason(BreachForced)` on detected breaches so the
 *    user's NEXT password change records the right `changeReason` in
 *    history.
 *  - Skip both writes on API failure (null result) — fail-open
 *    contract preserved.
 *
 * Privacy guards: the test asserts on the boolean detection outcome and
 * the user_state column shape only — never on plaintext, full SHA-1
 * hash, or full prefix+suffix bucket. The fake's `queryPrefixes` array
 * is the closest we get to the wire payload, and even that's only
 * inspected to confirm the 5-char prefix shape, not its content.
 *
 * The listener fires inside the live login flow; tests reach the same
 * code path by invoking `_runHibpOnLoginCheck()` directly (the listener
 * just wraps it in defensive try/catch). That keeps the test off
 * Craft's User authentication pipeline (which would also write a
 * separate audit log entry and complicate the assertions).
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craftpulse\passwordpolicy\enums\ChangeReason;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\records\UserStateRecord;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;
use craftpulse\passwordpolicy\tests\Support\HibpClientFake;

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->settings = $this->plugin->getSettings();

    $this->originalEdition = $this->plugin->edition;
    $this->originalEnableHibp = $this->settings->enableHibpOnLogin;
    $this->originalClient = $this->plugin->getHibpClient();

    // Pro is required for the listener to be registered at all; the
    // direct invocation below skips the registration check, but the
    // plugin's edition still gates `getIsPro()` checks deeper in.
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;
    $this->settings->enableHibpOnLogin = true;

    $this->fake = new HibpClientFake();
    $this->plugin->set('hibpClient', $this->fake);

    // The listener uses cache keys keyed by user-id + sha1-prefix; clear
    // any stale entries from a previous test run.
    Craft::$app->getCache()->flush();
});

afterEach(function() {
    $this->plugin->edition = $this->originalEdition;
    $this->settings->enableHibpOnLogin = $this->originalEnableHibp;
    $this->plugin->set('hibpClient', $this->originalClient);
});

// =============================================================================
// Helpers
// =============================================================================

/**
 * Invokes the private `_runHibpOnLoginCheck()` via reflection. The
 * listener registration in `PasswordPolicy::init()` only fires under
 * an actual login event — direct invocation lets us pin the side-effect
 * contract without a full auth flow.
 */
function runHibpCheck(craft\elements\User $user, string $plaintext): void
{
    $plugin = PasswordPolicy::$plugin;
    $reflection = new \ReflectionMethod($plugin, '_runHibpOnLoginCheck');
    $reflection->invoke($plugin, $user, $plaintext);
}

// =============================================================================
// Detected breach — both timestamps + pending reason set
// =============================================================================

it('sets BreachForced pending reason when HIBP detects the password', function() {
    $user = UserFactory::admin();
    $plaintext = 'Password123!';
    $this->fake->setBreachedHash(strtoupper(sha1($plaintext)));

    runHibpCheck($user, $plaintext);

    $state = UserStateRecord::findOne(['userId' => $user->id]);

    expect($state)->not->toBeNull()
        ->and($state->pendingResetReason)->toBe(ChangeReason::BreachForced->value)
        ->and($state->lastBreachDetectedAt)->not->toBeNull()
        ->and($state->lastBreachCheckAt)->not->toBeNull();
});

it('sets passwordResetRequired = true on a detected breach', function() {
    $user = UserFactory::admin();
    $plaintext = 'Password123!';
    $this->fake->setBreachedHash(strtoupper(sha1($plaintext)));

    runHibpCheck($user, $plaintext);

    // Read directly from the users table — `getUserById()` can return a
    // cached element that pre-dates the listener's save; the column
    // value is the source of truth.
    $flag = (new craft\db\Query())
        ->select(['passwordResetRequired'])
        ->from(craft\db\Table::USERS)
        ->where(['id' => $user->id])
        ->scalar();

    // MySQL boolean returns as '0'/'1' string; cast to bool.
    expect((bool)$flag)->toBeTrue();
});

// =============================================================================
// Clean check — lastBreachCheckAt only, no pending reason, no detected timestamp
// =============================================================================

it('records lastBreachCheckAt without pending reason on a clean check', function() {
    $user = UserFactory::admin();
    $this->fake->setCleanResponse();

    runHibpCheck($user, 'NotInTheBreachDb-7gT9p!Q');

    $state = UserStateRecord::findOne(['userId' => $user->id]);

    expect($state)->not->toBeNull()
        ->and($state->pendingResetReason)->toBeNull()
        ->and($state->lastBreachDetectedAt)->toBeNull()
        ->and($state->lastBreachCheckAt)->not->toBeNull();
});

it('does not flip passwordResetRequired on a clean check', function() {
    $user = UserFactory::admin();
    $this->fake->setCleanResponse();

    runHibpCheck($user, 'NotInTheBreachDb-7gT9p!Q');

    $reloaded = Craft::$app->getUsers()->getUserById($user->id);
    expect($reloaded->passwordResetRequired)->toBeFalse();
});

// =============================================================================
// API failure (null) — fail-open, no state mutation
// =============================================================================

it('writes no user_state row on HIBP API failure (null result)', function() {
    $user = UserFactory::admin();

    // `nextResponse = null` simulates an API outage / non-2xx. The
    // service returns null up the call stack; the listener must
    // short-circuit before any state write.
    $this->fake->nextResponse = null;

    runHibpCheck($user, 'whatever');

    expect(UserStateRecord::findOne(['userId' => $user->id]))->toBeNull();
});

// =============================================================================
// Backoff active — listener short-circuits before recordBreachCheck
// =============================================================================

it('does not record a check when the site-wide HIBP backoff is active', function() {
    $user = UserFactory::admin();
    $this->fake->backoffActive = true;

    runHibpCheck($user, 'whatever');

    expect(UserStateRecord::findOne(['userId' => $user->id]))->toBeNull()
        ->and($this->fake->queryCalls)->toBe(0);
});

// =============================================================================
// Privacy contract — what the fake observed (no plaintext, no full hash)
// =============================================================================

it('sends only the 5-char SHA-1 prefix to the HIBP client', function() {
    $user = UserFactory::admin();
    $this->fake->setCleanResponse();

    runHibpCheck($user, 'PrivacyCheck-9kL2m!P');

    expect($this->fake->queryCalls)->toBe(1)
        ->and($this->fake->queryPrefixes)->toHaveCount(1)
        ->and($this->fake->queryPrefixes[0])->toMatch('/^[0-9A-F]{5}$/');
});
