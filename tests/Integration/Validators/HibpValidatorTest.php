<?php
/**
 * Pest coverage for `HibpValidator` — the breach-database validator.
 *
 * Pinned contracts:
 *
 *  - Overrides `validateAttribute()` (not `validateValue()`) so the model
 *    under validation is in scope. Breach / check-failed audit rows
 *    capture the originating user id instead of always recording
 *    `userId: null`. Mirrors `PasswordHistoryValidator`.
 *  - A breached password adds a `password ... compromised` error and
 *    writes a `hibp_breach_detected` audit row tagged with the user id.
 *  - An API failure writes `hibp_check_failed`; fail-open accepts the
 *    password, fail-closed rejects it.
 *  - A clean password passes with no error and no rejection row.
 *  - An empty value short-circuits before any API call.
 *
 * The HIBP transport is swapped for `HibpClientFake` so no live calls
 * happen and breach / null / clean branches are driven deterministically.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craft\db\Query;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;
use craftpulse\passwordpolicy\tests\Support\HibpClientFake;
use craftpulse\passwordpolicy\validators\HibpValidator;

// =============================================================================
// Setup — swap the real HIBP client for the in-memory fake
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->settings = $this->plugin->getSettings();
    $this->validator = new HibpValidator();

    $this->originalFailMode = $this->settings->hibpFailMode;
    $this->originalAuditEnabled = $this->settings->enableAuditLog;
    $this->settings->enableAuditLog = true;

    $this->originalClient = $this->plugin->getHibpClient();
    $this->fake = new HibpClientFake();
    $this->plugin->set('hibpClient', $this->fake);

    Craft::$app->getDb()->createCommand()
        ->delete('{{%passwordpolicy_audit_log}}')
        ->execute();
});

afterEach(function() {
    $this->plugin->set('hibpClient', $this->originalClient);
    $this->settings->hibpFailMode = $this->originalFailMode;
    $this->settings->enableAuditLog = $this->originalAuditEnabled;
});

// =============================================================================
// Helpers
// =============================================================================

/**
 * Returns the most recent audit row for `$event`, or null.
 */
function latestHibpAuditRow(string $event): ?array
{
    $row = (new Query())
        ->from('{{%passwordpolicy_audit_log}}')
        ->where(['event' => $event])
        ->orderBy(['id' => SORT_DESC])
        ->one();

    return is_array($row) ? $row : null;
}

// =============================================================================
// Breach detected
// =============================================================================

it('rejects a breached password and records the row against the user id', function() {
    $user = UserFactory::admin();
    $hash = strtoupper(sha1('breached-password'));
    $this->fake->setBreachedHash($hash);

    $user->newPassword = 'breached-password';
    $this->validator->validateAttribute($user, 'newPassword');

    $errors = $user->getErrors('newPassword');
    expect($errors)->not->toBeEmpty();
    expect($errors[0])->toContain('compromised');

    $row = latestHibpAuditRow('hibp_breach_detected');
    expect($row)->not->toBeNull();
    expect((int)$row['userId'])->toBe((int)$user->id);
});

// =============================================================================
// API failure — fail-open vs fail-closed
// =============================================================================

it('accepts the password fail-open on an API failure but records the user id', function() {
    $this->settings->hibpFailMode = 'open';

    $user = UserFactory::admin();
    $this->fake->nextResponse = null; // API unreachable

    $user->newPassword = 'some-password';
    $this->validator->validateAttribute($user, 'newPassword');

    expect($user->getErrors('newPassword'))->toBeEmpty();

    $row = latestHibpAuditRow('hibp_check_failed');
    expect($row)->not->toBeNull();
    expect((int)$row['userId'])->toBe((int)$user->id);
});

it('rejects the password fail-closed on an API failure', function() {
    $this->settings->hibpFailMode = 'closed';

    $user = UserFactory::admin();
    $this->fake->nextResponse = null;

    $user->newPassword = 'some-password';
    $this->validator->validateAttribute($user, 'newPassword');

    $errors = $user->getErrors('newPassword');
    expect($errors)->not->toBeEmpty();
    expect($errors[0])->toContain('Unable to verify');

    $row = latestHibpAuditRow('hibp_check_failed');
    expect($row)->not->toBeNull();
    expect((int)$row['userId'])->toBe((int)$user->id);
});

// =============================================================================
// Clean password
// =============================================================================

it('accepts a clean password without an error or rejection row', function() {
    $user = UserFactory::admin();
    $this->fake->setCleanResponse();

    $user->newPassword = 'a-fresh-unbreached-password';
    $this->validator->validateAttribute($user, 'newPassword');

    expect($user->getErrors('newPassword'))->toBeEmpty();
    expect(latestHibpAuditRow('hibp_breach_detected'))->toBeNull();
    expect(latestHibpAuditRow('hibp_check_failed'))->toBeNull();
});

// =============================================================================
// Empty value short-circuit
// =============================================================================

it('short-circuits on an empty value without calling the API', function() {
    $user = UserFactory::admin();
    $this->fake->setBreachedHash(strtoupper(sha1('whatever')));

    $user->newPassword = '';
    $this->validator->validateAttribute($user, 'newPassword');

    expect($user->getErrors('newPassword'))->toBeEmpty();
    expect($this->fake->queryCalls)->toBe(0);
});

// =============================================================================
// New / non-User context — userId falls back to null
// =============================================================================

it('records userId null for a new user with no id', function() {
    $user = new \craft\elements\User([
        'admin' => true,
        'username' => 'pending-hibp',
        'email' => 'pending-hibp@craftpulse.test',
    ]);
    $hash = strtoupper(sha1('breached-new'));
    $this->fake->setBreachedHash($hash);

    $user->newPassword = 'breached-new';
    $this->validator->validateAttribute($user, 'newPassword');

    expect($user->getErrors('newPassword'))->not->toBeEmpty();

    $row = latestHibpAuditRow('hibp_breach_detected');
    expect($row)->not->toBeNull();
    expect($row['userId'])->toBeNull();
});
