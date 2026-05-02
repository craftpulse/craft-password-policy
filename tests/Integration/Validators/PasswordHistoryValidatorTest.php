<?php
/**
 * Pest coverage for `PasswordHistoryValidator` — the bcrypt-comparison
 * "no password reuse" rule. The validator delegates to
 * `PasswordHistoryService::isPasswordReused()` for the actual hash check;
 * tests pin the gate logic (Pro edition, `passwordHistoryCount > 0`,
 * existing user only) plus the integration with the service's constant-
 * time loop.
 *
 * Settings + edition mutate during tests — `beforeEach` snapshots the
 * starting state and `afterEach` restores it so tests don't bleed into
 * one another. The DB transaction wrapper handles row-level isolation.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craft\elements\User;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\tests\Support\Factories\PasswordHistoryFactory;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;
use craftpulse\passwordpolicy\validators\PasswordHistoryValidator;

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->validator = new PasswordHistoryValidator();
    $this->plugin = PasswordPolicy::$plugin;
    $this->settings = $this->plugin->getSettings();

    $this->originalEdition = $this->plugin->edition;
    $this->originalCount = $this->settings->passwordHistoryCount;

    // Pro + history enabled is the default starting state for these
    // tests — gate-off variants flip back explicitly.
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;
    $this->settings->passwordHistoryCount = 5;
});

afterEach(function() {
    $this->plugin->edition = $this->originalEdition;
    $this->settings->passwordHistoryCount = $this->originalCount;
});

// =============================================================================
// Edition gate — Lite skips entirely
// =============================================================================

it('returns early on Lite regardless of history count', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_LITE;
    $this->settings->passwordHistoryCount = 5;

    $user = UserFactory::admin();
    PasswordHistoryFactory::seedFor($user, ['oldpass1', 'oldpass2']);

    $user->newPassword = 'oldpass1';
    $this->validator->validateAttribute($user, 'newPassword');

    expect($user->getErrors('newPassword'))->toBeEmpty();
});

// =============================================================================
// Count gate — 0 (Lite default) skips; 1+ runs
// =============================================================================

it('returns early when passwordHistoryCount is zero', function() {
    $this->settings->passwordHistoryCount = 0;

    $user = UserFactory::admin();
    PasswordHistoryFactory::seedFor($user, ['oldpass']);

    $user->newPassword = 'oldpass';
    $this->validator->validateAttribute($user, 'newPassword');

    expect($user->getErrors('newPassword'))->toBeEmpty();
});

it('returns early when passwordHistoryCount is negative', function() {
    // Defensive — the SettingsModel UI clamps to 0..24, but the validator's
    // guard is `<= 0` so a hand-poked negative also short-circuits.
    $this->settings->passwordHistoryCount = -1;

    $user = UserFactory::admin();
    PasswordHistoryFactory::seedFor($user, ['oldpass']);

    $user->newPassword = 'oldpass';
    $this->validator->validateAttribute($user, 'newPassword');

    expect($user->getErrors('newPassword'))->toBeEmpty();
});

// =============================================================================
// Empty / new-user shortcuts
// =============================================================================

it('returns early when the new password is empty', function() {
    $user = UserFactory::admin();
    PasswordHistoryFactory::seedFor($user, ['oldpass']);

    $user->newPassword = '';
    $this->validator->validateAttribute($user, 'newPassword');

    expect($user->getErrors('newPassword'))->toBeEmpty();
});

it('returns early on a user with no id (new user, never saved)', function() {
    // Yii2 invokes validators with the model instance; for a brand-new User
    // the id is null and the validator's id-presence guard short-circuits
    // before the bcrypt loop runs.
    $user = new User([
        'admin' => true,
        'username' => 'pending',
        'email' => 'pending@craftpulse.test',
    ]);

    $user->newPassword = 'whatever';
    $this->validator->validateAttribute($user, 'newPassword');

    expect($user->getErrors('newPassword'))->toBeEmpty();
});

// =============================================================================
// Reuse detection — bcrypt loop matches stored hashes
// =============================================================================

it('rejects a password that exactly matches a recent history entry', function() {
    $user = UserFactory::admin();
    PasswordHistoryFactory::seedFor($user, ['CorrectHorseBattery1!']);

    $user->newPassword = 'CorrectHorseBattery1!';
    $this->validator->validateAttribute($user, 'newPassword');

    $errors = $user->getErrors('newPassword');

    expect($errors)->not->toBeEmpty()
        ->and($errors[0])->toContain('used recently');
});

it('accepts a password that does not match any history entry', function() {
    $user = UserFactory::admin();
    PasswordHistoryFactory::seedFor($user, ['Old1!Pass', 'Old2!Pass', 'Old3!Pass']);

    $user->newPassword = 'BrandNewPassword99!';
    $this->validator->validateAttribute($user, 'newPassword');

    expect($user->getErrors('newPassword'))->toBeEmpty();
});

it('matches even when the hash output differs across re-hashes', function() {
    // bcrypt's salt randomisation means two hashings of the same plaintext
    // produce different ciphertexts — yet `password_verify()` matches both.
    // The factory uses `Craft::$app->getSecurity()->hashPassword()` which
    // generates a fresh salt on each call. Pin that the validator still
    // matches a re-typed plaintext against a previously-hashed history
    // entry.
    $user = UserFactory::admin();

    // Seed once via the factory (one bcrypt invocation for hashing).
    PasswordHistoryFactory::seedFor($user, ['SamePlaintext!']);

    // Now validate the same plaintext — internally, the validator
    // re-hashes via `password_verify` against the stored hash.
    $user->newPassword = 'SamePlaintext!';
    $this->validator->validateAttribute($user, 'newPassword');

    expect($user->getErrors('newPassword'))->not->toBeEmpty();
});

// =============================================================================
// Count enforcement — only the most recent N entries are checked
// =============================================================================

it('only checks the most recent N entries', function() {
    // History has 5 entries (oldest to newest); count is 3 — so only the
    // last 3 should be matched. The 1st (oldest) plaintext is outside
    // the protected window and re-using it must NOT raise an error.
    $this->settings->passwordHistoryCount = 3;

    $user = UserFactory::admin();
    PasswordHistoryFactory::seedFor($user, [
        'OldEntry01!',  // outside count window
        'OldEntry02!',  // outside count window
        'Recent01!',    // inside count window
        'Recent02!',    // inside count window
        'Recent03!',    // inside count window
    ]);

    // Re-using the oldest entry (outside window) should be fine.
    $user->newPassword = 'OldEntry01!';
    $this->validator->validateAttribute($user, 'newPassword');

    expect($user->getErrors('newPassword'))->toBeEmpty();
});

it('rejects re-use of a recent entry within the count window', function() {
    $this->settings->passwordHistoryCount = 3;

    $user = UserFactory::admin();
    PasswordHistoryFactory::seedFor($user, [
        'OldEntry01!',
        'OldEntry02!',
        'Recent01!',
        'Recent02!',
        'Recent03!',
    ]);

    $user->newPassword = 'Recent02!';
    $this->validator->validateAttribute($user, 'newPassword');

    expect($user->getErrors('newPassword'))->not->toBeEmpty();
});

// =============================================================================
// Empty-history user — no error regardless of input
// =============================================================================

it('accepts any password for a user with no history rows', function() {
    $user = UserFactory::admin();

    $user->newPassword = 'anything';
    $this->validator->validateAttribute($user, 'newPassword');

    expect($user->getErrors('newPassword'))->toBeEmpty();
});

it('also checks the current users.password column when history is short', function() {
    // The service tops up the candidate hash list from the live
    // users.password column when history has fewer entries than the
    // configured limit. This is the "haven't changed since migration
    // seeding" path — codifies the safety net.
    $user = UserFactory::admin();

    // Craft strips `$user->password` on save (the column is populated only
    // via the `newPassword` flow), so to seed the live hash for this test
    // we update the column directly. The service queries the column via
    // raw SQL anyway — this matches what the migration seed path produces.
    $hash = Craft::$app->getSecurity()->hashPassword('CurrentLivePassword!');
    Craft::$app->getDb()->createCommand()
        ->update(\craft\db\Table::USERS, ['password' => $hash], ['id' => $user->id])
        ->execute();

    // No history rows — the service must still fall back to the user
    // table to detect re-use.
    $user->newPassword = 'CurrentLivePassword!';
    $this->validator->validateAttribute($user, 'newPassword');

    expect($user->getErrors('newPassword'))->not->toBeEmpty();
});
