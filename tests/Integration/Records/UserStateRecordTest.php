<?php
/**
 * Pest coverage for `passwordpolicy_user_state` round-trip + DB-level
 * constraint behavior.
 *
 * Pins the D0.2 schema contract from the application side: the record
 * inserts with the expected shape, the strict-in-range validator on
 * `pendingResetReason` rejects unknown values, the DB-level ENUM
 * constraint rejects unknown values that bypass the validator, and FK
 * CASCADE on userId removes the state row when the user is deleted.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use Carbon\Carbon;
use craft\db\Query;
use craft\helpers\StringHelper;
use craftpulse\passwordpolicy\enums\ChangeReason;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\records\UserStateRecord;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;

// =============================================================================
// Round-trip — insert + retrieve
// =============================================================================

it('round-trips a populated record through the database', function() {
    $user = UserFactory::admin();
    $now = Carbon::now('UTC');

    $record = new UserStateRecord();
    $record->userId = $user->id;
    $record->pendingResetReason = ChangeReason::BreachForced->value;
    $record->pendingResetSetAt = $now;
    $record->lastBreachCheckAt = $now;
    $record->lastBreachDetectedAt = $now;
    $record->uid = StringHelper::UUID();

    expect($record->save())->toBeTrue();

    $reloaded = UserStateRecord::findOne(['userId' => $user->id]);

    expect($reloaded)->not->toBeNull()
        ->and($reloaded->userId)->toBe($user->id)
        ->and($reloaded->pendingResetReason)->toBe(ChangeReason::BreachForced->value);
});

it('allows null pendingResetReason for users with no pending reset', function() {
    $user = UserFactory::admin();

    $record = new UserStateRecord();
    $record->userId = $user->id;
    $record->pendingResetReason = null;
    $record->lastBreachCheckAt = Carbon::now('UTC');
    $record->uid = StringHelper::UUID();

    expect($record->save())->toBeTrue();

    $reloaded = UserStateRecord::findOne(['userId' => $user->id]);

    expect($reloaded)->not->toBeNull()
        ->and($reloaded->pendingResetReason)->toBeNull();
});

// =============================================================================
// Validation — application-layer guard mirrors the DB-level ENUM constraint
// =============================================================================

it('rejects an unknown pendingResetReason at the validator', function() {
    $user = UserFactory::admin();

    $record = new UserStateRecord();
    $record->userId = $user->id;
    $record->pendingResetReason = 'made_up_reason';

    expect($record->validate())->toBeFalse()
        ->and($record->getFirstError('pendingResetReason'))->not->toBeNull();
});

it('accepts every ChangeReason enum case through the validator', function() {
    $user = UserFactory::admin();

    foreach (ChangeReason::cases() as $reason) {
        $record = new UserStateRecord();
        $record->userId = $user->id;
        $record->pendingResetReason = $reason->value;

        expect($record->validate(['pendingResetReason']))
            ->toBeTrue("expected '{$reason->value}' to validate cleanly");
    }
});

// =============================================================================
// DB-level ENUM constraint — bypass the validator and confirm SQL rejects
// =============================================================================

it('rejects an unknown pendingResetReason at the DB level on MySQL', function() {
    $user = UserFactory::admin();

    // Bypass the record validator and write directly via createCommand.
    // MySQL's ENUM column should reject the unknown value at the
    // database layer, raising a yii\db\Exception (wraps PDOException).
    expect(fn() => Craft::$app->getDb()->createCommand()->insert(
        '{{%passwordpolicy_user_state}}',
        [
            'userId' => $user->id,
            'pendingResetReason' => 'totally_made_up',
            'dateCreated' => Carbon::now('UTC')->format('Y-m-d H:i:s'),
            'dateUpdated' => Carbon::now('UTC')->format('Y-m-d H:i:s'),
            'uid' => StringHelper::UUID(),
        ],
    )->execute())->toThrow(\yii\db\Exception::class);
})->skip(
    fn() => !Craft::$app->getDb()->getIsMysql(),
    'MySQL ENUM-constraint test — requires MySQL.',
);

// =============================================================================
// FK CASCADE — deleting the user removes the state row
// =============================================================================

it('cascades user deletion to remove the user_state row', function() {
    $user = UserFactory::admin();

    $record = new UserStateRecord();
    $record->userId = $user->id;
    $record->pendingResetReason = ChangeReason::AdminForceReset->value;
    $record->uid = StringHelper::UUID();
    $record->save(false);

    expect((new Query())->from('{{%passwordpolicy_user_state}}')->where(['userId' => $user->id])->exists())
        ->toBeTrue();

    // Force a hard delete — Craft's User soft-delete leaves the row in
    // place which would mask a CASCADE-not-firing bug. The DB-level
    // FK is what we want to assert here, so go directly to the table.
    Craft::$app->getDb()->createCommand()
        ->delete(\craft\db\Table::USERS, ['id' => $user->id])
        ->execute();

    expect((new Query())->from('{{%passwordpolicy_user_state}}')->where(['userId' => $user->id])->exists())
        ->toBeFalse();
});

// =============================================================================
// Service surface — UserStateService basic shape (more in D1 wiring)
// =============================================================================

it('returns null from getStateForUser when the user has no state row', function() {
    $user = UserFactory::admin();

    $state = PasswordPolicy::$plugin->getUserState()->getStateForUser($user);

    expect($state)->toBeNull();
});

it('upserts a state row via setPendingReason', function() {
    $user = UserFactory::admin();

    PasswordPolicy::$plugin->getUserState()->setPendingReason($user, ChangeReason::AdminForceReset);

    $state = PasswordPolicy::$plugin->getUserState()->getStateForUser($user);

    expect($state)->not->toBeNull()
        ->and($state->pendingResetReason)->toBe(ChangeReason::AdminForceReset->value)
        ->and($state->pendingResetSetAt)->not->toBeNull();
});

it('clears a previously-set pending reason via clearPendingReason', function() {
    $user = UserFactory::admin();
    $service = PasswordPolicy::$plugin->getUserState();

    $service->setPendingReason($user, ChangeReason::AdminForceReset);
    $service->clearPendingReason($user);

    $state = $service->getStateForUser($user);

    expect($state)->not->toBeNull()
        ->and($state->pendingResetReason)->toBeNull()
        ->and($state->pendingResetSetAt)->toBeNull();
});

it('records a breach check that updates lastBreachCheckAt and lastBreachDetectedAt', function() {
    $user = UserFactory::admin();
    $service = PasswordPolicy::$plugin->getUserState();

    $service->recordBreachCheck($user, detected: true);

    $state = $service->getStateForUser($user);

    expect($state)->not->toBeNull()
        ->and($state->lastBreachCheckAt)->not->toBeNull()
        ->and($state->lastBreachDetectedAt)->not->toBeNull();
});

it('records a clean breach check that updates lastBreachCheckAt but not lastBreachDetectedAt', function() {
    $user = UserFactory::admin();
    $service = PasswordPolicy::$plugin->getUserState();

    $service->recordBreachCheck($user, detected: false);

    $state = $service->getStateForUser($user);

    expect($state)->not->toBeNull()
        ->and($state->lastBreachCheckAt)->not->toBeNull()
        ->and($state->lastBreachDetectedAt)->toBeNull();
});
