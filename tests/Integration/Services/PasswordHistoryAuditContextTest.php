<?php
/**
 * Pest coverage for the central password-history listener's audit-
 * context propagation (Phase D1). The listener at
 * `User::EVENT_AFTER_SAVE` is the single seam every password change
 * funnels through; this file pins the per-call-site `changeReason`
 * outcome plus the IP/UA round-trip and the consume-on-success
 * contract for `passwordpolicy_user_state.pendingResetReason`.
 *
 * Direct-context paths (D3 admin element action, future direct
 * `PasswordHistoryService::savePasswordHash($context)` calls) bypass
 * the listener consume-and-fall-back; coverage of those lives where
 * the direct callers are tested.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craft\db\Query;
use craftpulse\passwordpolicy\enums\ChangeReason;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\records\UserStateRecord;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;
use craftpulse\passwordpolicy\tests\Support\WebRequestStub;

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->settings = $this->plugin->getSettings();

    // Pro + history > 0 is the only configuration that actually writes
    // history rows (the listener gates on those flags). Save originals so
    // afterEach restores cleanly.
    $this->originalEdition = $this->plugin->edition;
    $this->originalCount = $this->settings->passwordHistoryCount;
    $this->originalRequest = Craft::$app->getRequest();
    $this->originalForceFirst = $this->settings->forceChangeOnFirstLogin;

    $this->plugin->edition = PasswordPolicy::EDITION_PRO;
    $this->settings->passwordHistoryCount = 5;
    $this->settings->forceChangeOnFirstLogin = false;
});

afterEach(function() {
    $this->plugin->edition = $this->originalEdition;
    $this->settings->passwordHistoryCount = $this->originalCount;
    $this->settings->forceChangeOnFirstLogin = $this->originalForceFirst;
    Craft::$app->set('request', $this->originalRequest);
});

// =============================================================================
// Helpers
// =============================================================================

/**
 * Returns the latest password-history row for a user, or null when none
 * exists. Includes the audit-shape columns added in D0.
 */
function latestHistoryRowFor(int $userId): ?array
{
    $row = (new Query())
        ->select([
            'userId',
            'changedByUserId',
            'changeReason',
            'changeSourceIp',
            'changeUserAgent',
            'policySnapshot',
        ])
        ->from('{{%passwordpolicy_password_history}}')
        ->where(['userId' => $userId])
        ->orderBy(['dateCreated' => SORT_DESC])
        ->one();

    return $row ?: null;
}

// =============================================================================
// Direct flows — no pending reason set
// =============================================================================

it('writes self_service when a logged-in user changes their password from a web request', function() {
    $request = new WebRequestStub();
    $request->stubUserIp = '198.51.100.42';
    $request->stubUserAgent = 'Mozilla/5.0 (Pest)';
    Craft::$app->set('request', $request);

    $user = UserFactory::admin();

    // Trigger a password change. Skip validation — the listener doesn't
    // care about validation outcome; it only fires on a successful save.
    $user->newPassword = 'NewSecret-7gT9p!Q';
    Craft::$app->getElements()->saveElement($user, false);

    $row = latestHistoryRowFor($user->id);

    expect($row)->not->toBeNull()
        ->and($row['changeReason'])->toBe(ChangeReason::SelfService->value)
        ->and($row['changeSourceIp'])->toBe('198.51.100.42')
        ->and($row['changeUserAgent'])->toBe('Mozilla/5.0 (Pest)')
        ->and($row['changedByUserId'])->toBeNull();
});

it('writes cli when the same change happens in console-request scope', function() {
    // Bootstrap binds a console request — leaving the original request in
    // place exercises the CLI fall-back branch in `_resolveAuditContext()`.
    $user = UserFactory::admin();

    $user->newPassword = 'NewSecret-7gT9p!Q';
    Craft::$app->getElements()->saveElement($user, false);

    $row = latestHistoryRowFor($user->id);

    expect($row)->not->toBeNull()
        ->and($row['changeReason'])->toBe(ChangeReason::Cli->value)
        // No IP/UA on console — `AuditContext::fromRequest()` returns
        // null for both when `getIsConsoleRequest()` is true.
        ->and($row['changeSourceIp'])->toBeNull()
        ->and($row['changeUserAgent'])->toBeNull();
});

// =============================================================================
// Pending-reason flows — listener consumes the reason on the next change
// =============================================================================

it('consumes a BreachForced pending reason and clears it after the write', function() {
    $request = new WebRequestStub();
    $request->stubUserIp = '203.0.113.99';
    Craft::$app->set('request', $request);

    $user = UserFactory::admin();
    $this->plugin->getUserState()->setPendingReason($user, ChangeReason::BreachForced);

    $user->newPassword = 'PostBreach-9kL2m!P';
    Craft::$app->getElements()->saveElement($user, false);

    $row = latestHistoryRowFor($user->id);

    expect($row)->not->toBeNull()
        ->and($row['changeReason'])->toBe(ChangeReason::BreachForced->value)
        ->and($row['changeSourceIp'])->toBe('203.0.113.99');

    // Pending reason was consumed — next change goes back to default.
    $state = UserStateRecord::findOne(['userId' => $user->id]);
    expect($state->pendingResetReason)->toBeNull()
        ->and($state->pendingResetSetAt)->toBeNull();
});

it('consumes an AdminForceReset pending reason set by the element action', function() {
    $request = new WebRequestStub();
    Craft::$app->set('request', $request);

    $user = UserFactory::admin();

    // Mirror what `ForcePasswordReset::performAction()` does.
    $this->plugin->getUserState()->setPendingReason($user, ChangeReason::AdminForceReset);

    $user->newPassword = 'PostAdminForce-5jK3p!A';
    Craft::$app->getElements()->saveElement($user, false);

    $row = latestHistoryRowFor($user->id);

    expect($row['changeReason'])->toBe(ChangeReason::AdminForceReset->value);

    $state = UserStateRecord::findOne(['userId' => $user->id]);
    expect($state->pendingResetReason)->toBeNull();
});

it('consumes an ExpiryForced pending reason set by RetentionService', function() {
    $request = new WebRequestStub();
    Craft::$app->set('request', $request);

    $user = UserFactory::admin();

    $this->plugin->getUserState()->setPendingReason($user, ChangeReason::ExpiryForced);

    $user->newPassword = 'PostExpiry-1zX0c!E';
    Craft::$app->getElements()->saveElement($user, false);

    $row = latestHistoryRowFor($user->id);

    expect($row['changeReason'])->toBe(ChangeReason::ExpiryForced->value);
});

it('consumes a FirstLoginForced pending reason after the user completes the forced change', function() {
    $request = new WebRequestStub();
    Craft::$app->set('request', $request);

    $user = UserFactory::admin();

    // The listener pins this when `forceChangeOnFirstLogin` flips
    // `passwordResetRequired` for a brand-new user; the user's NEXT
    // change is the forced one.
    $this->plugin->getUserState()->setPendingReason($user, ChangeReason::FirstLoginForced);

    $user->newPassword = 'PostFirstLogin-3hN8r!F';
    Craft::$app->getElements()->saveElement($user, false);

    $row = latestHistoryRowFor($user->id);

    expect($row['changeReason'])->toBe(ChangeReason::FirstLoginForced->value);
});

// =============================================================================
// Consume-once contract — second change goes back to default
// =============================================================================

it('falls back to self_service on the second change after a consume', function() {
    $request = new WebRequestStub();
    Craft::$app->set('request', $request);

    $user = UserFactory::admin();
    $this->plugin->getUserState()->setPendingReason($user, ChangeReason::BreachForced);

    // First change — consumes BreachForced.
    $user->newPassword = 'FirstChange-7gT9p!Q';
    Craft::$app->getElements()->saveElement($user, false);

    expect(latestHistoryRowFor($user->id)['changeReason'])
        ->toBe(ChangeReason::BreachForced->value);

    // Second change — no pending reason left, so listener defaults to
    // self-service from request.
    $user->newPassword = 'SecondChange-2pZ0r!W';
    Craft::$app->getElements()->saveElement($user, false);

    expect(latestHistoryRowFor($user->id)['changeReason'])
        ->toBe(ChangeReason::SelfService->value);
});

// =============================================================================
// Listener safety — non-password saves and edition gates
// =============================================================================

it('writes no history row when a User save does not include newPassword', function() {
    $user = UserFactory::admin();

    $existingCount = (int)(new Query())
        ->from('{{%passwordpolicy_password_history}}')
        ->where(['userId' => $user->id])
        ->count();

    // Touch a non-password field — the listener must not fire the
    // history write.
    $user->firstName = 'Updated';
    Craft::$app->getElements()->saveElement($user, false);

    $afterCount = (int)(new Query())
        ->from('{{%passwordpolicy_password_history}}')
        ->where(['userId' => $user->id])
        ->count();

    expect($afterCount)->toBe($existingCount);
});

it('does not consume a pending reason when no actual password change occurred', function() {
    $user = UserFactory::admin();

    $this->plugin->getUserState()->setPendingReason($user, ChangeReason::BreachForced);

    // Non-password save — pending reason must survive.
    $user->firstName = 'NoChange';
    Craft::$app->getElements()->saveElement($user, false);

    $state = UserStateRecord::findOne(['userId' => $user->id]);

    expect($state)->not->toBeNull()
        ->and($state->pendingResetReason)->toBe(ChangeReason::BreachForced->value);
});

// =============================================================================
// First-login forced — pending reason set when listener flips passwordResetRequired
// =============================================================================

it('pins FirstLoginForced as pending reason when forceChangeOnFirstLogin is enabled', function() {
    $request = new WebRequestStub();
    Craft::$app->set('request', $request);

    $this->settings->forceChangeOnFirstLogin = true;

    // New user with an initial password — the listener writes the
    // initial-password row (self_service from request) and then flips
    // passwordResetRequired + pins FirstLoginForced as pending.
    $unique = bin2hex(random_bytes(4));
    $user = new craft\elements\User([
        'admin' => true,
        'username' => "newuser-{$unique}",
        'email' => "newuser-{$unique}@craftpulse.test",
        'newPassword' => 'InitialAdminSet-1aB2cD!',
    ]);

    expect(Craft::$app->getElements()->saveElement($user, false))->toBeTrue();

    // The user_state row carries the pending reason for the NEXT change.
    $state = UserStateRecord::findOne(['userId' => $user->id]);

    expect($state)->not->toBeNull()
        ->and($state->pendingResetReason)->toBe(ChangeReason::FirstLoginForced->value)
        ->and($user->passwordResetRequired)->toBeTrue();
});
