<?php
/**
 * Pest coverage for the audit listeners on Craft's account lock /
 * unlock lifecycle events.
 *
 * Pins the contract: when `Users::EVENT_AFTER_LOCK_USER` or
 * `Users::EVENT_AFTER_UNLOCK_USER` fires, the audit row's `userId`
 * resolves from `UserEvent::$user->id` — NOT from `$event->sender`
 * (which is the Users service instance, not a User element).
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craft\db\Query;
use craft\events\UserEvent;
use craft\services\Users;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;
use yii\base\Event;

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->originalEdition = $this->plugin->edition;
    $this->originalEnableAuditLog = $this->plugin->getSettings()->enableAuditLog;

    $this->plugin->edition = PasswordPolicy::EDITION_ENTERPRISE;
    $this->plugin->getSettings()->enableAuditLog = true;

    Craft::$app->getDb()->createCommand()
        ->delete('{{%passwordpolicy_audit_log}}')
        ->execute();
});

afterEach(function() {
    $this->plugin->edition = $this->originalEdition;
    $this->plugin->getSettings()->enableAuditLog = $this->originalEnableAuditLog;
});

// =============================================================================
// Listener resolves the user via $event->user (not $event->sender)
// =============================================================================

it('records account_locked with userId from $event->user when Users::EVENT_AFTER_LOCK_USER fires', function() {
    $user = UserFactory::admin();

    Event::trigger(
        Users::class,
        Users::EVENT_AFTER_LOCK_USER,
        new UserEvent(['user' => $user]),
    );

    $row = (new Query())
        ->from('{{%passwordpolicy_audit_log}}')
        ->where(['event' => 'account_locked'])
        ->one();

    expect($row)->not->toBeNull();
    expect((int)$row['userId'])->toBe($user->id);
    expect($row['outcome'])->toBe('warning');
});

it('records account_unlocked with userId from $event->user when Users::EVENT_AFTER_UNLOCK_USER fires', function() {
    $user = UserFactory::admin();

    Event::trigger(
        Users::class,
        Users::EVENT_AFTER_UNLOCK_USER,
        new UserEvent(['user' => $user]),
    );

    $row = (new Query())
        ->from('{{%passwordpolicy_audit_log}}')
        ->where(['event' => 'account_unlocked'])
        ->one();

    expect($row)->not->toBeNull();
    expect((int)$row['userId'])->toBe($user->id);
    expect($row['outcome'])->toBe('success');
});
