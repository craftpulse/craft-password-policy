<?php
/**
 * Pest coverage for the `PolicyService` save-lifecycle extension seam:
 * `EVENT_BEFORE_SAVE_POLICY` + `EVENT_AFTER_SAVE_POLICY`.
 *
 * Pins the public extension contract third-party listeners can rely on:
 *
 *  - `EVENT_BEFORE_SAVE_POLICY` fires after `validate()` passes, BEFORE
 *    any DB I/O. A listener flipping `$event->isValid = false` aborts
 *    the save — no row is written and AFTER does not fire.
 *  - `EVENT_AFTER_SAVE_POLICY` fires after the transaction commits,
 *    BEFORE the inline G4 audit-diff capture. `$event->policy->id` is
 *    populated even on the INSERT path.
 *  - `$event->isNew` reflects the PRE-save shape and is consistent
 *    across BEFORE and AFTER for a single save call. Listeners use it
 *    to branch on "newly created" vs "updated existing" without
 *    re-deriving from `policy->id`.
 *  - Validation failure (`$policy->validate()` returned false) fires
 *    no events at all — the event surface is reserved for valid-shape
 *    policies.
 *  - The G4 inline audit-diff capture still runs on UPDATE. Adding the
 *    extension seam did not regress G4 — both observability layers
 *    coexist.
 *
 * Listeners are detached in `afterEach` via `Event::off(...)` — Yii
 * event handlers persist across Pest tests if not cleaned up, which
 * would cross-contaminate other tests in the same run.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craft\db\Query;
use craftpulse\passwordpolicy\events\PolicySaveEvent;
use craftpulse\passwordpolicy\models\PolicyModel;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\services\PolicyService;
use craftpulse\passwordpolicy\tests\Support\Factories\PolicyFactory;
use yii\base\Event;

// =============================================================================
// Setup — toggle audit logging on for the G4 regression sentinel test, wipe rows
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->originalEdition = $this->plugin->edition;
    $this->originalEnableAuditLog = $this->plugin->getSettings()->enableAuditLog;

    $this->plugin->edition = PasswordPolicy::EDITION_PRO;
    $this->plugin->getSettings()->enableAuditLog = true;

    Craft::$app->getDb()->createCommand()
        ->delete('{{%passwordpolicy_audit_log}}')
        ->execute();
});

afterEach(function() {
    $this->plugin->edition = $this->originalEdition;
    $this->plugin->getSettings()->enableAuditLog = $this->originalEnableAuditLog;

    // Detach every listener attached during this test. Yii event handlers
    // are class-level, not instance-level — they survive Pest's per-test
    // isolation and would cross-contaminate downstream tests if left
    // hanging.
    Event::off(PolicyService::class, PolicyService::EVENT_BEFORE_SAVE_POLICY);
    Event::off(PolicyService::class, PolicyService::EVENT_AFTER_SAVE_POLICY);
});

// =============================================================================
// BEFORE_SAVE fires with the correct payload
// =============================================================================

it('fires EVENT_BEFORE_SAVE_POLICY on a normal INSERT save', function() {
    $captured = null;
    Event::on(
        PolicyService::class,
        PolicyService::EVENT_BEFORE_SAVE_POLICY,
        function(PolicySaveEvent $event) use (&$captured) {
            $captured = $event;
        },
    );

    $policy = PolicyFactory::custom(['minLength' => 10]);

    expect($captured)->toBeInstanceOf(PolicySaveEvent::class);
    expect($captured->isNew)->toBeTrue();
    expect($captured->policy)->toBeInstanceOf(PolicyModel::class);
    expect($captured->policy->handle)->toBe($policy->handle);
    expect($captured->groupIds)->toBe([]);
    expect($captured->isValid)->toBeTrue();
});

// =============================================================================
// AFTER_SAVE: isNew=true on INSERT, isNew=false on UPDATE
// =============================================================================

it('fires EVENT_AFTER_SAVE_POLICY with isNew=true on INSERT', function() {
    $captured = null;
    Event::on(
        PolicyService::class,
        PolicyService::EVENT_AFTER_SAVE_POLICY,
        function(PolicySaveEvent $event) use (&$captured) {
            $captured = $event;
        },
    );

    $policy = PolicyFactory::custom(['minLength' => 10]);

    expect($captured)->toBeInstanceOf(PolicySaveEvent::class);
    expect($captured->isNew)->toBeTrue();
    // Auto-increment landed by the time AFTER_SAVE fires.
    expect($captured->policy->id)->toBe((int)$policy->id);
    expect($captured->policy->id)->not->toBeNull();
});

it('fires EVENT_AFTER_SAVE_POLICY with isNew=false on UPDATE', function() {
    $policy = PolicyFactory::custom(['minLength' => 10]);

    $captured = null;
    Event::on(
        PolicyService::class,
        PolicyService::EVENT_AFTER_SAVE_POLICY,
        function(PolicySaveEvent $event) use (&$captured) {
            $captured = $event;
        },
    );

    $reloaded = $this->plugin->getPolicies()->getPolicyById((int)$policy->id);
    expect($reloaded)->not->toBeNull();
    $reloaded->minLength = 16;

    $this->plugin->getPolicies()->savePolicy($reloaded);

    expect($captured)->toBeInstanceOf(PolicySaveEvent::class);
    expect($captured->isNew)->toBeFalse();
    expect($captured->policy->id)->toBe((int)$policy->id);
    expect($captured->policy->minLength)->toBe(16);
});

// =============================================================================
// Veto contract: BEFORE listener flipping isValid=false aborts the save
// =============================================================================

it('aborts the save when a BEFORE listener flips isValid=false', function() {
    Event::on(
        PolicyService::class,
        PolicyService::EVENT_BEFORE_SAVE_POLICY,
        function(PolicySaveEvent $event) {
            $event->isValid = false;
        },
    );

    $afterFired = false;
    Event::on(
        PolicyService::class,
        PolicyService::EVENT_AFTER_SAVE_POLICY,
        function(PolicySaveEvent $event) use (&$afterFired) {
            $afterFired = true;
        },
    );

    // Build the policy by hand — PolicyFactory::custom() throws when
    // savePolicy() returns false, which is exactly the veto path we want
    // to verify here.
    $unique = bin2hex(random_bytes(4));
    $policy = new PolicyModel();
    $policy->name = "Vetoed Policy {$unique}";
    $policy->handle = "vetoed{$unique}";
    $policy->minLength = 10;

    $result = $this->plugin->getPolicies()->savePolicy($policy);

    expect($result)->toBeFalse();
    expect($afterFired)->toBeFalse();

    // No row was written.
    $count = (new Query())
        ->from('{{%passwordpolicy_policies}}')
        ->where(['handle' => $policy->handle])
        ->count();
    expect((int)$count)->toBe(0);
});

// =============================================================================
// Validation failure — neither event fires
// =============================================================================

it('fires neither event when validation fails', function() {
    $beforeFired = false;
    $afterFired = false;

    Event::on(
        PolicyService::class,
        PolicyService::EVENT_BEFORE_SAVE_POLICY,
        function(PolicySaveEvent $event) use (&$beforeFired) {
            $beforeFired = true;
        },
    );
    Event::on(
        PolicyService::class,
        PolicyService::EVENT_AFTER_SAVE_POLICY,
        function(PolicySaveEvent $event) use (&$afterFired) {
            $afterFired = true;
        },
    );

    // Empty `name` + `handle` — `defineRules()` requires both, so
    // `validate()` returns false before the event surface is reached.
    $policy = new PolicyModel();
    $policy->name = '';
    $policy->handle = '';

    $result = $this->plugin->getPolicies()->savePolicy($policy);

    expect($result)->toBeFalse();
    expect($beforeFired)->toBeFalse();
    expect($afterFired)->toBeFalse();
});

// =============================================================================
// G4 regression: AFTER_SAVE coexists with the inline audit-diff capture
// =============================================================================

it('still writes the policy_changed audit row when AFTER_SAVE fires on UPDATE', function() {
    $policy = PolicyFactory::custom(['minLength' => 10]);

    $afterFired = false;
    Event::on(
        PolicyService::class,
        PolicyService::EVENT_AFTER_SAVE_POLICY,
        function(PolicySaveEvent $event) use (&$afterFired) {
            $afterFired = true;
        },
    );

    Craft::$app->getDb()->createCommand()
        ->delete('{{%passwordpolicy_audit_log}}')
        ->execute();

    $reloaded = $this->plugin->getPolicies()->getPolicyById((int)$policy->id);
    expect($reloaded)->not->toBeNull();
    $reloaded->minLength = 18;

    $this->plugin->getPolicies()->savePolicy($reloaded);

    expect($afterFired)->toBeTrue();

    $row = (new Query())
        ->from('{{%passwordpolicy_audit_log}}')
        ->where(['event' => 'policy_changed'])
        ->orderBy(['id' => SORT_DESC])
        ->limit(1)
        ->one();

    expect($row)->not->toBeNull();
    $details = is_string($row['details']) ? json_decode($row['details'], true) : $row['details'];
    expect($details)->toHaveKey('diff');
    expect($details['diff'])->toHaveKey('minLength');
    expect($details['diff']['minLength'])->toBe(['new' => 18, 'old' => 10]);
});
