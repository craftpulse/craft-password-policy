<?php
/**
 * Pest coverage for PP's governance emission onto the shared Audit Kit bus
 * ({@see \craftpulse\passwordpolicy\services\GovernanceAuditService}).
 *
 * Asserts the additive fan-out contract:
 *
 *  - A named-policy save emits exactly one `passwordpolicy.policy_saved`.
 *  - A named-policy delete emits exactly one `passwordpolicy.policy_deleted`.
 *  - Assigning a user-group to a policy emits one
 *    `passwordpolicy.group_assignment_changed` (change `assigned`) carrying the
 *    group's uid; removing it emits one with change `unassigned`.
 *  - Every event lands in category `permissions`, from emitter `password-policy`,
 *    targeting the policy, with scalar-only details.
 *  - The three governance event types are registered with the kit EventTypes
 *    registry, and the registry's fail-closed allowlist strips any details key
 *    outside the declared scalar set.
 *
 * Isolation: the test drives its own {@see CapturingBusSink} through
 * `Bus::setSinks()` and asserts against captured events only — it never touches
 * a real recorder's storage (Ledger's table is off-limits in the shared
 * playground).
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craftpulse\auditkit\audit\AuditEvent;
use craftpulse\auditkit\AuditKit;
use craftpulse\auditkit\services\Bus;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\services\GovernanceAuditService;
use craftpulse\passwordpolicy\tests\Support\CapturingBusSink;
use craftpulse\passwordpolicy\tests\Support\Factories\GroupFactory;
use craftpulse\passwordpolicy\tests\Support\Factories\PolicyFactory;
use craftpulse\passwordpolicy\tests\Support\ThrowingBusSink;
use yii\base\Event;

// =============================================================================
// Setup — swap in a capturing sink for the duration of each test
// =============================================================================

beforeEach(function() {
    $this->sink = new CapturingBusSink();
    AuditKit::getInstance()->getBus()->setSinks([$this->sink]);
});

afterEach(function() {
    AuditKit::getInstance()->getBus()->setSinks([]);
});

// =============================================================================
// policy_saved
// =============================================================================

it('emits exactly one policy_saved event on save', function() {
    $this->sink->events = [];

    $policy = PolicyFactory::nist();

    $saved = $this->sink->eventsNamed(GovernanceAuditService::EVENT_POLICY_SAVED);
    expect($saved)->toHaveCount(1);

    $event = $saved[0];
    expect($event)->toBeInstanceOf(AuditEvent::class);
    expect($event->category)->toBe('permissions');
    expect($event->emitter)->toBe('password-policy');
    expect($event->outcome)->toBe(AuditEvent::OUTCOME_SUCCESS);
    expect($event->targetType)->toBe('passwordPolicy');
    expect($event->targetId)->toBe((int)$policy->id);
    expect($event->targetUid)->toBe($policy->uid);
    expect($event->details['handle'])->toBe($policy->handle);
    expect($event->details['uid'])->toBe($policy->uid);
    expect($event->details['isNew'])->toBeTrue();
});

// =============================================================================
// policy_deleted
// =============================================================================

it('emits exactly one policy_deleted event on delete', function() {
    $policy = PolicyFactory::nist();
    $this->sink->events = [];

    PasswordPolicy::$plugin->getPolicies()->deletePolicy((int)$policy->id);

    $deleted = $this->sink->eventsNamed(GovernanceAuditService::EVENT_POLICY_DELETED);
    expect($deleted)->toHaveCount(1);

    $event = $deleted[0];
    expect($event->category)->toBe('permissions');
    expect($event->emitter)->toBe('password-policy');
    expect($event->targetId)->toBe((int)$policy->id);
    expect($event->details['handle'])->toBe($policy->handle);
    expect($event->details['uid'])->toBe($policy->uid);
});

// =============================================================================
// group_assignment_changed — assign
// =============================================================================

it('emits one group_assignment_changed (assigned) when a group is added', function() {
    $group = GroupFactory::create();
    $this->sink->events = [];

    $policy = PolicyFactory::nist([$group]);

    $changes = $this->sink->eventsNamed(GovernanceAuditService::EVENT_GROUP_ASSIGNMENT_CHANGED);
    expect($changes)->toHaveCount(1);

    $event = $changes[0];
    expect($event->category)->toBe('permissions');
    expect($event->targetId)->toBe((int)$policy->id);
    expect($event->details['policyHandle'])->toBe($policy->handle);
    expect($event->details['policyUid'])->toBe($policy->uid);
    expect($event->details['groupUid'])->toBe($group->uid);
    expect($event->details['change'])->toBe('assigned');
});

// =============================================================================
// group_assignment_changed — unassign
// =============================================================================

it('emits one group_assignment_changed (unassigned) when a group is removed', function() {
    $group = GroupFactory::create();
    $policy = PolicyFactory::nist([$group]);
    $this->sink->events = [];

    // Re-save with an empty group set — the one assignment is removed.
    PasswordPolicy::$plugin->getPolicies()->savePolicy($policy, []);

    $changes = $this->sink->eventsNamed(GovernanceAuditService::EVENT_GROUP_ASSIGNMENT_CHANGED);
    expect($changes)->toHaveCount(1);
    expect($changes[0]->details['groupUid'])->toBe($group->uid);
    expect($changes[0]->details['change'])->toBe('unassigned');
});

// =============================================================================
// No spurious group event when the assignment set is unchanged
// =============================================================================

it('emits no group_assignment_changed when the group set is unchanged', function() {
    $group = GroupFactory::create();
    $policy = PolicyFactory::nist([$group]);
    $this->sink->events = [];

    // Re-save with the same single group — nothing changed.
    PasswordPolicy::$plugin->getPolicies()->savePolicy($policy, [(int)$group->id]);

    expect($this->sink->eventsNamed(GovernanceAuditService::EVENT_GROUP_ASSIGNMENT_CHANGED))->toHaveCount(0);
});

// =============================================================================
// Registry + fail-closed allowlist
// =============================================================================

it('registers its three governance event types with the kit registry', function() {
    $registry = AuditKit::getInstance()->getEventTypes();

    foreach ([
        GovernanceAuditService::EVENT_POLICY_SAVED,
        GovernanceAuditService::EVENT_POLICY_DELETED,
        GovernanceAuditService::EVENT_GROUP_ASSIGNMENT_CHANGED,
    ] as $name) {
        $type = $registry->getEventType($name);
        expect($type)->not->toBeNull();
        expect($type->category)->toBe('permissions');
    }
});

// =============================================================================
// Fail-soft — an emission failure never unwinds the committed governance action
// =============================================================================

it('saves the policy even when a registered sink throws', function() {
    // The kit's `Bus::record()` isolates each sink in its own try/catch, so this
    // never reaches `GovernanceAuditService::_record()`. It is asserted anyway,
    // because the property PP depends on is end-to-end: a broken recorder
    // elsewhere in the estate must not be able to fail a policy save here.
    AuditKit::getInstance()->getBus()->setSinks([new ThrowingBusSink()]);

    $policy = PolicyFactory::nist();

    expect($policy->id)->not->toBeNull();
    expect(PasswordPolicy::$plugin->getPolicies()->getPolicyById((int)$policy->id))->not->toBeNull();
});

it('saves the policy even when sink registration itself throws', function() {
    // This is the path that actually exercises `_record()`'s own catch.
    // `Bus::getSinks()` resolves lazily by triggering
    // `EVENT_REGISTER_AUDIT_SINKS`, and a third-party listener on it is arbitrary
    // code. `setSinks()` memoizes an array, so the private property is nulled
    // back out to force the fan-out to run.
    $bus = AuditKit::getInstance()->getBus();
    $sinks = new ReflectionProperty($bus, '_sinks');
    $sinks->setValue($bus, null);

    $listener = static function(): never {
        throw new RuntimeException('sink registration exploded');
    };

    Event::on(Bus::class, Bus::EVENT_REGISTER_AUDIT_SINKS, $listener);

    try {
        $policy = PolicyFactory::nist();

        expect($policy->id)->not->toBeNull();
        expect(PasswordPolicy::$plugin->getPolicies()->getPolicyById((int)$policy->id))->not->toBeNull();
    } finally {
        Event::off(Bus::class, Bus::EVENT_REGISTER_AUDIT_SINKS, $listener);
        $bus->setSinks([]);
    }
});

it('strips a non-allowlisted details key through the kit registry sanitiser', function() {
    $eventTypes = AuditKit::getInstance()->getEventTypes();
    $type = $eventTypes->getEventType(GovernanceAuditService::EVENT_POLICY_SAVED);

    $sanitised = $eventTypes->sanitizeDetails($type, [
        'handle' => 'myPolicy',
        'uid' => 'policy-uid',
        'email' => 'leak@example.test',
    ]);

    expect($sanitised)->toHaveKeys(['handle', 'uid']);
    expect($sanitised)->not->toHaveKey('email');
});
