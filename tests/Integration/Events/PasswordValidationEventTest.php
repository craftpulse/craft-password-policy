<?php
/**
 * Pest coverage for `PasswordPolicy::EVENT_PASSWORD_VALIDATION`.
 *
 * The event class shipped in 5.2.0 alongside the events catalog (P1.15)
 * but no firing point existed — `events.md` documented the listener
 * shape, the class compiled cleanly, but `Event::trigger()` was never
 * called for it. Phase F polish wires the firing point at
 * `User::EVENT_AFTER_VALIDATE` (Yii's once-per-validate hook) so third-
 * party modules can finally subscribe.
 *
 * Tests pin the four invariants:
 *
 *  1. Fires on a successful validation (errors empty, isValid true).
 *  2. Fires on a failed validation (errors populated, isValid false).
 *  3. Skips firing when neither password nor newPassword is in scope —
 *     the listener filters out validate() calls triggered by unrelated
 *     edits (a name-only update, etc.).
 *  4. Listeners can push back onto the user via `addError()` and the
 *     error reaches the form-facing response. `$event->errors` is a
 *     snapshot at firing time; `$user->addError(...)` is the mutator.
 *
 * Privacy invariant pinned by reading the event's reflection — the
 * payload includes only the User element + an errors array + a
 * boolean. No plaintext, no hash, no HIBP bucket. A sanity assertion
 * exists for the property set; if a future refactor adds a
 * `plaintext` slot, the test fails.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craftpulse\passwordpolicy\events\PasswordValidationEvent;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;
use yii\base\Event;

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->captured = [];

    // Closure listener captures every PasswordValidationEvent into the
    // beforeEach-scoped array; afterEach detaches it. Yii's
    // `Event::off(class, name)` would clear EVERY listener for the
    // event — we attach a one-shot via Event::on with a closure handle
    // and remove that specific handler on teardown.
    $this->listener = function(PasswordValidationEvent $event): void {
        $this->captured[] = [
            'user' => $event->user,
            'errors' => $event->errors,
            'isValid' => $event->isValid,
        ];
    };

    Event::on(
        PasswordPolicy::class,
        PasswordPolicy::EVENT_PASSWORD_VALIDATION,
        $this->listener,
    );
});

afterEach(function() {
    Event::off(
        PasswordPolicy::class,
        PasswordPolicy::EVENT_PASSWORD_VALIDATION,
        $this->listener,
    );
});

// =============================================================================
// Firing — happy path (no password errors)
// =============================================================================

it('fires the event with isValid=true when the password validates cleanly', function() {
    $user = UserFactory::nonAdmin();

    // A long, passing password — no plugin rule complains. minLength
    // default is 6 and complexity toggles default to off, so a 16-char
    // alphabetic password lands clean.
    $user->newPassword = 'PassesValidationOk';
    $user->validate();

    expect($this->captured)->toHaveCount(1);
    expect($this->captured[0]['user']->id)->toBe($user->id);
    expect($this->captured[0]['errors'])->toBeArray()->toBeEmpty();
    expect($this->captured[0]['isValid'])->toBeTrue();
});

// =============================================================================
// Firing — failed validation (errors populated)
// =============================================================================

it('fires the event with isValid=false when the password is too short', function() {
    $user = UserFactory::nonAdmin();

    // minLength default is 6 — a 3-char password fails the always-on
    // length rule and the User collects an error on `newPassword`.
    $user->newPassword = 'abc';
    $user->validate();

    expect($this->captured)->toHaveCount(1);
    expect($this->captured[0]['errors'])->toBeArray();
    expect($this->captured[0]['errors'])->not->toBeEmpty();
    expect($this->captured[0]['isValid'])->toBeFalse();
});

// =============================================================================
// Skip — no password attribute in scope
// =============================================================================

it('does not fire when the User has neither password nor newPassword set', function() {
    $user = UserFactory::nonAdmin();

    // Trigger a validate() pass without touching either password slot.
    // The listener guard short-circuits and the event must not fire —
    // a name-only edit shouldn't broadcast a phantom validation event.
    $user->firstName = 'Renamed';
    $user->validate();

    expect($this->captured)->toBeEmpty();
});

// =============================================================================
// Listener can push errors back onto the user
// =============================================================================

it('lets a listener push errors back onto the user via addError()', function() {
    Event::off(
        PasswordPolicy::class,
        PasswordPolicy::EVENT_PASSWORD_VALIDATION,
        $this->listener,
    );

    // Replace the capture-only listener with one that adds an error.
    $mutator = function(PasswordValidationEvent $event): void {
        $event->user->addError('newPassword', 'Custom rule failure.');
        $event->errors[] = 'Custom rule failure.';
        $event->isValid = false;
    };
    Event::on(
        PasswordPolicy::class,
        PasswordPolicy::EVENT_PASSWORD_VALIDATION,
        $mutator,
    );

    try {
        $user = UserFactory::nonAdmin();
        $user->newPassword = 'StillValidPassword';
        $user->validate();

        // The error pushed via addError() is on the user even though
        // the plugin's own rules would have passed.
        expect($user->getErrors('newPassword'))->toContain('Custom rule failure.');
    } finally {
        Event::off(
            PasswordPolicy::class,
            PasswordPolicy::EVENT_PASSWORD_VALIDATION,
            $mutator,
        );
    }
});

// =============================================================================
// Privacy — payload shape is fixed; plaintext slot does not exist
// =============================================================================

it('exposes only user, errors, and isValid on the event class', function() {
    $reflection = new ReflectionClass(PasswordValidationEvent::class);
    $publicProperties = array_map(
        fn(ReflectionProperty $p) => $p->getName(),
        $reflection->getProperties(ReflectionProperty::IS_PUBLIC),
    );

    // Yii's Event base class ships its own public properties (`name`,
    // `sender`, `data`, `handled`); the plugin-owned ones are the
    // three we documented. Filter inherited Yii properties out and
    // assert exactly the plugin's set — additions land here, blocking
    // a privacy regression at code review time.
    $pluginProperties = array_values(array_diff(
        $publicProperties,
        ['name', 'sender', 'data', 'handled'],
    ));

    sort($pluginProperties);

    expect($pluginProperties)->toBe(['errors', 'isValid', 'user']);
});
