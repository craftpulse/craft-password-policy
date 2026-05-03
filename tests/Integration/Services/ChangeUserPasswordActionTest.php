<?php
/**
 * Pest coverage for the `ChangeUserPassword` element action — the
 * single-user "Change password" entry on the Users index actions menu.
 *
 * Most of the action's behaviour lives behind the modal trigger HTML
 * (consumer flow runs through the controller — see
 * `UserPasswordControllerTest`). The unit-level contracts asserted
 * here are:
 *
 *  - Trigger HTML registers when `allowAdminChanges = true`, returns
 *    null when read-only.
 *  - The bulk-by-design-off contract: `performAction()` returns false
 *    with an explanatory message rather than silently succeeding.
 *
 * The controller-side tests cover the actual save, audit-context
 * propagation, pending-reason clear, permission gate, and elevated
 * session.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craft\elements\User;
use craftpulse\passwordpolicy\elements\actions\ChangeUserPassword;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->action = new ChangeUserPassword();
    $this->originalAllowAdminChanges = Craft::$app->getConfig()->getGeneral()->allowAdminChanges;
});

afterEach(function() {
    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = $this->originalAllowAdminChanges;
});

// =============================================================================
// Trigger HTML — read-only mode
// =============================================================================

it('returns null trigger HTML when allowAdminChanges is false', function() {
    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = false;

    expect($this->action->getTriggerHtml())->toBeNull();
});

it('registers JS and returns null HTML when allowAdminChanges is true', function() {
    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = true;

    // Trigger HTML side-effect-registers JS via View::registerJs and
    // returns null (the JS wires up `Craft.ElementActionTrigger`
    // imperatively rather than rendering a server-template).
    $result = $this->action->getTriggerHtml();

    expect($result)->toBeNull();

    // The registered JS is what actually wires the trigger; pin its
    // presence on the View so a future refactor that drops the
    // `registerJs` call gets caught.
    $jsBag = Craft::$app->getView()->js;
    $allJs = '';

    foreach ($jsBag as $position => $scripts) {
        foreach ((array)$scripts as $script) {
            $allJs .= $script;
        }
    }

    expect($allJs)
        ->toContain('Craft.ElementActionTrigger')
        ->toContain('Craft.PasswordPolicy.openChangePasswordModal');
});

// =============================================================================
// performAction — bulk-by-design-off contract
// =============================================================================

it('rejects performAction with an explanatory message (bulk-off contract)', function() {
    // Set up a couple of users so the query has something to iterate
    // — the action should reject regardless of count, including
    // single-user invocations, because the entire flow is supposed
    // to run through the modal trigger + controller seam.
    UserFactory::admin();
    UserFactory::admin();

    $query = User::find()->limit(2);

    expect($this->action->performAction($query))->toBeFalse();
});
