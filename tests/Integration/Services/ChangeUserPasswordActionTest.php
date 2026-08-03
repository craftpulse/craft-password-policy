<?php
/**
 * Pest coverage for the `ChangeUserPassword` element action — the
 * single-user "Change password" entry on the per-user edit-screen
 * action menu.
 *
 * The action is intentionally NOT registered on the Users index
 * bulk-action menu (`User::EVENT_REGISTER_ACTIONS` deliberately omits
 * it — same password on N users is a security anti-pattern). Its
 * remaining surface is two static helpers consumed by
 * `PasswordPolicy::_registerUserEditActionMenu()` plus the
 * abstract-contract `performAction()` which always rejects.
 *
 * The controller-side tests (`UserPasswordControllerTest`) cover the
 * actual save, audit-context propagation, pending-reason clear,
 * permission gate, and elevated session.
 *
 * @link      https://craft-pulse.com
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
});

// =============================================================================
// Trigger HTML — bulk-action surface intentionally inert
// =============================================================================

it('returns null trigger HTML (no bulk-action surface)', function() {
    // ChangeUserPassword inherits ElementAction's default null
    // trigger because the action class is not registered as a bulk
    // action — its modal lives only on the per-user edit-screen
    // action menu. Pin null in both `allowAdminChanges` modes so a
    // future refactor that re-registers the bulk surface trips a
    // failing test instead of silently exposing a same-password-on-N
    // bulk affordance.
    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = false;
    expect($this->action->getTriggerHtml())->toBeNull();

    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = true;
    expect($this->action->getTriggerHtml())->toBeNull();
});

// =============================================================================
// registerModalHelper — static helper used by the edit-screen action
// menu listener
// =============================================================================

it('registers the modal helper JS via the static helper', function() {
    $view = Craft::$app->getView();
    $before = $view->js;

    ChangeUserPassword::registerModalHelper($view);

    $allJs = '';
    foreach ($view->js as $scripts) {
        foreach ((array)$scripts as $script) {
            $allJs .= $script;
        }
    }

    expect($allJs)
        ->toContain('Craft.PasswordPolicy.openChangePasswordModal')
        ->toContain('Craft.elevatedSessionManager.requireElevatedSession');
});

// =============================================================================
// performAction — bulk-by-design-off contract
// =============================================================================

it('rejects performAction with an explanatory message (bulk-off contract)', function() {
    // Set up a couple of users so the query has something to iterate
    // — the action should reject regardless of count, including
    // single-user invocations, because the entire flow is supposed
    // to run through the modal helper + controller seam exposed via
    // the edit-screen action menu.
    UserFactory::admin();
    UserFactory::admin();

    $query = User::find()->limit(2);

    expect($this->action->performAction($query))->toBeFalse();
});
