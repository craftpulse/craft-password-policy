<?php
/**
 * Pest coverage for the whole-screen edition deny on the settings sections
 * landed in the v5.2.0 CP edition-gating rework.
 *
 * Group Policies + Compliance Presets are Pro-only screens. The sidebar omits
 * them below Pro, but a crafted `password-policy/settings/groups` URL would
 * otherwise reach `SettingsController::actionEdit()`, so the action denies
 * directly:
 *
 *  - `actionEdit('groups')` / `actionEdit('presets')` 403 on Lite — the page
 *    never renders.
 *  - Universal sections (`configuration`, `audit`, ...) are NOT edition-denied
 *    — they render on every edition and omit only their higher-edition fields.
 *
 * Tests run through `runAction()` so `beforeAction()` fires the same
 * manageSettings permission gate a real HTTP request would, and the `section`
 * param binds exactly as the `password-policy/settings/<section>` route supplies it.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craft\web\Response;
use craftpulse\passwordpolicy\controllers\SettingsController;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;
use craftpulse\passwordpolicy\tests\Support\UserStub;
use craftpulse\passwordpolicy\tests\Support\WebRequestStub;
use yii\web\ForbiddenHttpException;

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->originalEdition = $this->plugin->edition;
    $this->originalAllowAdminChanges = Craft::$app->getConfig()->getGeneral()->allowAdminChanges;
    $this->originalRequest = Craft::$app->getRequest();
    $this->originalUser = Craft::$app->getUser();
    $this->originalResponse = Craft::$app->getResponse();

    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = true;

    $this->request = new WebRequestStub();
    $this->request->stubIsCpRequest = true;
    Craft::$app->set('request', $this->request);
    Craft::$app->set('response', new Response());

    $this->userStub = new UserStub();
    Craft::$app->set('user', $this->userStub);

    // Admin identity clears the `pp:manageSettings` permission gate in
    // `beforeAction()`, so the edition gate is the only thing left to fail on Lite.
    $this->actingAdmin = UserFactory::admin();
    $this->userStub->setIdentity($this->actingAdmin);
});

afterEach(function() {
    $this->plugin->edition = $this->originalEdition;
    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = $this->originalAllowAdminChanges;
    Craft::$app->set('request', $this->originalRequest);
    Craft::$app->set('user', $this->originalUser);
    Craft::$app->set('response', $this->originalResponse);
});

// =============================================================================
// Helpers
// =============================================================================

/**
 * Runs `SettingsController::actionEdit($section)` through `runAction()` so the
 * `requirePermission()` gate in `beforeAction()` fires and `section` binds from
 * the route the same way the real request does.
 */
function runSettingsEdit(string $section): mixed
{
    $controller = new SettingsController('settings', PasswordPolicy::$plugin);

    return $controller->runAction('edit', ['section' => $section]);
}

// =============================================================================
// Lite edition — the Pro-only sections deny outright
// =============================================================================

it('actionEdit(groups) 403s on Lite', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_LITE;

    expect(fn() => runSettingsEdit('groups'))
        ->toThrow(ForbiddenHttpException::class);
});

it('actionEdit(presets) 403s on Lite', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_LITE;

    expect(fn() => runSettingsEdit('presets'))
        ->toThrow(ForbiddenHttpException::class);
});

// =============================================================================
// Universal sections are never edition-denied
// =============================================================================

it('does not edition-deny a universal section on Lite', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_LITE;

    // `audit` renders on every edition. It will fail later at template render
    // in the console-bootstrapped test process, but it must NOT raise the
    // edition ForbiddenHttpException — that's the assertion under test.
    $forbidden = false;

    try {
        runSettingsEdit('audit');
    } catch (ForbiddenHttpException) {
        $forbidden = true;
    } catch (\Throwable) {
        // Any non-403 throwable (e.g. a template-render error) is fine —
        // it means execution passed the edition gate.
    }

    expect($forbidden)->toBeFalse('Universal `audit` section wrongly edition-denied on Lite');
});

// =============================================================================
// Pro edition — the Pro-only sections pass the edition gate
// =============================================================================

it('does not edition-deny the Pro sections on Pro', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;

    foreach (['groups', 'presets'] as $section) {
        $forbidden = false;

        try {
            runSettingsEdit($section);
        } catch (ForbiddenHttpException) {
            $forbidden = true;
        } catch (\Throwable) {
            // Passed the edition gate; a later render error is out of scope.
        }

        expect($forbidden)->toBeFalse("Pro section `{$section}` wrongly edition-denied on Pro");
    }
});
