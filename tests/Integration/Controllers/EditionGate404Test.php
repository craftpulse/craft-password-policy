<?php
/**
 * Pest coverage for the shared edition gate on the CP controllers behind
 * higher-edition screens.
 *
 * The hide-not-badge doctrine means a lower edition renders no trace of a
 * higher-edition screen: no subnav entry, no permission to grant, no disabled
 * teaser. A URL for such a screen therefore has to behave like any other
 * nonexistent route and 404. A 403 would confirm the screen exists, which is
 * exactly the signal the hidden nav withholds.
 *
 * {@see \craftpulse\passwordpolicy\base\RequiresEditionTrait} owns that
 * translation. This file asserts it end-to-end through `runAction()` for one
 * action per gated controller, in both directions: the gated edition 404s, and
 * the owning edition passes the gate (any later failure, e.g. a template render
 * in the console-bootstrapped test process, means the gate let it through).
 *
 * Controllers with their own dedicated edition coverage aren't repeated here:
 * see BlocklistControllerGuardsTest, GroupAlertControllerTest,
 * SettingsSectionEditionGuardTest, AuditExportControllerTest,
 * ReportControllerTest, WebhookEndpointControllerTest, ApiTokenControllerTest,
 * and ApiControllerTest.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craft\web\Response;
use craftpulse\passwordpolicy\controllers\InactiveAccountController;
use craftpulse\passwordpolicy\controllers\NotificationActivityController;
use craftpulse\passwordpolicy\controllers\NotificationTemplateController;
use craftpulse\passwordpolicy\controllers\PolicyController;
use craftpulse\passwordpolicy\controllers\SiemForwarderController;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;
use craftpulse\passwordpolicy\tests\Support\UserStub;
use craftpulse\passwordpolicy\tests\Support\WebRequestStub;
use yii\web\NotFoundHttpException;

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
    $this->originalPerGroup = $this->plugin->getSettings()->enablePerGroupPolicies;

    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = true;
    $this->plugin->getSettings()->enablePerGroupPolicies = true;

    $this->request = new WebRequestStub();
    $this->request->stubIsCpRequest = true;
    Craft::$app->set('request', $this->request);
    Craft::$app->set('response', new Response());

    $this->userStub = new UserStub();
    Craft::$app->set('user', $this->userStub);

    // Admin identity clears every permission gate, so the edition is the only
    // thing left that can stop an action.
    $this->userStub->setIdentity(UserFactory::admin());
});

afterEach(function() {
    $this->plugin->edition = $this->originalEdition;
    $this->plugin->getSettings()->enablePerGroupPolicies = $this->originalPerGroup;
    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = $this->originalAllowAdminChanges;
    Craft::$app->set('request', $this->originalRequest);
    Craft::$app->set('user', $this->originalUser);
    Craft::$app->set('response', $this->originalResponse);
});

// =============================================================================
// Helpers
// =============================================================================

/**
 * Runs an action through `runAction()` so `beforeAction()` fires exactly as it
 * would on a real request.
 *
 * @param class-string<\craft\web\Controller> $class
 * @param array<string, mixed> $params
 */
function runGatedAction(string $class, string $controllerId, string $actionId, array $params = []): mixed
{
    $controller = new $class($controllerId, PasswordPolicy::$plugin);

    return $controller->runAction($actionId, $params);
}

/**
 * Whether running the action raised the edition 404. Any other throwable counts
 * as "passed the gate": these actions go on to render CP templates, which the
 * console-bootstrapped test process can't complete.
 *
 * @param class-string<\craft\web\Controller> $class
 * @param array<string, mixed> $params
 */
function raisedEditionNotFound(string $class, string $controllerId, string $actionId, array $params = []): bool
{
    try {
        runGatedAction($class, $controllerId, $actionId, $params);
    } catch (NotFoundHttpException) {
        return true;
    } catch (Throwable) {
        return false;
    }

    return false;
}

// =============================================================================
// Pro-gated controllers — 404 on Lite
// =============================================================================

it('404s the inactive-accounts report on Lite', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_LITE;

    expect(raisedEditionNotFound(InactiveAccountController::class, 'inactive-account', 'index'))->toBeTrue();
});

it('404s the notification template editor on Lite', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_LITE;

    expect(raisedEditionNotFound(NotificationTemplateController::class, 'notification-template', 'index'))->toBeTrue();
});

it('404s the notification activity log on Lite', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_LITE;

    expect(raisedEditionNotFound(NotificationActivityController::class, 'notification-activity', 'index'))->toBeTrue();
});

it('404s the named-policy index on Lite', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_LITE;

    expect(raisedEditionNotFound(PolicyController::class, 'policy', 'index'))->toBeTrue();
});

// =============================================================================
// Pro-gated controllers — the gate opens on Pro
// =============================================================================

it('passes the edition gate for the Pro screens on Pro', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;

    expect(raisedEditionNotFound(InactiveAccountController::class, 'inactive-account', 'index'))->toBeFalse()
        ->and(raisedEditionNotFound(NotificationTemplateController::class, 'notification-template', 'index'))->toBeFalse()
        ->and(raisedEditionNotFound(NotificationActivityController::class, 'notification-activity', 'index'))->toBeFalse()
        ->and(raisedEditionNotFound(PolicyController::class, 'policy', 'index'))->toBeFalse();
});

// =============================================================================
// Enterprise-gated controllers — 404 below Enterprise
// =============================================================================

it('404s the SIEM forwarder screen on Lite and Pro', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_LITE;
    expect(raisedEditionNotFound(SiemForwarderController::class, 'siem-forwarder', 'index'))->toBeTrue();

    $this->plugin->edition = PasswordPolicy::EDITION_PRO;
    expect(raisedEditionNotFound(SiemForwarderController::class, 'siem-forwarder', 'index'))->toBeTrue();
});

it('passes the edition gate for the SIEM forwarder screen on Enterprise', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_ENTERPRISE;

    expect(raisedEditionNotFound(SiemForwarderController::class, 'siem-forwarder', 'index'))->toBeFalse();
});
