<?php
/**
 * Pest coverage for `GroupAlertController` — the Feature 3 per-group alert
 * editor CP surface.
 *
 * The editor is a Pro feature reachable on Lite at the controller level (the
 * subnav + permission don't, on their own, encode the edition tier), so the
 * controller gates explicitly:
 *
 *  - `actionIndex()` / `actionSave()` 404 on Lite: the editor doesn't exist on
 *    that edition, so it answers like any nonexistent route
 *    and a crafted POST can't persist a subscription on a sub-Pro install.
 *  - `actionSave()` 403s for a Pro user without `pp:notification-templates-manage`.
 *  - `actionSave()` persists the submitted subscriptions on Pro for a
 *    permitted user (diff-on-save).
 *
 * Tests run through `runAction()` so `beforeAction()` fires the same gates a
 * real HTTP request would. Mirrors `BlocklistControllerGuardsTest`.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craft\web\Response;
use craftpulse\passwordpolicy\controllers\GroupAlertController;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\records\GroupAlertSubscriptionRecord;
use craftpulse\passwordpolicy\tests\Support\Factories\GroupFactory;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;
use craftpulse\passwordpolicy\tests\Support\UserStub;
use craftpulse\passwordpolicy\tests\Support\WebRequestStub;
use yii\web\ForbiddenHttpException;
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

    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = true;

    $this->request = new WebRequestStub();
    $this->request->stubIsCpRequest = true;
    Craft::$app->set('request', $this->request);
    Craft::$app->set('response', new Response());

    $this->userStub = new UserStub();
    Craft::$app->set('user', $this->userStub);

    // Admin identity passes the `pp:notification-templates-manage` gate so
    // the edition gate is the only thing left to fail on Lite.
    $this->actingAdmin = UserFactory::admin();
    $this->userStub->setIdentity($this->actingAdmin);

    GroupAlertSubscriptionRecord::deleteAll();
    $this->group = GroupFactory::create();
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
 * Runs a `GroupAlertController` action through `runAction()` so the
 * `requireCpRequest` / edition / `requirePermission` gates in
 * `beforeAction()` fire before the body. The `setSuccessFlash()` override
 * suppresses the session flash that the console-bootstrapped test process
 * cannot provide (mirrors `BlocklistControllerGuardsTest`).
 */
function runGroupAlertAction(string $actionId): mixed
{
    $controller = new class('group-alert', PasswordPolicy::$plugin) extends GroupAlertController {
        /**
         * @param string|null $default
         * @param array<string, mixed> $settings
         *
         * @author CraftPulse
         * @since 5.2.0
         */
        public function setSuccessFlash(?string $default = null, array $settings = []): void
        {
            // Intentionally suppressed — no session in the console test process.
        }
    };

    return $controller->runAction($actionId);
}

// =============================================================================
// Lite edition — the editor is off
// =============================================================================

it('actionIndex 404s on Lite', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_LITE;

    expect(fn() => runGroupAlertAction('index'))
        ->toThrow(NotFoundHttpException::class);
});

it('actionSave 404s on Lite without persisting any subscription', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_LITE;

    $this->request->stubBodyParams = [
        'subscriptions' => [
            'new1' => [
                'groupId' => (int)$this->group->id,
                'eventType' => 'breach_detected',
                'recipientEmail' => 'crafted@craftpulse.test',
                'enabled' => '1',
            ],
        ],
    ];

    expect(fn() => runGroupAlertAction('save'))
        ->toThrow(NotFoundHttpException::class);

    expect(GroupAlertSubscriptionRecord::find()->count())->toBe(0);
});

// =============================================================================
// Permission gate — a user without the manage permission is forbidden
// =============================================================================

it('actionSave 403s for a user without pp:notification-templates-manage', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;

    // Non-admin without the permission — the gate is the only thing to fail.
    $this->userStub->setIdentity(UserFactory::nonAdmin());

    $this->request->stubBodyParams = [
        'subscriptions' => [
            'new1' => [
                'groupId' => (int)$this->group->id,
                'eventType' => 'breach_detected',
                'recipientEmail' => 'crafted@craftpulse.test',
                'enabled' => '1',
            ],
        ],
    ];

    expect(fn() => runGroupAlertAction('save'))
        ->toThrow(ForbiddenHttpException::class);

    expect(GroupAlertSubscriptionRecord::find()->count())->toBe(0);
});

// =============================================================================
// Pro edition — the editor persists subscriptions
// =============================================================================

it('actionSave persists a subscription on Pro for a permitted user', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;

    $this->request->stubBodyParams = [
        'subscriptions' => [
            'new1' => [
                'groupId' => (int)$this->group->id,
                'eventType' => 'new_device',
                'recipientEmail' => 'Contact@Craftpulse.Test',
                'enabled' => '1',
            ],
        ],
    ];

    runGroupAlertAction('save');

    /** @var GroupAlertSubscriptionRecord[] $rows */
    $rows = GroupAlertSubscriptionRecord::find()->all();
    expect($rows)->toHaveCount(1);
    expect($rows[0]->groupId)->toBe((int)$this->group->id);
    expect($rows[0]->eventType)->toBe('new_device');
    // Stored lowercase.
    expect($rows[0]->recipientEmail)->toBe('contact@craftpulse.test');
    expect((bool)$rows[0]->enabled)->toBeTrue();
});
