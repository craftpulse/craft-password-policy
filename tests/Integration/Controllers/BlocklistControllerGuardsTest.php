<?php
/**
 * Pest coverage for `BlocklistController` edition gates landed in the
 * v5.2.0 pre-tag fix-pack.
 *
 * The blocklist editor is a Pro screen, hidden below Pro: no subnav entry, no
 * `pp:blocklist-*` permissions on the permissions screen. `beforeAction()`
 * carries the same gate for anyone who arrives by URL anyway:
 *
 *  - `actionIndex()` 404s on Lite. The page doesn't exist on that edition, so
 *    it answers like any other nonexistent route rather than confirming the
 *    screen with a 403.
 *  - `actionSaveCustom()` 404s on Lite BEFORE touching the blocklist table, so
 *    a crafted POST can't persist a custom word on a sub-Pro install.
 *
 * Tests run through `runAction()` so `beforeAction()` fires the same
 * permission gates a real HTTP request would.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craft\db\Query;
use craft\web\Response;
use craftpulse\passwordpolicy\controllers\BlocklistController;
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

    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = true;

    $this->request = new WebRequestStub();
    $this->request->stubIsCpRequest = true;
    Craft::$app->set('request', $this->request);
    Craft::$app->set('response', new Response());

    $this->userStub = new UserStub();
    Craft::$app->set('user', $this->userStub);

    // Admin identity passes the `pp:blocklist-view` / `pp:blocklist-manage`
    // permission gates in `beforeAction()`, so the edition gate is the
    // only thing left to fail on Lite.
    $this->actingAdmin = UserFactory::admin();
    $this->userStub->setIdentity($this->actingAdmin);

    $this->plugin->getBlocklist()->clearCache();
});

afterEach(function() {
    $this->plugin->edition = $this->originalEdition;
    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = $this->originalAllowAdminChanges;
    Craft::$app->set('request', $this->originalRequest);
    Craft::$app->set('user', $this->originalUser);
    Craft::$app->set('response', $this->originalResponse);
    $this->plugin->getBlocklist()->clearCache();
});

// =============================================================================
// Helpers
// =============================================================================

/**
 * Runs a `BlocklistController` action through `runAction()` so the
 * `requireCpRequest` / `requirePermission` gates in `beforeAction()`
 * fire in the right order before the action body.
 *
 * Uses an anonymous subclass that suppresses `setSuccessFlash()` — the
 * console application's `getSession()` throws `MissingComponentException`,
 * but the Pest suite bootstraps as a console application and cannot
 * provide a real session. The session flash is tested at the HTTP-
 * integration level (manual tests T5.x); here we only assert on the DB
 * side-effect (the custom word persisted) and the gate side-effect (the
 * 404 fired before the write).
 */
function runBlocklistAction(string $actionId): mixed
{
    $controller = new class('blocklist', PasswordPolicy::$plugin) extends BlocklistController {
        /**
         * No-op override: `craft\web\Controller::setSuccessFlash()` calls
         * `Craft::$app->getSession()`, which throws in the console-
         * bootstrapped test process. The DB-persistence assertion is the
         * behaviour under test; the session flash is a UI side-effect
         * outside this test's scope.
         *
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

/**
 * Counts global custom blocklist rows (the surface the CP editor writes).
 */
function countGlobalCustomRows(): int
{
    return (int)(new Query())
        ->from('{{%passwordpolicy_blocklist}}')
        ->where(['source' => 'custom', 'policyId' => null])
        ->count();
}

// =============================================================================
// Lite edition — the custom blocklist editor is off
// =============================================================================

it('actionIndex 404s on Lite', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_LITE;

    expect(fn() => runBlocklistAction('index'))
        ->toThrow(NotFoundHttpException::class);
});

it('actionCheck 404s on Lite', function() {
    // The word-lookup AJAX only exists on the Pro editor page, so it's gated
    // with the rest of the controller rather than left reachable on Lite.
    $this->plugin->edition = PasswordPolicy::EDITION_LITE;

    $this->request->stubBodyParams = ['word' => 'hunter2'];
    $this->request->stubAcceptsJson = true;

    expect(fn() => runBlocklistAction('check'))
        ->toThrow(NotFoundHttpException::class);
});

it('actionSaveCustom 404s on Lite without persisting any custom word', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_LITE;

    $this->request->stubBodyParams = [
        'words' => [
            'new1' => ['word' => 'craftedinjection'],
        ],
    ];

    expect(fn() => runBlocklistAction('save-custom'))
        ->toThrow(NotFoundHttpException::class);

    // The gate fires before the blocklist diff — nothing landed.
    expect(countGlobalCustomRows())->toBe(0);
});

// =============================================================================
// Pro edition — the editor persists custom words
// =============================================================================

it('actionSaveCustom persists a custom word on Pro', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;

    $this->request->stubBodyParams = [
        'words' => [
            'new1' => ['word' => 'AcmeSecret'],
        ],
    ];

    runBlocklistAction('save-custom');

    $words = (new Query())
        ->select(['word'])
        ->from('{{%passwordpolicy_blocklist}}')
        ->where(['source' => 'custom', 'policyId' => null])
        ->column();

    expect($words)->toBe(['acmesecret']);
});
