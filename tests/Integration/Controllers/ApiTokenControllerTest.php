<?php
/**
 * Pest coverage for `ApiTokenController` — the Feature 2 CP token-management
 * surface (Enterprise). Pinned contracts:
 *
 *  - Edition gate: Pro / Lite → NotFoundHttpException in `beforeAction` (the
 *    screen doesn't exist below Enterprise, so it 404s rather than 403s)
 *    (the adversarial "Pro can't reach it" check).
 *  - `actionIssue` mints a token, persists only the hash + prefix (never the
 *    plaintext), and surfaces the plaintext once via the session flash.
 *  - An empty name is rejected without issuing.
 *  - `actionRevoke` deletes the row via JSON.
 *  - Read-only mode (`allowAdminChanges = false`) blocks issue + revoke.
 *
 * Mirrors the console-bootstrap CP-test pattern from
 * `WebhookEndpointControllerTest`: web-shaped `request`, `user`, and
 * elevated-session stubs.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craft\db\Query;
use craft\web\Response;
use craftpulse\passwordpolicy\controllers\ApiTokenController;
use craftpulse\passwordpolicy\PasswordPolicy;
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

    $this->originalRequest = Craft::$app->getRequest();
    $this->originalUser = Craft::$app->getUser();
    $this->originalEdition = $this->plugin->edition;
    $this->originalAllowAdminChanges = Craft::$app->getConfig()->getGeneral()->allowAdminChanges;

    $this->request = new WebRequestStub();
    $this->request->stubIsCpRequest = true;
    Craft::$app->set('request', $this->request);
    Craft::$app->set('response', new Response());

    $this->userStub = new UserStub();
    Craft::$app->set('user', $this->userStub);

    // Token management is Enterprise-only — pin Enterprise in setup.
    $this->plugin->edition = PasswordPolicy::EDITION_ENTERPRISE;
    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = true;

    $this->actingAdmin = UserFactory::admin();
    $this->userStub->setIdentity($this->actingAdmin);

    Craft::$app->getDb()->createCommand()->delete('{{%passwordpolicy_api_tokens}}')->execute();
});

afterEach(function() {
    Craft::$app->set('request', $this->originalRequest);
    Craft::$app->set('user', $this->originalUser);
    $this->plugin->edition = $this->originalEdition;
    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = $this->originalAllowAdminChanges;
});

// =============================================================================
// Helpers
// =============================================================================

/**
 * Runs an ApiTokenController action through `runAction()` so the
 * `beforeAction()` gate chain (CP request + Enterprise + `pp:api-manage` +
 * read-only) fires first. The console-bootstrapped test process has no
 * session, so `setSuccessFlash` / `setFailFlash` / `flashNewToken` are
 * overridden to no-ops (the once-only flash is asserted separately in the
 * issue test via an inline subclass that captures the plaintext).
 */
function runApiTokenAction(string $actionId, array $params = []): mixed
{
    $controller = new class('api-token', PasswordPolicy::$plugin) extends ApiTokenController {
        public function setSuccessFlash(?string $default = null, array $settings = []): void
        {
        }

        public function setFailFlash(?string $default = null, array $settings = []): void
        {
        }

        protected function flashNewToken(string $plaintext): void
        {
        }
    };

    return $controller->runAction($actionId, $params);
}

// =============================================================================
// Edition gate — adversarial "Pro / Lite can't reach it"
// =============================================================================

it('throws NotFoundHttpException on Pro', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;

    expect(fn() => runApiTokenAction('issue'))->toThrow(NotFoundHttpException::class);
});

it('throws NotFoundHttpException on Lite', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_LITE;

    expect(fn() => runApiTokenAction('issue'))->toThrow(NotFoundHttpException::class);
});

// =============================================================================
// actionIssue — mint, hash-at-rest, plaintext-once flash
// =============================================================================

it('issues a token, persists only the hash + prefix, and flashes the plaintext once', function() {
    $this->request->stubBodyParams = [
        'name' => 'CI pipeline',
    ];

    $controller = new class('api-token', PasswordPolicy::$plugin) extends ApiTokenController {
        /** @var string|null */
        public ?string $capturedToken = null;

        public function setSuccessFlash(?string $default = null, array $settings = []): void
        {
        }

        protected function flashNewToken(string $plaintext): void
        {
            $this->capturedToken = $plaintext;
        }
    };
    $controller->runAction('issue');

    $row = (new Query())
        ->from('{{%passwordpolicy_api_tokens}}')
        ->where(['name' => 'CI pipeline'])
        ->one();

    expect($row)->not->toBeNull()
        ->and($row['tokenHash'])->toMatch('/^[0-9a-f]{64}$/');

    // The flashed plaintext hashes to the stored hash — the plaintext is
    // never itself in the row.
    $flashed = $controller->capturedToken;

    expect($flashed)->toBeString()
        ->and(hash('sha256', $flashed))->toBe($row['tokenHash'])
        ->and($row['tokenPrefix'])->toBe(substr($flashed, 0, 8));

    // Plaintext appears in no string column of the row.
    foreach ($row as $value) {
        if (is_string($value)) {
            expect($value)->not->toBe($flashed);
        }
    }
});

it('rejects an empty token name without issuing', function() {
    $this->request->stubBodyParams = [
        'name' => '   ',
    ];

    runApiTokenAction('issue');

    $count = (new Query())->from('{{%passwordpolicy_api_tokens}}')->count();

    expect((int)$count)->toBe(0);
});

it('persists an expiry when expiresInDays is given', function() {
    $this->request->stubBodyParams = [
        'name' => 'Short-lived',
        'expiresInDays' => 7,
    ];

    runApiTokenAction('issue');

    $row = (new Query())
        ->from('{{%passwordpolicy_api_tokens}}')
        ->where(['name' => 'Short-lived'])
        ->one();

    expect($row['expiresAt'])->not->toBeNull();
});

// =============================================================================
// actionRevoke
// =============================================================================

it('revokes a token by id via JSON', function() {
    $issued = $this->plugin->getApiTokens()->issue('revoke-me');

    $this->request->stubBodyParams = ['id' => $issued['model']->id];
    $this->request->stubAcceptsJson = true;

    $response = runApiTokenAction('revoke');

    expect($response)->toBeInstanceOf(Response::class);

    $exists = (new Query())
        ->from('{{%passwordpolicy_api_tokens}}')
        ->where(['id' => $issued['model']->id])
        ->exists();

    expect($exists)->toBeFalse();
});

// =============================================================================
// Read-only mode
// =============================================================================

it('blocks issue in read-only mode', function() {
    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = false;

    $this->request->stubBodyParams = ['name' => 'blocked'];

    expect(fn() => runApiTokenAction('issue'))->toThrow(ForbiddenHttpException::class);
});

it('blocks revoke in read-only mode', function() {
    $issued = $this->plugin->getApiTokens()->issue('blocked-revoke');

    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = false;

    $this->request->stubBodyParams = ['id' => $issued['model']->id];
    $this->request->stubAcceptsJson = true;

    expect(fn() => runApiTokenAction('revoke'))->toThrow(ForbiddenHttpException::class);
});
