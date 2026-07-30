<?php
/**
 * Pest coverage for `NotificationTemplateController` defensive gates
 * landed in the v5.2.0 pre-tag fix-pack:
 *
 *  - `allowAdminChanges = false` → save / test-send both 403. The
 *    template-save and template-test surfaces follow the same UX
 *    intent as `SettingsController::actionSave` — when admin changes
 *    are off, the whole write/test surface is off, regardless of
 *    plugin permissions.
 *  - `actionTestSend()` failure response no longer leaks
 *    `$e->getMessage()` to the client — the JSON `message` field is
 *    the static "see the password-policy log for details" breadcrumb
 *    and the operator-facing error goes to the plugin log channel.
 *
 * The tests exercise the controller through `runAction()` so
 * `beforeAction()` fires the same way it would on a real HTTP request.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craft\web\Response;
use craftpulse\passwordpolicy\controllers\NotificationTemplateController;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;
use craftpulse\passwordpolicy\tests\Support\MailerFixture;
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

    // Pin a sendable mailer for the whole file: the test install carries no
    // `email` project config, so `Mailer::$from` is `['' => null]` and
    // composing any message throws inside Symfony Mime. The fixture also
    // snapshots the original state for `afterEach`.
    MailerFixture::pin();

    // Pro edition — the controller's beforeAction rejects Lite outright,
    // so every test runs at Pro+ to reach the inner guards.
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;
    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = true;

    $this->primarySiteId = Craft::$app->getSites()->getPrimarySite()->id;

    $this->request = new WebRequestStub();
    $this->request->stubIsCpRequest = true;
    Craft::$app->set('request', $this->request);
    Craft::$app->set('response', new Response());

    $this->userStub = new UserStub();
    Craft::$app->set('user', $this->userStub);

    $this->actingAdmin = UserFactory::admin();
    $this->userStub->setIdentity($this->actingAdmin);
});

afterEach(function() {
    $this->plugin->edition = $this->originalEdition;
    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = $this->originalAllowAdminChanges;
    Craft::$app->set('request', $this->originalRequest);
    Craft::$app->set('user', $this->originalUser);
    Craft::$app->set('response', $this->originalResponse);

    MailerFixture::restore();
});

// =============================================================================
// Helpers
// =============================================================================

function runNotificationTemplateAction(string $actionId): mixed
{
    $controller = new NotificationTemplateController(
        'notification-template',
        PasswordPolicy::$plugin,
    );

    return $controller->runAction($actionId);
}

// =============================================================================
// allowAdminChanges guard
// =============================================================================

it('actionSave rejects when allowAdminChanges is false', function() {
    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = false;

    $this->request->stubBodyParams = [
        'notificationKey' => 'expiry-reminder',
        'siteId' => $this->primarySiteId,
        'subject' => 'Updated subject',
        'body' => 'Updated body',
    ];

    expect(fn() => runNotificationTemplateAction('save'))
        ->toThrow(ForbiddenHttpException::class);
});

it('actionTestSend rejects when allowAdminChanges is false', function() {
    Craft::$app->getConfig()->getGeneral()->allowAdminChanges = false;

    $this->request->stubBodyParams = [
        'notificationKey' => 'expiry-reminder',
        'siteId' => $this->primarySiteId,
        'subject' => 'Some subject',
        'body' => 'Some body',
    ];
    $this->request->stubAcceptsJson = true;

    expect(fn() => runNotificationTemplateAction('test-send'))
        ->toThrow(ForbiddenHttpException::class);
});

// =============================================================================
// actionTestSend exception leak — JSON message is static
// =============================================================================

it('actionTestSend failure path returns a static message, not the exception', function() {
    // No template seeded for an arbitrary unknown site — but we need a
    // BadRequestHttpException for an unknown key, NOT a ForbiddenHttpException
    // for read-only mode. Use a real key but force a render failure by
    // pointing at a non-existent recipient context — the simplest path
    // here is to pin the admin user but break the mailer transport.
    //
    // Actually a cleaner approach: stand up a valid POST, but ensure
    // sending fails. We can null out the admin email so the controller
    // short-circuits on "no recipient" — that path returns a JSON failure
    // with a translated message that does NOT include $e->getMessage()
    // (no throwable in scope on that branch).
    //
    // To pin the post-throwable path (the actual leak fix), force the
    // mailer to throw. Simplest: use file transport and break the
    // `from` shape so Symfony Mime throws when composing.
    $this->request->stubBodyParams = [
        'notificationKey' => 'expiry-reminder',
        'siteId' => $this->primarySiteId,
        'subject' => 'Hi {{ user.friendlyName }}',
        'body' => 'Renders fine',
    ];
    $this->request->stubAcceptsJson = true;

    // Deliberately break the `from` the fixture pinned: Symfony Mime
    // requires a valid sender, so the compose path throws when the
    // test-send sets the recipient. `afterEach`'s `MailerFixture::restore()`
    // puts the sendable state back for the next test.
    Craft::$app->getMailer()->from = null;

    /** @var Response $response */
    $response = runNotificationTemplateAction('test-send');

    expect($response)->toBeInstanceOf(Response::class);

    // Yii's `asJson` populates `Response::$data` with the array; the
    // JSON encoding happens at the formatter stage. Inspect the raw
    // array so the test asserts on what the client would actually see.
    /** @var array<string, mixed> $data */
    $data = (array)$response->data;

    expect($data['success'] ?? null)->toBeFalse();

    $message = (string)($data['message'] ?? '');

    // The static breadcrumb must be present.
    expect($message)->toContain('See the password-policy log');

    // The exception detail (Symfony Mime error string) must NOT leak
    // through. Common phrases from the Symfony Mime stack are excluded
    // here defensively.
    expect($message)
        ->not->toContain('Symfony')
        ->and($message)->not->toContain('Mime')
        ->and($message)->not->toContain('From')
        ->and($message)->not->toContain('exception');
});

// =============================================================================
// actionTestSend per-key sample vars — devMode strict_variables
// =============================================================================
//
// Craft renders with `strict_variables` ON in devMode (the test config sets
// devMode = true). Pre-fix, actionTestSend built a fixed context
// (`user` + `daysUntilExpiry` + `siteName`) for EVERY key, so test-sending
// breach-detected / new-device-alert / admin-security-alert threw an
// "undefined variable" error on their key-specific tokens — the test-send
// always failed in dev. The per-key sample-var map resolves every key's
// tokens. These tests pin a successful test-send for the keys that carry
// distinct tokens.

it('test-sends the breach-detected template (detectedAt token) without a strict-variable error', function() {
    $this->request->stubBodyParams = [
        'notificationKey' => 'breach-detected',
        'siteId' => $this->primarySiteId,
    ];
    $this->request->stubAcceptsJson = true;

    /** @var Response $response */
    $response = runNotificationTemplateAction('test-send');
    $data = (array)$response->data;

    expect($data['success'] ?? null)->toBeTrue();
    // The rendered body excerpt actually substituted the per-key token —
    // it is not the literal `{{ detectedAt ... }}` token text.
    expect((string)($data['renderedBodyExcerpt'] ?? ''))->not->toContain('{{ detectedAt');
});

it('test-sends the new-device-alert template (deviceLabel / maskedIp tokens) without a strict-variable error', function() {
    $this->request->stubBodyParams = [
        'notificationKey' => 'new-device-alert',
        'siteId' => $this->primarySiteId,
    ];
    $this->request->stubAcceptsJson = true;

    /** @var Response $response */
    $response = runNotificationTemplateAction('test-send');
    $data = (array)$response->data;

    expect($data['success'] ?? null)->toBeTrue();
    // Sample device label resolved into the rendered body.
    expect((string)($data['renderedBodyExcerpt'] ?? ''))->toContain('Chrome on macOS');
});

it('test-sends the admin-security-alert template (event / context tokens, no user) without a strict-variable error', function() {
    $this->request->stubBodyParams = [
        'notificationKey' => 'admin-security-alert',
        'siteId' => $this->primarySiteId,
    ];
    $this->request->stubAcceptsJson = true;

    /** @var Response $response */
    $response = runNotificationTemplateAction('test-send');
    $data = (array)$response->data;

    expect($data['success'] ?? null)->toBeTrue();
    // The `event` token resolved in the rendered subject.
    expect((string)($data['renderedSubject'] ?? ''))->toContain('breach_detected');
});
