<?php
/**
 * Pest coverage for G11 — Enterprise custom email template paths.
 *
 * The G11 surface adds a nullable `templatePath` key to the JSON `content`
 * shape of `passwordpolicy_notification_templates`. When set AND the
 * plugin is running the Enterprise edition,
 * `NotificationService::composeFromTemplate()` renders the email body
 * from the named site Twig template (`View::TEMPLATE_MODE_SITE`) instead
 * of the DB-stored `body` field. Subject ALWAYS renders from the DB
 * `subject` field — admins want to edit subject without touching a Twig
 * file. The Enterprise gate is enforced at the renderer (not at field
 * load) so a downgrade from Enterprise to Pro silently falls back to the
 * DB body without rewriting any rows.
 *
 * This file pins:
 *  - Enterprise + templatePath set → body comes from the Twig file.
 *  - Pro + templatePath set → body falls back to DB body (renderer gate).
 *  - Enterprise + templatePath null → body comes from DB body (no branch).
 *  - Pro POST with crafted `templatePath` → strip-on-save persists null.
 *  - Enterprise + templatePath pointing at a non-existent file → save
 *    fails validation with the expected error message.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craft\helpers\Json;
use craft\web\Response;
use craftpulse\passwordpolicy\controllers\NotificationTemplateController;
use craftpulse\passwordpolicy\enums\NotificationStatus;
use craftpulse\passwordpolicy\models\NotificationTemplateModel;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\records\NotificationLogRecord;
use craftpulse\passwordpolicy\records\NotificationTemplateRecord;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;
use craftpulse\passwordpolicy\tests\Support\MailerFixture;
use craftpulse\passwordpolicy\tests\Support\UserStub;
use craftpulse\passwordpolicy\tests\Support\WebRequestStub;

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->originalEdition = $this->plugin->edition;
    // Default to Pro so the dispatch-side helpers (which gate on Pro)
    // work. Tests flip to Enterprise as needed.
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;

    $this->primarySiteId = Craft::$app->getSites()->getPrimarySite()->id;
    $this->service = $this->plugin->getNotificationTemplates();

    // The renderer-side tests assert `status = sent` to prove the body came
    // from the right source, so the send itself has to succeed. The test
    // install has no `email` project config — the fixture supplies one.
    MailerFixture::pin();
});

afterEach(function() {
    MailerFixture::restore();

    $this->plugin->edition = $this->originalEdition;
});

// =============================================================================
// Renderer-side gate — Enterprise + templatePath → file renders the body
// =============================================================================

it('renders body from Twig file when templatePath is set on Enterprise', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_ENTERPRISE;
    setTemplatePathOnPrimary($this, 'expiry-reminder', '_pp-test/expiry-body.twig');

    $user = UserFactory::admin();
    $user->email = 'recipient@example.test';

    $this->plugin->getNotification()->sendPasswordExpiryReminder($user, 7);

    /** @var NotificationLogRecord|null $row */
    $row = NotificationLogRecord::find()
        ->where(['userId' => $user->id, 'notificationType' => 'expiry_reminder'])
        ->orderBy(['id' => SORT_DESC])
        ->one();

    expect($row)->not->toBeNull();
    expect($row->status)->toBe(NotificationStatus::Sent->value);
    // Body comes from the site Twig file — pin the fixture marker so a
    // future regression that silently re-routes to the DB body fails
    // loudly.
    expect($row->body)->toContain('[G11-FIXTURE]');
    expect($row->body)->toContain('daysUntilExpiry=7');
});

it('falls back to DB body when templatePath is set but plugin is Pro', function() {
    // Edition stays Pro (beforeEach default). The renderer-side gate
    // suppresses the Twig-file branch even though the DB row has a
    // templatePath — defense-in-depth against downgrade scenarios.
    setTemplatePathOnPrimary($this, 'expiry-reminder', '_pp-test/expiry-body.twig');

    $user = UserFactory::admin();
    $user->email = 'recipient@example.test';

    $this->plugin->getNotification()->sendPasswordExpiryReminder($user, 7);

    /** @var NotificationLogRecord|null $row */
    $row = NotificationLogRecord::find()
        ->where(['userId' => $user->id, 'notificationType' => 'expiry_reminder'])
        ->orderBy(['id' => SORT_DESC])
        ->one();

    expect($row)->not->toBeNull();
    expect($row->status)->toBe(NotificationStatus::Sent->value);
    // Fixture marker MUST NOT appear — the renderer fell back to the DB
    // body because the plugin isn't Enterprise.
    expect($row->body)->not->toContain('[G11-FIXTURE]');
});

it('falls back to DB body when templatePath is null on Enterprise', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_ENTERPRISE;
    // No templatePath set — Enterprise renderer still goes through the
    // DB body. The Enterprise gate only swaps when the path is non-null;
    // the canonical "I haven't configured a custom template" shape is
    // unchanged from Pro.

    $user = UserFactory::admin();
    $user->email = 'recipient@example.test';

    $this->plugin->getNotification()->sendPasswordExpiryReminder($user, 7);

    /** @var NotificationLogRecord|null $row */
    $row = NotificationLogRecord::find()
        ->where(['userId' => $user->id, 'notificationType' => 'expiry_reminder'])
        ->orderBy(['id' => SORT_DESC])
        ->one();

    expect($row)->not->toBeNull();
    expect($row->status)->toBe(NotificationStatus::Sent->value);
    expect($row->body)->not->toContain('[G11-FIXTURE]');
});

// =============================================================================
// Controller strip — Pro POST with crafted templatePath persists null
// =============================================================================

it('strips templatePath from POST when plugin is Pro', function() {
    // Edition stays Pro (beforeEach default).
    $admin = UserFactory::admin();

    // Stub web context: CP POST request, authenticated admin, and a
    // web Response component (the console Response that the bootstrap
    // pins doesn't accept the `format` setter that `asModelSuccess()`
    // uses).
    $originalRequest = Craft::$app->getRequest();
    $originalUser = Craft::$app->getUser();
    $originalResponse = Craft::$app->getResponse();

    $request = new WebRequestStub();
    $request->stubIsCpRequest = true;
    $request->stubBodyParams = [
        'notificationKey' => 'expiry-reminder',
        'siteId' => $this->primarySiteId,
        'subject' => 'Hi {{ user.friendlyName }}',
        'body' => 'Your password expires in {{ daysUntilExpiry }} days.',
        'templatePath' => '_pp-test/expiry-body.twig',
    ];
    Craft::$app->set('request', $request);
    Craft::$app->set('response', new Response());

    $userStub = new UserStub();
    $userStub->setIdentity($admin);
    Craft::$app->set('user', $userStub);

    try {
        $controller = new NotificationTemplateController(
            'notification-template',
            PasswordPolicy::$plugin,
        );
        $controller->runAction('save');
    } finally {
        Craft::$app->set('request', $originalRequest);
        Craft::$app->set('user', $originalUser);
        Craft::$app->set('response', $originalResponse);
    }

    // Re-load the record and inspect the JSON `content` column. The
    // crafted templatePath should NOT be persisted.
    /** @var NotificationTemplateRecord|null $record */
    $record = NotificationTemplateRecord::find()
        ->where([
            'notificationKey' => 'expiry-reminder',
            'siteId' => $this->primarySiteId,
        ])
        ->one();

    expect($record)->not->toBeNull();

    $decoded = decodeContent($record->content);

    expect($decoded)->toBeArray();
    // The key may be absent or present-and-null — either is a successful
    // strip. Re-loading via the model normalises to null.
    if (array_key_exists('templatePath', $decoded)) {
        expect($decoded['templatePath'])->toBeNull();
    }

    $reloaded = NotificationTemplateModel::fromRecord($record);
    expect($reloaded->templatePath)->toBeNull();
});

// =============================================================================
// Validator — missing Twig file fails validation
// =============================================================================

it('fails validation when templatePath does not resolve to a real Twig file', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_ENTERPRISE;

    $template = $this->service->getTemplate('expiry-reminder', $this->primarySiteId);
    expect($template)->not->toBeNull();

    $template->templatePath = '_pp-test/does-not-exist.twig';

    expect($template->validate())->toBeFalse();
    expect($template->getErrors('templatePath'))->not->toBeEmpty();

    $errors = $template->getErrors('templatePath');
    // Error message references the bad path so operators can self-diagnose.
    expect($errors[0])->toContain('_pp-test/does-not-exist.twig');
});

// =============================================================================
// Helpers
// =============================================================================

/**
 * Persists a `templatePath` value on the seeded primary-site row for
 * `$key`. Goes through the model save path so the JSON content shape is
 * exercised end-to-end (encode → DB → decode in the test assertions).
 *
 * Edition must be Enterprise when called for the renderer-side tests
 * (Pro POST would be stripped at the controller); test flips edition
 * before invoking. Validation rules ALSO run on save — the only Twig
 * path passed here points at a real fixture under
 * `tests/_craft/templates/_pp-test/`.
 */
function setTemplatePathOnPrimary(object $ctx, string $key, string $templatePath): void
{
    $template = $ctx->service->getTemplate($key, $ctx->primarySiteId);
    expect($template)->not->toBeNull();

    $template->templatePath = $templatePath;
    expect($ctx->service->saveTemplate($template))->toBeTrue();
}

/**
 * Decodes the JSON `content` column on a NotificationTemplateRecord,
 * peeling a double-encoded layer when the driver round-trips it as a
 * quoted JSON string. Mirrors `NotificationTemplateModel::fromRecord()`'s
 * decode loop.
 *
 * @return array<string, mixed>
 */
function decodeContent(mixed $rawContent): array
{
    $decoded = is_string($rawContent) ? Json::decodeIfJson($rawContent) : $rawContent;

    if (is_string($decoded)) {
        $decoded = Json::decodeIfJson($decoded);
    }

    return is_array($decoded) ? $decoded : [];
}
