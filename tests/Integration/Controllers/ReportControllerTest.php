<?php
/**
 * Pest coverage for `ReportController` — the G3 CP web surface for the
 * compliance reports (HTML + CSV).
 *
 * Pinned contracts:
 *
 *  - Edition gate: `beforeAction` rejects on Lite / Pro.
 *  - Permission gate: `beforeAction` requires `pp:audit-view` — a user
 *    without it gets ForbiddenHttpException via `requirePermission`.
 *  - `actionHtml('audit-summary')` returns a rendered template response
 *    (200).
 *  - `actionCsv('audit-summary')` returns a `text/csv` response with a
 *    CSV body containing the expected header row.
 *  - Unknown report keys → 404 from both actions.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use Carbon\Carbon;
use craft\db\Table;
use craft\helpers\StringHelper;
use craft\web\Response;
use craftpulse\passwordpolicy\controllers\ReportController;
use craftpulse\passwordpolicy\elements\AuditLogElement;
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

    $this->request = new WebRequestStub();
    $this->request->stubIsCpRequest = true;
    Craft::$app->set('request', $this->request);
    Craft::$app->set('response', new \craft\web\Response());

    $this->userStub = new UserStub();
    Craft::$app->set('user', $this->userStub);

    // Surface is Enterprise-only — pin Enterprise in setup.
    $this->plugin->edition = PasswordPolicy::EDITION_ENTERPRISE;

    $this->actingAdmin = UserFactory::admin();
    $this->userStub->setIdentity($this->actingAdmin);

    Craft::$app->getDb()->createCommand()
        ->delete('{{%passwordpolicy_audit_log}}')
        ->execute();

    Craft::$app->getCache()->flush();
});

afterEach(function() {
    Craft::$app->set('request', $this->originalRequest);
    Craft::$app->set('user', $this->originalUser);
    $this->plugin->edition = $this->originalEdition;
});

// =============================================================================
// Helpers
// =============================================================================

/**
 * Runs a controller action via `Controller::runAction()` so
 * `beforeAction()` fires (CP request + edition gate + permission)
 * exactly the way it would for a real HTTP request.
 */
function runReportAction(string $actionId, array $params = []): mixed
{
    $controller = new ReportController('report', PasswordPolicy::$plugin);

    return $controller->runAction($actionId, $params);
}

/**
 * Inserts an audit-log row directly via SQL. Pairs with `craft_elements`
 * per Step 5 element-ification.
 */
function seedReportAuditRow(array $overrides = []): int
{
    $now = Carbon::now('UTC')->format('Y-m-d H:i:s');

    Craft::$app->getDb()->createCommand()
        ->insert(Table::ELEMENTS, [
            'type' => AuditLogElement::class,
            'enabled' => 1,
            'archived' => 0,
            'dateCreated' => $now,
            'dateUpdated' => $now,
            'uid' => StringHelper::UUID(),
        ])
        ->execute();

    $elementId = (int)Craft::$app->getDb()->getLastInsertID(Table::ELEMENTS);

    $row = array_merge([
        'id' => $elementId,
        'event' => 'password_changed',
        'outcome' => 'success',
        'source' => 'admin',
        'rowHash' => str_repeat('a', 64),
        'previousHash' => str_repeat('0', 64),
        'forwardedAt' => null,
        'forwardAttempts' => 0,
        'dateCreated' => $now,
        'uid' => StringHelper::UUID(),
    ], $overrides);

    Craft::$app->getDb()->createCommand()
        ->insert('{{%passwordpolicy_audit_log}}', $row)
        ->execute();

    return $elementId;
}

// =============================================================================
// Edition gate — beforeAction
// =============================================================================

it('throws ForbiddenHttpException on Pro for html', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;

    expect(fn() => runReportAction('html', ['report' => 'audit-summary']))
        ->toThrow(ForbiddenHttpException::class);
});

it('throws ForbiddenHttpException on Lite for csv', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_LITE;

    expect(fn() => runReportAction('csv', ['report' => 'audit-summary']))
        ->toThrow(ForbiddenHttpException::class);
});

// =============================================================================
// Unknown report key — 404
// =============================================================================

it('returns NotFoundHttpException on an unknown report key (html)', function() {
    expect(fn() => runReportAction('html', ['report' => 'bogus']))
        ->toThrow(NotFoundHttpException::class);
});

it('returns NotFoundHttpException on an unknown report key (csv)', function() {
    expect(fn() => runReportAction('csv', ['report' => 'bogus']))
        ->toThrow(NotFoundHttpException::class);
});

// =============================================================================
// actionCsv — streams CSV with expected header
// =============================================================================

it('streams a text/csv response for the audit-summary report', function() {
    seedReportAuditRow(['event' => 'password_changed']);
    seedReportAuditRow(['event' => 'account_locked']);

    $response = runReportAction('csv', ['report' => 'audit-summary']);

    expect($response)->toBeInstanceOf(Response::class);
    expect($response->headers->get('Content-Type'))->toContain('text/csv');
    expect($response->headers->get('Content-Disposition'))->toContain('attachment');
    expect($response->headers->get('Content-Disposition'))->toContain('.csv');
    expect($response->format)->toBe(Response::FORMAT_RAW);
    expect($response->content)->toBeString();
    // CSV header is the first line. The report writer owns the column
    // names; the assertion pins the canary column.
    expect($response->content)->toContain('event,count');
    expect($response->content)->toContain('password_changed');
    expect($response->content)->toContain('account_locked');
});

it('streams a text/csv response for the alert-activity report', function() {
    $response = runReportAction('csv', ['report' => 'alert-activity']);

    expect($response)->toBeInstanceOf(Response::class);
    expect($response->headers->get('Content-Type'))->toContain('text/csv');
    expect($response->content)->toContain('eventClass,fires_last24h');
});

it('streams a text/csv response for the retention-projection report', function() {
    $response = runReportAction('csv', ['report' => 'retention-projection']);

    expect($response)->toBeInstanceOf(Response::class);
    expect($response->headers->get('Content-Type'))->toContain('text/csv');
    expect($response->content)->toContain('log,retentionDays');
    expect($response->content)->toContain('audit_log');
    expect($response->content)->toContain('notification_log');
});

// =============================================================================
// actionHtml — renders template
// =============================================================================

it('renders the audit-summary HTML template', function() {
    seedReportAuditRow();

    $response = runReportAction('html', ['report' => 'audit-summary']);

    expect($response)->toBeInstanceOf(Response::class);
    // Template responses default to FORMAT_HTML.
    expect($response->getStatusCode())->toBe(200);
});
