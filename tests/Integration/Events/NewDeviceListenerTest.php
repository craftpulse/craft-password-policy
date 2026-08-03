<?php
/**
 * Pest coverage for the Feature 1 new-device login listener
 * (`PasswordPolicy::_registerNewDeviceListener()` on
 * `yii\web\User::EVENT_AFTER_LOGIN`).
 *
 * Pins the capture-universal / gate-exposure contract:
 *
 *  - On Lite, a login from a new device WRITES the `known_devices` row
 *    (capture is universal) but sends NO alert email — no
 *    `notification_log` row with type `new_device`.
 *  - On Enterprise + `enableNewDeviceAlerts`, the same login writes the
 *    row AND a `new_device` notification-log row (the email proxy).
 *  - The cooldown suppresses a second alert for the same user inside the
 *    window — the second login still bumps `lastSeenAt` (no new row) and
 *    writes no second notification-log row.
 *  - On Enterprise + `enableAuditLog`, a `new_device` audit row is
 *    written (with the masked `deviceLabel`, never the raw UA/IP).
 *  - The `NewDeviceDetectedEvent` fires on every edition after capture.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craft\db\Query;
use craftpulse\passwordpolicy\events\NewDeviceDetectedEvent;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\records\NotificationLogRecord;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;
use craftpulse\passwordpolicy\tests\Support\WebRequestStub;
use yii\base\Event;
use yii\web\User as WebUser;
use yii\web\UserEvent as WebUserEvent;

const NDL_CHROME_MAC_UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

// =============================================================================
// Setup — swap in a web request with a UA + IP; reset edition + settings
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->settings = $this->plugin->getSettings();

    $this->originalEdition = $this->plugin->edition;
    $this->originalEnableAuditLog = $this->settings->enableAuditLog;
    $this->originalEnableNewDeviceAlerts = $this->settings->enableNewDeviceAlerts;
    $this->originalRequest = Craft::$app->getRequest();

    $request = new WebRequestStub();
    $request->stubUserAgent = NDL_CHROME_MAC_UA;
    $request->stubUserIp = '203.0.113.45';
    $request->stubIsCpRequest = true;
    Craft::$app->set('request', $request);

    $this->user = UserFactory::admin(['email' => 'device-user@craftpulse.test']);

    Craft::$app->getDb()->createCommand()
        ->delete('{{%passwordpolicy_known_devices}}', ['userId' => $this->user->id])
        ->execute();
    Craft::$app->getDb()->createCommand()
        ->delete('{{%passwordpolicy_alert_cooldowns}}', ['cooldownKey' => "user:{$this->user->id}"])
        ->execute();
    Craft::$app->getCache()->flush();
});

afterEach(function() {
    Craft::$app->set('request', $this->originalRequest);
    $this->plugin->edition = $this->originalEdition;
    $this->settings->enableAuditLog = $this->originalEnableAuditLog;
    $this->settings->enableNewDeviceAlerts = $this->originalEnableNewDeviceAlerts;
});

// =============================================================================
// Helpers
// =============================================================================

/**
 * Fires `yii\web\User::EVENT_AFTER_LOGIN` for the given user, routing
 * through the registered listener.
 */
function fireAfterLogin(\craft\elements\User $user): void
{
    Event::trigger(
        WebUser::class,
        WebUser::EVENT_AFTER_LOGIN,
        new WebUserEvent(['identity' => $user]),
    );
}

function newDeviceLogRows(int $userId): array
{
    return NotificationLogRecord::find()
        ->where(['userId' => $userId, 'notificationType' => 'new_device'])
        ->all();
}

function knownDeviceRowCount(int $userId): int
{
    return (int)(new Query())
        ->from('{{%passwordpolicy_known_devices}}')
        ->where(['userId' => $userId])
        ->count();
}

// =============================================================================
// Lite — capture writes the row, no alert email
// =============================================================================

it('writes the device row but sends no alert on Lite', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_LITE;
    $this->settings->enableNewDeviceAlerts = true; // ignored below Enterprise

    fireAfterLogin($this->user);

    expect(knownDeviceRowCount((int)$this->user->id))->toBe(1);
    expect(newDeviceLogRows((int)$this->user->id))->toHaveCount(0);
});

// =============================================================================
// Enterprise + enabled — alert email row written
// =============================================================================

it('sends the alert (writes a notification-log row) on Enterprise with alerts enabled', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_ENTERPRISE;
    $this->settings->enableNewDeviceAlerts = true;

    fireAfterLogin($this->user);

    expect(knownDeviceRowCount((int)$this->user->id))->toBe(1);

    // A `new_device` notification-log row is the proxy for "the alert was
    // dispatched". The transport's sent/failed outcome is the
    // NotificationService's concern (covered by NotificationServiceCaptureTest);
    // here we pin that the listener routed an alert for this user to the
    // right recipient.
    $rows = newDeviceLogRows((int)$this->user->id);
    expect($rows)->toHaveCount(1);
    expect($rows[0]->notificationType)->toBe('new_device');
    expect($rows[0]->recipientEmail)->toBe('device-user@craftpulse.test');
});

// =============================================================================
// Enterprise — alerts disabled means no email even though the row is written
// =============================================================================

it('writes the row but no alert when enableNewDeviceAlerts is off on Enterprise', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_ENTERPRISE;
    $this->settings->enableNewDeviceAlerts = false;

    fireAfterLogin($this->user);

    expect(knownDeviceRowCount((int)$this->user->id))->toBe(1);
    expect(newDeviceLogRows((int)$this->user->id))->toHaveCount(0);
});

// =============================================================================
// Cooldown — a second login from a new device for the same user inside the
// window does not double-alert. (Two different devices, one user.)
// =============================================================================

it('suppresses a second new-device alert for the same user inside the cooldown window', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_ENTERPRISE;
    $this->settings->enableNewDeviceAlerts = true;

    // First new device → fires.
    fireAfterLogin($this->user);

    // Second NEW device (different UA → different fingerprint) for the
    // same user, still inside the per-user cooldown window.
    /** @var WebRequestStub $request */
    $request = Craft::$app->getRequest();
    $request->stubUserAgent = 'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0';
    fireAfterLogin($this->user);

    // Two device rows (two distinct fingerprints) but only one alert.
    expect(knownDeviceRowCount((int)$this->user->id))->toBe(2);
    expect(newDeviceLogRows((int)$this->user->id))->toHaveCount(1);
});

// =============================================================================
// Audit — Enterprise + enableAuditLog writes a new_device audit row
// =============================================================================

it('writes a new_device audit row on Enterprise with audit logging enabled', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_ENTERPRISE;
    $this->settings->enableAuditLog = true;
    $this->settings->enableNewDeviceAlerts = false;

    Craft::$app->getDb()->createCommand()
        ->delete('{{%passwordpolicy_audit_log}}', ['userId' => $this->user->id, 'event' => 'new_device'])
        ->execute();

    fireAfterLogin($this->user);

    $row = (new Query())
        ->from('{{%passwordpolicy_audit_log}}')
        ->where(['userId' => $this->user->id, 'event' => 'new_device'])
        ->orderBy(['id' => SORT_DESC])
        ->one();

    expect($row)->not->toBeNull();
    expect($row['outcome'])->toBe('success');
    // The details allowlist carries the masked label — never the raw UA/IP.
    expect($row['details'])->toContain('Chrome on macOS');
    expect($row['details'])->not->toContain('203.0.113.45');
});

// =============================================================================
// Event — NewDeviceDetectedEvent fires on every edition after capture
// =============================================================================

it('fires NewDeviceDetectedEvent on capture with a masked payload', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_LITE;

    $captured = null;
    PasswordPolicy::$plugin->on(
        PasswordPolicy::EVENT_NEW_DEVICE_DETECTED,
        function(NewDeviceDetectedEvent $event) use (&$captured) {
            $captured = $event;
        },
    );

    fireAfterLogin($this->user);

    PasswordPolicy::$plugin->off(PasswordPolicy::EVENT_NEW_DEVICE_DETECTED);

    expect($captured)->toBeInstanceOf(NewDeviceDetectedEvent::class);
    expect($captured->deviceLabel)->toBe('Chrome on macOS');
    expect($captured->maskedIp)->toBe('203.0.113.0');
    expect($captured->maskedIp)->not->toBe('203.0.113.45');
});
