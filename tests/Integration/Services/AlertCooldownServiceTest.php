<?php
/**
 * Pest coverage for `AlertCooldownService` — the G7 dedup substrate.
 *
 * Pins the four contracts:
 *
 *  - `shouldFire()` returns `true` when no row matches inside the
 *    window AND records the fire on its way out (per § 5 of the
 *    Phase G plan, "records the fire on true return"). A second call
 *    inside the window returns `false`. Once the row's `firedAt` is
 *    back-dated past the window, the next call returns `true` again.
 *  - `recordFire()` writes a row + fires
 *    `EVENT_ALERT_COOLDOWN_FIRED`. Listener exceptions don't unwind
 *    the row.
 *  - `pruneOldEntries()` deletes rows older than the longer of (a)
 *    the longest configured cooldown across known event classes or
 *    (b) the 7-day floor (`PRUNE_FLOOR_SECONDS`). Recent rows are
 *    preserved. Returns the deleted count.
 *  - Cache layer: a `shouldFire()` hit primes the cache; a follow-up
 *    call within the cooldown window short-circuits via cache,
 *    bypassing the DB read.
 *
 * Capture is universal — these tests run on whatever edition the
 * playground is at without elevation, because `AlertCooldownService`
 * doesn't gate on edition (capture-on-every-edition per
 * `project_audit_capture_principle.md`).
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use Carbon\Carbon;
use craft\db\Query;
use craftpulse\passwordpolicy\events\AlertCooldownEvent;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\services\AlertCooldownService;
use yii\base\Event;

// =============================================================================
// Setup — wipe both surfaces (cache + table) so tests are isolated
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->service = $this->plugin->getAlertCooldown();

    Craft::$app->getDb()->createCommand()
        ->delete('{{%passwordpolicy_alert_cooldowns}}')
        ->execute();

    Craft::$app->getCache()->flush();
});

afterEach(function() {
    Event::off(AlertCooldownService::class, AlertCooldownService::EVENT_ALERT_COOLDOWN_FIRED);
});

// =============================================================================
// Helpers
// =============================================================================

/**
 * Back-dates a cooldown row's `firedAt` so a subsequent
 * `shouldFire()` sees it as outside the window.
 */
function backdateCooldownRow(int $id, string $firedAt): void
{
    Craft::$app->getDb()->createCommand()
        ->update(
            '{{%passwordpolicy_alert_cooldowns}}',
            ['firedAt' => $firedAt],
            ['id' => $id],
        )
        ->execute();
}

// =============================================================================
// shouldFire — first call returns true and inserts a row
// =============================================================================

it('returns true on first call for a fresh (eventClass, cooldownKey) and inserts a row', function() {
    $result = $this->service->shouldFire('test_event', 'key:1', 60);

    expect($result)->toBeTrue();

    $rows = (new Query())
        ->from('{{%passwordpolicy_alert_cooldowns}}')
        ->where(['eventClass' => 'test_event', 'cooldownKey' => 'key:1'])
        ->all();

    expect($rows)->toHaveCount(1);
});

// =============================================================================
// shouldFire — second call inside the window returns false
// =============================================================================

it('returns false on the second call inside the cooldown window', function() {
    $first = $this->service->shouldFire('test_event', 'key:1', 60);
    $second = $this->service->shouldFire('test_event', 'key:1', 60);

    expect($first)->toBeTrue();
    expect($second)->toBeFalse();

    // Still only one row — the second call short-circuited.
    $rows = (new Query())
        ->from('{{%passwordpolicy_alert_cooldowns}}')
        ->where(['eventClass' => 'test_event', 'cooldownKey' => 'key:1'])
        ->all();

    expect($rows)->toHaveCount(1);
});

// =============================================================================
// shouldFire — cache hit short-circuits without touching the DB
// =============================================================================

it('short-circuits via cache when a recent fire primed it', function() {
    // Prime the row + cache via a real shouldFire call.
    $this->service->shouldFire('test_event', 'key:1', 60);

    // Delete the row directly — bypasses the service. If shouldFire's
    // cache layer is working, the next call still returns false because
    // the cache says the cooldown is active. (If the cache weren't
    // consulted, the DB-only path would see no row and return true.)
    Craft::$app->getDb()->createCommand()
        ->delete('{{%passwordpolicy_alert_cooldowns}}')
        ->execute();

    $cached = $this->service->shouldFire('test_event', 'key:1', 60);

    expect($cached)->toBeFalse();
});

// =============================================================================
// shouldFire — back-dating the row past the window allows the next fire
// =============================================================================

it('returns true again after the cooldown window elapses', function() {
    $this->service->shouldFire('test_event', 'key:1', 60);

    $row = (new Query())
        ->from('{{%passwordpolicy_alert_cooldowns}}')
        ->where(['eventClass' => 'test_event', 'cooldownKey' => 'key:1'])
        ->one();

    expect($row)->not->toBeNull();

    // Back-date past the window. Flush cache so the cache-layer
    // shortcut doesn't mask the DB-level outcome.
    backdateCooldownRow(
        (int)$row['id'],
        Carbon::now('UTC')->subSeconds(120)->format('Y-m-d H:i:s'),
    );
    Craft::$app->getCache()->flush();

    $afterWindow = $this->service->shouldFire('test_event', 'key:1', 60);

    expect($afterWindow)->toBeTrue();

    // Two rows now — original (back-dated) + new fire.
    $rows = (new Query())
        ->from('{{%passwordpolicy_alert_cooldowns}}')
        ->where(['eventClass' => 'test_event', 'cooldownKey' => 'key:1'])
        ->all();

    expect($rows)->toHaveCount(2);
});

// =============================================================================
// shouldFire — different cooldownKeys don't suppress each other
// =============================================================================

it('does not suppress fires with the same eventClass but different cooldownKey', function() {
    $first = $this->service->shouldFire('test_event', 'key:1', 60);
    $second = $this->service->shouldFire('test_event', 'key:2', 60);

    expect($first)->toBeTrue();
    expect($second)->toBeTrue();

    $rows = (new Query())
        ->from('{{%passwordpolicy_alert_cooldowns}}')
        ->where(['eventClass' => 'test_event'])
        ->all();

    expect($rows)->toHaveCount(2);
});

// =============================================================================
// recordFire — fires EVENT_ALERT_COOLDOWN_FIRED with the populated payload
// =============================================================================

it('fires EVENT_ALERT_COOLDOWN_FIRED on recordFire with payload populated', function() {
    $captured = null;
    Event::on(
        AlertCooldownService::class,
        AlertCooldownService::EVENT_ALERT_COOLDOWN_FIRED,
        function(AlertCooldownEvent $event) use (&$captured) {
            $captured = $event;
        },
    );

    $this->service->recordFire('hibp_login_burst', 'prefix:ABCDE');

    expect($captured)->toBeInstanceOf(AlertCooldownEvent::class);
    expect($captured->eventClass)->toBe('hibp_login_burst');
    expect($captured->cooldownKey)->toBe('prefix:ABCDE');
    expect($captured->firedAt)->toBeInstanceOf(\DateTime::class);
});

// =============================================================================
// recordFire — listener exceptions don't unwind the row write
// =============================================================================

it('keeps the cooldown row even when a listener throws', function() {
    Event::on(
        AlertCooldownService::class,
        AlertCooldownService::EVENT_ALERT_COOLDOWN_FIRED,
        function(AlertCooldownEvent $event) {
            throw new \RuntimeException('listener exploded');
        },
    );

    // No exception should propagate — the listener throw is caught and
    // logged. The row is the load-bearing write; observer failures are
    // observability-only.
    $this->service->recordFire('test_event', 'key:1');

    $rows = (new Query())
        ->from('{{%passwordpolicy_alert_cooldowns}}')
        ->where(['eventClass' => 'test_event', 'cooldownKey' => 'key:1'])
        ->all();

    expect($rows)->toHaveCount(1);
});

// =============================================================================
// pruneOldEntries — deletes rows older than the prune threshold
// =============================================================================

it('prunes rows older than the prune threshold and keeps recent ones', function() {
    // Recent row — should survive.
    $this->service->shouldFire('test_event', 'recent', 60);

    // Old row — back-date past the 7-day floor.
    $this->service->shouldFire('test_event', 'old', 60);
    $oldRow = (new Query())
        ->from('{{%passwordpolicy_alert_cooldowns}}')
        ->where(['cooldownKey' => 'old'])
        ->one();
    backdateCooldownRow(
        (int)$oldRow['id'],
        Carbon::now('UTC')->subDays(30)->format('Y-m-d H:i:s'),
    );

    $deleted = $this->service->pruneOldEntries();

    expect($deleted)->toBe(1);

    $surviving = (new Query())
        ->from('{{%passwordpolicy_alert_cooldowns}}')
        ->all();

    expect($surviving)->toHaveCount(1);
    expect($surviving[0]['cooldownKey'])->toBe('recent');
});

// =============================================================================
// pruneOldEntries — idempotent, returns 0 on a second invocation
// =============================================================================

it('returns 0 on a second prune when nothing else aged out', function() {
    $this->service->shouldFire('test_event', 'old', 60);
    $oldRow = (new Query())
        ->from('{{%passwordpolicy_alert_cooldowns}}')
        ->where(['cooldownKey' => 'old'])
        ->one();
    backdateCooldownRow(
        (int)$oldRow['id'],
        Carbon::now('UTC')->subDays(30)->format('Y-m-d H:i:s'),
    );

    $first = $this->service->pruneOldEntries();
    $second = $this->service->pruneOldEntries();

    expect($first)->toBe(1);
    expect($second)->toBe(0);
});

// =============================================================================
// F2 regression sentinel — expiry_reminder fires once per window
// =============================================================================

it('suppresses a second expiry_reminder fire within the configured window', function() {
    // The migrated `_hasRecentNotification()` path uses
    // `expiryReminderDays * 86400` as the cooldown. With the default
    // (14 days), a second fire for the same userId is suppressed.
    $first = $this->service->shouldFire(
        'expiry_reminder',
        'user:9001',
        14 * 86400,
    );
    $second = $this->service->shouldFire(
        'expiry_reminder',
        'user:9001',
        14 * 86400,
    );

    expect($first)->toBeTrue();
    expect($second)->toBeFalse();
});

// =============================================================================
// F2 regression sentinel — admin alerts dedup per event within 5 minutes
// =============================================================================

it('suppresses a second admin_security_alert for the same event inside 5 minutes', function() {
    $first = $this->service->shouldFire(
        'admin_security_alert:hibp_breach_detected',
        'event:hibp_breach_detected',
        AlertCooldownService::DEFAULT_COOLDOWN_ADMIN_SECURITY_ALERT,
    );
    $second = $this->service->shouldFire(
        'admin_security_alert:hibp_breach_detected',
        'event:hibp_breach_detected',
        AlertCooldownService::DEFAULT_COOLDOWN_ADMIN_SECURITY_ALERT,
    );

    expect($first)->toBeTrue();
    expect($second)->toBeFalse();
});
