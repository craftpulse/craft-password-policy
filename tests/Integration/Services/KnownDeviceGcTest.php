<?php
/**
 * Pest coverage for the Feature 1 known-device garbage-collection wiring
 * in `PasswordPolicy::runGc()`.
 *
 * Pins that `runGc()` aggregates a `knownDevices` count and that the count
 * reflects `DeviceTrackingService::pruneOldDevices($deviceRetentionDays)` —
 * rows last seen past the window are deleted, recent ones survive. This is
 * the regression guard for the `password-policy/gc/run` "Known devices: N"
 * stdout line.
 *
 * Universal capture — runs on whatever edition the playground is at; the
 * prune is edition-agnostic (device rows are written on every edition).
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use Carbon\Carbon;
use craft\db\Query;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;

const KDG_CHROME_MAC_UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->settings = $this->plugin->getSettings();
    $this->originalRetention = $this->settings->deviceRetentionDays;
    $this->user = UserFactory::admin();

    Craft::$app->getDb()->createCommand()
        ->delete('{{%passwordpolicy_known_devices}}', ['userId' => $this->user->id])
        ->execute();
});

afterEach(function() {
    $this->settings->deviceRetentionDays = $this->originalRetention;
});

// =============================================================================
// runGc aggregates a knownDevices count and prunes aged rows
// =============================================================================

it('prunes aged device rows through runGc and reports the count', function() {
    $this->settings->deviceRetentionDays = 30;
    $tracking = $this->plugin->getDeviceTracking();

    // Recent device — survives.
    $tracking->recordLogin($this->user, KDG_CHROME_MAC_UA, '203.0.113.45', null);
    // Aged device — pruned.
    $tracking->recordLogin($this->user, 'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0', '198.51.100.7', null);

    Craft::$app->getDb()->createCommand()
        ->update(
            '{{%passwordpolicy_known_devices}}',
            ['lastSeenAt' => Carbon::now('UTC')->subDays(90)->format('Y-m-d H:i:s')],
            ['userId' => $this->user->id, 'deviceLabel' => 'Firefox on Linux'],
        )
        ->execute();

    $results = $this->plugin->runGc();

    expect($results)->toHaveKey('knownDevices');
    expect($results['knownDevices'])->toBeGreaterThanOrEqual(1);

    $surviving = (new Query())
        ->from('{{%passwordpolicy_known_devices}}')
        ->where(['userId' => $this->user->id])
        ->all();

    expect($surviving)->toHaveCount(1);
    expect($surviving[0]['deviceLabel'])->toBe('Chrome on macOS');
});
