<?php
/**
 * Pest coverage for `DeviceTrackingService` — the Feature 1 known-devices
 * write + read path.
 *
 * Pins:
 *
 *  - First login from a fingerprint inserts a row and `recordLogin()`
 *    returns true; a repeat from the same UA + IP returns false and bumps
 *    `lastSeenAt` without inserting a second row.
 *  - The fingerprint is stable across calls (same UA + masked IP → same
 *    hash) and collapses addresses inside the same /24 (last-octet mask)
 *    onto one device.
 *  - `getDevicesForUser()` returns hydrated models, most-recently-seen
 *    first.
 *  - `pruneOldDevices()` deletes rows whose `lastSeenAt` aged past the TTL
 *    and keeps recent ones; a non-positive TTL is a no-op.
 *
 * Capture is universal — these run on whatever edition the playground is
 * at without elevation; the service has no edition gate.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use Carbon\Carbon;
use craft\db\Query;
use craftpulse\passwordpolicy\models\KnownDeviceModel;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;

const CHROME_MAC_UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

beforeEach(function() {
    $this->service = PasswordPolicy::$plugin->getDeviceTracking();
    $this->user = UserFactory::admin();

    Craft::$app->getDb()->createCommand()
        ->delete('{{%passwordpolicy_known_devices}}', ['userId' => $this->user->id])
        ->execute();
});

// =============================================================================
// Helpers
// =============================================================================

function deviceRows(int $userId): array
{
    return (new Query())
        ->from('{{%passwordpolicy_known_devices}}')
        ->where(['userId' => $userId])
        ->all();
}

function backdateDeviceRow(int $id, string $lastSeenAt): void
{
    Craft::$app->getDb()->createCommand()
        ->update(
            '{{%passwordpolicy_known_devices}}',
            ['lastSeenAt' => $lastSeenAt],
            ['id' => $id],
        )
        ->execute();
}

// =============================================================================
// recordLogin — new device inserts a row and returns true
// =============================================================================

it('returns true and inserts a row on the first login from a device', function() {
    $isNew = $this->service->recordLogin($this->user, CHROME_MAC_UA, '203.0.113.45', null);

    expect($isNew)->toBeTrue();

    $rows = deviceRows((int)$this->user->id);
    expect($rows)->toHaveCount(1);
    expect($rows[0]['deviceLabel'])->toBe('Chrome on macOS');
    // Never store the raw IP — only the masked form.
    expect($rows[0]['maskedIp'])->toBe('203.0.113.0');
    expect($rows[0]['maskedIp'])->not->toBe('203.0.113.45');
});

// =============================================================================
// recordLogin — known device returns false, bumps lastSeenAt, no new row
// =============================================================================

it('returns false and bumps lastSeenAt on a repeat login from the same device', function() {
    $this->service->recordLogin($this->user, CHROME_MAC_UA, '203.0.113.45', null);

    $firstRow = deviceRows((int)$this->user->id)[0];

    // Back-date both timestamps so the bump is observable against the
    // back-dated `lastSeenAt`.
    $backdated = Carbon::now('UTC')->subHours(2)->format('Y-m-d H:i:s');
    backdateDeviceRow((int)$firstRow['id'], $backdated);

    $isNew = $this->service->recordLogin($this->user, CHROME_MAC_UA, '203.0.113.45', null);

    expect($isNew)->toBeFalse();

    $rows = deviceRows((int)$this->user->id);
    expect($rows)->toHaveCount(1);
    expect($rows[0]['lastSeenAt'])->toBeGreaterThan($backdated);
});

// =============================================================================
// recordLogin — adjacent IPs in the same /24 collapse onto one device
// =============================================================================

it('treats two IPs in the same /24 as the same device (IP masked before hashing)', function() {
    $first = $this->service->recordLogin($this->user, CHROME_MAC_UA, '203.0.113.10', null);
    $second = $this->service->recordLogin($this->user, CHROME_MAC_UA, '203.0.113.99', null);

    expect($first)->toBeTrue();
    expect($second)->toBeFalse();
    expect(deviceRows((int)$this->user->id))->toHaveCount(1);
});

// =============================================================================
// fingerprint — stable + sensitive to UA / masked-IP changes
// =============================================================================

it('produces a stable fingerprint for the same UA + masked IP', function() {
    $a = $this->service->fingerprint(CHROME_MAC_UA, '203.0.113.0');
    $b = $this->service->fingerprint(CHROME_MAC_UA, '203.0.113.0');

    expect($a)->toBe($b);
    expect(strlen($a))->toBe(64);
});

it('produces a different fingerprint for a different user-agent', function() {
    $a = $this->service->fingerprint(CHROME_MAC_UA, '203.0.113.0');
    $b = $this->service->fingerprint('Firefox/121.0', '203.0.113.0');

    expect($a)->not->toBe($b);
});

// =============================================================================
// getDevicesForUser — hydrated models, most-recently-seen first
// =============================================================================

it('returns hydrated models most-recently-seen first', function() {
    $this->service->recordLogin($this->user, CHROME_MAC_UA, '203.0.113.45', null);
    $this->service->recordLogin($this->user, 'Firefox/121.0 (X11; Linux x86_64)', '198.51.100.7', null);

    // Back-date the Firefox row so the Chrome row is the most recent.
    $rows = deviceRows((int)$this->user->id);
    foreach ($rows as $row) {
        if ($row['deviceLabel'] === 'Firefox on Linux') {
            backdateDeviceRow(
                (int)$row['id'],
                Carbon::now('UTC')->subDays(3)->format('Y-m-d H:i:s'),
            );
        }
    }

    $devices = $this->service->getDevicesForUser((int)$this->user->id);

    expect($devices)->toHaveCount(2);
    expect($devices[0])->toBeInstanceOf(KnownDeviceModel::class);
    expect($devices[0]->deviceLabel)->toBe('Chrome on macOS');
    expect($devices[0]->lastSeenAt)->toBeInstanceOf(\DateTime::class);
});

// =============================================================================
// pruneOldDevices — deletes rows past the TTL, keeps recent ones
// =============================================================================

it('prunes devices last seen past the retention window and keeps recent ones', function() {
    $this->service->recordLogin($this->user, CHROME_MAC_UA, '203.0.113.45', null);
    $this->service->recordLogin($this->user, 'Firefox/121.0 (X11; Linux x86_64)', '198.51.100.7', null);

    // Age the Firefox row past a 30-day window.
    $rows = deviceRows((int)$this->user->id);
    foreach ($rows as $row) {
        if ($row['deviceLabel'] === 'Firefox on Linux') {
            backdateDeviceRow(
                (int)$row['id'],
                Carbon::now('UTC')->subDays(60)->format('Y-m-d H:i:s'),
            );
        }
    }

    $deleted = $this->service->pruneOldDevices(30);

    expect($deleted)->toBe(1);

    $surviving = deviceRows((int)$this->user->id);
    expect($surviving)->toHaveCount(1);
    expect($surviving[0]['deviceLabel'])->toBe('Chrome on macOS');
});

// =============================================================================
// pruneOldDevices — non-positive TTL is a no-op (never wipes the table)
// =============================================================================

it('does not prune when the retention window is non-positive', function() {
    $this->service->recordLogin($this->user, CHROME_MAC_UA, '203.0.113.45', null);

    expect($this->service->pruneOldDevices(0))->toBe(0);
    expect(deviceRows((int)$this->user->id))->toHaveCount(1);
});
