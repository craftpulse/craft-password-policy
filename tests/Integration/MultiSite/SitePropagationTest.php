<?php
/**
 * Pest coverage for the multi-site notification template propagation
 * listener (T9.7) — `Sites::EVENT_AFTER_SAVE_SITE` with `isNew = true`.
 *
 * When an admin adds a new site, the plugin's listener calls
 * {@see NotificationTemplateService::propagateToSite()} to copy every
 * notification template row from the primary site onto the new site,
 * one row per (notificationKey, siteId) pair. This pins:
 *
 *  - the listener fires on `isNew = true` and not on update
 *  - propagation copies the JSON content verbatim from the primary site
 *  - propagation skips rows that already exist (idempotent)
 *  - propagation respects the primary site as the source of truth
 *
 * Multi-site tests opt out of the standard transaction wrap because
 * `Sites::saveSite()` writes to project config, which commits
 * immediately and bypasses DB transactions. The {@see MultiSiteTestCase}
 * base deletes every non-primary site in `tearDown` to reset the
 * fixture between tests.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craft\db\Query;
use craft\models\Site;
use craftpulse\passwordpolicy\data\EmailDefaults;
use craftpulse\passwordpolicy\PasswordPolicy;

// =============================================================================
// Helpers — local closures for site fabrication
// =============================================================================

/**
 * Builds and saves a non-primary site, returning the saved Site model.
 * Reuses the primary site's group and language so we don't have to
 * fabricate a SiteGroup; pins a unique handle so multiple sites in a
 * single test process don't collide.
 */
function createSite(string $handle = ''): Site
{
    $sites = Craft::$app->getSites();
    $primary = $sites->getPrimarySite();
    $unique = $handle !== '' ? $handle : 'test' . bin2hex(random_bytes(3));

    $site = new Site([
        'groupId' => $primary->groupId,
        'name' => "Test Site {$unique}",
        'handle' => $unique,
        'language' => $primary->language,
        'hasUrls' => true,
        'baseUrl' => "https://{$unique}.craftcms.test/",
        'primary' => false,
    ]);

    if (!$sites->saveSite($site)) {
        throw new RuntimeException(
            'Site save failed: ' . implode('; ', $site->getFirstErrors()),
        );
    }

    return $site;
}

// =============================================================================
// Listener fires on new-site save and propagates rows
// =============================================================================

it('propagates a row for every notification key when a new site is created', function() {
    $site = createSite();

    $expectedKeys = array_keys(EmailDefaults::all());

    foreach ($expectedKeys as $key) {
        $row = (new Query())
            ->from('{{%passwordpolicy_notification_templates}}')
            ->where(['notificationKey' => $key, 'siteId' => $site->id])
            ->one();

        expect($row)->not->toBeNull(
            "expected propagated row for {$key} on new site {$site->id}",
        );
    }
});

it('copies the JSON content from the primary site row', function() {
    $primarySiteId = Craft::$app->getSites()->getPrimarySite()->id;
    $site = createSite();

    foreach (array_keys(EmailDefaults::all()) as $key) {
        $primary = (new Query())
            ->select(['content'])
            ->from('{{%passwordpolicy_notification_templates}}')
            ->where(['notificationKey' => $key, 'siteId' => $primarySiteId])
            ->scalar();

        $copied = (new Query())
            ->select(['content'])
            ->from('{{%passwordpolicy_notification_templates}}')
            ->where(['notificationKey' => $key, 'siteId' => $site->id])
            ->scalar();

        expect($copied)->toBe($primary);
    }
});

it('writes a recent dateCreated on each propagated row', function() {
    $site = createSite();

    $rows = (new Query())
        ->from('{{%passwordpolicy_notification_templates}}')
        ->where(['siteId' => $site->id])
        ->all();

    expect($rows)->not->toBeEmpty();

    // `dateCreated` is a naive UTC string (F3 now writes it correctly via
    // `Db::prepareDateForDb()`). Parse with an explicit UTC zone rather
    // than the bare `strtotime()` this assertion used before F3 — on a
    // non-UTC container (this DDEV environment's ambient PHP timezone is
    // NOT UTC), a bare `strtotime()` would misinterpret the now-correct
    // stored value and fail this assertion against a correctly-written row.
    $now = (new \DateTime('now', new \DateTimeZone('UTC')))->getTimestamp();

    foreach ($rows as $row) {
        $createdAt = (new \DateTime($row['dateCreated'], new \DateTimeZone('UTC')))->getTimestamp();

        expect($createdAt)->toBeGreaterThan($now - 60)
            ->and($createdAt)->toBeLessThanOrEqual($now + 5);
    }
});

// =============================================================================
// F3 — propagateToSite writes dateCreated/dateUpdated through Db::prepareDateForDb()
// =============================================================================

it('writes propagated dateCreated/dateUpdated in UTC, not the PHP-local wall clock', function() {
    // Regression: `propagateToSite()` previously wrote a bare
    // `(new \DateTime())->format('Y-m-d H:i:s')` — PHP's ambient default
    // timezone — directly into the UTC-convention `dateCreated` /
    // `dateUpdated` columns via `createCommand()`, bypassing
    // `Db::prepareDateForDb()`. The fix routes the value through it.
    //
    // Force PHP into a non-UTC zone for the duration of the propagation so
    // a regression to the bare constructor produces a timestamp offset by
    // the zone's UTC offset (10h for Honolulu) — well outside the
    // tolerance window below.
    $originalTz = date_default_timezone_get();
    date_default_timezone_set('Pacific/Honolulu');

    try {
        $utcBefore = (new \DateTime('now', new \DateTimeZone('UTC')))->getTimestamp();

        $site = createSite();

        $utcAfter = (new \DateTime('now', new \DateTimeZone('UTC')))->getTimestamp();
    } finally {
        date_default_timezone_set($originalTz);
    }

    $rows = (new Query())
        ->select(['dateCreated', 'dateUpdated'])
        ->from('{{%passwordpolicy_notification_templates}}')
        ->where(['siteId' => $site->id])
        ->all();

    expect($rows)->not->toBeEmpty();

    foreach ($rows as $row) {
        foreach (['dateCreated', 'dateUpdated'] as $column) {
            $storedTs = (new \DateTime($row[$column], new \DateTimeZone('UTC')))->getTimestamp();

            expect($storedTs)->toBeGreaterThanOrEqual($utcBefore - 5)
                ->and($storedTs)->toBeLessThanOrEqual($utcAfter + 5);
        }
    }
});

it('writes a unique uid on each propagated row', function() {
    $primarySiteId = Craft::$app->getSites()->getPrimarySite()->id;
    $site = createSite();

    foreach (array_keys(EmailDefaults::all()) as $key) {
        $primaryUid = (new Query())
            ->select(['uid'])
            ->from('{{%passwordpolicy_notification_templates}}')
            ->where(['notificationKey' => $key, 'siteId' => $primarySiteId])
            ->scalar();

        $copiedUid = (new Query())
            ->select(['uid'])
            ->from('{{%passwordpolicy_notification_templates}}')
            ->where(['notificationKey' => $key, 'siteId' => $site->id])
            ->scalar();

        // Each row gets its own UID — never reuse the primary's UID
        // because that would violate row-level identity expectations.
        expect($copiedUid)->not->toBe($primaryUid)
            ->and($copiedUid)->not->toBeEmpty();
    }
});

// =============================================================================
// Idempotency + edge cases
// =============================================================================

it('does not duplicate rows when propagation is run twice for the same site', function() {
    $site = createSite();

    $countAfterFirst = (new Query())
        ->from('{{%passwordpolicy_notification_templates}}')
        ->where(['siteId' => $site->id])
        ->count();

    // Manually invoke the service a second time — simulates a listener
    // re-firing in production (e.g. project-config replay during deploy).
    PasswordPolicy::$plugin->getNotificationTemplates()->propagateToSite($site->id);

    $countAfterSecond = (new Query())
        ->from('{{%passwordpolicy_notification_templates}}')
        ->where(['siteId' => $site->id])
        ->count();

    expect($countAfterSecond)->toBe($countAfterFirst);
});

it('skips propagation when called against the primary site itself', function() {
    $primarySiteId = Craft::$app->getSites()->getPrimarySite()->id;

    $countBefore = (new Query())
        ->from('{{%passwordpolicy_notification_templates}}')
        ->where(['siteId' => $primarySiteId])
        ->count();

    PasswordPolicy::$plugin->getNotificationTemplates()->propagateToSite($primarySiteId);

    $countAfter = (new Query())
        ->from('{{%passwordpolicy_notification_templates}}')
        ->where(['siteId' => $primarySiteId])
        ->count();

    expect($countAfter)->toBe($countBefore);
});

it('does not touch existing rows when propagation runs for a new site', function() {
    $primarySiteId = Craft::$app->getSites()->getPrimarySite()->id;

    $primaryBefore = (new Query())
        ->select(['notificationKey', 'content', 'dateCreated', 'dateUpdated', 'uid'])
        ->from('{{%passwordpolicy_notification_templates}}')
        ->where(['siteId' => $primarySiteId])
        ->all();

    createSite();

    $primaryAfter = (new Query())
        ->select(['notificationKey', 'content', 'dateCreated', 'dateUpdated', 'uid'])
        ->from('{{%passwordpolicy_notification_templates}}')
        ->where(['siteId' => $primarySiteId])
        ->all();

    expect($primaryAfter)->toBe($primaryBefore);
});

// =============================================================================
// Listener registration sanity — listener doesn't fire on plain updates
// =============================================================================

it('does not duplicate rows when an existing site is updated', function() {
    // Listener early-returns when `isNew` is false. Even if a future
    // regression made it fire on every save, the propagation service
    // skips rows that already exist (idempotent), so the user-visible
    // contract is the same: an update never produces new rows for the
    // site. Pin the contract.
    $site = createSite();

    $countBeforeUpdate = (new Query())
        ->from('{{%passwordpolicy_notification_templates}}')
        ->where(['siteId' => $site->id])
        ->count();

    $site->name = $site->name . ' (updated)';

    expect(Craft::$app->getSites()->saveSite($site))->toBeTrue();

    $countAfterUpdate = (new Query())
        ->from('{{%passwordpolicy_notification_templates}}')
        ->where(['siteId' => $site->id])
        ->count();

    expect($countAfterUpdate)->toBe($countBeforeUpdate);
});

// =============================================================================
// Multi-site fan-out — multiple non-primary sites each get their own row set
// =============================================================================

it('propagates independently for two new sites in sequence', function() {
    $siteA = createSite();
    $siteB = createSite();

    $expectedRowsPerSite = count(EmailDefaults::all());

    foreach ([$siteA, $siteB] as $site) {
        $count = (new Query())
            ->from('{{%passwordpolicy_notification_templates}}')
            ->where(['siteId' => $site->id])
            ->count();

        expect($count)->toBe((string)$expectedRowsPerSite);
    }
});
