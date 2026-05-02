<?php
/**
 * Pest coverage for the FK CASCADE behavior on
 * `passwordpolicy_notification_templates.siteId` (T9.7 — second half).
 *
 * Schema invariant: `passwordpolicy_notification_templates` has a
 * foreign key on `siteId` referencing `Table::SITES.id` with
 * `ON DELETE CASCADE`.
 *
 * Important quirk codified here: Craft's `Sites::deleteSite()` is a
 * **soft delete** — it sets `dateDeleted` on the sites row rather
 * than physically deleting it (see
 * {@see \craft\services\Sites::handleDeletedSite()}, which calls
 * `softDelete()` rather than `delete()`). Soft deletion does NOT
 * fire a FK ON DELETE CASCADE because the parent row stays
 * physically present. The cascade only triggers when garbage
 * collection eventually hard-deletes expired soft-deleted rows
 * (`Gc::hardDelete()`), or in tests via a direct
 * `createCommand()->delete(Table::SITES, ...)`.
 *
 * These tests pin BOTH facets:
 *  - soft delete leaves the per-site notification rows intact
 *    (current production behavior — admins re-enabling a soft-
 *    deleted site recover their per-site templates)
 *  - hard delete cascades — proves the schema FK is actually wired
 *    correctly so the eventual GC sweep cleans up cleanly
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craft\db\Query;
use craft\db\Table;
use craft\models\Site;

// =============================================================================
// Helpers
// =============================================================================

/**
 * Builds and saves a non-primary site, returning the saved Site model.
 * Reuses the primary site's group and language; pins a unique handle.
 */
function createSiteForCascade(string $handle = ''): Site
{
    $sites = Craft::$app->getSites();
    $primary = $sites->getPrimarySite();
    $unique = $handle !== '' ? $handle : 'cas' . bin2hex(random_bytes(3));

    $site = new Site([
        'groupId' => $primary->groupId,
        'name' => "Cascade Test Site {$unique}",
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
// Soft delete — `Sites::deleteSiteById()` does NOT cascade
// =============================================================================

it('leaves notification template rows in place when a site is soft-deleted', function() {
    $site = createSiteForCascade();
    $siteId = $site->id;

    $countBefore = (new Query())
        ->from('{{%passwordpolicy_notification_templates}}')
        ->where(['siteId' => $siteId])
        ->count();

    expect($countBefore)->toBe('2'); // expiry-reminder + breach-detected

    expect(Craft::$app->getSites()->deleteSiteById($siteId))->toBeTrue();

    // The sites row stays physically present with dateDeleted set —
    // FK CASCADE doesn't fire because the parent isn't gone.
    $countAfter = (new Query())
        ->from('{{%passwordpolicy_notification_templates}}')
        ->where(['siteId' => $siteId])
        ->count();

    expect($countAfter)->toBe($countBefore);
});

it('does not touch other sites rows when one site is soft-deleted', function() {
    $primarySiteId = Craft::$app->getSites()->getPrimarySite()->id;
    $siteToDelete = createSiteForCascade('drop');
    $siteToKeep = createSiteForCascade('keep');

    $primaryRowsBefore = (new Query())
        ->from('{{%passwordpolicy_notification_templates}}')
        ->where(['siteId' => $primarySiteId])
        ->count();

    $keepRowsBefore = (new Query())
        ->from('{{%passwordpolicy_notification_templates}}')
        ->where(['siteId' => $siteToKeep->id])
        ->count();

    Craft::$app->getSites()->deleteSiteById($siteToDelete->id);

    $primaryRowsAfter = (new Query())
        ->from('{{%passwordpolicy_notification_templates}}')
        ->where(['siteId' => $primarySiteId])
        ->count();

    $keepRowsAfter = (new Query())
        ->from('{{%passwordpolicy_notification_templates}}')
        ->where(['siteId' => $siteToKeep->id])
        ->count();

    expect($primaryRowsAfter)->toBe($primaryRowsBefore)
        ->and($keepRowsAfter)->toBe($keepRowsBefore);
});

// =============================================================================
// Hard delete — direct DB delete fires the FK CASCADE
// =============================================================================

it('drops every notification template row when the sites row is hard-deleted', function() {
    // Hard-delete bypasses Craft's soft-delete path. This is what the
    // GC sweep does when a soft-deleted site ages out (see
    // `Gc::hardDelete()`). Pin that the FK CASCADE catches it.
    $site = createSiteForCascade();
    $siteId = $site->id;

    expect(
        (new Query())
            ->from('{{%passwordpolicy_notification_templates}}')
            ->where(['siteId' => $siteId])
            ->count()
    )->toBe('2');

    Craft::$app->getDb()->createCommand()
        ->delete(Table::SITES, ['id' => $siteId])
        ->execute();

    $countAfter = (new Query())
        ->from('{{%passwordpolicy_notification_templates}}')
        ->where(['siteId' => $siteId])
        ->count();

    expect($countAfter)->toBe('0');
});

it('preserves the primary site row set when a non-primary site is hard-deleted', function() {
    // Capture the FULL primary site row set, hard-delete a non-primary
    // site, and pin that the primary rows are byte-identical afterwards.
    $primarySiteId = Craft::$app->getSites()->getPrimarySite()->id;

    $primaryBefore = (new Query())
        ->select(['notificationKey', 'content', 'uid'])
        ->from('{{%passwordpolicy_notification_templates}}')
        ->where(['siteId' => $primarySiteId])
        ->orderBy(['notificationKey' => SORT_ASC])
        ->all();

    $site = createSiteForCascade();

    Craft::$app->getDb()->createCommand()
        ->delete(Table::SITES, ['id' => $site->id])
        ->execute();

    $primaryAfter = (new Query())
        ->select(['notificationKey', 'content', 'uid'])
        ->from('{{%passwordpolicy_notification_templates}}')
        ->where(['siteId' => $primarySiteId])
        ->orderBy(['notificationKey' => SORT_ASC])
        ->all();

    expect($primaryAfter)->toBe($primaryBefore);
});
