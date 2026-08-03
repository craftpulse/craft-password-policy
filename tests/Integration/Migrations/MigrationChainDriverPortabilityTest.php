<?php
/**
 * Pest coverage for replaying the whole dated-migration chain on whatever engine
 * the suite is pointed at.
 *
 * `README.md` advertises PostgreSQL 13+, and two migrations aborted the entire
 * `migrate/all` run on that driver:
 *
 *  - `m260513_172440_ConvertPolicyToElement` threw on a non-MySQL driver ABOVE
 *    its two idempotency guards. On the real 5.1.2 to 5.2.0 path there is never
 *    any work for it to do, because the first dated migration
 *    (`m260429_224908_UpgradeTo520Schema`) runs `Install::safeUp()` and that
 *    creates `passwordpolicy_policies` already carrying the FK to
 *    `craft_elements.id`. So it threw on a no-op, `migrate/all` aborted, and the
 *    operator's update rolled back to the pre-update backup.
 *  - `m260513_142613_DeduplicateElementTableForeignKeys` enumerated foreign keys
 *    through `information_schema.referential_constraints.TABLE_NAME`, a MySQL
 *    extension absent from the ANSI view, in uppercase, against a catalog whose
 *    columns are genuinely lowercase. Its carefully written PostgreSQL branch
 *    was unreachable.
 *
 * Neither is visible on MySQL, which is the whole reason they shipped. These
 * tests therefore assert something MySQL satisfies trivially and PostgreSQL only
 * satisfies once both are fixed, and CI runs the file on both engines. On MySQL
 * they are a regression guard against the driver check drifting back above the
 * guards; on PostgreSQL they are the actual coverage.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craft\db\Table as CraftTable;
use craftpulse\passwordpolicy\migrations\m260513_172440_ConvertPolicyToElement;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\tests\Support\MigrationTestCase;

// =============================================================================
// Setup — tear the plugin schema back to its pre-5.2.0 state
// =============================================================================

beforeEach(function() {
    /** @var MigrationTestCase $this */
    $this->tearDownPluginSchema();
});

// =============================================================================
// Helpers
// =============================================================================

/**
 * Returns whether `$table` carries a foreign key from `id` to
 * `craft_elements.id`. Reads Yii's `TableSchema::foreignKeys`, which every
 * driver populates, so the check answers the same question on either engine.
 */
function chainTableIdIsElementBacked(string $table): bool
{
    $schema = Craft::$app->getDb()->getTableSchema($table, true);

    if ($schema === null) {
        return false;
    }

    $elementsTable = Craft::$app->getDb()->getSchema()->getRawTableName(CraftTable::ELEMENTS);

    foreach ($schema->foreignKeys as $reference) {
        $referencedTable = $reference[0] ?? null;
        unset($reference[0]);

        if ($referencedTable === $elementsTable && array_key_exists('id', $reference)) {
            return true;
        }
    }

    return false;
}

// =============================================================================
// The whole chain replays on this engine
// =============================================================================

it('replays every dated migration on the current driver', function() {
    $migrator = PasswordPolicy::$plugin->getMigrator();

    // The teardown wiped the history rows, so this is the full chain from
    // `m260429_224908_UpgradeTo520Schema` forward, in order, exactly as an
    // operator's `migrate/all` runs it.
    expect($migrator->getNewMigrations())->not->toBeEmpty();

    // `up()` returns null on success and throws (or returns false) when a
    // migration fails. On PostgreSQL this aborted partway before the fix.
    $migrator->up();

    expect($migrator->getNewMigrations())->toBeEmpty();

    // The chain's end state, not just its exit code: all three converted
    // tables element-backed, which is what `Install.php` promises a fresh
    // install and what an upgrade has to converge on.
    expect(chainTableIdIsElementBacked('{{%passwordpolicy_policies}}'))->toBeTrue()
        ->and(chainTableIdIsElementBacked('{{%passwordpolicy_audit_log}}'))->toBeTrue()
        ->and(chainTableIdIsElementBacked('{{%passwordpolicy_notification_log}}'))->toBeTrue();
});

// =============================================================================
// The policy conversion is a no-op on an already-converted table, on any driver
// =============================================================================

it('treats an already-converted policies table as a no-op rather than a driver error', function() {
    // Land the canonical schema the way the upgrade path does: the first dated
    // migration runs `Install::safeUp()`, which creates the policies table
    // already carrying its FK to `craft_elements.id`.
    PasswordPolicy::$plugin->getMigrator()->up();

    expect(chainTableIdIsElementBacked('{{%passwordpolicy_policies}}'))->toBeTrue();

    // Re-running the conversion against that shape must return cleanly on every
    // supported engine. Before the fix this threw on PostgreSQL, from a driver
    // check that sat above the guard which would have returned here.
    $migration = new m260513_172440_ConvertPolicyToElement();

    expect($migration->safeUp())->toBeTrue()
        // And it changed nothing: still exactly one FK from `id` to elements,
        // no duplicate left behind by a partial re-run.
        ->and(chainTableIdIsElementBacked('{{%passwordpolicy_policies}}'))->toBeTrue();
});

// =============================================================================
// The FK dedup enumerates constraints on any driver
// =============================================================================

it('leaves the canonical foreign keys in place after the dedup migration', function() {
    // The dedup drops every physical FK on the two element-backed log tables
    // and re-adds the canonical set. Its enumeration query is the part that was
    // MySQL-only, and a driver that can't enumerate can't re-add either: the
    // migration threw before reaching `addForeignKey()`, so the assertions
    // below are what catch it.
    PasswordPolicy::$plugin->getMigrator()->up();

    $auditKeys = Craft::$app->getDb()
        ->getTableSchema('{{%passwordpolicy_audit_log}}', true)
        ->foreignKeys;
    $notificationKeys = Craft::$app->getDb()
        ->getTableSchema('{{%passwordpolicy_notification_log}}', true)
        ->foreignKeys;

    // audit_log: id → elements, userId → users, changedByUserId → users.
    // notification_log: id → elements, userId → users, siteId → sites,
    // resentFromId → self.
    expect($auditKeys)->toHaveCount(3)
        ->and($notificationKeys)->toHaveCount(4);
});
