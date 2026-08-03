<?php
/**
 * Pest configuration.
 *
 * Wires the Integration suite to the plugin's TestCase (DB transaction
 * wrap, `Craft::$app` available). The Unit suite stays ungated — pure
 * unit tests don't need Craft boot and shouldn't pay the transaction
 * cost.
 *
 * Add global helpers here if a pattern repeats across multiple tests.
 * Factories belong in `tests/Support/Factories/`.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

use craftpulse\passwordpolicy\tests\Support\MigrationTestCase;
use craftpulse\passwordpolicy\tests\Support\MultiSiteTestCase;
use craftpulse\passwordpolicy\tests\TestCase;

// Pest's TestRepository iterates `uses()` rules in registration order and
// the first match to set the test case wins — any later match for the
// same file throws `TestCaseAlreadyInUse`. So we register the most-
// specific paths first, then the broader ones, and we DON'T register a
// blanket `Integration` rule because the per-subfolder bindings below
// cover every file. Migration tests run outside the standard transaction
// wrap (DDL is auto-committed in MySQL/MariaDB and can't roll back);
// multi-site tests run outside it (site saves trigger project-config
// writes that bypass DB transactions).
//
// `Integration/Permissions` holds the permission-grant migration coverage,
// and `Integration/Adoption` the Audit Kit module-adoption coverage. Both
// live outside `Integration/Migrations` deliberately: that folder is bound
// to the non-transactional `MigrationTestCase`, and Pest can't override a
// folder binding for a single file inside it. Neither migration touches a
// plugin table or any DDL — the permission rename moves `userpermissions*`
// rows and project-config group lists, the adoption migration moves
// `migrations` / `plugins` rows and one project-config entry — so both want
// the standard transaction wrap, not the schema drop/restore cycle.
//
// Because the enumeration below is hand-maintained, an unlisted folder
// silently falls back to a bare `PHPUnit\Framework\TestCase` — Craft is
// still booted by the bootstrap, so the tests pass, but nothing wraps
// them in a transaction and every write COMMITS to `db_test`.
// `tests/Unit/PestBindingCoverageTest.php` pins the enumeration against
// the real directory listing so the next folder can't be forgotten.
uses(MigrationTestCase::class)->in('Integration/Migrations');
uses(MultiSiteTestCase::class)->in('Integration/MultiSite');
uses(TestCase::class)->in(
    'Integration/Adoption',
    'Integration/Batchers',
    'Integration/ConditionRules',
    'Integration/Console',
    'Integration/Controllers',
    'Integration/Elements',
    'Integration/Events',
    'Integration/Helpers',
    'Integration/Integrations',
    'Integration/Jobs',
    'Integration/Models',
    'Integration/Permissions',
    'Integration/Records',
    'Integration/Rules',
    'Integration/Services',
    'Integration/TwigTags',
    'Integration/UserEditTab',
    'Integration/UserIndex',
    'Integration/Validators',
    'Integration/CraftBootstrapTest.php',
    'Integration/TemplateSyntaxTest.php',
);
