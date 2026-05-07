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
uses(MigrationTestCase::class)->in('Integration/Migrations');
uses(MultiSiteTestCase::class)->in('Integration/MultiSite');
uses(TestCase::class)->in(
    'Integration/ConditionRules',
    'Integration/Console',
    'Integration/Controllers',
    'Integration/Events',
    'Integration/Jobs',
    'Integration/Models',
    'Integration/Records',
    'Integration/Services',
    'Integration/TwigTags',
    'Integration/UserEditTab',
    'Integration/UserIndex',
    'Integration/Validators',
    'Integration/CraftBootstrapTest.php',
);
