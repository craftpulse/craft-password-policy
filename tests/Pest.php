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

use craftpulse\passwordpolicy\tests\TestCase;

uses(TestCase::class)->in('Integration');
