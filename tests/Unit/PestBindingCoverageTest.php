<?php
/**
 * Structural guard for `tests/Pest.php`'s `uses()` enumeration.
 *
 * Pest's `TestRepository::make()` throws `TestCaseAlreadyInUse` the moment
 * two `uses()` rules both resolve a test-case class for the same file, so
 * a blanket `uses(TestCase::class)->in('Integration')` can't coexist with
 * the narrower `Integration/Migrations` + `Integration/MultiSite` bindings.
 * The enumeration therefore has to be maintained by hand — and an omission
 * is silent: the bootstrap has already booted Craft, so an unbound file
 * runs against a bare `PHPUnit\Framework\TestCase`, passes, and COMMITS
 * every fixture it creates to `db_test`. That is exactly how
 * `Integration/Rules` leaked users, groups, policies and history rows on
 * every full-suite run.
 *
 * This test compares the paths listed in `tests/Pest.php` against the real
 * contents of `tests/Integration`, so the next folder someone adds fails
 * loudly instead of quietly losing its transaction wrap.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

// =============================================================================
// Helpers
// =============================================================================

/**
 * Returns every path string passed to a `uses(...)->in(...)` call in
 * `tests/Pest.php`, normalised to forward slashes and stripped of quotes.
 *
 * @return list<string>
 */
function pestBoundPaths(): array
{
    $source = file_get_contents(dirname(__DIR__) . '/Pest.php');

    expect($source)->toBeString();

    preg_match_all("/'(Integration[^']*)'/", (string)$source, $matches);

    return array_values(array_unique($matches[1]));
}

/**
 * Returns every path under `tests/Integration` that Pest needs a binding
 * for: each immediate subdirectory, plus each test file sitting directly
 * in `tests/Integration`.
 *
 * @return list<string>
 */
function pestPathsNeedingBinding(): array
{
    $root = dirname(__DIR__) . '/Integration';
    $paths = [];

    foreach (new DirectoryIterator($root) as $entry) {
        if ($entry->isDot()) {
            continue;
        }

        if ($entry->isDir()) {
            $paths[] = 'Integration/' . $entry->getFilename();
            continue;
        }

        if (str_ends_with($entry->getFilename(), 'Test.php')) {
            $paths[] = 'Integration/' . $entry->getFilename();
        }
    }

    sort($paths);

    return $paths;
}

// =============================================================================
// Every Integration path is bound to a TestCase
// =============================================================================

it('binds every tests/Integration folder and root-level test file in Pest.php', function() {
    $bound = pestBoundPaths();
    $needed = pestPathsNeedingBinding();

    // Sanity check the parser itself — an empty result would make the
    // assertion below vacuously true.
    expect($bound)->not->toBeEmpty();
    expect($needed)->not->toBeEmpty();

    $missing = array_values(array_diff($needed, $bound));

    expect($missing)->toBe(
        [],
        sprintf(
            'These tests/Integration paths have no uses() binding in tests/Pest.php, '
            . 'so their tests run without the DB transaction wrap and commit to db_test: %s',
            implode(', ', $missing),
        ),
    );
});

// =============================================================================
// No stale entries — a removed folder shouldn't linger in the enumeration
// =============================================================================

it('lists no tests/Integration path in Pest.php that no longer exists', function() {
    $stale = array_values(array_diff(pestBoundPaths(), pestPathsNeedingBinding()));

    expect($stale)->toBe(
        [],
        sprintf(
            'These paths are bound in tests/Pest.php but no longer exist under tests/: %s',
            implode(', ', $stale),
        ),
    );
});
