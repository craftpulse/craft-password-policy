<?php
/**
 * Structural guard: every queue job in `src/jobs/` must be enqueued from
 * somewhere in `src/`.
 *
 * `SiemForwardJob` and `WebhookForwardJob` both shipped complete, with
 * batchers, watermarks, retry policy, edition gates, and their own tests, and
 * nothing anywhere in `src/` ever pushed either one. On an Enterprise install
 * that meant audit rows were never forwarded to a SIEM and no webhook was ever
 * delivered, silently, with `forwardedAt` staying empty forever. Both were
 * found by accident during a documentation pass, which is not a system.
 *
 * This is the system. A job whose only references are its own declaration, a
 * docblock cross-reference, or its own log messages fails here.
 *
 * The predicate is deliberately narrow: a file outside `src/jobs/` must
 * contain `new <Job>(` or `<Job>::class`. A bare class-name search would have
 * passed on the two broken jobs, because `UnforwardedAuditRowBatcher`'s
 * docblock names `WebhookForwardJob` in a `{@see}` tag. Prose about a job is
 * not a trigger for it.
 *
 * A job that is only ever pushed from another job would fail here too. That is
 * intentional: today none are, and if one legitimately is, the exemption
 * should be an explicit decision rather than a silent gap.
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
 * Returns the short class name of every job in `src/jobs/`.
 *
 * @return list<string>
 */
function jobClassNames(): array
{
    $root = dirname(__DIR__, 2) . '/src/jobs';
    $names = [];

    foreach (new DirectoryIterator($root) as $entry) {
        if ($entry->isDot() || $entry->isDir()) {
            continue;
        }

        if (str_ends_with($entry->getFilename(), '.php')) {
            $names[] = basename($entry->getFilename(), '.php');
        }
    }

    sort($names);

    return $names;
}

/**
 * Returns the source of every PHP file under `src/` that does NOT live in
 * `src/jobs/`, keyed by path relative to `src/`.
 *
 * @return array<string, string>
 */
function nonJobSourceFiles(): array
{
    $root = dirname(__DIR__, 2) . '/src';
    $sources = [];

    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
    );

    foreach ($iterator as $file) {
        /** @var SplFileInfo $file */
        if ($file->getExtension() !== 'php') {
            continue;
        }

        $path = str_replace('\\', '/', substr($file->getPathname(), strlen($root) + 1));

        if (str_starts_with($path, 'jobs/')) {
            continue;
        }

        $sources[$path] = (string)file_get_contents($file->getPathname());
    }

    return $sources;
}

/**
 * Returns the paths under `src/` (excluding `src/jobs/`) that instantiate or
 * name the given job class in a way that can actually enqueue it.
 *
 * @param string $jobClass short class name
 * @return list<string>
 */
function enqueueSitesFor(string $jobClass): array
{
    $sites = [];

    foreach (nonJobSourceFiles() as $path => $source) {
        if (
            str_contains($source, "new {$jobClass}(")
            || str_contains($source, "{$jobClass}::class")
        ) {
            $sites[] = $path;
        }
    }

    return $sites;
}

// =============================================================================
// Every job has an enqueue site
// =============================================================================

it('enqueues every job in src/jobs from somewhere in src', function() {
    $jobs = jobClassNames();

    // Sanity check the scan itself — an empty list would make the loop below
    // vacuously true.
    expect($jobs)->not->toBeEmpty();
    expect(nonJobSourceFiles())->not->toBeEmpty();

    $unreachable = [];

    foreach ($jobs as $job) {
        if (enqueueSitesFor($job) === []) {
            $unreachable[] = $job;
        }
    }

    expect($unreachable)->toBe(
        [],
        sprintf(
            'These queue jobs are never instantiated outside src/jobs, so nothing in the '
            . 'plugin can ever run them: %s',
            implode(', ', $unreachable),
        ),
    );
});

// =============================================================================
// The two jobs that were unreachable are pinned by name
// =============================================================================

it('enqueues the SIEM and webhook forward sweeps from a console controller', function() {
    expect(enqueueSitesFor('SiemForwardJob'))
        ->toContain('console/controllers/SiemController.php');

    expect(enqueueSitesFor('WebhookForwardJob'))
        ->toContain('console/controllers/WebhookController.php');
});
