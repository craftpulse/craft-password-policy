<?php
/**
 * Pest coverage for the console `BlocklistController::actionImport`
 * edition gate landed in the v5.2.0 pre-tag fix-pack.
 *
 * The custom blocklist editor (and its console import surface) is a Pro
 * feature. The console surface can't tolerate exception-driven control
 * flow, so it gates with a graceful stderr + non-zero exit BEFORE
 * reaching the service-layer `addCustomWord()` throw:
 *
 *  - On Lite, `import` returns `ExitCode::UNSPECIFIED_ERROR` and writes a
 *    breadcrumb to stderr — it never touches the file or the table.
 *  - On Pro, the gate is transparent and the usual `--file` / file-read
 *    validation takes over.
 *
 * Stdout/stderr capture: `Yii\console\Controller::stdout/stderr` write
 * via `fwrite(\STDOUT|\STDERR, …)`, which PHP output buffering doesn't
 * catch. Tests use `CapturingBlocklistController` to buffer the output.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\tests\Support\CapturingBlocklistController;
use yii\console\ExitCode;

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->originalEdition = $this->plugin->edition;
});

afterEach(function() {
    $this->plugin->edition = $this->originalEdition;
});

// =============================================================================
// Helpers
// =============================================================================

function makeBlocklistConsole(): CapturingBlocklistController
{
    return new CapturingBlocklistController('blocklist', PasswordPolicy::$plugin);
}

// =============================================================================
// Lite — import is gated off with a non-zero exit, no exception
// =============================================================================

it('import returns a non-zero exit on Lite without reaching the file read', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_LITE;

    $controller = makeBlocklistConsole();
    // Point --file at a path that does NOT exist — if the edition gate
    // fails to short-circuit, the action would hit the IOERR branch and
    // return a different code. The gate must win first.
    $controller->file = '/nonexistent/blocklist-import.txt';

    $exitCode = $controller->runAction('import');

    expect($exitCode)->toBe(ExitCode::UNSPECIFIED_ERROR)
        ->and(implode('', $controller->stderrBuffer))->toContain('Pro edition');
});

// =============================================================================
// Pro — the gate is transparent; the file-validation path takes over
// =============================================================================

it('import passes the edition gate on Pro and reaches file validation', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;

    $controller = makeBlocklistConsole();
    $controller->file = '/nonexistent/blocklist-import.txt';

    // Past the edition gate, a missing --file path hits the IOERR branch
    // (ExitCode::IOERR), NOT the edition-gate exit code.
    $exitCode = $controller->runAction('import');

    expect($exitCode)->toBe(ExitCode::IOERR)
        ->and(implode('', $controller->stderrBuffer))->toContain('File not found');
});
