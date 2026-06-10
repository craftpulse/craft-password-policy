<?php
/**
 * Pest coverage for `InactiveController::actionScan` — the Feature 5 (Pro)
 * inactive-account scan console surface. Pins:
 *
 *  - Edition gate: a sub-Pro install fails with
 *    `ExitCode::UNSPECIFIED_ERROR` + a "requires the Pro edition" stderr
 *    message — graceful skip, never a throw (console convention).
 *  - Disabled gate: on Pro but with the feature off, the command refuses
 *    with a non-zero exit + a clear message rather than enqueuing a no-op.
 *  - Happy path: on Pro + enabled, the command enqueues and returns OK.
 *  - Invalid `--action` is rejected with a non-zero exit.
 *
 * Stdout/stderr capture via `CapturingInactiveController` — see
 * `AuditExportConsoleTest` for the buffering rationale.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\tests\Support\CapturingInactiveController;
use yii\console\ExitCode;

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->originalEdition = $this->plugin->edition;
    $this->originalEnabled = $this->plugin->getSettings()->inactiveAccountsEnabled;
});

afterEach(function() {
    $this->plugin->edition = $this->originalEdition;
    $this->plugin->getSettings()->inactiveAccountsEnabled = $this->originalEnabled;
});

function newScanner(): CapturingInactiveController
{
    return new CapturingInactiveController('inactive', PasswordPolicy::$plugin);
}

// =============================================================================
// Edition gate — sub-Pro skips gracefully with a non-zero exit
// =============================================================================

it('refuses the scan on a sub-Pro edition with the Pro message', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_LITE;

    $scanner = newScanner();
    $exitCode = $scanner->runAction('scan');

    expect($exitCode)->toBe(ExitCode::UNSPECIFIED_ERROR);
    expect(implode('', $scanner->stderrBuffer))->toContain('Pro edition');
});

// =============================================================================
// Disabled gate — Pro but feature off
// =============================================================================

it('refuses the scan when the feature is disabled', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;
    $this->plugin->getSettings()->inactiveAccountsEnabled = false;

    $scanner = newScanner();
    $exitCode = $scanner->runAction('scan');

    expect($exitCode)->toBe(ExitCode::UNSPECIFIED_ERROR);
    expect(implode('', $scanner->stderrBuffer))->toContain('disabled');
});

// =============================================================================
// Happy path — Pro + enabled enqueues and returns OK
// =============================================================================

it('enqueues the scan on Pro when enabled', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;
    $this->plugin->getSettings()->inactiveAccountsEnabled = true;

    $scanner = newScanner();
    $exitCode = $scanner->runAction('scan');

    expect($exitCode)->toBe(ExitCode::OK);
    expect(implode('', $scanner->stdoutBuffer))->toContain('enqueued');
});

// =============================================================================
// Invalid --action override is rejected
// =============================================================================

it('rejects an invalid --mode override', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;
    $this->plugin->getSettings()->inactiveAccountsEnabled = true;

    $scanner = newScanner();
    $scanner->mode = 'delete';
    $exitCode = $scanner->runAction('scan');

    expect($exitCode)->toBe(ExitCode::UNSPECIFIED_ERROR);
    expect(implode('', $scanner->stderrBuffer))->toContain('Invalid --mode');
});
