<?php
/**
 * Pest coverage for `AuditController::actionExport` — the console
 * audit-log export stdout + `--queue` surface. Pins:
 *
 *  - Edition gate covers BOTH modes: a sub-Enterprise install fails
 *    with `ExitCode::UNSPECIFIED_ERROR` + a stderr message for stdout
 *    AND `--queue`. Previously only `--queue` gated; stdout leaked the
 *    table on Lite/Pro.
 *  - Byte-parity with the queued job: stdout CSV uses the job's static
 *    `csvHeader()` (12 columns) and `formatCsvRow()`; stdout JSONL uses
 *    `formatJsonlRow()`. Previously stdout emitted a divergent
 *    6-column CSV.
 *
 * Stdout/stderr capture: `CapturingAuditController` overrides
 * `stdout()`/`stderr()` to append into buffers — the production path
 * writes via `fwrite(\STDOUT|\STDERR, …)` which output buffering can't
 * intercept.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craftpulse\passwordpolicy\jobs\AuditExportJob;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\tests\Support\CapturingAuditController;
use yii\console\ExitCode;

// =============================================================================
// Setup — Enterprise + audit logging on, wipe rows
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->originalEdition = $this->plugin->edition;
    $this->originalEnableAuditLog = $this->plugin->getSettings()->enableAuditLog;

    $this->plugin->edition = PasswordPolicy::EDITION_ENTERPRISE;
    $this->plugin->getSettings()->enableAuditLog = true;

    Craft::$app->getDb()->createCommand()
        ->delete('{{%passwordpolicy_audit_log}}')
        ->execute();
});

afterEach(function() {
    $this->plugin->edition = $this->originalEdition;
    $this->plugin->getSettings()->enableAuditLog = $this->originalEnableAuditLog;
});

function newExporter(): CapturingAuditController
{
    return new CapturingAuditController('audit', PasswordPolicy::$plugin);
}

// =============================================================================
// Edition gate — stdout mode
// =============================================================================

it('refuses stdout export on a sub-Enterprise edition', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;
    $this->plugin->getAuditLog()->logEvent(userId: null, event: 'password_changed');

    $exporter = newExporter();
    $exporter->format = 'csv';

    $exitCode = $exporter->runAction('export');

    expect($exitCode)->toBe(ExitCode::UNSPECIFIED_ERROR);
    expect(implode('', $exporter->stderrBuffer))->toContain('Enterprise edition');
    // Nothing leaked to stdout.
    expect(implode('', $exporter->stdoutBuffer))->toBe('');
});

it('refuses --queue export on a sub-Enterprise edition', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_LITE;
    $this->plugin->getAuditLog()->logEvent(userId: null, event: 'password_changed');

    $exporter = newExporter();
    $exporter->format = 'csv';
    $exporter->queue = true;

    $exitCode = $exporter->runAction('export');

    expect($exitCode)->toBe(ExitCode::UNSPECIFIED_ERROR);
    expect(implode('', $exporter->stderrBuffer))->toContain('Enterprise edition');
});

// =============================================================================
// Byte-parity — stdout CSV matches the queued job's 12-column schema
// =============================================================================

it('emits the queued-job CSV header (12 columns) on stdout', function() {
    $this->plugin->getAuditLog()->logEvent(userId: null, event: 'password_changed');

    $exporter = newExporter();
    $exporter->format = 'csv';

    $exitCode = $exporter->runAction('export');

    expect($exitCode)->toBe(ExitCode::OK);

    $output = implode('', $exporter->stdoutBuffer);
    $lines = explode("\n", trim($output));

    // Header is the job's static 12-column header — not the legacy
    // 6-column stdout shape.
    expect($lines[0])->toBe(AuditExportJob::csvHeader());
    expect(substr_count($lines[0], ','))->toBe(11);

    // The data row is byte-identical to what the queued formatter
    // produces for the same row.
    $rows = (new \craft\db\Query())
        ->from('{{%passwordpolicy_audit_log}}')
        ->orderBy(['id' => SORT_ASC])
        ->all();

    expect($lines[1])->toBe(AuditExportJob::formatCsvRow($rows[0]));
});

// =============================================================================
// Byte-parity — stdout JSONL matches the queued job's formatJsonlRow
// =============================================================================

it('emits queued-job-identical JSONL on stdout', function() {
    $this->plugin->getAuditLog()->logEvent(userId: null, event: 'account_locked');

    $exporter = newExporter();
    $exporter->format = 'jsonl';

    $exitCode = $exporter->runAction('export');

    expect($exitCode)->toBe(ExitCode::OK);

    $output = implode('', $exporter->stdoutBuffer);
    $lines = array_values(array_filter(
        explode("\n", $output),
        fn(string $l): bool => $l !== '',
    ));

    expect($lines)->toHaveCount(1);

    $rows = (new \craft\db\Query())
        ->from('{{%passwordpolicy_audit_log}}')
        ->orderBy(['id' => SORT_ASC])
        ->all();

    expect($lines[0])->toBe(AuditExportJob::formatJsonlRow($rows[0]));
});

// =============================================================================
// Empty result emits nothing to stdout (still gated, still exit 0)
// =============================================================================

it('emits nothing to stdout for an empty export window on Enterprise', function() {
    $exporter = newExporter();
    $exporter->format = 'csv';

    $exitCode = $exporter->runAction('export');

    expect($exitCode)->toBe(ExitCode::OK);
    expect(implode('', $exporter->stdoutBuffer))->toBe('');
    expect(implode('', $exporter->stderrBuffer))->toContain('No entries found');
});
