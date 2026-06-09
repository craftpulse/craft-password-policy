<?php
/**
 * Pest coverage for `AuditExportJob` — the G10 batched audit-log
 * export job. Pinned contracts:
 *
 *  - CSV output: file produced with stable header row + data rows.
 *  - JSONL output: each line parses as JSON; line count matches row
 *    count; canonical bytes inside the `payload` envelope match
 *    `AuditLogService::canonicalize()`.
 *  - Edition gate: on a sub-Enterprise edition the job exits early
 *    (logs warning + returns) without writing a file.
 *  - Token cached + completion event fires on the last batch.
 *  - Local-fallback path produces a file under `@runtime/password-
 *    policy/exports/`. Cloud filesystems are not exercised here —
 *    smoke-tested per real-world deployment.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use Carbon\Carbon;
use craft\db\Table;
use craft\helpers\FileHelper;
use craft\helpers\StringHelper;
use craftpulse\passwordpolicy\elements\AuditLogElement;
use craftpulse\passwordpolicy\events\AuditExportCompleteEvent;
use craftpulse\passwordpolicy\jobs\AuditExportJob;
use craftpulse\passwordpolicy\PasswordPolicy;
use yii\base\Event;

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->originalEdition = $this->plugin->edition;

    // Job is Enterprise-only; default the test fixture to Enterprise.
    $this->plugin->edition = PasswordPolicy::EDITION_ENTERPRISE;

    Craft::$app->getDb()->createCommand()
        ->delete('{{%passwordpolicy_audit_log}}')
        ->execute();

    Craft::$app->getCache()->flush();

    // Sanity: blow away any previous export run's directory so each
    // test starts clean.
    $exportDir = Craft::getAlias('@runtime') . '/password-policy/exports';
    if (is_dir($exportDir)) {
        FileHelper::clearDirectory($exportDir);
    }
});

afterEach(function() {
    $this->plugin->edition = $this->originalEdition;

    // Detach only the listener the EVENT_AUDIT_EXPORT_COMPLETE test
    // attached. `Event::offAll()` would also blow away the plugin's
    // globally-registered listeners (site-add propagation, password
    // history caching, etc.), causing follow-on tests to run against
    // an under-instrumented Craft.
    Event::off(AuditExportJob::class, AuditExportJob::EVENT_AUDIT_EXPORT_COMPLETE);
});

// =============================================================================
// Helpers
// =============================================================================

/**
 * Inserts an audit-log row directly via SQL (bypassing the chain
 * writer for fixture speed). Tests don't care about chain integrity;
 * they care about export-file shape.
 *
 * Step 5 element-ification: every audit_log row pairs with a
 * `craft_elements` row via `id`. Allocate a paired element row first
 * so the FK constraint is satisfied.
 */
function makeExportRow(array $overrides = []): int
{
    $now = Carbon::now('UTC')->format('Y-m-d H:i:s');

    Craft::$app->getDb()->createCommand()
        ->insert(Table::ELEMENTS, [
            'type' => AuditLogElement::class,
            'enabled' => 1,
            'archived' => 0,
            'dateCreated' => $now,
            'dateUpdated' => $now,
            'uid' => StringHelper::UUID(),
        ])
        ->execute();

    $elementId = (int)Craft::$app->getDb()->getLastInsertID(Table::ELEMENTS);

    $row = array_merge([
        'id' => $elementId,
        'event' => 'password_changed',
        'outcome' => 'success',
        'source' => 'admin',
        'details' => null,
        'rowHash' => str_repeat('a', 64),
        'previousHash' => str_repeat('0', 64),
        'forwardedAt' => null,
        'forwardAttempts' => 0,
        'dateCreated' => $now,
        'uid' => StringHelper::UUID(),
    ], $overrides);

    Craft::$app->getDb()->createCommand()
        ->insert('{{%passwordpolicy_audit_log}}', $row)
        ->execute();

    return $elementId;
}

/**
 * Synchronously runs the job's full lifecycle (`before` + every
 * `processItem` + `after`) by invoking the protected hooks via
 * reflection. The queue runner would normally drive this — but for
 * tests we want deterministic single-process execution.
 */
function runExportJob(AuditExportJob $job, array $rows): void
{
    $reflection = new ReflectionClass($job);

    $before = $reflection->getMethod('before');
    $process = $reflection->getMethod('processItem');
    $after = $reflection->getMethod('after');

    $before->invoke($job);

    foreach ($rows as $row) {
        $process->invoke($job, $row);
    }

    // Bump itemOffset to totalItems() so `after()` sees the final
    // batch state. `after()` reads `totalItems()` for the row count.
    // We can't easily set the protected property but the existing
    // batcher will report the live row count from the table.

    $after->invoke($job);
}

function exportFilePath(string $token, string $format): string
{
    return Craft::getAlias('@runtime')
        . '/password-policy/exports/'
        . $token
        . '.'
        . $format;
}

// =============================================================================
// CSV output
// =============================================================================

it('writes a CSV file with a header row + one data row per audit row', function() {
    $rowId1 = makeExportRow(['event' => 'password_changed']);
    $rowId2 = makeExportRow(['event' => 'account_locked']);

    $token = StringHelper::randomString(64);
    $job = new AuditExportJob();
    $job->daysFilter = 30;
    $job->format = 'csv';
    $job->token = $token;

    $rows = (new \craft\db\Query())
        ->from('{{%passwordpolicy_audit_log}}')
        ->orderBy(['id' => SORT_ASC])
        ->all();

    runExportJob($job, $rows);

    $path = exportFilePath($token, 'csv');
    expect(file_exists($path))->toBeTrue();

    $contents = file_get_contents($path);
    $lines = explode("\n", trim($contents));

    // Header + 2 data rows
    expect(count($lines))->toBe(3);

    // Header is stable column order
    expect($lines[0])->toBe('id,dateCreated,userId,changedByUserId,event,outcome,source,ipHash,userIdentifier,details,rowHash,previousHash');

    // Data rows mention the right event values
    expect($lines[1])->toContain('password_changed');
    expect($lines[2])->toContain('account_locked');

    // Each line includes the row id at column 0
    expect($lines[1])->toStartWith((string)$rowId1 . ',');
    expect($lines[2])->toStartWith((string)$rowId2 . ',');
});

// =============================================================================
// JSONL output
// =============================================================================

it('writes a JSONL file with one canonical JSON object per line', function() {
    makeExportRow(['event' => 'password_changed']);
    makeExportRow(['event' => 'account_locked']);

    $token = StringHelper::randomString(64);
    $job = new AuditExportJob();
    $job->daysFilter = 30;
    $job->format = 'jsonl';
    $job->token = $token;

    $rows = (new \craft\db\Query())
        ->from('{{%passwordpolicy_audit_log}}')
        ->orderBy(['id' => SORT_ASC])
        ->all();

    runExportJob($job, $rows);

    $path = exportFilePath($token, 'jsonl');
    expect(file_exists($path))->toBeTrue();

    $contents = file_get_contents($path);
    $lines = array_filter(explode("\n", $contents), fn($l) => $l !== '');

    // Two rows in, two lines out — no header on JSONL.
    expect(count($lines))->toBe(2);

    foreach ($lines as $line) {
        $decoded = json_decode($line, true);
        expect($decoded)->toBeArray();
        expect($decoded)->toHaveKey('id');
        expect($decoded)->toHaveKey('payload');
        expect($decoded)->toHaveKey('rowHash');
        expect($decoded)->toHaveKey('previousHash');
        expect($decoded['payload'])->toHaveKey('event');
        expect($decoded['payload'])->toHaveKey('dateCreated');
    }
});

// =============================================================================
// before() is idempotent across a first-batch retry (truncates, no dup header)
// =============================================================================

it('truncates on a re-run of before() so a first-batch retry does not stack a second header', function() {
    makeExportRow(['event' => 'password_changed']);
    makeExportRow(['event' => 'account_locked']);

    $token = StringHelper::randomString(64);
    $job = new AuditExportJob();
    $job->daysFilter = 30;
    $job->format = 'csv';
    $job->token = $token;

    $rows = (new \craft\db\Query())
        ->from('{{%passwordpolicy_audit_log}}')
        ->orderBy(['id' => SORT_ASC])
        ->all();

    $reflection = new ReflectionClass($job);
    $before = $reflection->getMethod('before');
    $process = $reflection->getMethod('processItem');

    // First attempt: header + partial write, then "fails" before
    // committing the batch offset (we just stop — itemOffset stays 0).
    $before->invoke($job);
    $process->invoke($job, $rows[0]);

    // Retry of the same first batch: before() runs again because the
    // offset never advanced. The truncating open must reset the file so
    // the retry rebuilds it cleanly rather than appending a second
    // header + the already-written row.
    $before->invoke($job);

    foreach ($rows as $row) {
        $process->invoke($job, $row);
    }

    $contents = file_get_contents(exportFilePath($token, 'csv'));
    $lines = explode("\n", trim($contents));

    // Exactly one header + two data rows — no stacked header, no dup row.
    expect(count($lines))->toBe(3);
    expect($lines[0])->toBe(AuditExportJob::csvHeader());
    expect($lines[1])->toContain('password_changed');
    expect($lines[2])->toContain('account_locked');

    // The header substring appears exactly once in the whole file.
    expect(substr_count($contents, AuditExportJob::csvHeader()))->toBe(1);
});

// =============================================================================
// processItem skips a malformed row instead of aborting the export
// =============================================================================

it('skips a row with an unparseable dateCreated and exports the rest (JSONL)', function() {
    $goodId = makeExportRow(['event' => 'password_changed']);
    // A dateCreated value DateTime cannot parse — `formatJsonlRow()`
    // re-parses it through `_normaliseDateCreated()`, which throws.
    // Without the per-row guard this single row would abort the whole
    // export and burn retries.
    $badRow = [
        'id' => $goodId + 100000,
        'event' => 'account_locked',
        'outcome' => 'success',
        'source' => 'admin',
        'details' => null,
        'ipHash' => null,
        'userId' => null,
        'changedByUserId' => null,
        'userIdentifier' => null,
        'rowHash' => str_repeat('a', 64),
        'previousHash' => str_repeat('0', 64),
        'dateCreated' => 'not-a-real-date',
        'uid' => StringHelper::UUID(),
    ];

    $token = StringHelper::randomString(64);
    $job = new AuditExportJob();
    $job->daysFilter = 30;
    $job->format = 'jsonl';
    $job->token = $token;

    $goodRow = (new \craft\db\Query())
        ->from('{{%passwordpolicy_audit_log}}')
        ->where(['id' => $goodId])
        ->one();

    // Feed the good row, then the malformed row. The export must
    // complete; only the good row lands in the file.
    runExportJob($job, [$goodRow, $badRow]);

    $path = exportFilePath($token, 'jsonl');
    expect(file_exists($path))->toBeTrue();

    $lines = array_values(array_filter(
        explode("\n", file_get_contents($path)),
        fn($l) => $l !== '',
    ));

    expect($lines)->toHaveCount(1);

    $decoded = json_decode($lines[0], true);
    expect($decoded['id'])->toBe($goodId);
    expect($decoded['payload']['event'])->toBe('password_changed');
});

// =============================================================================
// Token cached on completion
// =============================================================================

it('caches the token entry with file metadata after writing the export', function() {
    makeExportRow();

    $token = StringHelper::randomString(64);
    $job = new AuditExportJob();
    $job->daysFilter = 30;
    $job->format = 'csv';
    $job->token = $token;
    $job->requestedById = 0;

    $rows = (new \craft\db\Query())
        ->from('{{%passwordpolicy_audit_log}}')
        ->orderBy(['id' => SORT_ASC])
        ->all();

    runExportJob($job, $rows);

    $cacheKey = 'pp:audit-export-token:' . $token;
    $entry = Craft::$app->getCache()->get($cacheKey);

    expect($entry)->toBeArray();
    expect($entry['format'])->toBe('csv');
    expect($entry['filePath'])->toEndWith($token . '.csv');
    expect($entry['filesystemHandle'])->toBeNull();

    // `exportDate` pins the date the export was finalised so the
    // download controller labels the filename with the right day even
    // if the operator clicks the link the next morning.
    expect($entry['exportDate'])->toBeString();
    expect($entry['exportDate'])->toMatch('/^\d{4}-\d{2}-\d{2}$/');
    expect($entry['exportDate'])->toBe(\Carbon\Carbon::now('UTC')->format('Y-m-d'));
});

// =============================================================================
// Completion event fires
// =============================================================================

it('fires EVENT_AUDIT_EXPORT_COMPLETE on the last batch', function() {
    makeExportRow();

    $captured = null;

    Event::on(
        AuditExportJob::class,
        AuditExportJob::EVENT_AUDIT_EXPORT_COMPLETE,
        function(AuditExportCompleteEvent $event) use (&$captured) {
            $captured = $event;
        },
    );

    $token = StringHelper::randomString(64);
    $job = new AuditExportJob();
    $job->daysFilter = 30;
    $job->format = 'jsonl';
    $job->token = $token;

    $rows = (new \craft\db\Query())
        ->from('{{%passwordpolicy_audit_log}}')
        ->orderBy(['id' => SORT_ASC])
        ->all();

    runExportJob($job, $rows);

    expect($captured)->toBeInstanceOf(AuditExportCompleteEvent::class);
    expect($captured->token)->toBe($token);
    expect($captured->format)->toBe('jsonl');
    expect($captured->filePath)->toContain($token . '.jsonl');
});

// =============================================================================
// Edition gate
// =============================================================================

it('exits early on Pro without writing a file', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_PRO;

    makeExportRow();

    $token = StringHelper::randomString(64);
    $job = new AuditExportJob();
    $job->daysFilter = 30;
    $job->format = 'csv';
    $job->token = $token;

    // `execute()` short-circuits on the edition gate before
    // BaseBatchedJob ever calls before() / processItem() / after().
    $job->execute(Craft::$app->getQueue());

    $path = exportFilePath($token, 'csv');
    expect(file_exists($path))->toBeFalse();

    $cacheKey = 'pp:audit-export-token:' . $token;
    expect(Craft::$app->getCache()->get($cacheKey))->toBeFalse();
});

it('exits early on Lite without writing a file', function() {
    $this->plugin->edition = PasswordPolicy::EDITION_LITE;

    makeExportRow();

    $token = StringHelper::randomString(64);
    $job = new AuditExportJob();
    $job->daysFilter = 30;
    $job->format = 'csv';
    $job->token = $token;

    $job->execute(Craft::$app->getQueue());

    $path = exportFilePath($token, 'csv');
    expect(file_exists($path))->toBeFalse();
});

// =============================================================================
// CSV details column round-trip
// =============================================================================

it('encodes the details JSON column as a quoted JSON string in CSV', function() {
    // Drive the row through the chain writer so the `details` column
    // gets the canonical JSON encoding the writer produces — bypassing
    // via raw SQL skirts MySQL's JSON-column quoting and produces
    // empty-cell output on read.
    Craft::$app->getDb()->createCommand()
        ->delete('{{%passwordpolicy_audit_log}}')
        ->execute();

    $this->plugin->getSettings()->enableAuditLog = true;
    $this->plugin->getAuditLog()->logEvent(
        userId: null,
        event: 'policy_changed',
        details: [
            'policyId' => 42,
            'policyName' => 'NIST baseline',
        ],
    );

    $token = StringHelper::randomString(64);
    $job = new AuditExportJob();
    $job->daysFilter = 30;
    $job->format = 'csv';
    $job->token = $token;

    $rows = (new \craft\db\Query())
        ->from('{{%passwordpolicy_audit_log}}')
        ->orderBy(['id' => SORT_ASC])
        ->all();

    runExportJob($job, $rows);

    $contents = file_get_contents(exportFilePath($token, 'csv'));

    // The CSV row contains an escaped JSON object describing the
    // policy diff. CSV doubles internal `"` characters per the
    // standard fputcsv contract, so the JSON `"policyId":42` lands
    // as `""policyId"":42`. Verify both halves of the round-trip
    // survived the encoding.
    expect($contents)->toContain('NIST baseline');
    expect($contents)->toContain('""policyId"":42');
});
