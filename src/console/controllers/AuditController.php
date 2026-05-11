<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\console\controllers;

use Carbon\Carbon;
use craft\console\Controller;
use craft\db\Query;
use craft\helpers\App;
use craft\helpers\Json;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\services\AuditLogService;
use Throwable;
use yii\console\ExitCode;
use yii\helpers\Console;

/**
 * Class AuditController
 *
 * Console commands for audit log management and export.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class AuditController extends Controller
{
    // Const Properties
    // =========================================================================

    /**
     * `actionVerify` exit code for a detected chain break. Literal `1`
     * — the documented contract is `0` valid / `1` chain break / `2`
     * unreadable. `Yii\console\ExitCode::UNSPECIFIED_ERROR` happens to
     * be `1`, but the verifier publishes its own constant so the
     * contract isn't accidentally rebound by a Yii revision.
     *
     * @var int
     */
    public const EXIT_CHAIN_BREAK = 1;

    /**
     * `actionVerify` exit code for an unreadable / schema-drift / DB
     * connect failure / malformed canonical JSON case. Literal `2` —
     * Yii's `ExitCode` doesn't expose a constant for it. Distinct from
     * `EXIT_CHAIN_BREAK` so CI pipelines can route the two failure
     * modes differently (chain break = page security, unreadable =
     * page ops).
     *
     * @var int
     */
    public const EXIT_UNREADABLE = 2;

    /**
     * Safety margin (in seconds) added to the retention window when
     * deciding whether a non-genesis first surviving row's
     * `previousHash` is an acceptable retention boundary. Tolerates
     * clock drift between the prune-cron host and the verifier host
     * without papering over actual tampering — a recent first row
     * whose `previousHash` doesn't anchor anywhere is still a chain
     * break.
     *
     * @var int
     */
    private const RETENTION_BOUNDARY_SAFETY_MARGIN_SECONDS = 86400;

    // Public Properties
    // =========================================================================

    /**
     * @var int number of days of audit entries to retain
     */
    public int $days = 365;

    /**
     * @var bool overwrite an existing `CRAFT_AUDIT_PII_KEY` value
     *     during `generate-pii-key`. Without `--force`, the action
     *     refuses to rotate — accidental rotation orphans every
     *     historical row's `userIdentifier` correlation.
     *
     * @since 5.2.0
     */
    public bool $force = false;

    /**
     * @var string export format: `csv`, `jsonl`, or `json`. `csv` and
     *     `jsonl` are the streaming-friendly formats — `jsonl` matches
     *     the queued-job format byte-for-byte. `json` emits a single
     *     mega-array; preserved for backwards compatibility but emits
     *     a deprecation hint and may be removed in 5.3.
     */
    public string $format = 'csv';

    /**
     * @var bool whether to include user email in export
     */
    public bool $includeUserDetails = false;

    /**
     * @var bool when `true`, `actionExport` enqueues an `AuditExportJob`
     *     and writes the file to the configured filesystem (or local
     *     `@runtime` fallback). When `false` (the default — preserved
     *     for SIEM-piping operators), writes the export to stdout.
     *
     * Console invocation bypasses the edition gate; the plan is that
     * shell access is itself a privileged operation and CI pipelines
     * shouldn't have to authenticate as a CP admin to run a verifier
     * or export.
     *
     * @since 5.2.0
     */
    public bool $queue = false;

    /**
     * @var int|null start row id (inclusive) for `verify`. Unset means
     * full-table walk from the genesis row onward — the only mode that
     * activates retention-purged-row tolerance.
     */
    public ?int $from = null;

    /**
     * @var int|null end row id (inclusive) for `verify`.
     */
    public ?int $to = null;

    /**
     * @var bool emit machine-readable JSON instead of human-readable
     * text. On `verify`, that's JSON Lines (one row per line plus a
     * summary). On `schema`, that's a single JSON object encoding the
     * per-event allowlist registry.
     */
    public bool $json = false;

    /**
     * @var bool suppress per-row OK lines on a clean `verify` pass — only
     * the summary emits.
     */
    public bool $quiet = false;

    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function options($actionID): array
    {
        $options = parent::options($actionID);

        if ($actionID === 'purge') {
            $options[] = 'days';
        }

        if ($actionID === 'export') {
            $options[] = 'format';
            $options[] = 'days';
            $options[] = 'includeUserDetails';
            $options[] = 'queue';
        }

        if ($actionID === 'verify') {
            $options[] = 'from';
            $options[] = 'to';
            $options[] = 'json';
            $options[] = 'quiet';
        }

        if ($actionID === 'schema') {
            $options[] = 'json';
        }

        if ($actionID === 'generate-pii-key') {
            $options[] = 'force';
        }

        return $options;
    }

    /**
     * Generates a fresh HMAC key for audit-log PII hashing and writes
     * it to the local `.env` as `CRAFT_AUDIT_PII_KEY`.
     *
     * The key is the HMAC secret behind {@see AuditLogService::_hashUserIdentifier()}.
     * Operators rotate it to destroy historical-row correlation without
     * touching `securityKey` (which would also break sessions, CSRF
     * tokens, asset URLs). See `docs/user/features/audit-logging.md`
     * § "Rotating the PII key" for the operator workflow.
     *
     * Workflow:
     *  - Generates 32 cryptographically-random bytes via `random_bytes(32)`,
     *    hex-encoded to a 64-char string (same shape as Craft's
     *    `securityKey`).
     *  - Writes via `Craft::$app->getConfig()->setDotEnvVar()` —
     *    Craft's standard `.env`-mutation API.
     *  - Refuses to overwrite an existing value unless `--force` is set;
     *    accidental rotation orphans historical correlation.
     *  - Prints the new key to stdout so operators can copy it to
     *    production secret management.
     *
     * Console-direct: no permission gate (shell access is itself a
     * privileged operation, consistent with `actionVerify` and
     * `actionSchema`).
     *
     * @return int
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionGeneratePiiKey(): int
    {
        $envName = 'CRAFT_AUDIT_PII_KEY';
        $existing = App::env($envName);

        if (!empty($existing) && !$this->force) {
            $this->stderr(
                "$envName is already set. Generating a new key would orphan "
                . "every existing audit-log row's userIdentifier hash.\n"
                . "Use --force to overwrite if intentional rotation.\n",
                Console::FG_YELLOW,
            );

            return ExitCode::UNSPECIFIED_ERROR;
        }

        $key = bin2hex(random_bytes(32));

        try {
            \Craft::$app->getConfig()->setDotEnvVar($envName, $key);
        } catch (Throwable $e) {
            $this->stderr(
                "Failed to write $envName to .env: " . $e->getMessage() . "\n",
                Console::FG_RED,
            );

            return ExitCode::UNSPECIFIED_ERROR;
        }

        $this->stdout(
            "Generated and wrote $envName to .env\n",
            Console::FG_GREEN,
        );
        $this->stdout("\nKey: $key\n\n");
        $this->stdout(
            "Add $envName=$key to your production environment.\n"
            . "New audit-log rows will hash userIdentifier with this key.\n"
            . "Existing rows (hashed with the previous key) become uncorrelatable\n"
            . "against the new key — this is the intentional rotation behaviour.\n",
        );

        return ExitCode::OK;
    }

    /**
     * Purges audit log entries older than the specified number of days.
     *
     * @return int
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionPurge(): int
    {
        $this->stdout("Purging audit log entries older than {$this->days} days...\n");

        $count = PasswordPolicy::$plugin->getAuditLog()->purgeOldEntries($this->days);

        $this->stdout("Done. {$count} entries purged.\n");

        return ExitCode::OK;
    }

    /**
     * Exports audit log entries.
     *
     * Two modes:
     *
     *  - **stdout** (default) — prints rows in the requested format to
     *    stdout for secure piping to a SIEM or log aggregation system.
     *    Preserved as the default to keep the existing SIEM-piping
     *    contract intact.
     *  - **`--queue`** — enqueues an `AuditExportJob` (G10) which
     *    writes the file to the configured filesystem (or local
     *    `@runtime` fallback) and emits a one-time-use download token
     *    on completion. Surfaces the token on stdout so CI pipelines
     *    can capture it for follow-up download steps.
     *
     * Format flags:
     *
     *  - `csv` — default. Spreadsheet-friendly comma-separated rows.
     *  - `jsonl` — newline-delimited JSON. Matches the queued-job
     *    format byte-for-byte; downstream tooling (`jq`, `pandas`,
     *    SIEM ingest) parses each line as an independent JSON
     *    document.
     *  - `json` — single mega-array. Preserved for backwards
     *    compatibility with the 5.2.0-alpha tooling; emits a
     *    deprecation hint and may be removed in 5.3. Use `jsonl`.
     *
     * Console invocation bypasses the `pp:audit-export` permission
     * gate (consistent with `actionVerify` — operators with shell
     * access have already passed any meaningful gate, and CI pipelines
     * need to inspect the table without a CP user identity).
     *
     * @return int
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionExport(): int
    {
        if ($this->queue) {
            return $this->_exportViaQueue();
        }

        $threshold = Carbon::now('UTC')->subDays($this->days)->format('Y-m-d H:i:s');

        $query = (new Query())
            ->from('{{%passwordpolicy_audit_log}}')
            ->where(['>=', 'dateCreated', $threshold])
            ->orderBy(['dateCreated' => SORT_ASC]);

        // Cursor-style iteration: stream rows one at a time so the
        // export's memory footprint stays O(batch size) regardless of
        // row count. Production audit tables can exceed hundreds of
        // thousands of rows — `->all()` would OOM the console process
        // before any bytes hit stdout.
        if ($this->format === 'json') {
            $this->stderr(
                "Deprecated: --format=json emits a single mega-array that doesn't stream. "
                . "Use --format=jsonl (newline-delimited JSON) for streaming-friendly output. "
                . "The single-array shape may be removed in 5.3.\n",
            );
        }

        $hasRows = false;
        $emailCache = [];

        foreach ($query->each(1000) as $row) {
            if ($this->includeUserDetails) {
                $row['userEmail'] = $this->_resolveUserEmail((int)($row['userId'] ?? 0), $emailCache);
            }

            // Defer per-format preamble (CSV header / opening `[`)
            // until the first row arrives so an empty result emits
            // nothing to stdout — matches the pre-streaming behaviour.
            if (!$hasRows) {
                if ($this->format === 'json') {
                    $this->stdout('[');
                } elseif ($this->format !== 'jsonl') {
                    $this->stdout($this->_csvHeader() . "\n");
                }
            }

            match ($this->format) {
                'jsonl' => $this->_emitJsonlRow($row),
                'json' => $this->_emitJsonRow($row, !$hasRows),
                default => $this->_emitCsvRow($row),
            };

            $hasRows = true;
        }

        if (!$hasRows) {
            $this->stderr("No entries found within the specified period.\n");

            return ExitCode::OK;
        }

        if ($this->format === 'json') {
            $this->stdout("]\n");
        }

        return ExitCode::OK;
    }

    /**
     * Emits the per-event PII allowlist registry from
     * {@see AuditLogService::ALLOWED_DETAILS_BY_EVENT} as auditor-facing
     * static evidence: "this is what every event class is permitted to
     * log, and nothing else can land on disk."
     *
     * Default output is a human-readable table; `--json` emits a single
     * JSON object whose keys are event class strings and values are
     * the allowed-key arrays. Pipe to `jq` for shaped queries.
     *
     * Console-direct invocation bypasses the `pp:audit-view` permission
     * gate (consistent with `actionVerify` — operators with shell access
     * have already passed any meaningful gate, and CI pipelines need to
     * inspect the registry without a CP user identity).
     *
     * @return int
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionSchema(): int
    {
        $registry = AuditLogService::ALLOWED_DETAILS_BY_EVENT;

        if ($this->json) {
            $this->stdout(Json::encode($registry, JSON_PRETTY_PRINT) . "\n");

            return ExitCode::OK;
        }

        // Human-readable table. Sort by event class so the output is
        // deterministic regardless of registry source order.
        ksort($registry, SORT_STRING);

        $eventColumnWidth = max(
            strlen('Event class'),
            ...array_map(strlen(...), array_keys($registry)),
        );

        $header = sprintf(
            "%-{$eventColumnWidth}s  %s\n",
            'Event class',
            'Allowed detail keys',
        );
        $this->stdout($header);
        $this->stdout(str_repeat('-', $eventColumnWidth + 2 + 40) . "\n");

        foreach ($registry as $event => $allowedKeys) {
            $this->stdout(sprintf(
                "%-{$eventColumnWidth}s  %s\n",
                $event,
                implode(', ', $allowedKeys),
            ));
        }

        return ExitCode::OK;
    }

    /**
     * Walks the audit-log hash chain (G1) and reports whether every row
     * verifies against its canonical-payload SHA-256.
     *
     * Each row's `rowHash` is recomputed via
     * {@see AuditLogService::canonicalize()} and compared to the stored
     * `rowHash`; each row's `previousHash` is compared to the prior
     * row's stored `rowHash`. The first break exits non-zero so CI
     * pipelines can fail builds on tamper detection — the verifier does
     * not continue past a break.
     *
     * Open-source mandate: this verifier MUST stay in the public repo,
     * fully readable, no paywall, no license check, no build artifact.
     * The credibility multiplier on the audit chain is precisely that
     * auditors can read and run this code. Future maintainers — do not
     * gate this method.
     *
     * Hash recomputation MUST go through `AuditLogService::canonicalize()`
     * — sharing the writer's code path is what guarantees bit-identical
     * output. Don't inline a "fast path" verifier; drift between writer
     * and verifier silently invalidates the chain.
     *
     * Permission gating (`pp:audit-verify`) is enforced at the CP-side
     * launcher (a future surface). Console-direct invocation bypasses
     * the permission check — operators with shell access have already
     * passed any meaningful gate, and CI pipelines need to invoke the
     * verifier without a CP user identity.
     *
     * Exit codes:
     *
     *  - `0` — chain valid (full or partial-with-acceptable-boundary).
     *  - `1` — chain break detected. Names the offending row id.
     *  - `2` — unreadable / schema drift / DB connect failure / malformed
     *    canonical JSON. Distinct from `1` so CI can route them
     *    differently. Yii's `ExitCode` doesn't expose a `2` constant; the
     *    literal matches Unix convention for "misuse of shell builtins"
     *    / generic bail-out.
     *
     * @return int
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionVerify(): int
    {
        try {
            return $this->_walkChain();
        } catch (Throwable $e) {
            $message = 'Audit log verifier failed: ' . $e->getMessage();

            if ($this->json) {
                $this->stderr(Json::encode(['error' => $message]) . "\n");
            } else {
                $this->stderr($message . "\n");
            }

            return self::EXIT_UNREADABLE;
        }
    }

    // Private Methods
    // =========================================================================

    /**
     * Reconstructs the canonical-JSON payload from a raw audit-log row.
     * The shape mirrors the writer in
     * `AuditLogService::logEvent()` — alphabetical keys, MySQL string
     * fetches coerced back to int|null, JSON `details` decoded to an
     * array, `dateCreated` reformatted to the canonical UTC string.
     *
     * @param array<string, mixed> $row
     * @return array<string, mixed>
     *
     * @throws \Exception when DateTime parsing fails on a malformed dateCreated value
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _buildCanonicalPayload(array $row): array
    {
        return [
            'changedByUserId' => $this->_intOrNull($row['changedByUserId']),
            'dateCreated' => $this->_normaliseDateCreated((string)$row['dateCreated']),
            'details' => $this->_decodeDetails($row['details']),
            'event' => $row['event'],
            'ipHash' => $row['ipHash'],
            'outcome' => $row['outcome'],
            'source' => $row['source'],
            'uid' => $row['uid'],
            'userId' => $this->_intOrNull($row['userId']),
            'userIdentifier' => $row['userIdentifier'],
        ];
    }

    /**
     * Returns the CSV header line — the same column set the per-row
     * `_emitCsvRow()` writer emits, in the same order. Lifted out so
     * `actionExport()` can emit the header once before the first
     * streamed row.
     *
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _csvHeader(): string
    {
        $headers = ['id', 'userId', 'event', 'outcome', 'source', 'dateCreated'];

        if ($this->includeUserDetails) {
            $headers[] = 'userEmail';
        }

        return implode(',', $headers);
    }

    /**
     * Decodes the `details` JSON column to an array, or null when the
     * column is empty. JSON columns come back either as an already-
     * decoded array (Yii 2.0.50+) or as a JSON string — accept both.
     * Same shape the recompute migration uses.
     *
     * @param mixed $value
     * @return array<string, mixed>|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _decodeDetails(mixed $value): ?array
    {
        if ($value === null || $value === '') {
            return null;
        }

        if (is_array($value)) {
            return $value;
        }

        $decoded = json_decode((string)$value, true);

        return is_array($decoded) ? $decoded : null;
    }

    /**
     * Emits a chain-break record to stderr (human-readable) or stdout
     * as a JSON Lines object (`--json`). Always emits regardless of
     * `--quiet` — a break is an operational event, not a per-row OK.
     *
     * @param array<string, mixed> $row
     * @param string $expectedHash
     * @param string $reason
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _emitBreak(array $row, string $expectedHash, string $reason): void
    {
        if ($this->json) {
            $this->stdout(Json::encode([
                'id' => (int)$row['id'],
                'status' => 'break',
                'uid' => $row['uid'],
                'dateCreated' => (string)$row['dateCreated'],
                'expectedHash' => $expectedHash,
                'storedHash' => $row['rowHash'],
                'reason' => $reason,
            ]) . "\n");

            return;
        }

        $this->stderr(sprintf(
            "BREAK: row %d (uid %s, dateCreated %s) — %s\n  expected: %s\n  stored:   %s\n",
            (int)$row['id'],
            (string)$row['uid'],
            (string)$row['dateCreated'],
            $reason,
            $expectedHash,
            (string)$row['rowHash'],
        ));
    }

    /**
     * Emits a per-row OK record. Suppressed entirely under `--quiet`.
     *
     * @param array<string, mixed> $row
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _emitOk(array $row): void
    {
        if ($this->quiet) {
            return;
        }

        if ($this->json) {
            $this->stdout(Json::encode([
                'id' => (int)$row['id'],
                'status' => 'ok',
                'uid' => $row['uid'],
                'dateCreated' => (string)$row['dateCreated'],
            ]) . "\n");

            return;
        }

        $this->stdout(sprintf(
            "OK: row %d (uid %s, dateCreated %s)\n",
            (int)$row['id'],
            (string)$row['uid'],
            (string)$row['dateCreated'],
        ));
    }

    /**
     * Emits the run summary. JSON Lines summary is always a single
     * object on its own line — downstream tooling parses each line as
     * an independent JSON document.
     *
     * @param int $totalRows
     * @param int $verifiedRows
     * @param int $exitCode
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _emitSummary(int $totalRows, int $verifiedRows, int $exitCode): void
    {
        if ($this->json) {
            $this->stdout(Json::encode([
                'summary' => [
                    'totalRows' => $totalRows,
                    'verifiedRows' => $verifiedRows,
                    'exitCode' => $exitCode,
                ],
            ]) . "\n");

            return;
        }

        if ($exitCode === ExitCode::OK) {
            $this->stdout(sprintf("OK: %d rows verified\n", $verifiedRows));

            return;
        }

        $this->stderr(sprintf(
            "FAIL: chain broken after %d verified rows (of %d total in range)\n",
            $verifiedRows,
            $totalRows,
        ));
    }

    /**
     * Writes a single CSV-formatted row to stdout. Matches the column
     * set returned by `_csvHeader()`. Values containing commas or
     * double quotes are double-quote-escaped per RFC 4180.
     *
     * @param array<string, mixed> $entry
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _emitCsvRow(array $entry): void
    {
        $headers = ['id', 'userId', 'event', 'outcome', 'source', 'dateCreated'];

        if ($this->includeUserDetails) {
            $headers[] = 'userEmail';
        }

        $row = [];

        foreach ($headers as $header) {
            $value = $entry[$header] ?? '';

            if (str_contains((string)$value, ',') || str_contains((string)$value, '"')) {
                $value = '"' . str_replace('"', '""', (string)$value) . '"';
            }

            $row[] = $value;
        }

        $this->stdout(implode(',', $row) . "\n");
    }

    /**
     * Writes a single audit-log row as a JSON object inside the
     * legacy single-mega-array shape, comma-prefixed when it's not the
     * first row. The opening `[` and closing `]` are written by
     * `actionExport()` so this helper only handles the inter-row
     * separator. Cursor-style emission keeps memory bounded; the
     * shape stays bit-identical to the pre-streaming output for any
     * existing consumer.
     *
     * @param array<string, mixed> $entry
     * @param bool $isFirst whether this is the first row in the stream
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _emitJsonRow(array $entry, bool $isFirst): void
    {
        $prefix = $isFirst ? '' : ',';

        $this->stdout($prefix . Json::encode(
            $entry,
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE,
        ));
    }

    /**
     * Writes a single JSON Lines row to stdout (one JSON object per
     * line). Matches the queued-job format byte-for-byte — downstream
     * tooling that consumes the queued export's bytes can pipe stdin
     * through identical parsing logic.
     *
     * @param array<string, mixed> $entry
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _emitJsonlRow(array $entry): void
    {
        $this->stdout(Json::encode(
            $entry,
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE,
        ) . "\n");
    }

    /**
     * Enqueues an `AuditExportJob` and prints the download token to
     * stdout. CI pipelines capture the token to drive a follow-up
     * download step; operators tail the email for the same link.
     *
     * Edition gate: this path requires Enterprise (the underlying
     * job's queue picker also gates on it, but we want a fast
     * console-side error rather than a job that silently no-ops on
     * Lite/Pro). Console invocation bypasses the `pp:audit-export`
     * permission gate — see the action's main docblock.
     *
     * @return int
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _exportViaQueue(): int
    {
        if (!PasswordPolicy::$plugin->getIsEnterprise()) {
            $this->stderr(
                "Audit-log export via --queue requires the Enterprise edition.\n",
            );

            return ExitCode::UNSPECIFIED_ERROR;
        }

        $format = $this->format === 'jsonl' ? 'jsonl' : 'csv';

        if ($this->format === 'json') {
            $this->stderr(
                "Deprecated: --format=json is not supported with --queue. "
                . "Falling back to csv. Use --format=jsonl for streaming output.\n",
            );
        }

        $token = \Craft::$app->getSecurity()->generateRandomString(64);
        $admin = \Craft::$app->getUser()->getIdentity();

        $job = new \craftpulse\passwordpolicy\jobs\AuditExportJob();
        $job->daysFilter = $this->days;
        $job->format = $format;
        $job->filesystemHandle = PasswordPolicy::$plugin->getSettings()->auditExportFilesystem;
        $job->requestedById = $admin?->id ?? 0;
        $job->token = $token;

        \craft\helpers\Queue::push($job);

        $downloadPath = 'password-policy/audit-export/download/' . $token;

        $this->stdout("Export queued.\n");
        $this->stdout("Token: {$token}\n");
        $this->stdout("Download via: /admin/{$downloadPath}\n");

        return ExitCode::OK;
    }

    /**
     * Emits a chain-break record + summary + returns the exit code.
     * Collapses the three-step break path the verifier hits at four
     * different decision points.
     *
     * @param array<string, mixed> $row
     * @param string $expectedHash
     * @param string $reason
     * @param int $totalRows
     * @param int $verifiedRows
     * @return int
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _failBreak(
        array $row,
        string $expectedHash,
        string $reason,
        int $totalRows,
        int $verifiedRows,
    ): int {
        $this->_emitBreak(row: $row, expectedHash: $expectedHash, reason: $reason);
        $this->_emitSummary(
            totalRows: $totalRows,
            verifiedRows: $verifiedRows,
            exitCode: self::EXIT_CHAIN_BREAK,
        );

        return self::EXIT_CHAIN_BREAK;
    }

    /**
     * Coerces a database-fetched value to `int|null`. Yii's row-array
     * fetch returns numeric columns as strings on some drivers — the
     * canonical payload contract is bare integers, so the cast must
     * happen before encoding. Same shape the recompute migration uses.
     *
     * @param mixed $value
     * @return int|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _intOrNull(mixed $value): ?int
    {
        if ($value === null || $value === '') {
            return null;
        }

        return (int)$value;
    }

    /**
     * Returns true when a non-genesis first surviving row is an
     * acceptable retention-purge boundary. Two conditions both required:
     *
     *  1. Full-verify mode — `--from` is unset. Bounded ranges never
     *     get the boundary tolerance because the user explicitly
     *     asked to start mid-chain; we can't distinguish "intentional
     *     mid-chain start" from "tamper at the lower bound".
     *  2. The row's `dateCreated` is older than
     *     `now - auditLogRetentionDays + safety margin`. The 24h
     *     safety margin tolerates clock drift between the prune-cron
     *     host and the verifier host but doesn't paper over a recent
     *     first row that doesn't anchor anywhere.
     *
     * @param array<string, mixed> $row
     * @return bool
     *
     * @throws \Exception when DateTime parsing fails on a malformed value
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _isAcceptableRetentionBoundary(array $row): bool
    {
        if ($this->from !== null) {
            return false;
        }

        $retentionDays = PasswordPolicy::$plugin->getSettings()->auditLogRetentionDays;
        $cutoff = Carbon::now('UTC')
            ->subDays($retentionDays)
            ->subSeconds(self::RETENTION_BOUNDARY_SAFETY_MARGIN_SECONDS);

        $rowCreated = new \DateTime((string)$row['dateCreated'], new \DateTimeZone('UTC'));

        return $rowCreated->getTimestamp() < $cutoff->getTimestamp();
    }

    /**
     * Normalises the stored `dateCreated` to the canonical-payload
     * format. The column is `DATETIME` (no TZ); values are stored UTC
     * by the writer — re-parsing as UTC and reformatting in
     * `Y-m-d\TH:i:s\Z` produces the same string the writer hashed.
     * Same shape the recompute migration uses.
     *
     * @param string $value
     * @return string
     *
     * @throws \Exception when DateTime parsing fails on a malformed value
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _normaliseDateCreated(string $value): string
    {
        return (new \DateTime($value, new \DateTimeZone('UTC')))
            ->format(AuditLogService::CANONICAL_DATE_FORMAT);
    }

    /**
     * Memoised user-email lookup for the `--includeUserDetails` export
     * path. The streaming loop calls this once per row; cache hits
     * short-circuit before the DB query so a noisy single user dropping
     * a thousand audit rows still costs exactly one `users` table read.
     *
     * The `$cache` parameter is passed by reference so the caller's
     * lookup table accumulates across rows — keeps the cache lifecycle
     * scoped to a single export invocation without bolting state onto
     * the controller.
     *
     * @param int $userId zero / negative ids short-circuit to null
     * @param array<int, string|null> $cache passed by reference
     * @return string|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _resolveUserEmail(int $userId, array &$cache): ?string
    {
        if ($userId <= 0) {
            return null;
        }

        if (array_key_exists($userId, $cache)) {
            return $cache[$userId];
        }

        $email = (new Query())
            ->select(['email'])
            ->from(\craft\db\Table::USERS)
            ->where(['id' => $userId])
            ->scalar();

        $cache[$userId] = is_string($email) ? $email : null;

        return $cache[$userId];
    }

    /**
     * Builds the audit-log query, walks rows in `id ASC` order,
     * recomputes each row's `rowHash`, and emits OK / break records to
     * stdout (or JSON Lines on `--json`). Returns the action's exit
     * code.
     *
     * Invariants:
     *
     *  - Walks the full table when `--from` and `--to` are unset.
     *  - Stops at the first break — does not continue past a tampered
     *    row.
     *  - Treats the first surviving row's `previousHash` as a chain
     *    start when it equals the genesis sentinel, OR the verifier
     *    is in full-walk mode AND the row's `dateCreated` is older
     *    than `retentionDays + 24h`.
     *
     * @return int
     *
     * @throws \Exception when `_normaliseDateCreated` parses a malformed value
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _walkChain(): int
    {
        $query = (new Query())
            ->from('{{%passwordpolicy_audit_log}}')
            ->orderBy(['id' => SORT_ASC]);

        if ($this->from !== null) {
            $query->andWhere(['>=', 'id', $this->from]);
        }

        if ($this->to !== null) {
            $query->andWhere(['<=', 'id', $this->to]);
        }

        // Cursor-style iteration via `->each(1000)` keeps the chain
        // walk's memory footprint bounded at O(batch size) regardless
        // of audit-log row count. Production-scale tables can exceed
        // hundreds of thousands of rows — `->all()` would OOM the
        // verifier before it printed anything.
        $previousHash = AuditLogService::GENESIS_PREVIOUS_HASH;
        $isFirstRow = true;
        $verifiedRows = 0;
        $totalRows = 0;

        foreach ($query->each(1000) as $row) {
            $totalRows++;
            $expectedPayload = AuditLogService::canonicalize($this->_buildCanonicalPayload($row));
            $expectedHash = hash('sha256', $expectedPayload . $row['previousHash']);

            // First-row boundary handling. Three acceptable shapes:
            //   1. previousHash equals the genesis sentinel — adopt and
            //      walk normally from row 2 onward.
            //   2. `--from` is set — bounded walks have explicit user
            //      intent to start mid-chain. The first row's stored
            //      previousHash is trusted as the chain anchor; we
            //      can't disprove it without walking the prior rows
            //      the user excluded.
            //   3. Full-verify mode (no `--from`) AND the row's
            //      dateCreated predates the retention boundary
            //      (`auditLogRetentionDays + 24h`) — treat the stored
            //      previousHash as the running anchor. The row it
            //      referenced has been legitimately pruned.
            // Anything else with `previousHash` not matching the prior
            // row's `rowHash` is a chain break.
            if ($isFirstRow) {
                $isFirstRow = false;

                $isGenesis = $row['previousHash'] === AuditLogService::GENESIS_PREVIOUS_HASH;
                $isBoundedStart = $this->from !== null;
                $isRetentionBoundary = !$isGenesis
                    && !$isBoundedStart
                    && $this->_isAcceptableRetentionBoundary($row);

                if (!$isGenesis && !$isBoundedStart && !$isRetentionBoundary) {
                    return $this->_failBreak(
                        row: $row,
                        expectedHash: $expectedHash,
                        reason: 'previousHash mismatch',
                        totalRows: $totalRows,
                        verifiedRows: $verifiedRows,
                    );
                }
            } elseif ($row['previousHash'] !== $previousHash) {
                return $this->_failBreak(
                    row: $row,
                    expectedHash: $expectedHash,
                    reason: 'previousHash mismatch',
                    totalRows: $totalRows,
                    verifiedRows: $verifiedRows,
                );
            }

            if ($expectedHash !== $row['rowHash']) {
                return $this->_failBreak(
                    row: $row,
                    expectedHash: $expectedHash,
                    reason: 'rowHash mismatch',
                    totalRows: $totalRows,
                    verifiedRows: $verifiedRows,
                );
            }

            $this->_emitOk($row);
            $verifiedRows++;
            $previousHash = $row['rowHash'];
        }

        $this->_emitSummary(
            totalRows: $totalRows,
            verifiedRows: $verifiedRows,
            exitCode: ExitCode::OK,
        );

        return ExitCode::OK;
    }
}
