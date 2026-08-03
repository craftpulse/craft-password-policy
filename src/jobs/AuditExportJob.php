<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\jobs;

use Carbon\Carbon;
use Craft;
use craft\base\FsInterface;
use craft\helpers\FileHelper;
use craft\queue\BaseBatchedJob;
use craftpulse\passwordpolicy\batchers\AuditExportBatcher;
use craftpulse\passwordpolicy\events\AuditExportCompleteEvent;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\services\AuditLogService;
use DateTime;
use DateTimeZone;
use RuntimeException;
use Throwable;
use yii\base\Event;
use yii\queue\RetryableJobInterface;

/**
 * Class AuditExportJob
 *
 * Enterprise-only batched job that streams a date-bounded slice of the
 * audit log to a filesystem-backed file (CSV or JSONL) and notifies the
 * requesting admin via email when the file is ready. Completes the
 * audit-log read-side trifecta after G8 (SIEM forwarder) and G9
 * (webhook forwarder).
 *
 * Pattern: same campaign-style batcher as the P1.4 expiry-reminder job
 * — `AuditExportBatcher` re-queries each slice rather than caching the
 * row list at construction. The date threshold captured on enqueue
 * provides a stable upper bound; concurrent inserts during the run
 * land past the threshold and are naturally excluded.
 *
 * Output formats
 * --------------
 * - **CSV** — column-by-column with `fputcsv` semantics. Stable column
 *   order: `id`, `dateCreated`, `userId`, `changedByUserId`, `event`,
 *   `outcome`, `source`, `ipHash`, `userIdentifier`, `details`,
 *   `rowHash`, `previousHash`. `details` JSON is emitted as a quoted
 *   JSON string. The header row is written on the first batch only.
 * - **JSONL** — one canonical-JSON line per row via
 *   {@see AuditLogService::canonicalize()} merged with the row's
 *   `rowHash` + `previousHash`. Reuses the chain-canonicalisation
 *   bytes — auditors can recompute hashes from the export and match
 *   them to the source rows without re-deriving the canonical form.
 *
 * Filesystem
 * ----------
 * - **Local fallback** (settings handle null/empty): writes to
 *   `@runtime/password-policy/exports/<token>.<format>` via direct
 *   `fopen('a')`. Directory created on first batch.
 * - **FsInterface** (handle set): resolves via
 *   `Craft::$app->getFs($handle)`. Writes are buffered to a local
 *   temp file then uploaded on completion (`writeFileFromStream`
 *   semantics). Local fallback is the only path verified end-to-end
 *   in 5.2.0; cloud adapters work in theory because the contract goes
 *   through the FsInterface, but smoke-testing every adapter is out
 *   of scope.
 *
 * Completion
 * ----------
 * On `after()`:
 *  - File closed + uploaded (if remote).
 *  - Cache key `pp:audit-export-token:{token}` written with the file
 *    metadata + 24h TTL. Consumed on first download.
 *  - `EVENT_AUDIT_EXPORT_COMPLETE` fired so SIEM listeners can mirror
 *    the export event off-site.
 *  - Email sent to the requesting admin via `composeFromKey`. If the
 *    admin has been deleted between enqueue and completion, the email
 *    skip is logged and the file still exists for any operator with
 *    the token from another channel.
 *
 * Edition gate
 * ------------
 * Top of `execute()`. Mirror of G8's silent-exit-on-downgrade pattern:
 * a job that survives an Enterprise → Pro downgrade in the queue logs
 * a warning and returns rather than crashing every retry. The export
 * payload sits incomplete on disk until manually cleaned up by GC.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 *
 * @property \yii\queue\Queue $queue
 */
class AuditExportJob extends BaseBatchedJob implements RetryableJobInterface
{
    // Const Properties
    // =========================================================================

    /**
     * Fired after the export job finishes writing every batch and the
     * file is fully materialised. Listeners receive the token, file
     * path, format, row count, requesting admin id, and 24h expiry
     * timestamp. Use cases: SIEM-side mirroring of export events for
     * audit-trail-of-exports compliance, custom webhook forwarders, etc.
     *
     * @event AuditExportCompleteEvent
     *
     * @since 5.2.0
     */
    public const EVENT_AUDIT_EXPORT_COMPLETE = 'auditExportComplete';

    /**
     * TTL (in seconds) of the one-time-use download token cache entry.
     * 24h matches what most evidence-collection workflows need to
     * download a fresh export — long enough that an operator clicking
     * the email link an hour after lunch still hits a valid file.
     *
     * @var int
     */
    public const TOKEN_TTL_SECONDS = 86400;

    // Public Properties
    // =========================================================================

    /**
     * @var int the number of days back from NOW() to include in the
     *     export. Captured at job-enqueue time so the threshold is
     *     stable across retries.
     */
    public int $daysFilter = 30;

    /**
     * @var string output format — `csv` or `jsonl`.
     */
    public string $format = 'csv';

    /**
     * @var string|null the filesystem handle the export writes through.
     *     `null` falls back to local `@runtime` storage.
     */
    public ?string $filesystemHandle = null;

    /**
     * @var int the userId of the admin who requested the export. Used
     *     to look up the recipient email on completion.
     */
    public int $requestedById = 0;

    /**
     * @var string the 64-char URL-safe random token. Doubles as the
     *     filename and the cache key suffix — a unique, unguessable
     *     identifier the download URL surfaces to the admin.
     */
    public string $token = '';

    // Static Methods
    // =========================================================================

    /**
     * Returns the canonical CSV header row. Stable column order — the
     * export file is auditor evidence, so the column shape must not
     * drift between releases without an explicit format-version bump.
     *
     * Public + static so the synchronous-stream controller path can
     * produce byte-identical output to the queued path without
     * duplicating the column list.
     *
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function csvHeader(): string
    {
        return self::_csvRow([
            'id',
            'dateCreated',
            'userId',
            'changedByUserId',
            'event',
            'outcome',
            'source',
            'ipHash',
            'userIdentifier',
            'details',
            'rowHash',
            'previousHash',
        ]);
    }

    /**
     * Format a single audit-log row as a CSV line. `details` is
     * emitted as a JSON string when present.
     *
     * Public + static so the synchronous-stream controller path
     * shares the writer with the queued path.
     *
     * @param array<string, mixed> $row
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function formatCsvRow(array $row): string
    {
        return self::_csvRow([
            (string)($row['id'] ?? ''),
            (string)($row['dateCreated'] ?? ''),
            self::_stringify($row['userId'] ?? null),
            self::_stringify($row['changedByUserId'] ?? null),
            (string)($row['event'] ?? ''),
            (string)($row['outcome'] ?? ''),
            (string)($row['source'] ?? ''),
            (string)($row['ipHash'] ?? ''),
            (string)($row['userIdentifier'] ?? ''),
            self::_formatDetails($row['details'] ?? null),
            (string)($row['rowHash'] ?? ''),
            (string)($row['previousHash'] ?? ''),
        ]);
    }

    /**
     * Format a single audit-log row as a JSONL line. The shape
     * merges the canonical-JSON payload with the chain-link columns
     * (`rowHash`, `previousHash`) so the export bytes stay
     * verifiable against the chain.
     *
     * Public + static so the synchronous-stream controller path
     * shares the writer with the queued path.
     *
     * @param array<string, mixed> $row
     * @return string
     *
     * @throws \Exception when DateTime parsing fails on a malformed dateCreated
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function formatJsonlRow(array $row): string
    {
        $canonical = AuditLogService::canonicalize([
            'changedByUserId' => self::_intOrNull($row['changedByUserId'] ?? null),
            'dateCreated' => self::_normaliseDateCreated((string)$row['dateCreated']),
            'details' => self::_decodeDetails($row['details'] ?? null),
            'event' => $row['event'] ?? '',
            'ipHash' => $row['ipHash'] ?? null,
            'outcome' => $row['outcome'] ?? '',
            'source' => $row['source'] ?? null,
            'uid' => $row['uid'] ?? '',
            'userId' => self::_intOrNull($row['userId'] ?? null),
            'userIdentifier' => $row['userIdentifier'] ?? null,
        ]);

        $envelope = [
            'id' => (int)($row['id'] ?? 0),
            'payload' => json_decode($canonical, true),
            'rowHash' => $row['rowHash'] ?? '',
            'previousHash' => $row['previousHash'] ?? '',
        ];

        return json_encode(
            $envelope,
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE,
        );
    }

    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function init(): void
    {
        parent::init();
        $this->batchSize = 1000;
    }

    /**
     * @inheritdoc
     *
     * 30 minutes — exports of 100k+ rows on large installs need
     * headroom past the 5-minute default and past the 5-minute SIEM
     * forwarder TTR. Smaller exports finish well inside the window;
     * the larger value is a ceiling, not a budget.
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getTtr(): int
    {
        return 1800;
    }

    /**
     * @inheritdoc
     *
     * Lower retry ceiling than P1.4's expiry reminders (5) — exports
     * are operator-initiated. Retry-once-or-twice covers transient
     * filesystem hiccups; failures past that point need manual
     * intervention (the operator re-triggers from the utility).
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function canRetry($attempt, $error): bool
    {
        return $attempt < 3;
    }

    // Protected Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * Edition gate at the very top. A queue picker that finds this job
     * post-downgrade exits silently after logging a warning — the file
     * sits half-written until GC reaps it; no token gets cached so the
     * download URL would 404 anyway. Mirror of G8's pattern.
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function execute($queue): void
    {
        if (!PasswordPolicy::$plugin->getIsEnterprise()) {
            Craft::warning(
                'AuditExportJob skipped: audit-log export requires the Enterprise edition.',
                'password-policy',
            );

            return;
        }

        parent::execute($queue);
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected function defaultDescription(): ?string
    {
        return Craft::t(
            'password-policy',
            'Exporting audit log to {format}',
            ['format' => $this->format],
        );
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected function loadData(): AuditExportBatcher
    {
        return new AuditExportBatcher($this->daysFilter);
    }

    /**
     * @inheritdoc
     *
     * Runs once before the first item of the first batch (Craft's
     * `BaseBatchedJob::execute()` only calls this when `itemOffset ===
     * 0`, so spawned continuation jobs skip it). Sets up the export
     * directory and writes the format-specific header.
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected function before(): void
    {
        parent::before();

        $absolutePath = $this->_resolveLocalPath();
        FileHelper::createDirectory(dirname($absolutePath));

        // Truncate to zero bytes at the top of `before()`. `before()`
        // runs once per first batch (`itemOffset === 0`), but a first
        // batch that THREW before committing its offset is re-run from
        // the top on retry — and `before()` fires again. Opening with
        // 'a' (the per-row `_appendLine` mode) on that retry would
        // stack a SECOND CSV header + re-append every row the failed
        // attempt already wrote, corrupting the export. A 'w' open here
        // resets the file so the retry rebuilds it cleanly.
        // Continuation batches (`itemOffset > 0`) never call `before()`,
        // so a multi-batch export's earlier batches are never clobbered.
        //
        // This also satisfies the empty-result contract: the truncate
        // leaves a zero-byte file (JSONL) or a header-only file (CSV)
        // so the download URL never 404s for an admin who exported a
        // date window with no rows.
        $handle = @fopen($absolutePath, 'w');

        if ($handle === false) {
            throw new RuntimeException("Failed to open export file: {$absolutePath}");
        }

        fclose($handle);

        // CSV gets a header row on the first write; JSONL does not
        // (each line is self-contained, so no header is meaningful).
        if ($this->format === 'csv') {
            $this->_appendLine($absolutePath, self::csvHeader());
        }
    }

    /**
     * @inheritdoc
     *
     * Per-row writer. The header is written once in `before()`; this
     * just appends the row in the configured format.
     *
     * @param array<string, mixed> $item the audit-log row
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected function processItem(mixed $item): void
    {
        if (!is_array($item) || !isset($item['id'])) {
            return;
        }

        $absolutePath = $this->_resolveLocalPath();

        // Per-row formatting is wrapped so one malformed row can't abort
        // the whole export. `formatJsonlRow()` re-parses `dateCreated`
        // through `_normaliseDateCreated()`, which throws on a value
        // `DateTime` can't parse (a corrupt or hand-edited row). Without
        // the guard a single bad row would bubble the throw up through
        // `BaseBatchedJob`, fail the batch, and burn retries on a
        // condition no retry can fix. Log the offending id and skip —
        // the export completes with every row it COULD format.
        try {
            $line = $this->format === 'jsonl'
                ? self::formatJsonlRow($item)
                : self::formatCsvRow($item);
        } catch (Throwable $e) {
            Craft::warning(
                'AuditExportJob skipped malformed audit row ' . (int)$item['id']
                . ' during export: ' . $e->getMessage(),
                'password-policy',
            );

            return;
        }

        $this->_appendLine($absolutePath, $line);
    }

    /**
     * @inheritdoc
     *
     * Runs once after the last item of the last batch (Craft's
     * `BaseBatchedJob::execute()` only calls this when no more items
     * remain). Optionally uploads to the configured FsInterface,
     * writes the token cache entry, fires the completion event, and
     * emails the requesting admin.
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected function after(): void
    {
        parent::after();

        $localPath = $this->_resolveLocalPath();

        // Upload to remote filesystem if configured. Local fallback is
        // a no-op — the file is already at the resolved local path.
        $remoteRelativePath = null;

        if ($this->filesystemHandle !== null && $this->filesystemHandle !== '') {
            $remoteRelativePath = $this->_uploadToFs($localPath);
        }

        // Resolve the canonical file location ONCE and reuse it for both
        // the cache entry and the completion event. On a remote-FS
        // install `_uploadToFs()` returns the filesystem-relative path;
        // the local temp file is incidental. Previously the cache stored
        // the remote relative path while the completion event published
        // the local temp path — listeners (SIEM mirrors, evidence
        // queues) that resolved the event's `filePath` against the
        // configured filesystem looked in the wrong place. A single
        // resolved value keeps both surfaces consistent.
        $resolvedPath = $remoteRelativePath ?? $localPath;

        // Cache the token with the file metadata. The download
        // controller looks this up, sends the file, and deletes the
        // entry. Stored as an array for forward-compat (a future
        // signed-URL field could land here without changing callers).
        //
        // `exportDate` pins the date the export was finalised so the
        // download filename reflects when the data covers, not when
        // the operator happens to click the email link. Without this
        // a 24-hour-old export downloaded the next morning would
        // label itself with the wrong day.
        $expiresAt = Carbon::now('UTC')
            ->addSeconds(self::TOKEN_TTL_SECONDS)
            ->toDateTime();

        Craft::$app->getCache()->set(
            $this->_tokenCacheKey(),
            [
                'exportDate' => Carbon::now('UTC')->format('Y-m-d'),
                'filePath' => $resolvedPath,
                'filesystemHandle' => $this->filesystemHandle,
                'format' => $this->format,
                'requestedById' => $this->requestedById,
                'requestedAt' => Carbon::now('UTC')->format(DateTime::ATOM),
            ],
            self::TOKEN_TTL_SECONDS,
        );

        // Notify the admin via email + fire the public completion event.
        // Both are best-effort — neither failure unwinds the export
        // (the file already exists; the token is cached).
        $rowCount = $this->totalItems();

        $this->_fireCompletionEvent($expiresAt, $rowCount, $resolvedPath);
        $this->_sendCompletionEmail($expiresAt, $rowCount);
    }

    // Private Methods
    // =========================================================================

    /**
     * Appends a single line + trailing newline to the export file. Uses
     * `LOCK_EX` so concurrent batch workers (parallel queue runners on
     * the same job — uncommon but possible) don't interleave writes.
     *
     * @param string $absolutePath
     * @param string $line
     * @return void
     *
     * @throws RuntimeException when the file cannot be opened
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _appendLine(string $absolutePath, string $line): void
    {
        $handle = @fopen($absolutePath, 'a');

        if ($handle === false) {
            throw new RuntimeException("Failed to open export file: {$absolutePath}");
        }

        try {
            flock($handle, LOCK_EX);
            fwrite($handle, $line . "\n");
            fflush($handle);
            flock($handle, LOCK_UN);
        } finally {
            fclose($handle);
        }
    }

    /**
     * Encodes one row as a CSV line via PHP's `fputcsv` semantics
     * (comma separator, double-quote enclosure, double-quote escape).
     * Uses an in-memory stream so the encoding contract matches
     * `fputcsv` exactly without writing to disk twice.
     *
     * @param array<int, string> $values
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private static function _csvRow(array $values): string
    {
        $stream = fopen('php://temp', 'r+');
        fputcsv($stream, $values, ',', '"', '\\');
        rewind($stream);
        $line = stream_get_contents($stream);
        fclose($stream);

        // `fputcsv` appends a `\n`; trim it because the file writer
        // adds its own newline downstream.
        return rtrim($line, "\r\n");
    }

    /**
     * Decodes the `details` JSON column to an array. Yii returns JSON
     * columns either pre-decoded (2.0.50+) or as a string — accept
     * both shapes. Mirror of the verifier's
     * {@see \craftpulse\passwordpolicy\console\controllers\AuditController::_decodeDetails()}.
     *
     * @param mixed $value
     * @return array<string, mixed>|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private static function _decodeDetails(mixed $value): ?array
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
     * Renders the `details` column as a JSON string for CSV output.
     * Empty values become an empty string (CSV-friendly), otherwise
     * encoded with the same flags the writer uses.
     *
     * @param mixed $value
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private static function _formatDetails(mixed $value): string
    {
        $decoded = self::_decodeDetails($value);

        if ($decoded === null) {
            return '';
        }

        return json_encode($decoded, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    /**
     * Fires the completion event with the file metadata. Best-effort —
     * a listener exception logs and continues; the export file already
     * exists and the token is cached.
     *
     * `$resolvedPath` is the SAME location written to the token cache —
     * the filesystem-relative path on a remote-FS install, the absolute
     * local path on the local-fallback path. Listeners resolve it
     * against the configured filesystem so they read the bytes from the
     * same place the download controller does.
     *
     * @param DateTime $expiresAt
     * @param int $rowCount
     * @param string $resolvedPath
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _fireCompletionEvent(DateTime $expiresAt, int $rowCount, string $resolvedPath): void
    {
        try {
            Event::trigger(
                self::class,
                self::EVENT_AUDIT_EXPORT_COMPLETE,
                new AuditExportCompleteEvent([
                    'token' => $this->token,
                    'filePath' => $resolvedPath,
                    'format' => $this->format,
                    'rowCount' => $rowCount,
                    'requestedById' => $this->requestedById,
                    'expiresAt' => $expiresAt,
                    'filesystemHandle' => $this->filesystemHandle,
                ]),
            );
        } catch (Throwable $e) {
            Craft::warning(
                'AuditExportJob completion event listener threw: ' . $e->getMessage(),
                'password-policy',
            );
        }
    }

    /**
     * Coerces a database-fetched value to `int|null`. Mirror of the
     * verifier's helper — see its rationale.
     *
     * @param mixed $value
     * @return int|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private static function _intOrNull(mixed $value): ?int
    {
        if ($value === null || $value === '') {
            return null;
        }

        return (int)$value;
    }

    /**
     * Reformats a stored `dateCreated` to the canonical UTC string so
     * the JSONL bytes match the chain-canonical bytes the writer
     * hashed. Mirror of the verifier's helper.
     *
     * @param string $value
     * @return string
     *
     * @throws \Exception when DateTime parsing fails on a malformed value
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private static function _normaliseDateCreated(string $value): string
    {
        return (new DateTime($value, new DateTimeZone('UTC')))
            ->format('Y-m-d\TH:i:s\Z');
    }

    /**
     * Resolves the absolute local path the job writes to. Always under
     * `@runtime/password-policy/exports/` — never under `@webroot` or
     * any web-public path. Token is the filename (URL-safe, 64 chars).
     *
     * Even when a remote filesystem handle is configured, writes still
     * go local first then upload on completion. Mid-run failures leave
     * a partial local file (cleaned up by manual or scheduled GC) and
     * never a partial remote object.
     *
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _resolveLocalPath(): string
    {
        return Craft::getAlias('@runtime')
            . '/password-policy/exports/'
            . $this->token
            . '.'
            . $this->format;
    }

    /**
     * Sends the audit-export-ready email to the requesting admin.
     * Best-effort: a missing admin (deleted between enqueue and
     * completion) logs and skips — the file still exists for any
     * operator with the token from another channel.
     *
     * @param DateTime $expiresAt
     * @param int $rowCount
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _sendCompletionEmail(DateTime $expiresAt, int $rowCount): void
    {
        $admin = Craft::$app->getUsers()->getUserById($this->requestedById);

        if ($admin === null || $admin->email === null) {
            Craft::warning(
                'AuditExportJob completed but the requesting admin (id ' . $this->requestedById
                . ') has no resolvable email, so the notification was skipped. The export file is still '
                . 'available via the token.',
                'password-policy',
            );

            return;
        }

        $downloadUrl = \craft\helpers\UrlHelper::cpUrl('password-policy/audit-export/download/' . $this->token);

        try {
            $message = Craft::$app->getMailer()->composeFromKey(
                'password-policy:audit-export-ready',
                [
                    'downloadUrl' => $downloadUrl,
                    'expiresAt' => $expiresAt,
                    'rowCount' => $rowCount,
                    'format' => strtoupper($this->format),
                ],
            );

            $message->setTo($admin->email)->send();
        } catch (Throwable $e) {
            Craft::error(
                'Failed to send audit-export-ready email to admin ' . $this->requestedById
                . ': ' . $e->getMessage(),
                'password-policy',
            );
        }
    }

    /**
     * Stringifies a database-fetched value for CSV output. `null`
     * becomes an empty string; anything else casts to string. Same
     * behaviour `fputcsv` would produce for a null cell.
     *
     * @param mixed $value
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private static function _stringify(mixed $value): string
    {
        return $value === null ? '' : (string)$value;
    }

    /**
     * Cache key for the one-time-use download token. 64-char URL-safe
     * random tokens combined with the static prefix produce keys that
     * can never collide with the SIEM (`pp:siem-*`), webhook
     * (`pp:webhook-*`), or alert-cooldown
     * (`pp:alert-cooldown-*`) namespaces.
     *
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _tokenCacheKey(): string
    {
        return 'pp:audit-export-token:' . $this->token;
    }

    /**
     * Uploads the local export file to the configured FsInterface and
     * returns the relative path inside the filesystem. Best-effort: a
     * failure logs and falls back to local-fallback semantics (the
     * cache entry points at the local file).
     *
     * @param string $localPath
     * @return string|null relative path inside the FS, or null on failure
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _uploadToFs(string $localPath): ?string
    {
        try {
            $fs = Craft::$app->getFs()->getFilesystemByHandle((string)$this->filesystemHandle);

            if (!$fs instanceof FsInterface) {
                return null;
            }

            $relativePath = 'password-policy/exports/' . $this->token . '.' . $this->format;
            $stream = fopen($localPath, 'rb');

            if ($stream === false) {
                return null;
            }

            try {
                $fs->writeFileFromStream($relativePath, $stream);
            } finally {
                fclose($stream);
            }

            return $relativePath;
        } catch (Throwable $e) {
            Craft::warning(
                'AuditExportJob filesystem upload failed (handle ' . $this->filesystemHandle
                . '): ' . $e->getMessage() . '. Falling back to local-path serve.',
                'password-policy',
            );

            return null;
        }
    }
}
