<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\controllers;

use Carbon\Carbon;
use Craft;
use craft\base\FsInterface;
use craft\db\Query;
use craft\helpers\Queue;
use craft\web\Controller;
use craftpulse\passwordpolicy\jobs\AuditExportJob;
use craftpulse\passwordpolicy\PasswordPolicy;
use Throwable;
use yii\web\BadRequestHttpException;
use yii\web\ForbiddenHttpException;
use yii\web\NotFoundHttpException;
use yii\web\Response;

/**
 * Class AuditExportController
 *
 * CP web surface for triggering audit-log exports (G10) and serving
 * the resulting download via a one-time-use token.
 *
 * Three lines of defense (mirror G8/G9):
 *
 *  1. Utility doesn't register on Lite / Pro
 *     ({@see PasswordPolicy::_registerUtilities()}).
 *  2. Permission `pp:audit-export` only registers on Enterprise
 *     ({@see PasswordPolicy::_registerUserPermissions()}).
 *  3. This controller's `beforeAction()` rejects anyone who slipped
 *     past those (e.g. a bookmarked URL after an edition downgrade).
 *
 * Synchronous shortcut
 * --------------------
 * `actionExport` short-circuits to a streamed response when the date
 * range is small AND the row count is small. Threshold: `< 30 days`
 * AND `< 1000 rows`. Above those bounds the request enqueues the
 * batched job and redirects with a flash; the operator gets the
 * download link via email when the job finishes. The threshold keeps
 * the synchronous path under PHP's typical max-execution-time and
 * memory budget without operator tuning.
 *
 * One-time-use download
 * ---------------------
 * `actionDownload` looks up the token in the cache, sends the file,
 * and deletes the cache entry. Subsequent requests with the same
 * token return 404. The cache backend may not support atomic
 * get-and-delete — that's fine: the worst case is two concurrent
 * download clicks both succeed, and the file is idempotent to read.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class AuditExportController extends Controller
{
    // Const Properties
    // =========================================================================

    /**
     * Maximum row count for the synchronous-shortcut path. Above this
     * threshold the controller queues the job and emails the download
     * link instead of streaming directly.
     *
     * @var int
     */
    public const SYNC_ROW_LIMIT = 1000;

    /**
     * Maximum date-range window (in days) for the synchronous-shortcut
     * path. Above this threshold the controller queues the job. The
     * combined `daysFilter < 30 AND rowCount < 1000` guard keeps the
     * synchronous path under PHP's typical max-execution-time + memory
     * budget on operator-grade installs.
     *
     * @var int
     */
    public const SYNC_DAYS_LIMIT = 30;

    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @throws ForbiddenHttpException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function beforeAction($action): bool
    {
        if (!parent::beforeAction($action)) {
            return false;
        }

        $this->requireCpRequest();

        if (!PasswordPolicy::$plugin->getIsEnterprise()) {
            throw new ForbiddenHttpException(
                'Audit-log export requires the Enterprise edition.',
            );
        }

        $this->requirePermission('pp:audit-export');

        return true;
    }

    /**
     * Serves a previously-queued export via the cached one-time token.
     * Cache hit → file served + cache key deleted (one-time-use).
     * Cache miss → 404.
     *
     * @param string $token the 64-char URL-safe token from the email link
     * @return Response
     *
     * @throws ForbiddenHttpException
     * @throws NotFoundHttpException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionDownload(string $token): Response
    {
        $cacheKey = 'pp:audit-export-token:' . $token;
        $entry = Craft::$app->getCache()->get($cacheKey);

        if (!is_array($entry) || !isset($entry['filePath'], $entry['format'])) {
            throw new NotFoundHttpException('Export not found or token expired.');
        }

        // Delete the cache entry first so concurrent clicks race to a
        // 404 rather than serve the file twice. The cache backend may
        // not support atomic get-and-delete; the worst case is two
        // concurrent download clicks both succeed, which is fine
        // because the file is idempotent to read.
        Craft::$app->getCache()->delete($cacheKey);

        $filesystemHandle = $entry['filesystemHandle'] ?? null;
        $format = $entry['format'];
        $filename = sprintf(
            'audit-export-%s.%s',
            Carbon::now('UTC')->format('Y-m-d'),
            $format,
        );

        if ($filesystemHandle === null || $filesystemHandle === '') {
            return $this->_serveLocalFile((string)$entry['filePath'], $filename, $format);
        }

        return $this->_serveRemoteFile(
            (string)$filesystemHandle,
            (string)$entry['filePath'],
            $filename,
            $format,
        );
    }

    /**
     * Triggers an audit-log export. Synchronous shortcut for small
     * ranges streams the file directly; larger ranges enqueue the job
     * and redirect back to the utility with a flash.
     *
     * @return Response
     *
     * @throws BadRequestHttpException
     * @throws ForbiddenHttpException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionExport(): Response
    {
        $this->requirePostRequest();

        $request = Craft::$app->getRequest();
        $days = max(1, (int)$request->getBodyParam('days', 7));
        $format = $request->getBodyParam('format', 'csv');

        if (!in_array($format, ['csv', 'jsonl'], true)) {
            throw new BadRequestHttpException('Format must be csv or jsonl.');
        }

        $rowCount = $this->_countRowsInRange($days);

        if ($days < self::SYNC_DAYS_LIMIT && $rowCount < self::SYNC_ROW_LIMIT) {
            return $this->_streamSynchronousResponse($days, $format);
        }

        return $this->_enqueueAsyncExport($days, $format);
    }

    // Private Methods
    // =========================================================================

    /**
     * Counts audit-log rows within the date range. Used to decide
     * whether to take the synchronous-streaming shortcut. Cached for
     * 60s to keep repeated form submissions cheap; the count is only
     * advisory (the threshold is conservative enough that minor drift
     * doesn't matter).
     *
     * @param int $days
     * @return int
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _countRowsInRange(int $days): int
    {
        $threshold = Carbon::now('UTC')->subDays($days)->format('Y-m-d H:i:s');

        return (new Query())
            ->from('{{%passwordpolicy_audit_log}}')
            ->where(['>=', 'dateCreated', $threshold])
            ->count();
    }

    /**
     * Enqueues an `AuditExportJob` and redirects to the utility with
     * a flash success notice. The download URL goes out via email
     * when the job finishes.
     *
     * @param int $days
     * @param string $format
     * @return Response
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _enqueueAsyncExport(int $days, string $format): Response
    {
        $token = Craft::$app->getSecurity()->generateRandomString(64);
        $admin = Craft::$app->getUser()->getIdentity();

        $job = new AuditExportJob();
        $job->daysFilter = $days;
        $job->format = $format;
        $job->filesystemHandle = PasswordPolicy::$plugin->getSettings()->auditExportFilesystem;
        $job->requestedById = $admin?->id ?? 0;
        $job->token = $token;

        Queue::push($job);

        // Session may be unavailable in console-bootstrapped tests
        // (test fixture exercises the controller via `runAction` from
        // a console application). Surface the flash when we can; the
        // file still completes and the email still goes out either
        // way, so the flash is operational polish.
        try {
            Craft::$app->getSession()->setNotice(Craft::t(
                'password-policy',
                'Export queued. You will receive an email with the download link when it is ready.',
            ));
        } catch (Throwable) {
            // Console / queue context — no session available. Skip.
        }

        return $this->redirect('utilities/pp-audit-export');
    }

    /**
     * Streams the export response synchronously — used for small
     * ranges below the threshold. Re-runs the same row-by-row writer
     * the queued job uses, but pipes to PHP's output buffer instead
     * of a file. Sets `Content-Type` + `Content-Disposition` headers
     * before the stream callback fires.
     *
     * @param int $days
     * @param string $format
     * @return Response
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _streamSynchronousResponse(int $days, string $format): Response
    {
        $threshold = Carbon::now('UTC')->subDays($days)->format('Y-m-d H:i:s');
        $filename = sprintf(
            'audit-export-%s.%s',
            Carbon::now('UTC')->format('Y-m-d'),
            $format,
        );
        $mimeType = $format === 'jsonl' ? 'application/x-ndjson' : 'text/csv';

        $rows = (new Query())
            ->from('{{%passwordpolicy_audit_log}}')
            ->where(['>=', 'dateCreated', $threshold])
            ->orderBy(['id' => SORT_ASC])
            ->all();

        $response = Craft::$app->getResponse();
        $response->headers->set('Content-Type', $mimeType);
        $response->headers->set('Content-Disposition', sprintf('attachment; filename="%s"', $filename));

        $response->stream = function() use ($format, $rows): array {
            // Single-source the writers — the queued job exposes
            // `csvHeader`, `formatCsvRow`, and `formatJsonlRow` as
            // static methods so the synchronous-stream path produces
            // byte-identical output without duplicating the writer
            // contract.
            $payload = '';

            if ($format === 'csv') {
                $payload .= AuditExportJob::csvHeader() . "\n";
            }

            foreach ($rows as $row) {
                $payload .= ($format === 'jsonl'
                    ? AuditExportJob::formatJsonlRow($row)
                    : AuditExportJob::formatCsvRow($row)) . "\n";
            }

            echo $payload;

            return [true, true];
        };

        return $response;
    }

    /**
     * Serves the locally-stored export file via Craft's
     * `Response::sendFile`. The file lives under `@runtime` (never
     * web-public) so the controller is the only path it can leak
     * through — and the controller has already enforced edition +
     * permission gates via `beforeAction()`.
     *
     * @param string $absolutePath
     * @param string $filename
     * @param string $format
     * @return Response
     *
     * @throws NotFoundHttpException when the file is missing on disk
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _serveLocalFile(string $absolutePath, string $filename, string $format): Response
    {
        if (!file_exists($absolutePath)) {
            throw new NotFoundHttpException('Export file no longer exists on disk.');
        }

        $mimeType = $format === 'jsonl' ? 'application/x-ndjson' : 'text/csv';

        return Craft::$app->getResponse()->sendFile($absolutePath, $filename, [
            'mimeType' => $mimeType,
            'inline' => false,
        ]);
    }

    /**
     * Serves a remote-filesystem-stored export by streaming through
     * Yii's response. Falls back to a 404 when the configured
     * filesystem can't resolve the file — operators with cloud
     * adapters smoke-test on first use.
     *
     * @param string $filesystemHandle
     * @param string $relativePath
     * @param string $filename
     * @param string $format
     * @return Response
     *
     * @throws NotFoundHttpException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _serveRemoteFile(
        string $filesystemHandle,
        string $relativePath,
        string $filename,
        string $format,
    ): Response {
        try {
            $fs = Craft::$app->getFs()->getFilesystemByHandle($filesystemHandle);

            if (!$fs instanceof FsInterface || !$fs->fileExists($relativePath)) {
                throw new NotFoundHttpException('Export file no longer exists on remote filesystem.');
            }

            $contents = $fs->read($relativePath);
        } catch (Throwable $e) {
            Craft::warning(
                'AuditExportController failed to read remote export (handle ' . $filesystemHandle
                . '): ' . $e->getMessage(),
                'password-policy',
            );

            throw new NotFoundHttpException('Export file no longer exists on remote filesystem.');
        }

        $mimeType = $format === 'jsonl' ? 'application/x-ndjson' : 'text/csv';

        return Craft::$app->getResponse()->sendContentAsFile(
            $contents,
            $filename,
            ['mimeType' => $mimeType, 'inline' => false],
        );
    }
}
