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
use craft\web\Controller;
use craftpulse\passwordpolicy\base\RequiresEditionTrait;
use craftpulse\passwordpolicy\PasswordPolicy;
use Generator;
use yii\web\ForbiddenHttpException;
use yii\web\NotFoundHttpException;
use yii\web\Response;

/**
 * Class ReportController
 *
 * CP web surface for the G3 compliance reports. Three report keys:
 *
 *  - `audit-summary` — totals + by event class.
 *  - `alert-activity` — alert-cooldown fires in the last 24 hours.
 *  - `retention-projection` — current retention windows + oldest rows.
 *
 * Two formats per report:
 *
 *  - `html` — renders `password-policy/_reports/<report>` using the CP
 *    layout for inline review + browser print-to-PDF (evidence packages).
 *  - `csv` — streams a downloadable CSV via
 *    `Craft::$app->getResponse()->stream()`. Yields rows lazily so the
 *    aggregator's bounded result sets never have to materialise as a
 *    single string in memory.
 *
 * Three lines of defense (mirror `AuditExportController`):
 *
 *  1. Utility doesn't register on Lite / Pro
 *     ({@see PasswordPolicy::_registerUtilities()}).
 *  2. URL rules register on every edition (the gate isn't at routing
 *     time), but `beforeAction()` rejects anyone not on Enterprise.
 *  3. Permission gate `pp:audit-view` — read access on the audit log
 *     is the read access on the reports.
 *
 * PDF intentionally deferred — the HTML reports are sufficient for
 * evidence packages via browser print-to-PDF per the Phase G plan.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class ReportController extends Controller
{
    // Traits
    // =========================================================================

    use RequiresEditionTrait;

    // Const Properties
    // =========================================================================

    /**
     * Recognised report keys. Unknown keys 404 — the URL rule's regex
     * accepts any `[\w-]+` so we can't constrain at routing.
     *
     * @var string[]
     */
    private const VALID_REPORTS = [
        'audit-summary',
        'alert-activity',
        'retention-projection',
    ];

    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @throws ForbiddenHttpException if the user lacks the required permission
     * @throws NotFoundHttpException if the edition is below Enterprise
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
        $this->requireEnterpriseEdition();

        $this->requirePermission('pp:audit-view');

        return true;
    }

    /**
     * Streams a CSV of the named report. Filename is suffixed with the
     * UTC date for evidence-package traceability.
     *
     * Yii's `Response::stream` callable contract: yield `[chunk, finished]`
     * tuples until the stream is exhausted. The aggregator's bounded
     * row counts mean this could just as well be a `FORMAT_RAW`
     * response, but streaming keeps the controller honest if a report
     * later grows beyond what's comfortable to materialise in memory.
     *
     * @param string $report
     * @return Response
     *
     * @throws NotFoundHttpException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionCsv(string $report): Response
    {
        $this->_assertValidReport($report);

        $filename = sprintf(
            'password-policy-%s-%s.csv',
            $report,
            Carbon::now('UTC')->format('Y-m-d'),
        );

        $payload = '';

        foreach ($this->_csvRowsForReport($report) as $row) {
            $payload .= $this->_formatCsvRow($row) . "\n";
        }

        $response = Craft::$app->getResponse();
        $response->headers->set('Content-Type', 'text/csv; charset=utf-8');
        $response->headers->set(
            'Content-Disposition',
            sprintf('attachment; filename="%s"', $filename),
        );
        $response->format = Response::FORMAT_RAW;
        $response->content = $payload;

        return $response;
    }

    /**
     * Renders the named report's HTML template using the CP layout.
     * Intended for inline review + browser print-to-PDF (evidence
     * packages).
     *
     * @param string $report
     * @return Response
     *
     * @throws NotFoundHttpException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionHtml(string $report): Response
    {
        $this->_assertValidReport($report);

        return $this->renderTemplate(
            sprintf('password-policy/_reports/%s', $report),
            [
                'aggregates' => PasswordPolicy::$plugin->getComplianceAggregates(),
                'report' => $report,
            ],
        );
    }

    // Private Methods
    // =========================================================================

    /**
     * 404s if the report key isn't recognised. Bare strings allow-listed
     * here rather than method-dispatched so a typo'd report key fails
     * loudly at the boundary rather than rendering an empty CSV body.
     *
     * @param string $report
     * @return void
     *
     * @throws NotFoundHttpException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _assertValidReport(string $report): void
    {
        if (!in_array($report, self::VALID_REPORTS, true)) {
            throw new NotFoundHttpException(sprintf(
                'Unknown report key: %s',
                $report,
            ));
        }
    }

    /**
     * Yields header + body rows for the named report. The shape stays
     * narrow on purpose — three reports' worth of rows each fit on a
     * single screen on the dashboard's spreadsheet handoff path.
     *
     * @param string $report
     * @return Generator<int, array<int, int|string>>
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _csvRowsForReport(string $report): Generator
    {
        $aggregates = PasswordPolicy::$plugin->getComplianceAggregates();

        switch ($report) {
            case 'audit-summary':
                $totals = $aggregates->getTotals();
                yield ['event', 'count'];
                yield ['__total__', $totals['total']];
                yield ['__last30Days__', $totals['last30Days']];
                foreach ($totals['byEventClass'] as $eventClass => $count) {
                    yield [$eventClass, $count];
                }
                return;

            case 'alert-activity':
                $activity = $aggregates->getAlertCooldownActivity();
                yield ['eventClass', 'fires_last24h'];
                foreach ($activity['byEventClass'] as $eventClass => $count) {
                    yield [$eventClass, $count];
                }
                yield ['__total__', $activity['last24h']];
                return;

            case 'retention-projection':
                $retention = $aggregates->getRetentionStatus();
                yield ['log', 'retentionDays', 'oldestAge', 'projectedNextPrune'];
                yield [
                    'audit_log',
                    $retention['auditLogRetentionDays'],
                    $retention['auditLogOldestAge'] ?? '',
                    $retention['auditLogProjectedNextPrune']?->format('Y-m-d H:i:s') ?? '',
                ];
                yield [
                    'notification_log',
                    $retention['notificationLogRetentionDays'],
                    $retention['notificationLogOldestAge'] ?? '',
                    '',
                ];
                return;
        }
    }

    /**
     * Formats a single CSV row per RFC 4180 — fields containing commas,
     * double quotes, or newlines are double-quote-escaped.
     *
     * @param array<int, int|string> $row
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _formatCsvRow(array $row): string
    {
        $escaped = [];

        foreach ($row as $value) {
            $value = (string)$value;

            if (
                str_contains($value, ',')
                || str_contains($value, '"')
                || str_contains($value, "\n")
            ) {
                $value = '"' . str_replace('"', '""', $value) . '"';
            }

            $escaped[] = $value;
        }

        return implode(',', $escaped);
    }
}
