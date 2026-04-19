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

use craft\console\Controller;
use craft\db\Query;
use craft\helpers\Json;
use craftpulse\passwordpolicy\PasswordPolicy;
use yii\console\ExitCode;

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
    // Public Properties
    // =========================================================================

    /**
     * @var int number of days of audit entries to retain
     */
    public int $days = 365;

    /**
     * @var string export format: csv or json
     */
    public string $format = 'csv';

    /**
     * @var bool whether to include user email in export
     */
    public bool $includeUserDetails = false;

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
        }

        return $options;
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
     * Exports audit log entries to stdout.
     *
     * Output defaults to stdout for secure piping to your SIEM or
     * log aggregation system.
     *
     * @return int
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionExport(): int
    {
        $threshold = (new \DateTime())->modify("-{$this->days} days")->format('Y-m-d H:i:s');

        $query = (new Query())
            ->from('{{%passwordpolicy_audit_log}}')
            ->where(['>=', 'dateCreated', $threshold])
            ->orderBy(['dateCreated' => SORT_ASC]);

        $entries = $query->all();

        if (empty($entries)) {
            $this->stderr("No entries found within the specified period.\n");
            return ExitCode::OK;
        }

        // Optionally resolve user emails
        if ($this->includeUserDetails) {
            $userIds = array_filter(array_unique(array_column($entries, 'userId')));
            $users = [];
            if (!empty($userIds)) {
                $users = (new Query())
                    ->select(['id', 'email'])
                    ->from(\craft\db\Table::USERS)
                    ->where(['id' => $userIds])
                    ->indexBy('id')
                    ->all();
            }

            foreach ($entries as &$entry) {
                $entry['userEmail'] = $users[$entry['userId']]['email'] ?? null;
            }
            unset($entry);
        }

        match ($this->format) {
            'json' => $this->_exportJson($entries),
            default => $this->_exportCsv($entries),
        };

        return ExitCode::OK;
    }

    // Private Methods
    // =========================================================================

    /**
     * Outputs entries as CSV to stdout.
     *
     * @param array $entries
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _exportCsv(array $entries): void
    {
        $headers = ['id', 'userId', 'event', 'outcome', 'source', 'dateCreated'];

        if ($this->includeUserDetails) {
            $headers[] = 'userEmail';
        }

        $this->stdout(implode(',', $headers) . "\n");

        foreach ($entries as $entry) {
            $row = [];
            foreach ($headers as $header) {
                $value = $entry[$header] ?? '';
                // Escape CSV values
                if (str_contains((string)$value, ',') || str_contains((string)$value, '"')) {
                    $value = '"' . str_replace('"', '""', (string)$value) . '"';
                }
                $row[] = $value;
            }
            $this->stdout(implode(',', $row) . "\n");
        }
    }

    /**
     * Outputs entries as JSON to stdout.
     *
     * @param array $entries
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _exportJson(array $entries): void
    {
        $this->stdout(Json::encode($entries, JSON_PRETTY_PRINT) . "\n");
    }
}
