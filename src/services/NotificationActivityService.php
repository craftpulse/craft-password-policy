<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\services;

use craft\db\Query;
use craftpulse\passwordpolicy\enums\NotificationStatus;
use craftpulse\passwordpolicy\records\NotificationLogRecord;
use yii\base\Component;

/**
 * Class NotificationActivityService
 *
 * Read-side companion to {@see NotificationService}. Owns the queries
 * that drive the CP `Notifications → Activity` index, the per-user
 * notifications panel embedded in the Password Security screen, and
 * any CLI / SIEM consumer that needs to walk the notification log.
 *
 * Kept narrow on purpose — write paths stay in `NotificationService`
 * (so the audit invariant "row write happens on both branches" lives
 * in one place). This service is read-only.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class NotificationActivityService extends Component
{
    // Const Properties
    // =========================================================================

    /**
     * @var int default cap on per-user panel reads when the caller
     *     doesn't pass a limit. Sized to fit the Password Security
     *     screen without scrolling on any reasonable user.
     */
    public const DEFAULT_PER_USER_LIMIT = 10;

    /**
     * @var int default page size for the activity index — chosen to
     *     match Craft's element-index defaults so the table feels
     *     native. Operators rarely need to scroll past page one when
     *     looking for a specific recent send.
     */
    public const DEFAULT_PAGE_SIZE = 50;

    // Public Methods
    // =========================================================================

    /**
     * Returns the most recent notification log rows for a single
     * user, newest first. Used by the per-user panel on the Password
     * Security screen.
     *
     * @param int $userId
     * @param int $limit
     * @return NotificationLogRecord[]
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function recentForUser(int $userId, int $limit = self::DEFAULT_PER_USER_LIMIT): array
    {
        /** @var NotificationLogRecord[] $rows */
        $rows = NotificationLogRecord::find()
            ->where(['userId' => $userId])
            ->orderBy(['sentAt' => SORT_DESC, 'id' => SORT_DESC])
            ->limit($limit)
            ->all();

        return $rows;
    }

    /**
     * Returns a paginated slice of the activity log filtered by the
     * given criteria. Drives the CP activity index. Returns the rows
     * for the requested page plus the total row count so the index
     * can render Craft's paginate() output.
     *
     * Filter shape:
     *  - `userId` (int) — restrict to a single user
     *  - `notificationType` (string) — `expiry_reminder`, `breach_detected`, etc.
     *  - `status` (string) — `sent` / `failed`
     *  - `siteId` (int)
     *  - `dateFrom` (string `Y-m-d H:i:s`, UTC)
     *  - `dateTo` (string `Y-m-d H:i:s`, UTC)
     *
     * Unrecognised keys are ignored — defensive against typo-driven
     * empty result sets that look like data loss.
     *
     * @param array<string, mixed> $filters
     * @param int $page 1-indexed
     * @param int $perPage
     * @return array{rows: NotificationLogRecord[], total: int}
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function paginated(array $filters = [], int $page = 1, int $perPage = self::DEFAULT_PAGE_SIZE): array
    {
        $page = max(1, $page);
        $perPage = max(1, $perPage);

        $query = $this->_buildFilteredQuery($filters);

        $total = (int)(clone $query)->count();

        /** @var NotificationLogRecord[] $rows */
        $rows = $query
            ->orderBy(['sentAt' => SORT_DESC, 'id' => SORT_DESC])
            ->limit($perPage)
            ->offset(($page - 1) * $perPage)
            ->all();

        return [
            'rows' => $rows,
            'total' => $total,
        ];
    }

    /**
     * Returns a single notification log row by id, or null when not
     * found. Used by the activity detail screen + the resend
     * controller action.
     *
     * @param int $id
     * @return NotificationLogRecord|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getById(int $id): ?NotificationLogRecord
    {
        /** @var NotificationLogRecord|null $row */
        $row = NotificationLogRecord::findOne(['id' => $id]);

        return $row;
    }

    /**
     * Returns the distinct notification types currently present in
     * the log. Drives the type-filter dropdown on the activity index
     * — only show types that have ever had a row, so the dropdown
     * doesn't list dead options.
     *
     * @return string[]
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function knownTypes(): array
    {
        /** @var string[] $types */
        $types = (new Query())
            ->select('notificationType')
            ->from('{{%passwordpolicy_notification_log}}')
            ->distinct()
            ->orderBy(['notificationType' => SORT_ASC])
            ->column();

        return $types;
    }

    /**
     * Returns the count of failed notifications in the given window
     * (defaults to last 24 hours). Surfaced on the CP dashboard
     * sidebar badge so an operator notices delivery problems without
     * proactively visiting the Activity index.
     *
     * @param int $hoursBack
     * @return int
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function recentFailureCount(int $hoursBack = 24): int
    {
        $threshold = (new \DateTimeImmutable("-{$hoursBack} hours"))
            ->format('Y-m-d H:i:s');

        return (int)(new Query())
            ->from('{{%passwordpolicy_notification_log}}')
            ->where(['status' => NotificationStatus::Failed->value])
            ->andWhere(['>=', 'sentAt', $threshold])
            ->count();
    }

    // Private Methods
    // =========================================================================

    /**
     * Builds a `NotificationLogRecord::find()` query pre-filtered by
     * the supported filter keys. Centralised so the paginated read
     * and any future export path share the same filter shape.
     *
     * @param array<string, mixed> $filters
     * @return \yii\db\ActiveQuery
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _buildFilteredQuery(array $filters): \yii\db\ActiveQuery
    {
        $query = NotificationLogRecord::find();

        if (isset($filters['userId']) && $filters['userId'] !== '') {
            $query->andWhere(['userId' => (int)$filters['userId']]);
        }

        if (isset($filters['notificationType']) && $filters['notificationType'] !== '') {
            $query->andWhere(['notificationType' => $filters['notificationType']]);
        }

        if (isset($filters['status']) && $filters['status'] !== '') {
            // Reject unknown status strings defensively — a typo on the
            // filter form shouldn't return zero rows and look like the
            // log is empty.
            if (in_array($filters['status'], NotificationStatus::values(), true)) {
                $query->andWhere(['status' => $filters['status']]);
            }
        }

        if (isset($filters['siteId']) && $filters['siteId'] !== '') {
            $query->andWhere(['siteId' => (int)$filters['siteId']]);
        }

        if (isset($filters['dateFrom']) && $filters['dateFrom'] !== '') {
            $query->andWhere(['>=', 'sentAt', $filters['dateFrom']]);
        }

        if (isset($filters['dateTo']) && $filters['dateTo'] !== '') {
            $query->andWhere(['<=', 'sentAt', $filters['dateTo']]);
        }

        return $query;
    }
}
