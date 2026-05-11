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
use craftpulse\passwordpolicy\elements\NotificationLogElement;
use craftpulse\passwordpolicy\enums\NotificationStatus;
use yii\base\Component;

/**
 * Class NotificationActivityService
 *
 * Read-side companion to {@see NotificationService}. Returns
 * {@see NotificationLogElement} instances backing the per-user panel
 * embedded on the Password Security screen + any CLI / SIEM consumer
 * that needs to walk the notification log.
 *
 * The CP `Notifications → Activity` index renders via the native
 * element index (see
 * {@see \craftpulse\passwordpolicy\controllers\NotificationActivityController})
 * — this service exists for read paths the element index doesn't
 * cover (per-user list, distinct-types dropdown source, dashboard
 * failure count).
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

    // Public Methods
    // =========================================================================

    /**
     * Returns a single notification log element by id, or null when
     * not found. Used by the activity detail screen + the resend
     * controller action.
     *
     * @param int $id
     * @return NotificationLogElement|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getById(int $id): ?NotificationLogElement
    {
        /** @var NotificationLogElement|null $element */
        $element = NotificationLogElement::find()
            ->id($id)
            ->status(null)
            ->one();

        return $element;
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

    /**
     * Returns the most recent notification log elements for a single
     * user, newest first. Used by the per-user panel on the Password
     * Security screen.
     *
     * @param int $userId
     * @param int $limit
     * @return NotificationLogElement[]
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function recentForUser(int $userId, int $limit = self::DEFAULT_PER_USER_LIMIT): array
    {
        /** @var NotificationLogElement[] $elements */
        $elements = NotificationLogElement::find()
            ->userId($userId)
            ->status(null)
            ->orderBy(['passwordpolicy_notification_log.sentAt' => SORT_DESC])
            ->limit($limit)
            ->all();

        return $elements;
    }
}
