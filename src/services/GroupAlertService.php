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

use Carbon\Carbon;
use craft\elements\User;
use craft\helpers\StringHelper;
use craftpulse\passwordpolicy\models\GroupAlertSubscriptionModel;
use craftpulse\passwordpolicy\records\GroupAlertSubscriptionRecord;
use yii\base\Component;

/**
 * Class GroupAlertService
 *
 * Owns the `passwordpolicy_group_alert_subscriptions` read + write path for
 * Feature 3 (per-group alerts, Pro). A subscription routes a COPY of a
 * `breach_detected` / `new_device` alert to a group-designated security
 * contact, in addition to the end-user's own alert.
 *
 * **Resolution hazard (load-bearing).** {@see recipientsForUser()} resolves
 * recipients from the affected user's ACTUAL resolved group set
 * (`$user->getGroups()`) at alert time — NEVER from a global setting. This
 * is the documented per-group-resolution bug class
 * (`project_per_group_resolution_hazard.md`): re-reading a global instead of
 * the resolved per-user set silently bypasses the paid per-group feature. A
 * user in groups A + B that both subscribe a contact gets that contact ONCE
 * (the recipient set is de-duplicated across the user's groups).
 *
 * Storage is edition-independent (subscriptions can be configured on any
 * edition); the dispatch that consumes {@see recipientsForUser()} is
 * Pro-gated one layer up at the listener / `NotificationService`.
 *
 * Date handling: `Carbon` (service layer) for the timestamps written to the
 * table — never `DateTimeHelper` here, per the "DateTimeHelper in
 * elements/queries, Carbon in services" split.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class GroupAlertService extends Component
{
    // Public Methods
    // =========================================================================

    /**
     * Returns every subscription, ordered by group then event then
     * recipient — the read surface for the CP editor.
     *
     * @return GroupAlertSubscriptionModel[]
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getAllSubscriptions(): array
    {
        /** @var GroupAlertSubscriptionRecord[] $records */
        $records = GroupAlertSubscriptionRecord::find()
            ->orderBy(['groupId' => SORT_ASC, 'eventType' => SORT_ASC, 'recipientEmail' => SORT_ASC])
            ->all();

        return array_map(
            static fn(GroupAlertSubscriptionRecord $record): GroupAlertSubscriptionModel => GroupAlertSubscriptionModel::fromRecord($record),
            $records,
        );
    }

    /**
     * Returns the distinct enabled recipient emails, paired with the
     * resolving group id, for the alert of `$eventType` triggered by
     * `$user`.
     *
     * **Resolved, not global.** Recipients come from `$user->getGroups()` —
     * the user's actual group membership at alert time — intersected with
     * enabled subscriptions for `$eventType`. Re-reading a global setting
     * here would silently no-op the per-group feature
     * (`project_per_group_resolution_hazard.md`).
     *
     * The return is keyed by recipient email so a contact subscribed via
     * two of the user's groups is alerted ONCE; the value is the FIRST
     * resolving group id, used by the caller as the cooldown-key component
     * (`group:{groupId}:{eventType}`) so a burst against one group's members
     * throttles per group, not per recipient.
     *
     * @param User $user the user who triggered the alert
     * @param string $eventType `breach_detected` or `new_device`
     * @return array<string, int> recipient email => resolving group id
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function recipientsForUser(User $user, string $eventType): array
    {
        $groupIds = array_map(
            static fn($group): int => (int)$group->id,
            $user->getGroups(),
        );

        if ($groupIds === []) {
            return [];
        }

        /** @var GroupAlertSubscriptionRecord[] $records */
        $records = GroupAlertSubscriptionRecord::find()
            ->where([
                'groupId' => $groupIds,
                'eventType' => $eventType,
                'enabled' => true,
            ])
            ->all();

        $recipients = [];

        foreach ($records as $record) {
            $email = strtolower(trim((string)$record->recipientEmail));

            if ($email === '') {
                continue;
            }

            // First resolving group wins — a contact subscribed via two of
            // the user's groups is alerted once, keyed on the first group.
            if (!isset($recipients[$email])) {
                $recipients[$email] = (int)$record->groupId;
            }
        }

        return $recipients;
    }

    /**
     * Replaces the full subscription set with `$rows` using diff-on-save
     * semantics (matches the blocklist editor). Numeric `rowId` keys whose
     * values are unchanged are kept; everything else (new rows, edited
     * existing rows) is inserted, and existing ids not present in the
     * submitted set are deleted.
     *
     * Each row must carry `groupId`, `eventType`, and `recipientEmail`;
     * `enabled` defaults to true when absent. Rows missing a required field
     * are skipped (the editor sends incomplete add-rows as the admin types).
     *
     * @param array<int|string, array<string, mixed>> $rows the editable-table POST
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function saveSubscriptions(array $rows): void
    {
        $existing = [];
        foreach (GroupAlertSubscriptionRecord::find()->all() as $record) {
            /** @var GroupAlertSubscriptionRecord $record */
            $existing[(int)$record->id] = $this->_signature(
                (int)$record->groupId,
                (string)$record->eventType,
                (string)$record->recipientEmail,
                (bool)$record->enabled,
            );
        }

        $keepIds = [];
        $newRows = [];

        foreach ($rows as $rowId => $row) {
            $groupId = (int)($row['groupId'] ?? 0);
            $eventType = trim((string)($row['eventType'] ?? ''));
            $email = strtolower(trim((string)($row['recipientEmail'] ?? '')));
            $enabled = !empty($row['enabled']);

            if ($groupId <= 0 || $eventType === '' || $email === '') {
                continue;
            }

            $signature = $this->_signature($groupId, $eventType, $email, $enabled);

            if (is_numeric($rowId) && ($existing[(int)$rowId] ?? null) === $signature) {
                $keepIds[] = (int)$rowId;
            } else {
                $newRows[] = [
                    'groupId' => $groupId,
                    'eventType' => $eventType,
                    'recipientEmail' => $email,
                    'enabled' => $enabled,
                ];
            }
        }

        foreach (array_diff(array_keys($existing), $keepIds) as $idToRemove) {
            GroupAlertSubscriptionRecord::deleteAll(['id' => $idToRemove]);
        }

        foreach ($newRows as $row) {
            $this->_insert($row['groupId'], $row['eventType'], $row['recipientEmail'], $row['enabled']);
        }
    }

    // Private Methods
    // =========================================================================

    /**
     * Inserts a single subscription row with current UTC timestamps.
     *
     * @param int $groupId
     * @param string $eventType
     * @param string $recipientEmail stored lowercase
     * @param bool $enabled
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _insert(int $groupId, string $eventType, string $recipientEmail, bool $enabled): void
    {
        $now = Carbon::now('UTC')->format('Y-m-d H:i:s');

        $record = new GroupAlertSubscriptionRecord();
        $record->groupId = $groupId;
        $record->eventType = $eventType;
        $record->recipientEmail = $recipientEmail;
        $record->enabled = $enabled;
        $record->dateCreated = $now;
        $record->dateUpdated = $now;
        $record->uid = StringHelper::UUID();
        $record->save(false);
    }

    /**
     * Builds the value signature used by `saveSubscriptions()` to detect
     * unchanged rows. A keep is only a keep when every column matches.
     *
     * @param int $groupId
     * @param string $eventType
     * @param string $recipientEmail
     * @param bool $enabled
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _signature(int $groupId, string $eventType, string $recipientEmail, bool $enabled): string
    {
        return implode('|', [
            $groupId,
            $eventType,
            strtolower(trim($recipientEmail)),
            $enabled ? '1' : '0',
        ]);
    }
}
