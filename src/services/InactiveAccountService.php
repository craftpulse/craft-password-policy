<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\services;

use Carbon\Carbon;
use Craft;
use craft\db\Query;
use craft\db\Table;
use craft\elements\User;
use craftpulse\passwordpolicy\enums\InactiveAction;
use craftpulse\passwordpolicy\events\AccountInactiveEvent;
use craftpulse\passwordpolicy\PasswordPolicy;
use Throwable;
use yii\base\Component;
use yii\db\Expression;

/**
 * Class InactiveAccountService
 *
 * Detection + action engine for Feature 5 (inactive-account handling, Pro).
 *
 * "Inactive" is measured against `users.lastLoginDate`, falling back to
 * `users.dateCreated` for accounts that have never logged in. Inactivity is
 * "hasn't logged in", NOT "hasn't changed their password" — so this service
 * deliberately reads `lastLoginDate`, never `lastPasswordChangeDate`.
 *
 * Scope: ACTIVE dormant accounts only. The scan excludes accounts that are
 * already suspended (no point re-suspending), pending activation (Craft core
 * already purges those via `purgePendingUsersDuration`), or in the `locked`
 * state (a transient lockout, not dormancy). Admins ARE included — a dormant
 * admin account is exactly the kind of standing privilege compliance regimes
 * want disabled.
 *
 * The scan is OPERATOR-SCHEDULED, not automatic — operators wire
 * `password-policy/inactive/scan` to cron as the recommended production setup
 * (see `feedback_retention_gc_framing`). It is NOT a GC concern (GC prunes
 * plugin-owned retention tables; this actions live Craft user accounts).
 *
 * Three action modes ({@see InactiveAction}):
 *  - `report`  — no state change, no email. The CP report surface reads the
 *                detection query directly.
 *  - `notify`  — email the dormant user the seeded `inactive-account`
 *                template; no state change.
 *  - `suspend` — set `User::$suspended = true` (Craft's native, reversible
 *                suspension) and save. Never a deletion.
 *
 * Capture vs. exposure: detection + the three actions run on Pro. The
 * `account_inactive` AUDIT row is Enterprise-gated at the `applyAction()`
 * call site (the audit write itself is universal-capture-safe, but the
 * meaningful surfacing of that data is Enterprise — gate exposure, not
 * capture, per `project_audit_capture_principle.md`).
 *
 * Date handling: `Carbon` (service layer) for the threshold arithmetic —
 * never `DateTimeHelper` here, per the "DateTimeHelper in elements/queries,
 * Carbon in services" split.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class InactiveAccountService extends Component
{
    // Public Methods
    // =========================================================================

    /**
     * Returns a bounded `Query` over the IDs of active accounts whose last
     * activity (`lastLoginDate`, falling back to `dateCreated`) predates the
     * inactivity threshold.
     *
     * Returns a `Query` rather than a materialised array so the batched scan
     * job can stream IDs in slices without loading every dormant user into
     * memory at once. Callers that want models hydrate via `User::find()`
     * keyed on the returned IDs.
     *
     * The query is built additively and selects only `users.id`. No GROUP BY
     * is used (nothing is aggregated), so MySQL `ONLY_FULL_GROUP_BY` is a
     * non-issue. The COALESCE collapses the never-logged-in case onto
     * `dateCreated` so a brand-new account isn't flagged the instant it's
     * created — its `dateCreated` has to age past the threshold too.
     *
     * Exclusions (the "active dormant" scope):
     *  - `suspended = false`     — don't re-suspend an already-suspended user.
     *  - `pending = false`       — Craft core purges pending users separately.
     *  - `locked = false`        — a transient lockout is not dormancy.
     *  - element not soft-deleted / not a draft / not a revision (joined
     *    `elements` row).
     *
     * @param int $thresholdDays days of inactivity before an account counts
     *     as inactive. A non-positive value yields a query that matches
     *     nothing (defensive — never flags every user on a misconfig).
     * @return Query
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function findInactiveUsers(int $thresholdDays): Query
    {
        $query = (new Query())
            ->select(['users.id'])
            ->from(['users' => Table::USERS])
            ->innerJoin(['elements' => Table::ELEMENTS], '[[elements.id]] = [[users.id]]')
            ->where([
                'users.suspended' => false,
                'users.pending' => false,
                'users.locked' => false,
                'elements.dateDeleted' => null,
                'elements.draftId' => null,
                'elements.revisionId' => null,
            ]);

        if ($thresholdDays <= 0) {
            // Defensive: a misconfigured (or zero) threshold must never
            // flag the entire user base. Match nothing.
            return $query->andWhere('1 = 0');
        }

        $cutoff = Carbon::now('UTC')->subDays($thresholdDays)->format('Y-m-d H:i:s');

        // COALESCE(lastLoginDate, dateCreated) < cutoff — never-logged-in
        // accounts fall back to dateCreated.
        return $query->andWhere(
            ['<', new Expression('COALESCE([[users.lastLoginDate]], [[users.dateCreated]])'), $cutoff],
        );
    }

    /**
     * Returns a hydrated report of the currently-flagged inactive accounts
     * for the CP read surface — most-stale first.
     *
     * Each row carries the User element plus the resolved last-activity
     * timestamp (`lastLoginDate`, falling back to `dateCreated`) and the
     * computed days-inactive count. The list is bounded by `$limit` so the
     * report page never tries to render an unbounded dormant-user table.
     *
     * @param int $thresholdDays days of inactivity before an account counts
     *     as inactive
     * @param int $limit the maximum number of rows to return
     * @return array<int, array{user: User, lastActivity: ?\DateTime, daysInactive: int}>
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getInactiveReport(int $thresholdDays, int $limit = 500): array
    {
        $rows = $this->findInactiveUsers($thresholdDays)
            ->addSelect([
                'lastActivity' => new Expression('COALESCE([[users.lastLoginDate]], [[users.dateCreated]])'),
            ])
            ->orderBy(['lastActivity' => SORT_ASC])
            ->limit($limit)
            ->all();

        if (empty($rows)) {
            return [];
        }

        $userIds = array_map(static fn(array $row) => (int)$row['id'], $rows);
        $users = User::find()->id($userIds)->status(null)->indexBy('id')->all();

        $now = Carbon::now('UTC');
        $report = [];

        foreach ($rows as $row) {
            $userId = (int)$row['id'];
            $user = $users[$userId] ?? null;

            if ($user === null) {
                continue;
            }

            $lastActivity = null;
            $daysInactive = 0;

            if (!empty($row['lastActivity'])) {
                try {
                    $lastActivity = new \DateTime((string)$row['lastActivity'], new \DateTimeZone('UTC'));
                    $daysInactive = (int)$now->diffInDays(Carbon::instance($lastActivity));
                } catch (Throwable) {
                    $lastActivity = null;
                }
            }

            $report[] = [
                'user' => $user,
                'lastActivity' => $lastActivity,
                'daysInactive' => $daysInactive,
            ];
        }

        return $report;
    }

    /**
     * Applies the configured action to a single inactive user.
     *
     * `report` is a deliberate no-op — the report surface reads the
     * detection query directly, so there is no state to write. `notify`
     * enqueues nothing extra here; it sends synchronously through
     * `NotificationService` (the caller is already a batched job, so each
     * item is naturally isolated). `suspend` flips Craft's native
     * `suspended` flag and saves.
     *
     * Enterprise installs additionally capture an `account_inactive` audit
     * row (when `enableAuditLog` is on) — the audit write is fire-and-forget
     * and never blocks the action. The row carries only the action taken +
     * the dormancy source string, never PII (the allowlist in
     * `AuditLogService::ALLOWED_DETAILS_BY_EVENT` enforces this).
     *
     * @param User $user the inactive user to action
     * @param string $action one of {@see InactiveAction}'s values
     * @return void
     *
     * @throws Throwable when the suspend save throws (caller soft-fails)
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function applyAction(User $user, string $action): void
    {
        $resolved = InactiveAction::tryFrom($action) ?? InactiveAction::Report;

        match ($resolved) {
            InactiveAction::Report => null,
            InactiveAction::Notify => $this->_notify($user),
            InactiveAction::Suspend => $this->_suspend($user),
        };

        $this->_audit($user, $resolved);

        if (PasswordPolicy::$plugin->getSettings()->inactiveNotifyAdmin) {
            $this->_notifyAdmin($user, $resolved);
        }

        // Fire AFTER the action settled so listeners observe final state.
        // Triggered from the plugin instance (not the service) so listeners
        // attach to `PasswordPolicy::class` — matching every other plugin
        // event's convention.
        $plugin = PasswordPolicy::$plugin;
        if ($plugin->hasEventHandlers(PasswordPolicy::EVENT_ACCOUNT_INACTIVE)) {
            $plugin->trigger(PasswordPolicy::EVENT_ACCOUNT_INACTIVE, new AccountInactiveEvent([
                'user' => $user,
                'action' => $resolved->value,
            ]));
        }
    }

    // Private Methods
    // =========================================================================

    /**
     * Writes the Enterprise `account_inactive` audit row. No-op below
     * Enterprise — capture stays universal-safe, but the meaningful
     * surfacing of inactivity actions is an Enterprise affordance, so the
     * write is gated here at the call site (the AuditLogService allowlist
     * keeps the row PII-free regardless).
     *
     * @param User $user
     * @param InactiveAction $action
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _audit(User $user, InactiveAction $action): void
    {
        if (!PasswordPolicy::$plugin->getIsEnterprise()) {
            return;
        }

        PasswordPolicy::$plugin->getAuditLog()->logEvent(
            userId: (int)$user->id,
            event: 'account_inactive',
            details: [
                'action' => $action->value,
                'source' => 'inactive_scan',
            ],
            source: 'cli',
        );
    }

    /**
     * Sends the dormant user the `inactive-account` notification.
     *
     * @param User $user
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _notify(User $user): void
    {
        PasswordPolicy::$plugin->getNotification()->sendInactiveAccount($user);
    }

    /**
     * Alerts the admin that the scan actioned an inactive user. Routes
     * through the Enterprise admin-security-alert surface; on sub-Enterprise
     * installs `NotificationService::sendAdminSecurityAlert()` throws the
     * edition gate, which is swallowed here — the admin-alert toggle is a
     * best-effort add-on to the primary action, never a hard failure.
     *
     * @param User $user
     * @param InactiveAction $action
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _notifyAdmin(User $user, InactiveAction $action): void
    {
        try {
            PasswordPolicy::$plugin->getNotification()->sendAdminSecurityAlert(
                'account_inactive',
                [
                    'userId' => (int)$user->id,
                    'action' => $action->value,
                ],
            );
        } catch (Throwable $e) {
            PasswordPolicy::$plugin->log(
                'Inactive-account admin alert skipped for user {userId}: {error}',
                [
                    'userId' => $user->id,
                    'error' => $e->getMessage(),
                ],
            );
        }
    }

    /**
     * Suspends the user via Craft's native, reversible suspension.
     *
     * @param User $user
     * @return void
     *
     * @throws Throwable when the save throws
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _suspend(User $user): void
    {
        if ($user->suspended) {
            return;
        }

        $user->suspended = true;
        Craft::$app->getUsers()->suspendUser($user);
    }
}
