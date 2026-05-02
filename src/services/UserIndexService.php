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

use Craft;
use craft\db\Query;
use craft\db\Table;
use craft\elements\User;
use craft\helpers\Html;
use craftpulse\passwordpolicy\enums\ChangeReason;
use craftpulse\passwordpolicy\PasswordPolicy;
use DateInterval;
use DateTime;
use DateTimeInterface;
use yii\base\Component;

/**
 * Class UserIndexService
 *
 * Powers the password-policy columns on the Users element index — the
 * headline Lite/Pro affordance for "who's expired, who's breached, who
 * hasn't changed in a year, at a glance." Owns column registration,
 * sort-option mapping, per-cell HTML rendering, and the once-per-request
 * batched preload that keeps cell rendering from collapsing into N
 * queries per visible user.
 *
 * Architecture:
 *
 *  - **Capture vs. exposure.** The Users index is the EXPOSURE side of
 *    the audit-capture principle (memory `project_audit_capture_principle.md`).
 *    Plugin-edition gates on the Pro-tier columns and the Craft-edition
 *    gate on the policy columns are intentional — the underlying
 *    `passwordpolicy_user_state` and `passwordpolicy_password_history`
 *    rows are written on every edition; only the surfacing varies.
 *
 *  - **Preload over per-cell queries.** The CP renders all visible users
 *    in a single page hit, then dispatches a `DefineAttributeHtmlEvent`
 *    per (user, attribute) pair. Naïve column readers issue O(visibleUsers
 *    × columns) queries. {@see self::preloadForUsers()} runs at most five
 *    bounded queries to populate {@see self::$_cache} and every cell read
 *    becomes an array lookup.
 *
 *  - **Direct DB scalar reads for non-selected User columns.**
 *    `craft\elements\db\UserQuery::beforePrepare()` does not select
 *    `lastPasswordChangeDate` or `passwordResetRequired` (memory gap #9
 *    plus D1's same-class find on `passwordResetRequired`). The preload
 *    pulls both via one direct `Table::USERS` query rather than reading
 *    them off the cached User element.
 *
 *  - **Status priority order** for the composite badge:
 *    1. breached (red) — within {@see self::BREACHED_RECENT_DAYS} of
 *       `user_state.lastBreachDetectedAt`
 *    2. expired (red) — past the resolved expiry window
 *    3. reset_required (orange) — `users.passwordResetRequired = true`
 *    4. policy_drift (yellow) — Pro+/Team+ only; most-recent history
 *       row's `policySnapshot` !== current resolver result
 *    5. expiring (yellow) — within {@see self::EXPIRING_SOON_DAYS} of
 *       expiry
 *    6. never_changed (gray) — no history row at all
 *    7. ok (green) — none of the above
 *
 *  - **Edition matrix:**
 *    - Lite + any Craft edition: columns 1-6 (no breached, no policy
 *      columns).
 *    - Pro + Solo: columns 1-7 (breached); the two policy columns drop
 *      because Solo can't have user groups.
 *    - Pro + Team or Pro: all 9 columns.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class UserIndexService extends Component
{
    // Const Properties
    // =========================================================================

    /**
     * @var int days within which a `lastBreachDetectedAt` timestamp
     *     contributes "breached" to the composite status badge. Beyond
     *     this window, the badge falls through to the next state — the
     *     incident is still surfaced via the `passwordpolicy_breached`
     *     column (which has no recent gate) but doesn't dominate the
     *     status cell anymore. Hardcoded for 5.2.0; promote to a setting
     *     if customers ask for it.
     */
    public const BREACHED_RECENT_DAYS = 90;

    /**
     * @var int days before expiry that contribute the "expiring" state to
     *     the composite status badge. Hardcoded for 5.2.0; promote to a
     *     setting if customers ask.
     */
    public const EXPIRING_SOON_DAYS = 7;

    /**
     * @var string[] all attribute keys this service registers.
     *     Order is the order they appear in the column picker.
     */
    public const ATTRIBUTE_KEYS = [
        self::ATTR_LAST_CHANGE,
        self::ATTR_DAYS_UNTIL_EXPIRY,
        self::ATTR_EXPIRED,
        self::ATTR_RESET_REQUIRED,
        self::ATTR_STATUS,
        self::ATTR_LAST_CHANGE_REASON,
        self::ATTR_BREACHED,
        self::ATTR_POLICY_DRIFT,
        self::ATTR_GROUP_POLICIES,
    ];

    public const ATTR_BREACHED = 'passwordpolicy_breached';

    public const ATTR_DAYS_UNTIL_EXPIRY = 'passwordpolicy_daysUntilExpiry';

    public const ATTR_EXPIRED = 'passwordpolicy_expired';

    public const ATTR_GROUP_POLICIES = 'passwordpolicy_groupPolicies';

    public const ATTR_LAST_CHANGE = 'passwordpolicy_lastChange';

    public const ATTR_LAST_CHANGE_REASON = 'passwordpolicy_lastChangeReason';

    public const ATTR_POLICY_DRIFT = 'passwordpolicy_policyDrift';

    public const ATTR_RESET_REQUIRED = 'passwordpolicy_resetRequired';

    public const ATTR_STATUS = 'passwordpolicy_status';

    /**
     * Possible composite-status values, in priority order. Index tests
     * reach into this list to assert the priority contract.
     *
     * @var string[]
     */
    public const STATUS_ORDER = [
        self::STATUS_BREACHED,
        self::STATUS_EXPIRED,
        self::STATUS_RESET_REQUIRED,
        self::STATUS_POLICY_DRIFT,
        self::STATUS_EXPIRING,
        self::STATUS_NEVER_CHANGED,
        self::STATUS_OK,
    ];

    public const STATUS_BREACHED = 'breached';

    public const STATUS_EXPIRED = 'expired';

    public const STATUS_EXPIRING = 'expiring';

    public const STATUS_NEVER_CHANGED = 'never_changed';

    public const STATUS_OK = 'ok';

    public const STATUS_POLICY_DRIFT = 'policy_drift';

    public const STATUS_RESET_REQUIRED = 'reset_required';

    // Private Properties
    // =========================================================================

    /**
     * Per-request cache of preloaded user state. Populated by
     * {@see self::preloadForUsers()}; consumed by
     * {@see self::renderAttributeHtml()}. Each entry has the shape:
     *
     *     [
     *         'lastChange' => ?DateTime,
     *         'passwordResetRequired' => bool,
     *         'lastHistoryReason' => ?ChangeReason,
     *         'lastHistoryPolicy' => ?string,
     *         'lastBreachAt' => ?DateTime,
     *         'currentPolicyId' => ?string,
     *         'appliedPolicies' => string[],
     *     ]
     *
     * @var array<int, array<string, mixed>>
     */
    private array $_cache = [];

    /**
     * @var bool flag set after the first {@see self::preloadForUsers()}
     *     call, used by the listener to avoid repeating preload when
     *     multiple `EVENT_DEFINE_ATTRIBUTE_HTML` callbacks fire for the
     *     same render cycle. Safe to leave true across the request — the
     *     cache is keyed by userId, so additional preload calls with new
     *     IDs still populate correctly.
     */
    private bool $_preloaded = false;

    // Public Methods
    // =========================================================================

    /**
     * Returns the composite-status state for the given user using the
     * configured priority order. Pure function over the preloaded cache;
     * relies on {@see self::preloadForUsers()} having run first.
     *
     * Exposed so condition rules and tests can pin the status without
     * piggybacking on the HTML cell. Returns one of the
     * {@see self::STATUS_*} constants.
     *
     * @param User $user
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getStatusForUser(User $user): string
    {
        $cached = $this->_getCachedForUser((int)$user->id);
        $plugin = PasswordPolicy::$plugin;
        $isPolicyDriftEligible = $plugin->getIsPro() && $plugin->isCraftTeamOrBetter();

        // 1. Breached (recent window)
        if ($cached['lastBreachAt'] instanceof DateTime) {
            $cutoff = (new DateTime('now'))->modify('-' . self::BREACHED_RECENT_DAYS . ' days');
            if ($cached['lastBreachAt'] >= $cutoff) {
                return self::STATUS_BREACHED;
            }
        }

        $expiryThreshold = $this->_getExpiryThreshold();
        $lastChange = $cached['lastChange'];

        // 2. Expired
        if ($expiryThreshold !== null && $lastChange instanceof DateTime) {
            if ($lastChange < $expiryThreshold) {
                return self::STATUS_EXPIRED;
            }
        }

        // 3. Reset required
        if ($cached['passwordResetRequired']) {
            return self::STATUS_RESET_REQUIRED;
        }

        // 4. Policy drift (Pro + Team+)
        if ($isPolicyDriftEligible && $this->_hasPolicyDrift($cached)) {
            return self::STATUS_POLICY_DRIFT;
        }

        // 5. Expiring soon
        if ($expiryThreshold !== null && $lastChange instanceof DateTime) {
            $soonCutoff = $expiryThreshold->getTimestamp() + (self::EXPIRING_SOON_DAYS * 86400);
            if ($lastChange->getTimestamp() < $soonCutoff) {
                return self::STATUS_EXPIRING;
            }
        }

        // 6. Never changed
        if ($lastChange === null) {
            return self::STATUS_NEVER_CHANGED;
        }

        // 7. OK
        return self::STATUS_OK;
    }

    /**
     * Returns the table-attribute registration array for
     * `Element::EVENT_REGISTER_TABLE_ATTRIBUTES`. Edition gates apply —
     * Lite installs get the six baseline columns, Pro installs add the
     * breached column on every Craft edition, and Team or Pro Craft
     * installs additionally get the policy-drift + applied-policies
     * columns.
     *
     * @return array<string, array<string, string>>
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getAttributesForRegistration(): array
    {
        $plugin = PasswordPolicy::$plugin;
        $attributes = [
            self::ATTR_LAST_CHANGE => ['label' => Craft::t('password-policy', 'Last password change')],
            self::ATTR_DAYS_UNTIL_EXPIRY => ['label' => Craft::t('password-policy', 'Days until expiry')],
            self::ATTR_EXPIRED => ['label' => Craft::t('password-policy', 'Expired')],
            self::ATTR_RESET_REQUIRED => ['label' => Craft::t('password-policy', 'Reset required')],
            self::ATTR_STATUS => ['label' => Craft::t('password-policy', 'Password status')],
            self::ATTR_LAST_CHANGE_REASON => ['label' => Craft::t('password-policy', 'Last change reason')],
        ];

        if ($plugin->getIsPro()) {
            $attributes[self::ATTR_BREACHED] = ['label' => Craft::t('password-policy', 'Breached')];

            if ($plugin->isCraftTeamOrBetter()) {
                $attributes[self::ATTR_POLICY_DRIFT] = ['label' => Craft::t('password-policy', 'Policy drift')];
                $attributes[self::ATTR_GROUP_POLICIES] = ['label' => Craft::t('password-policy', 'Applied policies')];
            }
        }

        return $attributes;
    }

    /**
     * Returns the sort-option mapping for `Element::EVENT_REGISTER_SORT_OPTIONS`.
     * Only the columns whose underlying expression is cheap to ORDER BY
     * are sortable — composite or subquery-based columns
     * (status, lastChangeReason, breached, policy*) are excluded so the
     * Users index doesn't grow surprising query costs.
     *
     * @return array<string, string>
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getSortOptions(): array
    {
        return [
            self::ATTR_LAST_CHANGE => Craft::t('password-policy', 'Last password change'),
            self::ATTR_DAYS_UNTIL_EXPIRY => Craft::t('password-policy', 'Days until expiry'),
            self::ATTR_EXPIRED => Craft::t('password-policy', 'Expired'),
            self::ATTR_RESET_REQUIRED => Craft::t('password-policy', 'Reset required'),
        ];
    }

    /**
     * Returns the SQL ORDER BY mapping for an attribute key, or null if
     * the attribute is not sortable. Listener handlers translate the
     * configured sort-option keys into the `attribute => column[]` shape
     * Craft expects.
     *
     * @param string $attribute
     * @return array<string, int>|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getSortMapping(string $attribute): ?array
    {
        return match ($attribute) {
            self::ATTR_LAST_CHANGE,
            self::ATTR_DAYS_UNTIL_EXPIRY,
            self::ATTR_EXPIRED => [
                'users.lastPasswordChangeDate' => SORT_ASC,
            ],
            self::ATTR_RESET_REQUIRED => [
                'users.passwordResetRequired' => SORT_DESC,
            ],
            default => null,
        };
    }

    /**
     * Renders a cell HTML for a single (user, attribute) pair. Pulls
     * exclusively from the preload cache; if {@see self::preloadForUsers()}
     * wasn't called, returns an empty string and logs a warning rather
     * than re-running the preload per-cell (which would defeat the whole
     * batching strategy).
     *
     * @param User $user
     * @param string $attribute
     * @return string|null cell HTML, or null when the attribute isn't ours
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function renderAttributeHtml(User $user, string $attribute): ?string
    {
        if (!in_array($attribute, self::ATTRIBUTE_KEYS, true)) {
            return null;
        }

        if ($user->id === null) {
            return '';
        }

        $cached = $this->_getCachedForUser($user->id);

        return match ($attribute) {
            self::ATTR_LAST_CHANGE => $this->_renderLastChange($cached),
            self::ATTR_DAYS_UNTIL_EXPIRY => $this->_renderDaysUntilExpiry($cached),
            self::ATTR_EXPIRED => $this->_renderExpired($cached),
            self::ATTR_RESET_REQUIRED => $this->_renderResetRequired($cached),
            self::ATTR_STATUS => $this->_renderStatus($user),
            self::ATTR_LAST_CHANGE_REASON => $this->_renderLastChangeReason($cached),
            self::ATTR_BREACHED => $this->_renderBreached($cached),
            self::ATTR_POLICY_DRIFT => $this->_renderPolicyDrift($cached),
            self::ATTR_GROUP_POLICIES => $this->_renderGroupPolicies($cached),
        };
    }

    /**
     * Populates {@see self::$_cache} for the given user IDs in at most
     * five bounded queries (regardless of count). Idempotent — calling
     * with previously-loaded IDs is a cheap re-fetch; calling with a
     * superset of previously-loaded IDs adds the new ones.
     *
     * Query budget:
     *
     *  1. `users.lastPasswordChangeDate` + `users.passwordResetRequired`
     *     for all userIds (single SELECT against `Table::USERS`).
     *  2. Most-recent `passwordpolicy_password_history` row per userId
     *     (subquery on `MAX(dateCreated) GROUP BY userId`).
     *  3. `passwordpolicy_user_state.lastBreachDetectedAt` for all userIds.
     *  4. (Pro + Team or higher only) Per-user resolved policy ID — one
     *     `PolicyResolverService::resolveForUser()` call per user, but
     *     gated so it's a no-op on Lite or Solo.
     *  5. (Pro + Team or higher only) Per-user applied policy names —
     *     populated alongside (4) since the resolver consults the same
     *     groups.
     *
     * Steps 4 and 5 currently iterate per-user because the resolver is
     * shaped around a single User. If the suite grows past hundreds of
     * users per page (operator pain point), wrap them in a batched
     * resolver call — for v5.2.0, the per-user cost is acceptable and
     * the resolver's own caching helps.
     *
     * @param int[] $userIds
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function preloadForUsers(array $userIds): void
    {
        $userIds = array_values(array_unique(array_map('intval', $userIds)));
        $userIds = array_filter($userIds, fn(int $id) => $id > 0);

        // Filter out users already in cache — preload is idempotent and
        // additive; calling it twice with overlapping IDs should produce
        // the same query count as one call with the union.
        $newIds = array_values(array_filter(
            $userIds,
            fn(int $id) => !isset($this->_cache[$id]),
        ));

        if (empty($newIds)) {
            $this->_preloaded = true;

            return;
        }

        // Initialise empty entries so cell renderers always have a row
        // even if a downstream query returns nothing.
        foreach ($newIds as $userId) {
            $this->_cache[$userId] = [
                'lastChange' => null,
                'passwordResetRequired' => false,
                'lastHistoryReason' => null,
                'lastHistoryPolicy' => null,
                'lastBreachAt' => null,
                'currentPolicyId' => null,
                'appliedPolicies' => [],
            ];
        }

        $this->_preloadUserColumns($newIds);
        $this->_preloadHistoryRows($newIds);
        $this->_preloadBreachState($newIds);
        $this->_preloadResolvedPolicies($newIds);

        $this->_preloaded = true;
    }

    /**
     * Resets the preload cache and flag. Test affordance — production
     * code never needs to clear cache mid-request because the cache is
     * keyed by userId and additive.
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function resetCache(): void
    {
        $this->_cache = [];
        $this->_preloaded = false;
    }

    // Private Methods
    // =========================================================================

    /**
     * Returns the active expiry threshold from settings, or null when
     * expiry isn't configured. Mirrors `RetentionService` / the existing
     * `PasswordExpiredConditionRule` logic — kept inline rather than
     * factored out so the service has no cross-service dependency.
     *
     * @return DateTime|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _getExpiryThreshold(): ?DateTime
    {
        $settings = PasswordPolicy::$plugin->getSettings();

        if ($settings->expiryAmount === null || $settings->expiryAmount <= 0) {
            return null;
        }

        $interval = match ($settings->expiryPeriod) {
            'day' => "P{$settings->expiryAmount}D",
            'week' => "P{$settings->expiryAmount}W",
            'month' => "P{$settings->expiryAmount}M",
            'year' => "P{$settings->expiryAmount}Y",
            default => null,
        };

        if ($interval === null) {
            return null;
        }

        return (new DateTime('now'))->sub(new DateInterval($interval));
    }

    /**
     * Returns the cached row for a userId, or a defaulted empty row when
     * preload didn't include this user. Defensive — if a renderer fires
     * for a user the listener missed, we render an empty cell rather
     * than crash.
     *
     * @param int $userId
     * @return array<string, mixed>
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _getCachedForUser(int $userId): array
    {
        if (!isset($this->_cache[$userId])) {
            if (!$this->_preloaded) {
                Craft::warning(
                    "UserIndexService cell renderer fired for user {$userId} without prior preloadForUsers() — falling back to per-user query.",
                    'password-policy',
                );
            }

            // Backfill on demand. Single-user preload is one query
            // burst, not five; the warning above flags that the listener
            // is wired wrong.
            $this->preloadForUsers([$userId]);
        }

        return $this->_cache[$userId];
    }

    /**
     * Returns whether the user's most-recent password history row's
     * `policySnapshot` differs from their currently resolved policy.
     * Both null is "not drifted" (never had a policy, still doesn't).
     *
     * @param array<string, mixed> $cached
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _hasPolicyDrift(array $cached): bool
    {
        $snapshot = $cached['lastHistoryPolicy'];
        $current = $cached['currentPolicyId'];

        if ($snapshot === null && $current === null) {
            return false;
        }

        return $snapshot !== $current;
    }

    /**
     * Preloads `passwordpolicy_user_state.lastBreachDetectedAt` for all
     * userIds in one query.
     *
     * @param int[] $userIds
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _preloadBreachState(array $userIds): void
    {
        $rows = (new Query())
            ->select(['userId', 'lastBreachDetectedAt'])
            ->from('{{%passwordpolicy_user_state}}')
            ->where(['userId' => $userIds])
            ->all();

        foreach ($rows as $row) {
            $userId = (int)$row['userId'];

            if (!isset($this->_cache[$userId])) {
                continue;
            }

            $this->_cache[$userId]['lastBreachAt'] = $this->_toDateTime($row['lastBreachDetectedAt']);
        }
    }

    /**
     * Preloads the most-recent password history row per userId in one
     * query, joining on `(userId, MAX(dateCreated))`. Populates the
     * `lastHistoryReason` and `lastHistoryPolicy` slots.
     *
     * @param int[] $userIds
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _preloadHistoryRows(array $userIds): void
    {
        $latestSubquery = (new Query())
            ->select(['userId', 'maxDate' => 'MAX([[dateCreated]])'])
            ->from('{{%passwordpolicy_password_history}}')
            ->where(['userId' => $userIds])
            ->groupBy(['userId']);

        $rows = (new Query())
            ->select(['h.userId', 'h.changeReason', 'h.policySnapshot'])
            ->from(['h' => '{{%passwordpolicy_password_history}}'])
            ->innerJoin(
                ['latest' => $latestSubquery],
                '[[h.userId]] = [[latest.userId]] AND [[h.dateCreated]] = [[latest.maxDate]]',
            )
            ->all();

        foreach ($rows as $row) {
            $userId = (int)$row['userId'];

            if (!isset($this->_cache[$userId])) {
                continue;
            }

            $reason = $row['changeReason'] !== null ? ChangeReason::tryFrom((string)$row['changeReason']) : null;
            $this->_cache[$userId]['lastHistoryReason'] = $reason;
            $this->_cache[$userId]['lastHistoryPolicy'] = $row['policySnapshot'] ?? null;
        }
    }

    /**
     * Preloads the resolved current policy + applied policy name list per
     * user. Skipped when not Pro or when Craft is on Solo (no groups).
     * Iterates per-user — the resolver isn't shaped for batched reads —
     * but gated so Lite/Solo installs pay nothing.
     *
     * @param int[] $userIds
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _preloadResolvedPolicies(array $userIds): void
    {
        $plugin = PasswordPolicy::$plugin;

        if (!$plugin->getIsPro() || !$plugin->isCraftTeamOrBetter()) {
            return;
        }

        $users = User::find()
            ->id($userIds)
            ->status(null)
            ->all();

        $policyService = $plugin->getPolicies();

        foreach ($users as $user) {
            if ($user->id === null || !isset($this->_cache[$user->id])) {
                continue;
            }

            $groups = $user->getGroups();

            if (empty($groups)) {
                continue;
            }

            $groupIds = array_map(fn($g) => (int)$g->id, $groups);
            $policies = $policyService->getPoliciesForGroupIds($groupIds);

            if (empty($policies)) {
                continue;
            }

            // Single-policy snapshot for drift comparison: lowest
            // sortOrder wins (the resolver's natural order). Multi-
            // policy installs render the comma-list separately via
            // `appliedPolicies`.
            $primary = $policies[0];

            $this->_cache[$user->id]['currentPolicyId'] = (string)$primary->id;
            $this->_cache[$user->id]['appliedPolicies'] = array_map(fn($p) => $p->name, $policies);
        }
    }

    /**
     * Preloads `lastPasswordChangeDate` + `passwordResetRequired` for
     * the given userIds. Direct DB scalar query because
     * `craft\elements\db\UserQuery::beforePrepare()` doesn't select
     * either column (memory gap #9 + D1 finding).
     *
     * @param int[] $userIds
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _preloadUserColumns(array $userIds): void
    {
        $rows = (new Query())
            ->select(['id', 'lastPasswordChangeDate', 'passwordResetRequired'])
            ->from(Table::USERS)
            ->where(['id' => $userIds])
            ->all();

        foreach ($rows as $row) {
            $userId = (int)$row['id'];

            if (!isset($this->_cache[$userId])) {
                continue;
            }

            $this->_cache[$userId]['lastChange'] = $this->_toDateTime($row['lastPasswordChangeDate']);
            $this->_cache[$userId]['passwordResetRequired'] = (bool)$row['passwordResetRequired'];
        }
    }

    /**
     * Renders the breached cell — yes/no badge with relative-date suffix
     * when set. Distinct from the composite status badge in that this
     * column has no recent-window gate; if `lastBreachDetectedAt` was
     * ever set, it shows here. Operators want both: "what's the current
     * incident state" (status badge) plus "what's their breach history"
     * (this column).
     *
     * @param array<string, mixed> $cached
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _renderBreached(array $cached): string
    {
        $detectedAt = $cached['lastBreachAt'];

        if (!$detectedAt instanceof DateTime) {
            return Html::tag('span', Craft::t('password-policy', 'No'), ['class' => 'status']);
        }

        $relative = $this->_relativeTime($detectedAt);
        $label = Craft::t('password-policy', 'Yes — {when}', ['when' => $relative]);

        return Html::tag('span', $label, ['class' => 'status red']);
    }

    /**
     * Renders the days-until-expiry cell: numeric badge with traffic-
     * light coloring (red < 0, yellow 0..7, green > 7), or a gray dash
     * when no expiry policy is configured.
     *
     * @param array<string, mixed> $cached
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _renderDaysUntilExpiry(array $cached): string
    {
        $threshold = $this->_getExpiryThreshold();

        if ($threshold === null) {
            return Html::tag('span', '—', ['class' => 'light']);
        }

        $lastChange = $cached['lastChange'];

        if (!$lastChange instanceof DateTime) {
            // No password set yet — treat as already expired.
            return Html::tag('span', Craft::t('password-policy', 'Expired'), ['class' => 'status red']);
        }

        $settings = PasswordPolicy::$plugin->getSettings();
        $expiresAt = (clone $lastChange);
        $expiryInterval = match ($settings->expiryPeriod) {
            'day' => "P{$settings->expiryAmount}D",
            'week' => "P{$settings->expiryAmount}W",
            'month' => "P{$settings->expiryAmount}M",
            'year' => "P{$settings->expiryAmount}Y",
            default => null,
        };

        if ($expiryInterval === null) {
            return Html::tag('span', '—', ['class' => 'light']);
        }

        $expiresAt->add(new DateInterval($expiryInterval));
        $now = new DateTime('now');
        $diff = $now->diff($expiresAt);
        $days = (int)$diff->days * ($diff->invert ? -1 : 1);

        $colorClass = match (true) {
            $days < 0 => 'red',
            $days <= 7 => 'orange',
            default => 'green',
        };

        return Html::tag('span', (string)$days, ['class' => "status {$colorClass}"]);
    }

    /**
     * Renders the expired cell: red "Expired" badge or muted "No".
     *
     * @param array<string, mixed> $cached
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _renderExpired(array $cached): string
    {
        $threshold = $this->_getExpiryThreshold();

        if ($threshold === null) {
            return Html::tag('span', '—', ['class' => 'light']);
        }

        $lastChange = $cached['lastChange'];

        // No history + expiry configured == effectively expired
        if (!$lastChange instanceof DateTime) {
            return Html::tag('span', Craft::t('password-policy', 'Expired'), ['class' => 'status red']);
        }

        if ($lastChange < $threshold) {
            return Html::tag('span', Craft::t('password-policy', 'Expired'), ['class' => 'status red']);
        }

        return Html::tag('span', Craft::t('password-policy', 'No'), ['class' => 'status']);
    }

    /**
     * Renders the applied-policies cell — comma-list of policy names, or
     * a muted dash when the user has no policies applied.
     *
     * @param array<string, mixed> $cached
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _renderGroupPolicies(array $cached): string
    {
        $policies = $cached['appliedPolicies'];

        if (empty($policies)) {
            return Html::tag('span', '—', ['class' => 'light']);
        }

        return Html::encode(implode(', ', $policies));
    }

    /**
     * Renders the last password change cell — Craft datetime via
     * `Cp::elementHtml` would be more native but introduces a dep on
     * formatter context; a plain ISO-style date keeps the cell
     * deterministic for tests and locale-correct via the formatter.
     *
     * @param array<string, mixed> $cached
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _renderLastChange(array $cached): string
    {
        $lastChange = $cached['lastChange'];

        if (!$lastChange instanceof DateTime) {
            return Html::tag('span', Craft::t('password-policy', 'Never'), ['class' => 'light']);
        }

        $formatted = Craft::$app->getFormatter()->asDatetime($lastChange, 'short');

        return Html::tag('span', Html::encode($formatted));
    }

    /**
     * Renders the last-change-reason cell using the enum's human label.
     * Falls back to a muted dash when the user has no history yet.
     *
     * @param array<string, mixed> $cached
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _renderLastChangeReason(array $cached): string
    {
        $reason = $cached['lastHistoryReason'];

        if (!$reason instanceof ChangeReason) {
            return Html::tag('span', '—', ['class' => 'light']);
        }

        return Html::encode($reason->label());
    }

    /**
     * Renders the policy-drift cell: yes/no badge with a clarifying
     * suffix when drifted. The suffix uses raw policy IDs because
     * resolving the snapshot ID's NAME is not always possible (the row
     * may reference a since-deleted policy); the IDs are stable enough
     * for an admin to recognise the change.
     *
     * @param array<string, mixed> $cached
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _renderPolicyDrift(array $cached): string
    {
        if (!$this->_hasPolicyDrift($cached)) {
            return Html::tag('span', Craft::t('password-policy', 'No'), ['class' => 'status']);
        }

        $current = $cached['currentPolicyId'] ?? '—';
        $snapshot = $cached['lastHistoryPolicy'] ?? '—';

        $label = Craft::t(
            'password-policy',
            'Yes (current: {current}, was: {snapshot})',
            [
                'current' => $current,
                'snapshot' => $snapshot,
            ],
        );

        return Html::tag('span', $label, ['class' => 'status orange']);
    }

    /**
     * Renders the reset-required cell: orange "Yes" badge or muted "No".
     *
     * @param array<string, mixed> $cached
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _renderResetRequired(array $cached): string
    {
        if ($cached['passwordResetRequired']) {
            return Html::tag('span', Craft::t('password-policy', 'Yes'), ['class' => 'status orange']);
        }

        return Html::tag('span', Craft::t('password-policy', 'No'), ['class' => 'status']);
    }

    /**
     * Renders the composite status cell using {@see self::getStatusForUser()}'s
     * resolution. Each status maps to a distinct color and (where
     * appropriate) an extra clarifying string — for the expiring state,
     * the days-remaining count is appended.
     *
     * @param User $user
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _renderStatus(User $user): string
    {
        $status = $this->getStatusForUser($user);

        return match ($status) {
            self::STATUS_BREACHED => Html::tag(
                'span',
                Craft::t('password-policy', 'Breached'),
                ['class' => 'status red'],
            ),
            self::STATUS_EXPIRED => Html::tag(
                'span',
                Craft::t('password-policy', 'Expired'),
                ['class' => 'status red'],
            ),
            self::STATUS_RESET_REQUIRED => Html::tag(
                'span',
                Craft::t('password-policy', 'Reset required'),
                ['class' => 'status orange'],
            ),
            self::STATUS_POLICY_DRIFT => Html::tag(
                'span',
                Craft::t('password-policy', 'Policy drift'),
                ['class' => 'status orange'],
            ),
            self::STATUS_EXPIRING => $this->_renderExpiringStatus($user),
            self::STATUS_NEVER_CHANGED => Html::tag(
                'span',
                Craft::t('password-policy', 'Never changed'),
                ['class' => 'status'],
            ),
            // STATUS_OK + the defensive `default` covers the case where
            // `getStatusForUser()` is widened in the future without
            // updating this match — PHPStan otherwise flags the implicit
            // string-not-handled arm.
            default => Html::tag(
                'span',
                Craft::t('password-policy', 'OK'),
                ['class' => 'status green'],
            ),
        };
    }

    /**
     * Renders the "expiring in N days" status with the day count baked
     * into the label. Falls back to a generic label if the math can't
     * compute (no expiry threshold or no last change date).
     *
     * @param User $user
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _renderExpiringStatus(User $user): string
    {
        $cached = $this->_getCachedForUser((int)$user->id);
        $threshold = $this->_getExpiryThreshold();
        $lastChange = $cached['lastChange'];

        if ($threshold === null || !$lastChange instanceof DateTime) {
            return Html::tag(
                'span',
                Craft::t('password-policy', 'Expiring'),
                ['class' => 'status orange'],
            );
        }

        $expiresAt = $threshold->getTimestamp() + (self::EXPIRING_SOON_DAYS * 86400);
        $remainingSeconds = max(0, $expiresAt - $lastChange->getTimestamp());
        $days = (int)floor($remainingSeconds / 86400);

        return Html::tag(
            'span',
            Craft::t('password-policy', 'Expires in {days} days', ['days' => $days]),
            ['class' => 'status orange'],
        );
    }

    /**
     * Returns a coarse human-readable relative time ("3 days ago",
     * "yesterday") for breach detection. Locale-aware via Craft's
     * formatter to avoid hand-rolled English; format is "Yes — {whenever}"
     * at the call site.
     *
     * @param DateTimeInterface $when
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _relativeTime(DateTimeInterface $when): string
    {
        return Craft::$app->getFormatter()->asRelativeTime($when);
    }

    /**
     * Coerces a raw DB datetime string into a `DateTime`. ActiveRecord
     * returns datetime columns as strings (memory gap #10); cells need
     * actual DateTime instances for arithmetic, so the preload paths
     * convert at the boundary.
     *
     * @param mixed $value
     * @return DateTime|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _toDateTime(mixed $value): ?DateTime
    {
        // Carbon extends DateTime so a single instanceof check catches
        // both. ActiveRecord datetime columns come back as raw strings
        // (memory gap #10), which is the path we actually need to handle.
        if ($value instanceof DateTime) {
            return $value;
        }

        if (is_string($value) && $value !== '') {
            try {
                return new DateTime($value);
            } catch (\Exception) {
                return null;
            }
        }

        return null;
    }
}
