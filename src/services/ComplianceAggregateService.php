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
use Craft;
use craft\db\Query;
use craft\helpers\DateTimeHelper;
use craftpulse\passwordpolicy\PasswordPolicy;
use DateTime;
use DateTimeZone;
use Throwable;
use yii\base\Component;

/**
 * Class ComplianceAggregateService
 *
 * Read-only aggregates over the Phase G audit infrastructure for the G3
 * compliance dashboard + report exports. Each public method returns a
 * fixed-shape array consumed by the dashboard template and the report
 * controller — see per-method docblocks for the contract.
 *
 * Capture is universal (per `project_audit_capture_principle.md`), so
 * the aggregate service runs the same shape across editions and does
 * NOT gate on `getIsEnterprise()`. Edition gating happens at the utility
 * + controller layer one step above. Running the service on every
 * edition keeps capture-side observability symmetric with the underlying
 * tables: Lite installs grow the audit log too, and an operator who
 * upgrades to Enterprise mid-life expects the dashboard to reflect
 * everything captured so far.
 *
 * Caching policy is per-aggregate — see each method's docblock for the
 * TTL and cache key. The dashboard is allowed to be slightly stale; the
 * trade-off is bounded query cost on a CP page that may render on every
 * request to `/admin/utilities/...`. The chain-health aggregate carries
 * the longest TTL (300s) because it walks the entire audit table —
 * verifier-style — and we explicitly don't want that on every render.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class ComplianceAggregateService extends Component
{
    // Const Properties
    // =========================================================================

    /**
     * Cache key for `getAlertCooldownActivity()`. 5-minute TTL.
     *
     * @var string
     */
    public const CACHE_KEY_COOLDOWN_ACTIVITY = 'pp:compliance:cooldown-activity';

    /**
     * Cache key for `getChainHealth()`. 5-minute TTL — the verifier walk
     * is O(N) over the audit log and must not run on every dashboard
     * render.
     *
     * @var string
     */
    public const CACHE_KEY_CHAIN_HEALTH = 'pp:compliance:chain-health';

    /**
     * Cache key for `getPendingForwards()`. 1-minute TTL — operators
     * actively unsticking a forwarder expect near-real-time feedback.
     *
     * @var string
     */
    public const CACHE_KEY_PENDING_FORWARDS = 'pp:compliance:pending-forwards';

    /**
     * Cache key for `getRetentionStatus()`. 5-minute TTL.
     *
     * @var string
     */
    public const CACHE_KEY_RETENTION = 'pp:compliance:retention';

    /**
     * Cache key for `getTotals()`. 5-minute TTL.
     *
     * @var string
     */
    public const CACHE_KEY_TOTALS = 'pp:compliance:totals';

    /**
     * Default TTL for aggregates that walk the audit table or scan large
     * indexes. Five minutes — auditor-grade staleness for a CP dashboard
     * with verifier-class workload underneath.
     *
     * @var int seconds
     */
    public const TTL_DEFAULT = 300;

    /**
     * TTL for the pending-forwards aggregate. One minute — operators
     * actively unsticking a SIEM forwarder expect near-real-time feedback
     * on the dashboard.
     *
     * @var int seconds
     */
    public const TTL_PENDING_FORWARDS = 60;

    /**
     * Genesis sentinel for the audit chain. Sixty-four zero hex chars —
     * mirrors {@see AuditLogService::GENESIS_PREVIOUS_HASH}. Declared here
     * so the verifier walk doesn't have to reach across the service
     * boundary for a literal sentinel.
     *
     * @var string
     */
    private const GENESIS_PREVIOUS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

    // Public Methods
    // =========================================================================

    /**
     * Returns alert-cooldown fire activity in the last 24 hours.
     *
     * Shape:
     *  - `byEventClass`: `array<string, int>` — fire count keyed by event class
     *  - `last24h`: `int` — total fires in the last 24 hours
     *
     * Cached for {@see self::TTL_DEFAULT} seconds under
     * {@see self::CACHE_KEY_COOLDOWN_ACTIVITY}.
     *
     * @return array{byEventClass: array<string, int>, last24h: int}
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getAlertCooldownActivity(): array
    {
        $cache = Craft::$app->getCache();
        $cached = $cache->get(self::CACHE_KEY_COOLDOWN_ACTIVITY);

        if (is_array($cached)) {
            /** @var array{byEventClass: array<string, int>, last24h: int} $cached */
            return $cached;
        }

        $threshold = Carbon::now('UTC')->subDay()->format('Y-m-d H:i:s');

        /** @var array<int, array{eventClass: string, count: int|string}> $rows */
        $rows = (new Query())
            ->select(['eventClass', 'count' => 'COUNT(*)'])
            ->from('{{%passwordpolicy_alert_cooldowns}}')
            ->where(['>=', 'firedAt', $threshold])
            ->groupBy(['eventClass'])
            ->orderBy(['eventClass' => SORT_ASC])
            ->all();

        $byEventClass = [];
        $total = 0;

        foreach ($rows as $row) {
            $count = (int)$row['count'];
            $byEventClass[(string)$row['eventClass']] = $count;
            $total += $count;
        }

        $result = [
            'byEventClass' => $byEventClass,
            'last24h' => $total,
        ];

        $cache->set(self::CACHE_KEY_COOLDOWN_ACTIVITY, $result, self::TTL_DEFAULT);

        return $result;
    }

    /**
     * Returns the current audit-chain health.
     *
     * Shape:
     *  - `status`: `'healthy'|'broken'` — chain integrity outcome
     *  - `lastRunAt`: `DateTime|null` — when the dashboard last ran the
     *     verifier (now() at the moment of cache fill; null when no
     *     check has run yet in this cache lifetime)
     *  - `firstBreakRowId`: `int|null` — first offending row's id when
     *     broken; null otherwise
     *  - `checkedRowCount`: `int` — rows walked before finishing or
     *     hitting the first break
     *
     * Cached for {@see self::TTL_DEFAULT} seconds under
     * {@see self::CACHE_KEY_CHAIN_HEALTH} — the verifier walks the entire
     * audit log per call, so the dashboard must not retrigger it on
     * every page render.
     *
     * Shares {@see AuditLogService::canonicalize()} with the writer; the
     * verifier and the writer produce bit-identical bytes. If the
     * audit-log table is empty the chain is trivially healthy (no rows
     * means no break to find).
     *
     * @return array{status: string, lastRunAt: ?DateTime, firstBreakRowId: ?int, checkedRowCount: int}
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getChainHealth(): array
    {
        $cache = Craft::$app->getCache();
        $cached = $cache->get(self::CACHE_KEY_CHAIN_HEALTH);

        if (is_array($cached)) {
            /** @var array{status: string, lastRunAt: ?DateTime, firstBreakRowId: ?int, checkedRowCount: int} $cached */
            return $cached;
        }

        try {
            $result = $this->_verifyChain();
        } catch (Throwable $e) {
            Craft::warning(
                'ComplianceAggregateService chain verification failed: ' . $e->getMessage(),
                'password-policy',
            );

            // Verifier-unreadable maps to "broken" on the dashboard. The
            // dashboard is a single-pixel surface; auditors who need
            // verifier exit codes 0/1/2 use the CLI.
            $result = [
                'status' => 'broken',
                'lastRunAt' => Carbon::now('UTC')->toDateTime(),
                'firstBreakRowId' => null,
                'checkedRowCount' => 0,
            ];
        }

        $cache->set(self::CACHE_KEY_CHAIN_HEALTH, $result, self::TTL_DEFAULT);

        return $result;
    }

    /**
     * Returns the number of audit-log rows pending SIEM forwarding +
     * the age of the oldest pending row.
     *
     * Shape:
     *  - `count`: `int` — rows with `forwardedAt IS NULL`
     *  - `oldestAge`: `string|null` — human-readable duration from the
     *     oldest pending row's `dateCreated` to now; null when none pending
     *
     * Cached for {@see self::TTL_PENDING_FORWARDS} seconds under
     * {@see self::CACHE_KEY_PENDING_FORWARDS}.
     *
     * @return array{count: int, oldestAge: ?string}
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getPendingForwards(): array
    {
        $cache = Craft::$app->getCache();
        $cached = $cache->get(self::CACHE_KEY_PENDING_FORWARDS);

        if (is_array($cached)) {
            /** @var array{count: int, oldestAge: ?string} $cached */
            return $cached;
        }

        $count = (int)(new Query())
            ->from('{{%passwordpolicy_audit_log}}')
            ->where(['forwardedAt' => null])
            ->count();

        $oldestAge = null;

        if ($count > 0) {
            $oldestDateCreated = (new Query())
                ->select(['dateCreated'])
                ->from('{{%passwordpolicy_audit_log}}')
                ->where(['forwardedAt' => null])
                ->orderBy(['id' => SORT_ASC])
                ->limit(1)
                ->scalar();

            if (is_string($oldestDateCreated) && $oldestDateCreated !== '') {
                $oldestAge = $this->_humanDurationSince($oldestDateCreated);
            }
        }

        $result = [
            'count' => $count,
            'oldestAge' => $oldestAge,
        ];

        $cache->set(self::CACHE_KEY_PENDING_FORWARDS, $result, self::TTL_PENDING_FORWARDS);

        return $result;
    }

    /**
     * Returns retention-cadence status for the audit log + notification
     * log: configured retention windows, oldest surviving row's age,
     * projected next prune date.
     *
     * Shape:
     *  - `auditLogRetentionDays`: `int`
     *  - `auditLogOldestAge`: `string|null` — human duration since the
     *     oldest surviving audit row's `dateCreated`; null when empty
     *  - `auditLogProjectedNextPrune`: `DateTime|null` — when the
     *     oldest row will hit the retention boundary; null when empty
     *  - `notificationLogRetentionDays`: `int`
     *  - `notificationLogOldestAge`: `string|null`
     *
     * Cached for {@see self::TTL_DEFAULT} seconds under
     * {@see self::CACHE_KEY_RETENTION}.
     *
     * @return array{
     *     auditLogRetentionDays: int,
     *     auditLogOldestAge: ?string,
     *     auditLogProjectedNextPrune: ?DateTime,
     *     notificationLogRetentionDays: int,
     *     notificationLogOldestAge: ?string,
     * }
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getRetentionStatus(): array
    {
        $cache = Craft::$app->getCache();
        $cached = $cache->get(self::CACHE_KEY_RETENTION);

        if (is_array($cached)) {
            /** @var array{
             *     auditLogRetentionDays: int,
             *     auditLogOldestAge: ?string,
             *     auditLogProjectedNextPrune: ?DateTime,
             *     notificationLogRetentionDays: int,
             *     notificationLogOldestAge: ?string,
             * } $cached
             */
            return $cached;
        }

        $settings = PasswordPolicy::$plugin->getSettings();

        $auditOldestDateCreated = (new Query())
            ->select(['dateCreated'])
            ->from('{{%passwordpolicy_audit_log}}')
            ->orderBy(['id' => SORT_ASC])
            ->limit(1)
            ->scalar();

        $auditLogOldestAge = null;
        $auditLogProjectedNextPrune = null;

        if (is_string($auditOldestDateCreated) && $auditOldestDateCreated !== '') {
            $auditLogOldestAge = $this->_humanDurationSince($auditOldestDateCreated);
            $oldestDt = new DateTime($auditOldestDateCreated, new DateTimeZone('UTC'));
            $auditLogProjectedNextPrune = Carbon::instance($oldestDt)
                ->addDays($settings->auditLogRetentionDays)
                ->toDateTime();
        }

        // The notification_log table uses `sentAt` (mirrors the email's
        // delivery timestamp) rather than the `dateCreated` /
        // `dateUpdated` pair Craft typically pins. Reflect that here so
        // the oldest-row scan lands on the right column.
        $notificationOldestSentAt = (new Query())
            ->select(['sentAt'])
            ->from('{{%passwordpolicy_notification_log}}')
            ->orderBy(['id' => SORT_ASC])
            ->limit(1)
            ->scalar();

        $notificationLogOldestAge = null;

        if (is_string($notificationOldestSentAt) && $notificationOldestSentAt !== '') {
            $notificationLogOldestAge = $this->_humanDurationSince($notificationOldestSentAt);
        }

        $result = [
            'auditLogRetentionDays' => $settings->auditLogRetentionDays,
            'auditLogOldestAge' => $auditLogOldestAge,
            'auditLogProjectedNextPrune' => $auditLogProjectedNextPrune,
            'notificationLogRetentionDays' => $settings->notificationLogRetentionDays,
            'notificationLogOldestAge' => $notificationLogOldestAge,
        ];

        $cache->set(self::CACHE_KEY_RETENTION, $result, self::TTL_DEFAULT);

        return $result;
    }

    /**
     * Returns audit-log row totals — overall, last 30 days, and by
     * event class.
     *
     * Shape:
     *  - `total`: `int` — all audit rows
     *  - `last30Days`: `int` — rows created in the last 30 days
     *  - `byEventClass`: `array<string, int>` — total count keyed by event
     *
     * Cached for {@see self::TTL_DEFAULT} seconds under
     * {@see self::CACHE_KEY_TOTALS}.
     *
     * @return array{total: int, last30Days: int, byEventClass: array<string, int>}
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getTotals(): array
    {
        $cache = Craft::$app->getCache();
        $cached = $cache->get(self::CACHE_KEY_TOTALS);

        if (is_array($cached)) {
            /** @var array{total: int, last30Days: int, byEventClass: array<string, int>} $cached */
            return $cached;
        }

        $total = (int)(new Query())
            ->from('{{%passwordpolicy_audit_log}}')
            ->count();

        $thirtyDaysAgo = Carbon::now('UTC')->subDays(30)->format('Y-m-d H:i:s');

        $last30Days = (int)(new Query())
            ->from('{{%passwordpolicy_audit_log}}')
            ->where(['>=', 'dateCreated', $thirtyDaysAgo])
            ->count();

        /** @var array<int, array{event: string, count: int|string}> $rows */
        $rows = (new Query())
            ->select(['event', 'count' => 'COUNT(*)'])
            ->from('{{%passwordpolicy_audit_log}}')
            ->groupBy(['event'])
            ->orderBy(['event' => SORT_ASC])
            ->all();

        $byEventClass = [];

        foreach ($rows as $row) {
            $byEventClass[(string)$row['event']] = (int)$row['count'];
        }

        $result = [
            'total' => $total,
            'last30Days' => $last30Days,
            'byEventClass' => $byEventClass,
        ];

        $cache->set(self::CACHE_KEY_TOTALS, $result, self::TTL_DEFAULT);

        return $result;
    }

    // Private Methods
    // =========================================================================

    /**
     * Returns a human-readable duration string from the given UTC
     * datetime string to now. Uses Craft's `DateTimeHelper::humanDuration`
     * for locale-friendly formatting ("3 days, 4 hours").
     *
     * @param string $dateCreatedUtc UTC `Y-m-d H:i:s` string
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _humanDurationSince(string $dateCreatedUtc): string
    {
        $start = new DateTime($dateCreatedUtc, new DateTimeZone('UTC'));
        $seconds = max(0, time() - $start->getTimestamp());

        return DateTimeHelper::humanDuration($seconds, false);
    }

    /**
     * Walks the audit-log hash chain and returns a result shape suitable
     * for the dashboard.
     *
     * Walks the full table via batched cursor reads to keep the memory
     * footprint bounded. Stops at the first detected break. Treats both
     * the genesis sentinel and an "older than retention + 24h" first
     * surviving row as acceptable chain anchors — see
     * {@see \craftpulse\passwordpolicy\console\controllers\AuditController::_walkChain()}
     * for the parallel CLI implementation.
     *
     * Shares the canonical-payload primitives with the writer
     * ({@see AuditLogService::canonicalize()} +
     * {@see AuditLogService::CANONICAL_DATE_FORMAT}) so the verifier
     * walks bit-identical bytes. Don't inline a "fast path" canonicaliser
     * here — drift between writer and verifier silently invalidates the
     * chain.
     *
     * @return array{status: string, lastRunAt: DateTime, firstBreakRowId: ?int, checkedRowCount: int}
     *
     * @throws \Exception when DateTime parsing fails on a malformed value
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _verifyChain(): array
    {
        $lastRunAt = Carbon::now('UTC')->toDateTime();

        $query = (new Query())
            ->from('{{%passwordpolicy_audit_log}}')
            ->orderBy(['id' => SORT_ASC]);

        $previousHash = self::GENESIS_PREVIOUS_HASH;
        $isFirstRow = true;
        $verifiedRows = 0;

        foreach ($query->each(1000) as $row) {
            $expectedPayload = AuditLogService::canonicalize($this->_buildCanonicalPayload($row));
            $expectedHash = hash('sha256', $expectedPayload . (string)$row['previousHash']);

            if ($isFirstRow) {
                $isFirstRow = false;

                $isGenesis = $row['previousHash'] === self::GENESIS_PREVIOUS_HASH;
                $isRetentionBoundary = !$isGenesis && $this->_isAcceptableRetentionBoundary($row);

                if (!$isGenesis && !$isRetentionBoundary) {
                    return [
                        'status' => 'broken',
                        'lastRunAt' => $lastRunAt,
                        'firstBreakRowId' => (int)$row['id'],
                        'checkedRowCount' => $verifiedRows,
                    ];
                }
            } elseif ($row['previousHash'] !== $previousHash) {
                return [
                    'status' => 'broken',
                    'lastRunAt' => $lastRunAt,
                    'firstBreakRowId' => (int)$row['id'],
                    'checkedRowCount' => $verifiedRows,
                ];
            }

            if ($expectedHash !== $row['rowHash']) {
                return [
                    'status' => 'broken',
                    'lastRunAt' => $lastRunAt,
                    'firstBreakRowId' => (int)$row['id'],
                    'checkedRowCount' => $verifiedRows,
                ];
            }

            $verifiedRows++;
            $previousHash = (string)$row['rowHash'];
        }

        return [
            'status' => 'healthy',
            'lastRunAt' => $lastRunAt,
            'firstBreakRowId' => null,
            'checkedRowCount' => $verifiedRows,
        ];
    }

    /**
     * Reconstructs the canonical-JSON payload from a raw audit-log row.
     * Mirrors the writer in {@see AuditLogService::logEvent()} —
     * alphabetical keys, MySQL string-fetched numeric columns coerced
     * back to `int|null`, JSON `details` decoded to an array,
     * `dateCreated` reformatted to the canonical UTC string.
     *
     * @param array<string, mixed> $row
     * @return array<string, mixed>
     *
     * @throws \Exception when DateTime parsing fails on a malformed value
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _buildCanonicalPayload(array $row): array
    {
        // Mirrors the writer in `AuditLogService::logEvent()` exactly.
        // The mutable FK ints `userId` + `changedByUserId` are EXCLUDED
        // — both are `ON DELETE SET NULL`, so hashing them would make a
        // deleted user recompute a different rowHash (GDPR erasure would
        // self-report as tampering). The immutable HMAC identities
        // `userIdentifier` (subject) + `changedByIdentifier` (actor) are
        // hashed instead.
        return [
            'changedByIdentifier' => $row['changedByIdentifier'],
            'dateCreated' => (new DateTime((string)$row['dateCreated'], new DateTimeZone('UTC')))
                ->format(AuditLogService::CANONICAL_DATE_FORMAT),
            'details' => $this->_decodeDetails($row['details']),
            'event' => $row['event'],
            'ipHash' => $row['ipHash'],
            'outcome' => $row['outcome'],
            'source' => $row['source'],
            'uid' => $row['uid'],
            'userIdentifier' => $row['userIdentifier'],
        ];
    }

    /**
     * Decodes the `details` JSON column to an array, or null when the
     * column is empty. Mirrors `AuditController::_decodeDetails()`.
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
     * Returns true when the first surviving row's `previousHash` is an
     * acceptable retention-purge boundary (predates `retentionDays + 24h`).
     * Mirrors `AuditController::_isAcceptableRetentionBoundary()`. The
     * dashboard always runs in full-walk mode (no `--from` / `--to`),
     * so the bounded-walk branch from the CLI doesn't apply.
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
        $retentionDays = PasswordPolicy::$plugin->getSettings()->auditLogRetentionDays;
        $cutoff = Carbon::now('UTC')
            ->subDays($retentionDays)
            ->subSeconds(86400);

        $rowCreated = new DateTime((string)$row['dateCreated'], new DateTimeZone('UTC'));

        return $rowCreated->getTimestamp() < $cutoff->getTimestamp();
    }
}
