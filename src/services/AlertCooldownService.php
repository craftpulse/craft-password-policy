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
use craft\helpers\StringHelper;
use craftpulse\passwordpolicy\events\AlertCooldownEvent;
use craftpulse\passwordpolicy\PasswordPolicy;
use Throwable;
use yii\base\Component;

/**
 * Class AlertCooldownService
 *
 * Per-(eventClass, cooldownKey) suppression service. Generalises the
 * pre-G7 dedup logic that lived inline in
 * `NotificationService::_hasRecentNotification()` and
 * `NotificationService::sendAdminSecurityAlert()`'s 5-minute filter.
 * Future alert types (G8 SIEM forwarder circuit-breaker, HIBP-on-login
 * burst suppression, group-deletion cascade alert, etc.) register against
 * this service rather than reinventing throttling.
 *
 * Two storage surfaces emerge once this service lands:
 *
 *  - `passwordpolicy_notification_log` — what was sent + when + with
 *    what subject / body. Operator-readable activity trail.
 *  - `passwordpolicy_alert_cooldowns` — when alerting fired regardless
 *    of whether an email or row was emitted. Auditor-readable
 *    suppression record.
 *
 * Why a table over cache-only: per memory rule
 * `project_audit_capture_principle.md`, "did we suppress an alert?"
 * must be answerable from the database. A cache-only implementation
 * loses the suppression record on every cache flush — but an auditor
 * asking "you had a credential-stuffing burst on 2026-05-04, show me the
 * alert suppression record" needs durable storage. Cache sits *in front
 * of* the table for read performance, never instead of it.
 *
 * Cache layer (per `feedback_skill_gaps.md` rule #11): Yii's cache
 * `get()` returns `bool false` for missing keys, which collides with a
 * cached `false` value. This service uses `Craft::$app->getCache()
 * ->exists()` for the cache-miss check rather than encoding bool-domain
 * sentinels — there's no false-positive value to encode here, just a
 * "this key has been recorded" presence check, and `exists()` is
 * unambiguous. TTL on cache writes matches the `cooldownSeconds`
 * argument so the cache entry naturally expires at the same time the
 * row stops blocking the next fire.
 *
 * Edition: universal capture. Every edition writes cooldown rows. Edition
 * gates apply to read surfaces (G8's SIEM forwarder reads cooldowns for
 * its circuit-breaker; that's an Enterprise consumer of universal data,
 * not an edition gate on the writes here).
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class AlertCooldownService extends Component
{
    // Const Properties
    // =========================================================================

    /**
     * Default cooldown for the `admin_security_alert:<event>` event
     * class — five minutes, matching the pre-G7 hardcoded window in
     * `NotificationService::sendAdminSecurityAlert()`.
     *
     * @var int seconds
     *
     * @since 5.2.0
     */
    public const DEFAULT_COOLDOWN_ADMIN_SECURITY_ALERT = 300;

    /**
     * Default cooldown for the `force_reset_burst` event class — five
     * minutes. Per § 5 of the Phase G plan: catches an admin running
     * SendPasswordResetEmail bulk on a large set so the alert fires
     * once per actor, not per user.
     *
     * @var int seconds
     *
     * @since 5.2.0
     */
    public const DEFAULT_COOLDOWN_FORCE_RESET_BURST = 300;

    /**
     * Default cooldown for the `group_deletion_cascade` event class —
     * five minutes. Per § 5 of the Phase G plan: catches an admin
     * nuking a 5000-user group so the alert fires once for the cascade,
     * not per user.
     *
     * @var int seconds
     *
     * @since 5.2.0
     */
    public const DEFAULT_COOLDOWN_GROUP_DELETION_CASCADE = 300;

    /**
     * Default cooldown for Feature 3 per-group alert routing — one hour.
     * The cooldown key is per resolving group + event
     * (`group:{groupId}:{eventType}`), so a burst (e.g. a mass HIBP
     * detection against many members of one group) routes a single copy to
     * the group security contact per hour, not one per affected user. An
     * hour (rather than the 24h HIBP-login-burst window) keeps the contact
     * reasonably current on a genuinely distinct second incident while still
     * collapsing a stuffing burst.
     *
     * @var int seconds
     *
     * @since 5.2.0
     */
    public const DEFAULT_COOLDOWN_GROUP_ALERT = 3600;

    /**
     * Default cooldown for the `hibp_login_burst` event class — 24
     * hours. Per § 5 of the Phase G plan: catches mass detection of one
     * breached password against many users (credential stuffing
     * pattern) so the admin gets one alert per day per breached prefix,
     * not one per user.
     *
     * @var int seconds
     *
     * @since 5.2.0
     */
    public const DEFAULT_COOLDOWN_HIBP_LOGIN_BURST = 86400;

    /**
     * Default cooldown for the `new_device` event class — 24 hours.
     * Feature 1: a user signing in repeatedly from a freshly-recorded
     * device within a day produces a single new-device alert email, not
     * one per login. The cooldown key is per-user (`user:<id>`), so each
     * user's first sighting of a new device alerts once per day at most.
     *
     * @var int seconds
     *
     * @since 5.2.0
     */
    public const DEFAULT_COOLDOWN_NEW_DEVICE = 86400;

    /**
     * Fired after `recordFire()` writes a row to the cooldowns table.
     * Listeners observe the fire — they don't gate it. See
     * {@see AlertCooldownEvent} for the use cases (SIEM mirroring,
     * compliance dashboard, third-party incident queue).
     *
     * @event AlertCooldownEvent
     *
     * @since 5.2.0
     */
    public const EVENT_ALERT_COOLDOWN_FIRED = 'alertCooldownFired';

    /**
     * Floor / ceiling for the prune threshold computed by
     * `pruneOldEntries()`. Rows older than `max(longest configured
     * cooldown, 7 days)` are deleted. Anchored at 7 days so a deployment
     * with only short cooldowns configured (say, all 5-min windows)
     * doesn't prune cooldown rows so aggressively that the auditor's
     * "show me last week's suppression record" query comes up empty.
     *
     * @var int seconds
     *
     * @since 5.2.0
     */
    public const PRUNE_FLOOR_SECONDS = 604800;

    // Static Methods
    // =========================================================================

    /**
     * Returns the cache key for a given (eventClass, cooldownKey) pair.
     * Stable shape so cache-warming hits the same slot across processes.
     *
     * @param string $eventClass
     * @param string $cooldownKey
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private static function _cacheKey(string $eventClass, string $cooldownKey): string
    {
        return "pp:alert-cooldown:{$eventClass}:{$cooldownKey}";
    }

    // Public Methods
    // =========================================================================

    /**
     * Prunes cooldown rows older than the longer of (a) the longest
     * configured cooldown across all known event classes, or (b)
     * `PRUNE_FLOOR_SECONDS` (7 days). Idempotent — safe to call from
     * `gc/run` cron without risk of double-deletion.
     *
     * Per memory rule `feedback_retention_gc_framing.md`, this prune is
     * recommended production setup via cron (`password-policy/gc/run`),
     * not edge-case maintenance. Without a periodic run the table grows
     * unbounded.
     *
     * @return int the number of rows deleted
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function pruneOldEntries(): int
    {
        $longest = $this->_longestConfiguredCooldown();
        $thresholdSeconds = max($longest, self::PRUNE_FLOOR_SECONDS);
        $threshold = Carbon::now('UTC')->subSeconds($thresholdSeconds)->format('Y-m-d H:i:s');

        return Craft::$app->getDb()->createCommand()
            ->delete(
                '{{%passwordpolicy_alert_cooldowns}}',
                ['<', 'firedAt', $threshold],
            )
            ->execute();
    }

    /**
     * Records a fire unconditionally. Inserts a row in
     * `passwordpolicy_alert_cooldowns` with `firedAt = now` and triggers
     * `EVENT_ALERT_COOLDOWN_FIRED`. Does NOT prime the cache — that's a
     * `shouldFire()` concern (cache primes are tied to the cooldown-
     * window TTL, which `recordFire()` callers don't supply).
     *
     * The triggered event is wrapped in try/catch so a listener throwing
     * cannot unwind the cooldown record. The row is the load-bearing
     * write — listeners are observation-only.
     *
     * Most callers should prefer `shouldFire()`, which returns
     * `true` only when the cooldown is clear and records the fire on
     * its way out — `recordFire()` is for callers that have already
     * decided they will fire and just need the record (or for tests
     * priming state).
     *
     * @param string $eventClass logical alert type
     * @param string $cooldownKey dedup key (e.g. `user:123`,
     *     `event:hibp_breach_detected`)
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function recordFire(string $eventClass, string $cooldownKey): void
    {
        $now = Carbon::now('UTC');
        $firedAtString = $now->format('Y-m-d H:i:s');

        Craft::$app->getDb()->createCommand()
            ->insert('{{%passwordpolicy_alert_cooldowns}}', [
                'eventClass' => $eventClass,
                'cooldownKey' => $cooldownKey,
                'firedAt' => $firedAtString,
                'dateCreated' => $firedAtString,
                'dateUpdated' => $firedAtString,
                'uid' => StringHelper::UUID(),
            ])
            ->execute();

        // Listener exceptions cannot unwind the cooldown record — the
        // row is the load-bearing write, the event is observation-only.
        try {
            $this->trigger(
                self::EVENT_ALERT_COOLDOWN_FIRED,
                new AlertCooldownEvent([
                    'eventClass' => $eventClass,
                    'cooldownKey' => $cooldownKey,
                    'firedAt' => $now->toDateTime(),
                ]),
            );
        } catch (Throwable $e) {
            Craft::error(
                'AlertCooldownService listener threw on EVENT_ALERT_COOLDOWN_FIRED: ' . $e->getMessage(),
                'password-policy',
            );
        }
    }

    /**
     * Returns `true` when the alert may fire now (no fire within
     * `$cooldownSeconds`), `false` when a recent fire is still
     * suppressing it. **On `true` return, internally calls
     * `recordFire()` so the call site doesn't have to remember.** The
     * documented contract per § 5 of the Phase G plan: "Returns true
     * if the alert may fire now; records the fire on true return."
     *
     * Read path (cache-fast, DB-correct):
     *
     *  - Cache hit → cooled (return false).
     *  - Cache miss → consult the DB. If a row in the cooldown window
     *    exists, return false WITHOUT recording (the cache will warm
     *    naturally when the row's owning fire-call originally
     *    happened, or on next miss-driven DB read on this instance).
     *  - DB miss → record the fire (write a row + fire the event +
     *    prime the cache) and return true.
     *
     * The cache's TTL matches `$cooldownSeconds`, so the cache entry
     * naturally expires at the same point the row stops blocking the
     * next fire. No manual cache invalidation required.
     *
     * Cache idiom: `cache->exists($key)` rather than encoding a
     * sentinel string. The check is presence-only — there's no
     * bool-domain value to disambiguate a la HIBP's `breached` /
     * `clean` cache (memory rule `feedback_skill_gaps.md` #11).
     *
     * @param string $eventClass logical alert type (e.g.
     *     `expiry_reminder`, `admin_security_alert:<event>`,
     *     `hibp_login_burst`)
     * @param string $cooldownKey dedup key shape (e.g. `user:<id>`,
     *     `event:<event>`, `prefix:<5char-sha1>`)
     * @param int $cooldownSeconds the suppression window in seconds —
     *     `firedAt >= now - cooldownSeconds` blocks the next fire
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function shouldFire(string $eventClass, string $cooldownKey, int $cooldownSeconds): bool
    {
        $cache = Craft::$app->getCache();
        $cacheKey = self::_cacheKey($eventClass, $cooldownKey);

        if ($cache->exists($cacheKey)) {
            return false;
        }

        // Atomicity: the check (DB read) and the record (DB write + cache
        // prime) must be a single critical section. Without it, two
        // concurrent dispatches for the same (eventClass, cooldownKey)
        // can both read "no recent row" before either writes, and both
        // fire — double-alerting the operator / double-emailing the
        // user. A short Craft mutex keyed on the same slot as the cache
        // serialises the section. The lock is best-effort: if the mutex
        // backend can't grant within the timeout we proceed anyway
        // (degrades to the pre-mutex non-atomic behaviour rather than
        // dropping the alert entirely — losing an alert is worse than a
        // rare double under contention). Released in finally so a throw
        // inside recordFire() can't leave the lock held.
        $mutex = Craft::$app->getMutex();
        $lockAcquired = $mutex->acquire($cacheKey, 2);

        try {
            // Authoritative re-check INSIDE the lock: a waiter that blocked
            // on the mutex must re-read the DB, because the holder ahead of
            // it may have just recorded a fire. The `firedAt` query below is
            // the source of truth (the cache is only a fast-path prime), so
            // it covers the double-check without a redundant cache lookup
            // that static analysis can't see past the early-return guard.
            $threshold = Carbon::now('UTC')->subSeconds($cooldownSeconds)->format('Y-m-d H:i:s');
            $hasRecent = (new Query())
                ->from('{{%passwordpolicy_alert_cooldowns}}')
                ->where([
                    'eventClass' => $eventClass,
                    'cooldownKey' => $cooldownKey,
                ])
                ->andWhere(['>=', 'firedAt', $threshold])
                ->exists();

            if ($hasRecent) {
                return false;
            }

            $this->recordFire($eventClass, $cooldownKey);
            // Prime cache with the same TTL as the cooldown window so a hot
            // re-check on the same key short-circuits without touching the
            // DB until the window itself expires.
            $cache->set($cacheKey, '1', $cooldownSeconds);

            return true;
        } finally {
            if ($lockAcquired) {
                $mutex->release($cacheKey);
            }
        }
    }

    // Private Methods
    // =========================================================================

    /**
     * Returns the longest configured cooldown across the union of (a)
     * the per-class settings array (`SettingsModel::$alertCooldowns`)
     * and (b) the service's `DEFAULT_COOLDOWN_*` constants. Used by
     * `pruneOldEntries()` to compute the prune horizon.
     *
     * @return int seconds
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _longestConfiguredCooldown(): int
    {
        $defaults = [
            self::DEFAULT_COOLDOWN_ADMIN_SECURITY_ALERT,
            self::DEFAULT_COOLDOWN_FORCE_RESET_BURST,
            self::DEFAULT_COOLDOWN_GROUP_ALERT,
            self::DEFAULT_COOLDOWN_GROUP_DELETION_CASCADE,
            self::DEFAULT_COOLDOWN_HIBP_LOGIN_BURST,
            self::DEFAULT_COOLDOWN_NEW_DEVICE,
        ];

        $configured = PasswordPolicy::$plugin->getSettings()->alertCooldowns;
        $configuredSeconds = [];

        foreach ($configured as $value) {
            if (is_int($value) && $value > 0) {
                $configuredSeconds[] = $value;
            }
        }

        return (int)max(array_merge($defaults, $configuredSeconds));
    }
}
