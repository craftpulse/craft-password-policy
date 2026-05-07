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
use craft\helpers\App;
use craft\helpers\Json;
use craft\helpers\StringHelper;
use craftpulse\passwordpolicy\models\SiemForwarderModel;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\records\SiemForwarderRecord;
use RuntimeException;
use Throwable;
use yii\base\Component;

/**
 * Class SiemService
 *
 * Forwards audit-log rows to one or more registered SIEM endpoints over
 * syslog-TLS (RFC 5424 framing on a `tls://` stream socket). The first
 * forwarder in the matrix; HTTP webhook ships separately as G9.
 *
 * Architectural anchor: `project_audit_capture_principle.md`. Capture is
 * universal — every edition writes audit rows; the audit_log table ships
 * `forwardedAt` + `forwardAttempts` columns + index on every install
 * (Install.php). Exposure is gated — only Enterprise installs see the CP
 * subnav, can register forwarders, and run the queue job that consumes
 * them. The forwarders table exists empty on Lite / Pro and that's the
 * correct state. SIEM forwarding is the canonical example of "exposure
 * gated, capture universal."
 *
 * Failure mode contract: forwarder failures NEVER block the originating
 * audit/notification write. The forwarder is read-side only. `forward()`
 * never throws — it returns bool. The job's `processItem` is the only
 * place that can soft-fail per row, and a row left with `forwardedAt =
 * NULL` is naturally retriable on the next batch.
 *
 * Multi-forwarder semantics: a row is "forwarded" the moment ONE
 * forwarder accepts it. Operators with multiple endpoints get
 * at-least-once delivery to one of them; downstream SIEMs dedup on event
 * UID. Different intent (all-forwarders-must-succeed) is trivial to flip
 * — it's a single condition in `SiemForwardJob::processItem`.
 *
 * Circuit breaker (HIBP-style cache + DB durability):
 *
 *  - Cache key `pp:siem-forwarder-circuit:{forwarderId}` holds the
 *    consecutive-failure counter as a string. Cache `get()` returns
 *    `false` for missing keys (`feedback_skill_gaps.md` #11) so we use
 *    string sentinels and `cache->exists()` for presence checks.
 *  - `consecutiveFailures` + `circuitOpenAt` columns on
 *    `passwordpolicy_siem_forwarders` mirror the cache, so a flush
 *    doesn't reset circuit state.
 *  - Threshold (default 5) opens the circuit. `getActiveForwarders()`
 *    excludes opened forwarders within their cooldown window (default
 *    300s).
 *  - Half-open probe: a forwarder past its cooldown is included in the
 *    next batch — the next forward attempt IS the probe. On probe
 *    success, reset; on probe failure, push `circuitOpenAt` forward.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class SiemService extends Component
{
    // Const Properties
    // =========================================================================

    /**
     * Cache key prefix for the per-forwarder circuit-breaker counter.
     * Stable shape so cache-warming hits the same slot across processes.
     *
     * @var string
     *
     * @since 5.2.0
     */
    public const CACHE_KEY_CIRCUIT = 'pp:siem-forwarder-circuit:';

    /**
     * RFC 5424 syslog facility for "local0" — the conventional facility
     * for application-emitted audit events. Multiplied with severity to
     * produce the priority value that opens the syslog frame.
     *
     * @var int
     *
     * @since 5.2.0
     */
    public const SYSLOG_FACILITY_LOCAL0 = 16;

    /**
     * RFC 5424 syslog severity "notice" — the conventional severity for
     * audit-trail events that are operationally noteworthy but neither
     * warning nor error.
     *
     * @var int
     *
     * @since 5.2.0
     */
    public const SYSLOG_SEVERITY_NOTICE = 5;

    /**
     * Connect timeout for the TLS stream socket, in seconds. A SIEM
     * endpoint that doesn't accept inside 5s is effectively offline for
     * the purpose of an audit-forwarder retry; the queue job will pick
     * up the row on its next pass.
     *
     * @var int
     *
     * @since 5.2.0
     */
    public const TLS_CONNECT_TIMEOUT = 5;

    // Public Methods
    // =========================================================================

    /**
     * Deletes a forwarder by ID. No-op when the forwarder doesn't exist.
     * Returns true on a successful delete (or no-op), false on DB
     * failure.
     *
     * @param int $id
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function deleteForwarder(int $id): bool
    {
        try {
            Craft::$app->getDb()->createCommand()
                ->delete(SiemForwarderRecord::tableName(), ['id' => $id])
                ->execute();

            // Best-effort cache cleanup. The cache entry naturally
            // expires anyway, so a failure here is harmless.
            Craft::$app->getCache()->delete(self::CACHE_KEY_CIRCUIT . $id);
        } catch (Throwable $e) {
            Craft::error(
                'Failed to delete SIEM forwarder ' . $id . ': ' . $e->getMessage(),
                'password-policy',
            );

            return false;
        }

        return true;
    }

    /**
     * Sends a syslog-over-TLS frame for `$auditRow` to `$forwarder`.
     *
     * Returns true when the full frame writes successfully, false on any
     * failure (connect timeout, TLS handshake error, partial write).
     * NEVER throws — the failure-mode contract requires that originating
     * audit writes are decoupled from forwarder health, and the only
     * caller is the queue job's `processItem`, which records the
     * boolean outcome on the row.
     *
     * Updates the circuit-breaker state on every call:
     *
     *  - Success: resets the per-forwarder cache counter to 0 and
     *    clears `consecutiveFailures` + `circuitOpenAt` on the DB row
     *    (only when the prior state was non-zero — avoids a useless
     *    write on every successful forward).
     *  - Failure: increments cache + DB counter; opens the circuit
     *    (writes `circuitOpenAt = NOW()`) when the threshold is
     *    crossed.
     *
     * @param array<string, mixed> $auditRow the audit-log row to forward
     *     (raw row shape from the `passwordpolicy_audit_log` query — the
     *     full row, not just the canonical payload, so the consumer SIEM
     *     sees `id`, `rowHash`, `forwardedAt` if it cares to)
     * @param SiemForwarderModel $forwarder
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function forward(array $auditRow, SiemForwarderModel $forwarder): bool
    {
        if ($forwarder->id === null) {
            return false;
        }

        try {
            $this->_writeToSocket($forwarder, $this->_buildSyslogFrame($auditRow));
            $this->_recordSuccess($forwarder);

            return true;
        } catch (Throwable $e) {
            // NEVER log the full request payload. Body of an audit row
            // can carry the (already-allowlist-filtered) `details` blob,
            // but a per-row error log every time the SIEM is unreachable
            // would dump that across the plugin log on every retry. The
            // diagnostic kept in the log is opaque: forwarder id +
            // exception message only.
            Craft::warning(
                'SIEM forward failed for forwarder ' . $forwarder->id . ': ' . $e->getMessage(),
                'password-policy',
            );
            $this->_recordFailure($forwarder);

            return false;
        }
    }

    /**
     * Returns the active forwarders eligible to receive an audit row
     * right now. "Active" means:
     *
     *  - `enabled = true`
     *  - circuit is closed (`circuitOpenAt IS NULL`), OR
     *  - circuit is open but past the cooldown window (half-open
     *    probe — next forward attempt IS the probe).
     *
     * The cooldown window is configurable via
     * `SettingsModel::$siemCircuitCooldownSeconds` (default 300s).
     *
     * @return array<int, SiemForwarderModel>
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getActiveForwarders(): array
    {
        $cooldownSeconds = $this->_circuitCooldownSeconds();
        $cooldownThreshold = Carbon::now('UTC')
            ->subSeconds($cooldownSeconds)
            ->format('Y-m-d H:i:s');

        $rows = SiemForwarderRecord::find()
            ->where(['enabled' => true])
            ->andWhere([
                'or',
                ['circuitOpenAt' => null],
                ['<=', 'circuitOpenAt', $cooldownThreshold],
            ])
            ->all();

        $models = [];
        foreach ($rows as $row) {
            /** @var SiemForwarderRecord $row */
            $models[] = SiemForwarderModel::fromRecord($row);
        }

        return $models;
    }

    /**
     * Returns the event-class allowlist a forwarder consumes against.
     * Per-forwarder override wins when populated (non-null + non-empty);
     * otherwise the global `SettingsModel::$siemForwardEventClasses`
     * applies.
     *
     * The allowlist describes which TABLE STREAMS the forwarder pulls
     * from. For 5.2.0 only `audit_log` is supported. The setting shape
     * is forward-compatible — `notification_log` joins as a 5.3
     * expansion without a schema change.
     *
     * Per-event-name filtering on the audit `event` column (e.g. only
     * forward `password_changed`, not `account_locked`) is a 5.3
     * enhancement — the model supports the array shape now, the queue
     * job and CP UI don't drive that distinction.
     *
     * @param SiemForwarderModel $forwarder
     * @return array<int, string>
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getEligibleEventClasses(SiemForwarderModel $forwarder): array
    {
        if (!empty($forwarder->eventClasses)) {
            return array_values($forwarder->eventClasses);
        }

        return PasswordPolicy::$plugin->getSettings()->siemForwardEventClasses;
    }

    /**
     * Returns a single forwarder by ID, hydrated as a model. Returns
     * null when no row matches.
     *
     * @param int $id
     * @return SiemForwarderModel|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getForwarderById(int $id): ?SiemForwarderModel
    {
        /** @var SiemForwarderRecord|null $record */
        $record = SiemForwarderRecord::findOne(['id' => $id]);

        if ($record === null) {
            return null;
        }

        return SiemForwarderModel::fromRecord($record);
    }

    /**
     * Returns all configured forwarders ordered by ID (creation order).
     * Used by the CP index template; no edition gating here — the
     * controller / subnav are gated and that's where exposure stops.
     *
     * @return array<int, SiemForwarderModel>
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function listForwarders(): array
    {
        $rows = SiemForwarderRecord::find()
            ->orderBy(['id' => SORT_ASC])
            ->all();

        $models = [];
        foreach ($rows as $row) {
            /** @var SiemForwarderRecord $row */
            $models[] = SiemForwarderModel::fromRecord($row);
        }

        return $models;
    }

    /**
     * Resets a forwarder's circuit state on demand — clears
     * `circuitOpenAt`, zeroes `consecutiveFailures`, and deletes the
     * cache counter. Surfaced as a CP button so an operator who fixed a
     * SIEM-side issue (firewall / cert / endpoint outage) doesn't have
     * to wait for the cooldown to elapse.
     *
     * No-op when the forwarder is already in clean state. Returns true
     * on a successful reset (or no-op), false on DB failure.
     *
     * @param int $id
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function resetCircuit(int $id): bool
    {
        try {
            $now = Carbon::now('UTC')->format('Y-m-d H:i:s');

            Craft::$app->getDb()->createCommand()
                ->update(
                    SiemForwarderRecord::tableName(),
                    [
                        'circuitOpenAt' => null,
                        'consecutiveFailures' => 0,
                        'dateUpdated' => $now,
                    ],
                    ['id' => $id],
                )
                ->execute();

            Craft::$app->getCache()->delete(self::CACHE_KEY_CIRCUIT . $id);
        } catch (Throwable $e) {
            Craft::error(
                'Failed to reset SIEM forwarder circuit ' . $id . ': ' . $e->getMessage(),
                'password-policy',
            );

            return false;
        }

        return true;
    }

    /**
     * Persists a forwarder model to its record. Handles both new
     * (insert) and existing (update) paths. Returns false when the
     * model fails validation; the caller pulls per-field errors off the
     * model.
     *
     * @param SiemForwarderModel $forwarder
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function saveForwarder(SiemForwarderModel $forwarder): bool
    {
        if (!$forwarder->validate()) {
            return false;
        }

        $record = $forwarder->id !== null
            ? SiemForwarderRecord::findOne(['id' => $forwarder->id])
            : null;

        if ($record === null) {
            $record = new SiemForwarderRecord();
            $forwarder->uid = $forwarder->uid ?: StringHelper::UUID();
        }

        $record->name = $forwarder->name;
        $record->protocol = $forwarder->protocol;
        $record->host = $forwarder->host;
        $record->port = $forwarder->port;
        $record->tlsCertVerify = $forwarder->tlsCertVerify;
        $record->tlsCaBundlePath = $forwarder->tlsCaBundlePath;
        $record->eventClasses = !empty($forwarder->eventClasses)
            ? array_values($forwarder->eventClasses)
            : null;
        $record->enabled = $forwarder->enabled;
        $record->uid = $forwarder->uid ?? StringHelper::UUID();

        // Save without re-validating — model already passed
        // validate() above; ActiveRecord's own rules don't apply.
        $record->save(false);

        $forwarder->id = (int)$record->id;

        return true;
    }

    /**
     * Fires a synthetic `siem_test` audit event and forwards the
     * resulting row through `$forwarder` synchronously. Surfaces
     * success / failure to the caller via boolean return + thrown
     * exception on infrastructure errors (e.g. table unwritable). The
     * "Send test event" CP button POSTs through the controller into
     * this method.
     *
     * The synthetic event must already be registered in
     * `AuditLogService::ALLOWED_DETAILS_BY_EVENT` (see G5 — fail-closed
     * registry). Without that entry the audit row drops on the floor,
     * and the test would erroneously surface "no row to forward."
     *
     * Throws `RuntimeException` when the audit row can't be located
     * after the write (DB transient or registry gap) — the caller
     * surfaces the message verbatim. Throws nothing on a forward
     * failure; the boolean return distinguishes "endpoint accepted"
     * from "endpoint refused or timed out."
     *
     * @param SiemForwarderModel $forwarder
     * @return bool true when the endpoint accepted the frame, false on
     *     refusal / timeout
     *
     * @throws RuntimeException when the audit row can't be located
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function sendTestEvent(SiemForwarderModel $forwarder): bool
    {
        $currentUser = Craft::$app->getUser()->getIdentity();
        $userId = $currentUser?->id;

        PasswordPolicy::$plugin->getAuditLog()->logEvent(
            userId: $userId,
            event: 'siem_test',
            details: ['source' => 'admin'],
            outcome: 'success',
        );

        // Look up the just-written row. Order by `id DESC LIMIT 1`
        // because the chain insert is serialized; the row is on disk
        // at the moment `logEvent` returns.
        $row = (new Query())
            ->from('{{%passwordpolicy_audit_log}}')
            ->where(['event' => 'siem_test'])
            ->orderBy(['id' => SORT_DESC])
            ->limit(1)
            ->one();

        if (!is_array($row)) {
            throw new RuntimeException(
                'Test event was logged but could not be located for forwarding.',
            );
        }

        return $this->forward($row, $forwarder);
    }

    // Private Methods
    // =========================================================================

    /**
     * Builds an RFC 5424 syslog frame for `$auditRow`.
     *
     * Frame shape:
     *
     *     <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
     *
     * - PRI = facility * 8 + severity (133 for local0.notice).
     * - VERSION = 1 (RFC 5424).
     * - TIMESTAMP = ISO 8601 with explicit `Z` suffix.
     * - HOSTNAME = the system uname.
     * - APP-NAME = `password-policy`.
     * - PROCID = current process id.
     * - MSGID = `audit-log`.
     * - STRUCTURED-DATA = `-` (no SDATA blocks).
     * - MSG = JSON-encoded audit row body (BOM-free).
     *
     * @param array<string, mixed> $auditRow
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _buildSyslogFrame(array $auditRow): string
    {
        $priority = (self::SYSLOG_FACILITY_LOCAL0 * 8) + self::SYSLOG_SEVERITY_NOTICE;
        $timestamp = Carbon::now('UTC')->format('Y-m-d\TH:i:s\Z');
        $hostname = (string)(gethostname() ?: '-');
        $procId = (string)getmypid() ?: '-';
        $body = Json::encode(
            $auditRow,
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE,
        );

        return sprintf(
            '<%d>1 %s %s %s %s %s - %s',
            $priority,
            $timestamp,
            $hostname,
            'password-policy',
            $procId,
            'audit-log',
            $body,
        );
    }

    /**
     * Returns the configured circuit-breaker cooldown window in seconds.
     * Falls back to 300s if the setting is somehow non-positive.
     *
     * @return int
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _circuitCooldownSeconds(): int
    {
        $configured = PasswordPolicy::$plugin->getSettings()->siemCircuitCooldownSeconds;

        return $configured > 0 ? $configured : 300;
    }

    /**
     * Returns the configured failure threshold that opens the circuit.
     * Falls back to 5 if the setting is somehow non-positive.
     *
     * @return int
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _circuitFailureThreshold(): int
    {
        $configured = PasswordPolicy::$plugin->getSettings()->siemCircuitFailureThreshold;

        return $configured > 0 ? $configured : 5;
    }

    /**
     * Records a forward failure. Increments cache + DB counter and
     * opens the circuit when the threshold is crossed. Best-effort:
     * a write failure is logged but never rethrown (the originating
     * forward already failed; we don't want to compound the noise).
     *
     * @param SiemForwarderModel $forwarder
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _recordFailure(SiemForwarderModel $forwarder): void
    {
        if ($forwarder->id === null) {
            return;
        }

        $threshold = $this->_circuitFailureThreshold();
        $cache = Craft::$app->getCache();
        $cacheKey = self::CACHE_KEY_CIRCUIT . $forwarder->id;

        $current = (int)($cache->get($cacheKey) ?: 0);
        $next = $current + 1;
        $cache->set($cacheKey, (string)$next, $this->_circuitCooldownSeconds());

        $update = [
            'consecutiveFailures' => $next,
            'dateUpdated' => Carbon::now('UTC')->format('Y-m-d H:i:s'),
        ];

        if ($next >= $threshold && $forwarder->circuitOpenAt === null) {
            $update['circuitOpenAt'] = Carbon::now('UTC')->format('Y-m-d H:i:s');
        }

        try {
            Craft::$app->getDb()->createCommand()
                ->update(
                    SiemForwarderRecord::tableName(),
                    $update,
                    ['id' => $forwarder->id],
                )
                ->execute();
        } catch (Throwable $e) {
            Craft::error(
                'Failed to update SIEM forwarder failure state: ' . $e->getMessage(),
                'password-policy',
            );
        }
    }

    /**
     * Records a forward success. Resets the cache counter and clears
     * the DB circuit state — but only writes to the DB when the prior
     * state was non-zero, so a steady-state of healthy forwards
     * doesn't generate a row update on every send.
     *
     * @param SiemForwarderModel $forwarder
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _recordSuccess(SiemForwarderModel $forwarder): void
    {
        if ($forwarder->id === null) {
            return;
        }

        $cache = Craft::$app->getCache();
        $cache->delete(self::CACHE_KEY_CIRCUIT . $forwarder->id);

        // Skip the DB write when the prior state was already clean.
        if ($forwarder->consecutiveFailures === 0 && $forwarder->circuitOpenAt === null) {
            return;
        }

        try {
            Craft::$app->getDb()->createCommand()
                ->update(
                    SiemForwarderRecord::tableName(),
                    [
                        'consecutiveFailures' => 0,
                        'circuitOpenAt' => null,
                        'dateUpdated' => Carbon::now('UTC')->format('Y-m-d H:i:s'),
                    ],
                    ['id' => $forwarder->id],
                )
                ->execute();
        } catch (Throwable $e) {
            Craft::error(
                'Failed to clear SIEM forwarder circuit on success: ' . $e->getMessage(),
                'password-policy',
            );
        }
    }

    /**
     * Opens a TLS stream to `$forwarder` and writes the syslog frame.
     * Throws on any failure — caller wraps in the failure-mode try/catch
     * inside `forward()`.
     *
     * Stream context honors:
     *  - `verify_peer` per the forwarder's `tlsCertVerify`
     *  - `cafile` per the env-resolved `tlsCaBundlePath` (only when set)
     *  - `verify_peer_name` follows `verify_peer` — operators who turn
     *    off cert verification expect host verification to follow
     *
     * Per `security.md`, this overrides any site-level
     * `config/guzzle.php` `verify => false` because we use a raw stream
     * socket, not Guzzle. Defense-in-depth.
     *
     * @param SiemForwarderModel $forwarder
     * @param string $frame the RFC 5424 syslog frame
     * @return void
     *
     * @throws RuntimeException on connect failure, TLS handshake error,
     *     or partial write
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _writeToSocket(SiemForwarderModel $forwarder, string $frame): void
    {
        $contextOptions = [
            'ssl' => [
                'verify_peer' => $forwarder->tlsCertVerify,
                'verify_peer_name' => $forwarder->tlsCertVerify,
            ],
        ];

        if ($forwarder->tlsCaBundlePath !== null && $forwarder->tlsCaBundlePath !== '') {
            $resolved = App::parseEnv($forwarder->tlsCaBundlePath);

            if (is_string($resolved) && $resolved !== '') {
                $contextOptions['ssl']['cafile'] = $resolved;
            }
        }

        $context = stream_context_create($contextOptions);
        $address = sprintf('tls://%s:%d', $forwarder->host, $forwarder->port);
        $errno = 0;
        $errstr = '';

        $socket = @stream_socket_client(
            $address,
            $errno,
            $errstr,
            self::TLS_CONNECT_TIMEOUT,
            STREAM_CLIENT_CONNECT,
            $context,
        );

        if ($socket === false) {
            throw new RuntimeException(sprintf(
                'TLS connect failed (%d): %s',
                $errno,
                $errstr !== '' ? $errstr : 'unknown error',
            ));
        }

        // Append a newline so a downstream syslog reader using
        // line-delimited framing can split frames cleanly.
        $payload = $frame . "\n";
        $written = @fwrite($socket, $payload);
        @fclose($socket);

        if ($written === false || $written < strlen($payload)) {
            throw new RuntimeException('TLS write was incomplete or failed.');
        }
    }
}
