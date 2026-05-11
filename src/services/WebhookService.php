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
use craft\helpers\StringHelper;
use craftpulse\passwordpolicy\events\WebhookDeliveryAttemptEvent;
use craftpulse\passwordpolicy\models\WebhookEndpointModel;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\records\WebhookEndpointRecord;
use RuntimeException;
use Throwable;
use yii\base\Component;

/**
 * Class WebhookService
 *
 * Forwards audit-log rows to one or more registered HTTP webhook
 * endpoints with HMAC-signed payloads. Second forwarder in the matrix;
 * pairs with the syslog-over-TLS forwarder shipped in G8.
 *
 * Multi-endpoint dispatch semantics
 * ---------------------------------
 * Each endpoint is an INDEPENDENT subscriber. Endpoint A's success does
 * NOT mark endpoint B's row delivered. Tracking is per-endpoint via the
 * `lastDeliveredRowId` watermark column — the queue job dispatches rows
 * where `id > endpoint.lastDeliveredRowId` and bumps the cursor on each
 * success. Differs intentionally from G8's at-least-once-to-one
 * semantics; webhook subscribers are typically distinct ops systems
 * (compliance dashboards, incident queues, etc.) and A's success
 * tells you nothing about B's reachability.
 *
 * The audit_log table's `forwardedAt` / `forwardAttempts` columns
 * belong to the SIEM forwarder. Webhook state lives entirely on the
 * endpoint row.
 *
 * HMAC scheme (per § 4 of phase-g-build-plan.md, locked)
 * ------------------------------------------------------
 * Headers on every dispatch:
 *
 *  - `Content-Type: application/json`
 *  - `X-PasswordPolicy-Timestamp: <unix-epoch-seconds>`
 *  - `X-PasswordPolicy-Event-Id: <auditRow.uid>` — stable across
 *    retries of the same row, fresh per row. Consumer dedups on this.
 *  - `X-PasswordPolicy-Signature: sha256=<hex>` where `<hex>` =
 *    `hash_hmac('sha256', "{$timestamp}.{$eventId}.{$body}",
 *    $secretCurrent)`. The recipient verifies against the bytes
 *    received — no canonicalisation on the recipient side.
 *
 * Body: canonical JSON of the audit row via
 * `AuditLogService::canonicalize()`. SIEM and webhook consumers see
 * the same byte sequence.
 *
 * Replay window enforcement is consumer-side. The plugin signs and
 * sends; a 5-minute drift window between the timestamp and "now" is
 * the documented contract for downstream verifiers.
 *
 * Secret rotation
 * ---------------
 * Each endpoint carries `secretCurrent` and `secretPrevious` columns,
 * both encrypted at rest at the model boundary. Rotation:
 *
 *  1. Operator clicks "Rotate secret" in CP (or runs the console
 *     action). `rotateSecret()` moves current → previous, generates a
 *     new current, sets `secretRotatedAt = NOW()`.
 *  2. The new secret is surfaced ONCE — flash message + display panel
 *     in CP, stdout in console. The plaintext is gone from the
 *     controller layer immediately after.
 *  3. During the grace window (default 24h, configurable up to 7d via
 *     `webhookSecretGracePeriodHours`), consumers may still verify
 *     against the old secret. The plugin signs with the new one
 *     exclusively — the dual-secret window is for the consumer's
 *     benefit.
 *  4. `RotateWebhookSecretJob` reaps `secretPrevious` on schedule.
 *
 * Circuit breaker (mirrors G8's shape)
 * ------------------------------------
 *
 *  - Cache key `pp:webhook-endpoint-circuit:{endpointId}` holds the
 *    consecutive-failure counter as a string.
 *  - `consecutiveFailures` + `circuitOpenAt` columns on
 *    `passwordpolicy_webhook_endpoints` mirror the cache so a flush
 *    doesn't reset circuit state.
 *  - Threshold (`webhookCircuitFailureThreshold`, default 5) opens the
 *    circuit. `getActiveEndpoints()` excludes opened endpoints inside
 *    their cooldown window (`webhookCircuitCooldownSeconds`, default
 *    300s).
 *  - Half-open probe: an endpoint past its cooldown is included in
 *    the next batch — the next dispatch IS the probe.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class WebhookService extends Component
{
    // Const Properties
    // =========================================================================

    /**
     * Cache key prefix for the per-endpoint circuit-breaker counter.
     *
     * @var string
     *
     * @since 5.2.0
     */
    public const CACHE_KEY_CIRCUIT = 'pp:webhook-endpoint-circuit:';

    /**
     * Maximum body length, in bytes, returned by `sendTestEvent()` for
     * display in the CP. Keeps the JSON response payload bounded
     * regardless of what the endpoint echoes back.
     *
     * @var int
     *
     * @since 5.2.0
     */
    public const TEST_RESPONSE_BODY_LIMIT = 1024;

    /**
     * Total Guzzle request timeout in seconds. Applies to connect + TLS
     * handshake + send + receive. An endpoint that doesn't respond
     * within this window is treated as failed for the purpose of the
     * circuit breaker; the queue retries on the next pass.
     *
     * @var int
     *
     * @since 5.2.0
     */
    public const TIMEOUT_SECONDS = 10;

    /**
     * Fired after every dispatch attempt — success or failure. Lets
     * observability listeners capture per-delivery outcomes without
     * subscribing to the audit-log writes themselves. Edition-
     * independent (capture surface).
     *
     * @event WebhookDeliveryAttemptEvent
     *
     * @since 5.2.0
     */
    public const EVENT_WEBHOOK_DELIVERY_ATTEMPT = 'webhookDeliveryAttempt';

    // Public Methods
    // =========================================================================

    /**
     * Deletes an endpoint by ID. No-op when the endpoint doesn't exist.
     * Returns true on a successful delete (or no-op), false on DB
     * failure.
     *
     * @param int $id
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function deleteEndpoint(int $id): bool
    {
        try {
            Craft::$app->getDb()->createCommand()
                ->delete(WebhookEndpointRecord::tableName(), ['id' => $id])
                ->execute();

            // Best-effort cache cleanup. The cache entry naturally
            // expires anyway, so a failure here is harmless.
            Craft::$app->getCache()->delete(self::CACHE_KEY_CIRCUIT . $id);
        } catch (Throwable $e) {
            Craft::error(
                'Failed to delete webhook endpoint ' . $id . ': ' . $e->getMessage(),
                'password-policy',
            );

            return false;
        }

        return true;
    }

    /**
     * POSTs an HMAC-signed JSON body for `$auditRow` to `$endpoint`.
     *
     * Returns true when the endpoint responds 2xx; false on any other
     * outcome (4xx, 5xx, transport failure, timeout). NEVER throws —
     * the failure-mode contract decouples originating audit writes
     * from endpoint health.
     *
     * Updates the circuit-breaker state on every call. Fires
     * `EVENT_WEBHOOK_DELIVERY_ATTEMPT` regardless of outcome so
     * observability listeners see the full picture.
     *
     * @param array<string, mixed> $auditRow the audit-log row to
     *     forward (raw row shape from the
     *     `passwordpolicy_audit_log` query)
     * @param WebhookEndpointModel $endpoint
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function dispatch(array $auditRow, WebhookEndpointModel $endpoint): bool
    {
        if ($endpoint->id === null || $endpoint->secretCurrent === null) {
            return false;
        }

        $url = App::parseEnv($endpoint->url);

        if (!is_string($url) || $url === '') {
            return false;
        }

        $auditRowId = isset($auditRow['id']) ? (int)$auditRow['id'] : 0;
        $eventId = isset($auditRow['uid']) ? (string)$auditRow['uid'] : StringHelper::UUID();

        $body = AuditLogService::canonicalize($auditRow);
        $timestamp = (string)Carbon::now('UTC')->getTimestamp();
        $signature = 'sha256=' . hash_hmac(
            'sha256',
            $timestamp . '.' . $eventId . '.' . $body,
            $endpoint->secretCurrent,
        );

        $startedAt = microtime(true);
        $statusCode = null;
        $errorMessage = null;
        $success = false;

        try {
            $client = Craft::createGuzzleClient([
                'verify' => true,
                'http_errors' => false,
                'timeout' => self::TIMEOUT_SECONDS,
            ]);

            $response = $client->request('POST', $url, [
                'headers' => [
                    'Content-Type' => 'application/json',
                    'X-PasswordPolicy-Timestamp' => $timestamp,
                    'X-PasswordPolicy-Event-Id' => $eventId,
                    'X-PasswordPolicy-Signature' => $signature,
                ],
                'body' => $body,
            ]);

            $statusCode = $response->getStatusCode();
            $success = $statusCode >= 200 && $statusCode < 300;
        } catch (Throwable $e) {
            // NEVER log the request body or signature — they're already
            // in the audit log and the cryptographic identifier
            // shouldn't leak through diagnostics. Endpoint id +
            // exception message is the diagnostic kept here.
            // GuzzleException implements Throwable; the catch-all
            // here is correct.
            $errorMessage = $e->getMessage();
            Craft::warning(
                'Webhook dispatch failed for endpoint ' . $endpoint->id . ': ' . $e->getMessage(),
                'password-policy',
            );
        }

        $duration = (int)round((microtime(true) - $startedAt) * 1000);

        if ($success) {
            $this->_recordSuccess($endpoint);
        } else {
            $this->_recordFailure($endpoint);
        }

        $this->_fireDeliveryEvent(
            endpointId: (int)$endpoint->id,
            auditRowId: $auditRowId,
            statusCode: $statusCode,
            duration: $duration,
            success: $success,
            errorMessage: $errorMessage,
        );

        return $success;
    }

    /**
     * Returns the active endpoints eligible to receive an audit row
     * right now. "Active" means:
     *
     *  - `enabled = true`
     *  - circuit is closed (`circuitOpenAt IS NULL`), OR
     *  - circuit is open but past the cooldown window (half-open
     *    probe — next dispatch IS the probe).
     *
     * The cooldown window is configurable via
     * `SettingsModel::$webhookCircuitCooldownSeconds` (default 300s).
     *
     * @return array<int, WebhookEndpointModel>
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getActiveEndpoints(): array
    {
        $cooldownSeconds = $this->_circuitCooldownSeconds();
        $cooldownThreshold = Carbon::now('UTC')
            ->subSeconds($cooldownSeconds)
            ->format('Y-m-d H:i:s');

        $rows = WebhookEndpointRecord::find()
            ->where(['enabled' => true])
            ->andWhere([
                'or',
                ['circuitOpenAt' => null],
                ['<=', 'circuitOpenAt', $cooldownThreshold],
            ])
            ->all();

        $models = [];
        foreach ($rows as $row) {
            /** @var WebhookEndpointRecord $row */
            $models[] = WebhookEndpointModel::fromRecord($row);
        }

        return $models;
    }

    /**
     * Returns the event-class allowlist an endpoint consumes against.
     * Per-endpoint override wins when populated (non-null + non-empty);
     * otherwise the global `SettingsModel::$webhookForwardEventClasses`
     * applies.
     *
     * The allowlist describes which TABLE STREAMS the endpoint pulls
     * from. For 5.2.0 only `audit_log` is supported, but the shape is
     * forward-compatible — `notification_log` joins as a 5.3 expansion
     * without a schema change.
     *
     * @param WebhookEndpointModel $endpoint
     * @return array<int, string>
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getEligibleEventClasses(WebhookEndpointModel $endpoint): array
    {
        if (!empty($endpoint->eventClasses)) {
            return array_values($endpoint->eventClasses);
        }

        return PasswordPolicy::$plugin->getSettings()->webhookForwardEventClasses;
    }

    /**
     * Returns a single endpoint by ID, hydrated as a model. Returns
     * null when no row matches.
     *
     * @param int $id
     * @return WebhookEndpointModel|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getEndpointById(int $id): ?WebhookEndpointModel
    {
        /** @var WebhookEndpointRecord|null $record */
        $record = WebhookEndpointRecord::findOne(['id' => $id]);

        if ($record === null) {
            return null;
        }

        return WebhookEndpointModel::fromRecord($record);
    }

    /**
     * Returns all configured endpoints ordered by ID (creation order).
     * Used by the CP index template; no edition gating here — the
     * controller / subnav are gated and that's where exposure stops.
     *
     * @return array<int, WebhookEndpointModel>
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function listEndpoints(): array
    {
        $rows = WebhookEndpointRecord::find()
            ->orderBy(['id' => SORT_ASC])
            ->all();

        $models = [];
        foreach ($rows as $row) {
            /** @var WebhookEndpointRecord $row */
            $models[] = WebhookEndpointModel::fromRecord($row);
        }

        return $models;
    }

    /**
     * Resets an endpoint's circuit state on demand — clears
     * `circuitOpenAt`, zeroes `consecutiveFailures`, and deletes the
     * cache counter. Surfaced as a CP button so an operator who fixed
     * a downstream issue (firewall / cert / endpoint outage) doesn't
     * have to wait for the cooldown to elapse.
     *
     * No-op when the endpoint is already in clean state. Returns true
     * on a successful reset (or no-op), false on DB failure.
     *
     * @param int $endpointId
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function resetCircuit(int $endpointId): bool
    {
        try {
            $now = Carbon::now('UTC')->format('Y-m-d H:i:s');

            Craft::$app->getDb()->createCommand()
                ->update(
                    WebhookEndpointRecord::tableName(),
                    [
                        'circuitOpenAt' => null,
                        'consecutiveFailures' => 0,
                        'dateUpdated' => $now,
                    ],
                    ['id' => $endpointId],
                )
                ->execute();

            Craft::$app->getCache()->delete(self::CACHE_KEY_CIRCUIT . $endpointId);
        } catch (Throwable $e) {
            Craft::error(
                'Failed to reset webhook endpoint circuit ' . $endpointId . ': ' . $e->getMessage(),
                'password-policy',
            );

            return false;
        }

        return true;
    }

    /**
     * Rotates the endpoint's HMAC secret. Moves `secretCurrent` to
     * `secretPrevious`, sets a freshly generated random secret as the
     * new `secretCurrent`, and pins `secretRotatedAt = NOW()`.
     *
     * Returns the new plaintext secret. The CALLER is responsible for
     * surfacing the secret to the operator exactly once — via a CP
     * flash + display panel after creation/rotation, or by writing it
     * to stdout in the console action. After this method returns,
     * the model goes back to its persistence shape (encrypted at
     * rest); the plaintext is GONE outside the caller's local scope.
     *
     * Pass a non-null `$newSecret` to use a caller-supplied value
     * (test fixtures, CI provisioning, IaC pipelines). Production
     * paths leave it null and use the `Security::generateRandomString`
     * default.
     *
     * @param WebhookEndpointModel $endpoint
     * @param string|null $newSecret
     * @return string the new plaintext secret
     *
     * @throws RuntimeException when the endpoint can't be saved after
     *     rotation
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function rotateSecret(WebhookEndpointModel $endpoint, ?string $newSecret = null): string
    {
        if ($newSecret === null || $newSecret === '') {
            $newSecret = Craft::$app->getSecurity()->generateRandomString(64);
        }

        $endpoint->secretPrevious = $endpoint->secretCurrent;
        $endpoint->secretCurrent = $newSecret;
        $endpoint->secretRotatedAt = Carbon::now('UTC')->toDateTime();

        if (!$this->saveEndpoint($endpoint)) {
            throw new RuntimeException(
                'Failed to persist webhook secret rotation: ' . implode('; ', $endpoint->getErrorSummary(true)),
            );
        }

        return $newSecret;
    }

    /**
     * Persists an endpoint model to its record. Handles both new
     * (insert) and existing (update) paths. Returns false when the
     * model fails validation; the caller pulls per-field errors off
     * the model.
     *
     * For NEW endpoints, generates an initial `secretCurrent` if the
     * caller hasn't supplied one — keeps the controller and the
     * console action's "create" path symmetrical.
     *
     * Encryption happens at the model boundary in
     * `WebhookEndpointModel::toRecordAttributes()`; the record stores
     * opaque ciphertext only.
     *
     * @param WebhookEndpointModel $endpoint
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function saveEndpoint(WebhookEndpointModel $endpoint): bool
    {
        // Auto-generate the initial secret on a fresh endpoint when
        // the caller hasn't supplied one. The controller's `actionSave`
        // doesn't always carry a secret in POST (we never re-render it
        // in the form), so this is the natural place to fill it in.
        if ($endpoint->id === null && ($endpoint->secretCurrent === null || $endpoint->secretCurrent === '')) {
            $endpoint->secretCurrent = Craft::$app->getSecurity()->generateRandomString(64);
        }

        if (!$endpoint->validate()) {
            return false;
        }

        $record = $endpoint->id !== null
            ? WebhookEndpointRecord::findOne(['id' => $endpoint->id])
            : null;

        if ($record === null) {
            $record = new WebhookEndpointRecord();
            $endpoint->uid = $endpoint->uid ?: StringHelper::UUID();
        }

        foreach ($endpoint->toRecordAttributes() as $key => $value) {
            $record->{$key} = $value;
        }

        $record->uid = $endpoint->uid ?? StringHelper::UUID();

        // Save without re-validating — model already passed
        // validate() above; ActiveRecord's own rules don't apply.
        $record->save(false);

        $endpoint->id = (int)$record->id;

        return true;
    }

    /**
     * Fires a synthetic `webhook_test` audit event and dispatches the
     * resulting row through `$endpoint` synchronously. Returns the
     * dispatch outcome shape the CP "Send test event" button consumes:
     * `['statusCode', 'duration', 'body', 'success']`.
     *
     * Body is the truncated response body (capped at
     * {@see TEST_RESPONSE_BODY_LIMIT} bytes) so the CP panel doesn't
     * have to render an unbounded payload.
     *
     * The synthetic event must already be registered in
     * `AuditLogService::ALLOWED_DETAILS_BY_EVENT` (G5 — fail-closed
     * registry). Without that entry the audit row drops on the floor,
     * and the test would erroneously surface "no row to dispatch."
     *
     * Throws `RuntimeException` when the audit row can't be located
     * after the write (DB transient or registry gap) — the controller
     * surfaces the message verbatim.
     *
     * @param WebhookEndpointModel $endpoint
     * @return array{statusCode: ?int, duration: int, body: string, success: bool}
     *
     * @throws RuntimeException when the audit row can't be located
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function sendTestEvent(WebhookEndpointModel $endpoint): array
    {
        $currentUser = Craft::$app->getUser()->getIdentity();
        $userId = $currentUser?->id;

        $rowId = PasswordPolicy::$plugin->getAuditLog()->logEvent(
            userId: $userId,
            event: 'webhook_test',
            details: ['source' => 'admin'],
            outcome: 'success',
        );

        // Fetch the just-written row by primary key. Using the returned
        // id instead of `ORDER BY id DESC LIMIT 1` removes the race
        // against concurrent admin clicks — without it, a second test
        // arriving between this write and read would steal the lookup.
        if ($rowId === null) {
            throw new RuntimeException(
                'Test event could not be written to the audit log; the log may be disabled or misconfigured.',
            );
        }

        $row = (new Query())
            ->from('{{%passwordpolicy_audit_log}}')
            ->where(['id' => $rowId])
            ->one();

        if (!is_array($row)) {
            throw new RuntimeException(
                'Test event was logged but could not be located for dispatch.',
            );
        }

        // Capture the dispatch via a one-shot listener so we don't
        // double-up Guzzle calls just to grab the response shape. The
        // listener is detached on the way out regardless of outcome.
        $captured = [
            'statusCode' => null,
            'duration' => 0,
            'success' => false,
            'errorMessage' => null,
        ];

        $handler = function(WebhookDeliveryAttemptEvent $event) use (&$captured): void {
            $captured['statusCode'] = $event->statusCode;
            $captured['duration'] = $event->duration;
            $captured['success'] = $event->success;
            $captured['errorMessage'] = $event->errorMessage;
        };

        $this->on(self::EVENT_WEBHOOK_DELIVERY_ATTEMPT, $handler);
        try {
            $this->dispatch($row, $endpoint);
        } finally {
            $this->off(self::EVENT_WEBHOOK_DELIVERY_ATTEMPT, $handler);
        }

        $body = $captured['errorMessage'] ?? '';
        if (strlen($body) > self::TEST_RESPONSE_BODY_LIMIT) {
            $body = substr($body, 0, self::TEST_RESPONSE_BODY_LIMIT) . '...';
        }

        return [
            'statusCode' => $captured['statusCode'],
            'duration' => $captured['duration'],
            'body' => $body,
            'success' => $captured['success'],
        ];
    }

    // Private Methods
    // =========================================================================

    /**
     * Returns the configured circuit-breaker cooldown window in
     * seconds. Falls back to 300s if the setting is somehow
     * non-positive.
     *
     * @return int
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _circuitCooldownSeconds(): int
    {
        $configured = PasswordPolicy::$plugin->getSettings()->webhookCircuitCooldownSeconds;

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
        $configured = PasswordPolicy::$plugin->getSettings()->webhookCircuitFailureThreshold;

        return $configured > 0 ? $configured : 5;
    }

    /**
     * Fires `EVENT_WEBHOOK_DELIVERY_ATTEMPT` with the dispatch outcome
     * payload. Skipped silently when no listeners are attached so
     * dispatch never pays for an event with no consumers.
     *
     * @param int $endpointId
     * @param int $auditRowId
     * @param int|null $statusCode
     * @param int $duration
     * @param bool $success
     * @param string|null $errorMessage
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _fireDeliveryEvent(
        int $endpointId,
        int $auditRowId,
        ?int $statusCode,
        int $duration,
        bool $success,
        ?string $errorMessage,
    ): void {
        if (!$this->hasEventHandlers(self::EVENT_WEBHOOK_DELIVERY_ATTEMPT)) {
            return;
        }

        $event = new WebhookDeliveryAttemptEvent();
        $event->endpointId = $endpointId;
        $event->auditRowId = $auditRowId;
        $event->statusCode = $statusCode;
        $event->duration = $duration;
        $event->success = $success;
        $event->errorMessage = $errorMessage;

        $this->trigger(self::EVENT_WEBHOOK_DELIVERY_ATTEMPT, $event);
    }

    /**
     * Records a dispatch failure. Increments cache + DB counter and
     * opens the circuit when the threshold is crossed. Best-effort:
     * a write failure is logged but never rethrown (the originating
     * dispatch already failed; we don't want to compound the noise).
     *
     * @param WebhookEndpointModel $endpoint
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _recordFailure(WebhookEndpointModel $endpoint): void
    {
        if ($endpoint->id === null) {
            return;
        }

        $threshold = $this->_circuitFailureThreshold();
        $cache = Craft::$app->getCache();
        $cacheKey = self::CACHE_KEY_CIRCUIT . $endpoint->id;

        $current = (int)($cache->get($cacheKey) ?: 0);
        $next = $current + 1;
        $cache->set($cacheKey, (string)$next, $this->_circuitCooldownSeconds());

        $update = [
            'consecutiveFailures' => $next,
            'dateUpdated' => Carbon::now('UTC')->format('Y-m-d H:i:s'),
        ];

        if ($next >= $threshold && $endpoint->circuitOpenAt === null) {
            $update['circuitOpenAt'] = Carbon::now('UTC')->format('Y-m-d H:i:s');
        }

        try {
            Craft::$app->getDb()->createCommand()
                ->update(
                    WebhookEndpointRecord::tableName(),
                    $update,
                    ['id' => $endpoint->id],
                )
                ->execute();
        } catch (Throwable $e) {
            Craft::error(
                'Failed to update webhook endpoint failure state: ' . $e->getMessage(),
                'password-policy',
            );
        }
    }

    /**
     * Records a dispatch success. Resets the cache counter and clears
     * the DB circuit state — but only writes to the DB when the prior
     * state was non-zero, so a steady-state of healthy dispatches
     * doesn't generate a row update on every send.
     *
     * @param WebhookEndpointModel $endpoint
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _recordSuccess(WebhookEndpointModel $endpoint): void
    {
        if ($endpoint->id === null) {
            return;
        }

        $cache = Craft::$app->getCache();
        $cache->delete(self::CACHE_KEY_CIRCUIT . $endpoint->id);

        // Skip the DB write when the prior state was already clean.
        if ($endpoint->consecutiveFailures === 0 && $endpoint->circuitOpenAt === null) {
            return;
        }

        try {
            Craft::$app->getDb()->createCommand()
                ->update(
                    WebhookEndpointRecord::tableName(),
                    [
                        'consecutiveFailures' => 0,
                        'circuitOpenAt' => null,
                        'dateUpdated' => Carbon::now('UTC')->format('Y-m-d H:i:s'),
                    ],
                    ['id' => $endpoint->id],
                )
                ->execute();
        } catch (Throwable $e) {
            Craft::error(
                'Failed to clear webhook endpoint circuit on success: ' . $e->getMessage(),
                'password-policy',
            );
        }
    }
}
