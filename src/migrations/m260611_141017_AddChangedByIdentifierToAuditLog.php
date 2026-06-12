<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\migrations;

use Craft;
use craft\db\Migration;
use craft\db\Query;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\services\AuditLogService;

/**
 * Class m260611_141017_AddChangedByIdentifierToAuditLog
 *
 * Re-bases the audit-log hash chain onto an immutable identity payload
 * — the ship-blocking fix for the GDPR-erasure chain break.
 *
 * The pre-fix canonical payload hashed `userId` AND `changedByUserId`,
 * both `ON DELETE SET NULL` foreign keys on `passwordpolicy_audit_log`.
 * Deleting a user nulled those columns on every one of that user's
 * historical rows, so the verifier recomputed a different `rowHash`
 * than was stored and reported the chain as tampered. A routine
 * compliant admin action (right-to-erasure) was indistinguishable from
 * log tampering.
 *
 * The fix hashes only IMMUTABLE, post-write-stable identity columns.
 * The subject already had `userIdentifier` (HMAC of the user's email,
 * set once at write, survives deletion). The actor gets a mirror —
 * `changedByIdentifier` — added by this migration. The mutable FK ints
 * stay as columns (useful for joins / display / the SET NULL retention
 * behaviour) but leave the canonical payload entirely.
 *
 * Three phases, all idempotent:
 *
 *  1. **Add the column.** `changedByIdentifier` (nullable string),
 *     guarded by a `getColumn()` check so a re-run is a no-op.
 *  2. **Backfill the column.** For every row with a non-null
 *     `changedByUserId` whose user still exists with an email, set
 *     `changedByIdentifier = hash_hmac('sha256', email, auditPiiKey)`
 *     using the SAME key resolution as
 *     {@see AuditLogService::_resolveAuditPiiKey()} (settings
 *     `auditPiiKey` ?: `securityKey`). Rows whose actor is gone or has
 *     no email keep a null identifier — exactly the post-deletion state
 *     the new format tolerates.
 *  3. **Recompute the whole chain.** Walk every row in `id` ASC order
 *     and recompute `rowHash` from the NEW canonical key set
 *     (`changedByIdentifier, dateCreated, details, event, ipHash,
 *     outcome, source, uid, userIdentifier`), re-linking `previousHash`
 *     to the prior recomputed `rowHash`. The genesis row anchors to
 *     {@see AuditLogService::GENESIS_PREVIOUS_HASH}. This re-bases the
 *     chain to the new format so `verify` passes immediately AND future
 *     user deletions never break it again.
 *
 * Re-run safety: phase 1 skips when the column exists; phases 2 and 3
 * are pure functions of the current row state — re-running recomputes
 * the identical chain. (Unlike the G1 recompute, there is no
 * placeholder-hash guard: the new key set changes EVERY row's hash, so
 * every row must be rewritten, and a re-run simply rewrites the same
 * values.)
 *
 * Like the G1 recompute migration and the bcrypt-seed migration, the
 * recompute loop disables Yii's query logging + profiling so the
 * canonical payloads (containing `userIdentifier` / `changedByIdentifier`
 * HMACs, `ipHash` SHA-256, `details` JSON) don't reach debug logs at
 * SQL bind time. Restored in `finally`.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class m260611_141017_AddChangedByIdentifierToAuditLog extends Migration
{
    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @throws \Exception when DateTime parsing fails on a malformed dateCreated value
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function safeUp(): bool
    {
        $table = '{{%passwordpolicy_audit_log}}';

        // Phase 1 — add the column idempotently.
        $schema = $this->db->getSchema()->getTableSchema(
            $this->db->getSchema()->getRawTableName($table),
        );

        if ($schema !== null && $schema->getColumn('changedByIdentifier') === null) {
            $this->addColumn($table, 'changedByIdentifier', $this->string()->after('userIdentifier'));
        }

        // Phases 2 + 3 — backfill the actor identifier and recompute the
        // whole chain onto the new immutable-identity payload. Both run
        // with query logging + profiling disabled so the HMAC / hash
        // material never lands in debug logs at SQL bind time.
        $db = Craft::$app->getDb();
        $enableLogging = $db->enableLogging;
        $enableProfiling = $db->enableProfiling;
        $db->enableLogging = false;
        $db->enableProfiling = false;

        try {
            $this->_backfillChangedByIdentifier();
            $this->_recomputeChain();
        } finally {
            $db->enableLogging = $enableLogging;
            $db->enableProfiling = $enableProfiling;
        }

        return true;
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function safeDown(): bool
    {
        echo "m260611_141017_AddChangedByIdentifierToAuditLog cannot be reverted.\n";

        return false;
    }

    // Private Methods
    // =========================================================================

    /**
     * Backfills `changedByIdentifier` for every row whose actor
     * (`changedByUserId`) still exists with an email. Mirrors
     * {@see AuditLogService::_hashUserIdentifier()} +
     * {@see AuditLogService::_resolveAuditPiiKey()}: the HMAC is keyed
     * by the operator-managed `auditPiiKey`, falling back to
     * `securityKey`. Rows whose actor is gone or has no email keep a
     * null identifier — the post-deletion state the new format is
     * designed to tolerate.
     *
     * Distinct actor ids are resolved up front, hashed once each, then
     * applied with a single UPDATE per actor — avoids re-hashing the
     * same actor's email on every row they touched.
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _backfillChangedByIdentifier(): void
    {
        $key = $this->_resolveAuditPiiKey();

        /** @var array<int, int> $actorIds */
        $actorIds = (new Query())
            ->select(['changedByUserId'])
            ->distinct()
            ->from('{{%passwordpolicy_audit_log}}')
            ->where(['not', ['changedByUserId' => null]])
            ->column();

        foreach ($actorIds as $actorId) {
            $actorId = (int)$actorId;
            $user = Craft::$app->getUsers()->getUserById($actorId);

            if ($user === null || $user->email === null) {
                continue;
            }

            $identifier = hash_hmac('sha256', $user->email, $key);

            $this->db->createCommand()
                ->update(
                    '{{%passwordpolicy_audit_log}}',
                    ['changedByIdentifier' => $identifier],
                    ['changedByUserId' => $actorId],
                )
                ->execute();
        }
    }

    /**
     * Walks every audit row in `id` ASC order and recomputes the
     * `rowHash` / `previousHash` columns from the NEW canonical payload
     * (immutable HMAC identities, no mutable FK ints). The genesis row
     * anchors to {@see AuditLogService::GENESIS_PREVIOUS_HASH}; every
     * subsequent row's `previousHash` is the prior row's recomputed
     * `rowHash`.
     *
     * Every row is rewritten — the new key set changes every hash, so
     * there is no skip-if-unchanged guard. A re-run recomputes the same
     * values, so the migration stays idempotent.
     *
     * @return void
     *
     * @throws \Exception when DateTime parsing fails on a malformed dateCreated value
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _recomputeChain(): void
    {
        $rows = (new Query())
            ->from('{{%passwordpolicy_audit_log}}')
            ->orderBy(['id' => SORT_ASC])
            ->all();

        $previousHash = AuditLogService::GENESIS_PREVIOUS_HASH;

        foreach ($rows as $row) {
            $canonicalPayload = AuditLogService::canonicalize([
                'changedByIdentifier' => $row['changedByIdentifier'],
                'dateCreated' => $this->_normaliseDateCreated($row['dateCreated']),
                'details' => $this->_decodeDetails($row['details']),
                'event' => $row['event'],
                'ipHash' => $row['ipHash'],
                'outcome' => $row['outcome'],
                'source' => $row['source'],
                'uid' => $row['uid'],
                'userIdentifier' => $row['userIdentifier'],
            ]);

            $rowHash = hash('sha256', $canonicalPayload . $previousHash);

            $this->db->createCommand()
                ->update(
                    '{{%passwordpolicy_audit_log}}',
                    [
                        'rowHash' => $rowHash,
                        'previousHash' => $previousHash,
                    ],
                    ['id' => $row['id']],
                )
                ->execute();

            $previousHash = $rowHash;
        }
    }

    /**
     * Decodes the `details` JSON column to an array, or null when the
     * column is empty. JSON columns come back either as an already-
     * decoded array (Yii 2.0.50+) or as a JSON string — accept both.
     * Same shape the verifier + G1 recompute use.
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
     * Normalises the stored `dateCreated` to the canonical-payload
     * format. The column is `DATETIME` (no TZ), values are stored UTC
     * by the writer — re-parsing as UTC and reformatting in
     * `Y-m-d\TH:i:s\Z` produces the same string the writer hashed.
     *
     * @param string $value the raw column value
     * @return string
     *
     * @throws \Exception when DateTime parsing fails on a malformed value
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _normaliseDateCreated(string $value): string
    {
        return (new \DateTime($value, new \DateTimeZone('UTC')))
            ->format(AuditLogService::CANONICAL_DATE_FORMAT);
    }

    /**
     * Resolves the HMAC key for identifier hashing — mirrors
     * {@see AuditLogService::_resolveAuditPiiKey()} so the backfilled
     * `changedByIdentifier` matches what the writer would have produced.
     * Reads `SettingsModel::$auditPiiKey`, falling back to `securityKey`.
     *
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _resolveAuditPiiKey(): string
    {
        $configured = PasswordPolicy::$plugin->getSettings()->auditPiiKey;

        if (!empty($configured)) {
            return $configured;
        }

        return Craft::$app->getConfig()->getGeneral()->securityKey;
    }
}
