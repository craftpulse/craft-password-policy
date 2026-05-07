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
use craftpulse\passwordpolicy\services\AuditLogService;

/**
 * Class m260507_081852_RecomputeAuditLogChain
 *
 * Phase G — G1 layer 4. Walks every existing row in
 * `passwordpolicy_audit_log` (id ASC) and recomputes the `rowHash` /
 * `previousHash` columns the prior schema migration
 * {@see m260507_081201_AddRowHashAndPreviousHashToAuditLog} added with
 * a placeholder default of `'0'`.
 *
 * After this migration runs, the table is a fully-anchored SHA-256
 * forward chain — the verifier (G2) can walk it from id 1 onward and
 * recompute every row's hash to prove non-tampering.
 *
 * Idempotent. Skips rows whose `rowHash` is no longer the placeholder
 * `'0'` (recompute already applied, or the row was written post-G1 by
 * the chain-aware service). On a fresh install with zero rows the
 * loop is a no-op.
 *
 * The recompute loop disables Yii's query logging + profiling so the
 * canonical payloads (which contain `userIdentifier` HMAC, `ipHash`
 * SHA-256, and `details` JSON) don't end up in debug logs at SQL bind
 * time. Toggle is restored in `finally` so a mid-loop throw still
 * leaves the connection in its prior state. Same idiom the bcrypt-
 * seed migration {@see m260429_224908_UpgradeTo520Schema} uses.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class m260507_081852_RecomputeAuditLogChain extends Migration
{
    // Const Properties
    // =========================================================================

    /**
     * Stable sentinel for the genesis row's `previousHash`. Mirrors the
     * value in `AuditLogService::GENESIS_PREVIOUS_HASH` (private there
     * because it's an implementation detail of the writer; copied here
     * so the recompute migration stays self-contained and doesn't depend
     * on the service exposing it).
     *
     * @var string
     */
    private const GENESIS_PREVIOUS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

    /**
     * Placeholder default applied by
     * {@see m260507_081201_AddRowHashAndPreviousHashToAuditLog}. Rows
     * still showing this value haven't been recomputed yet.
     *
     * @var string
     */
    private const PLACEHOLDER_HASH = '0';

    /**
     * Canonical-payload `dateCreated` format. Must stay in lockstep with
     * `AuditLogService::CANONICAL_DATE_FORMAT` — drift here silently
     * invalidates every hash this migration writes.
     *
     * @var string
     */
    private const CANONICAL_DATE_FORMAT = 'Y-m-d\TH:i:s\Z';

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
        $db = Craft::$app->getDb();
        $enableLogging = $db->enableLogging;
        $enableProfiling = $db->enableProfiling;
        $db->enableLogging = false;
        $db->enableProfiling = false;

        try {
            $rows = (new Query())
                ->from('{{%passwordpolicy_audit_log}}')
                ->orderBy(['id' => SORT_ASC])
                ->all();

            $previousHash = self::GENESIS_PREVIOUS_HASH;

            foreach ($rows as $row) {
                // Idempotent guard — skip rows whose `rowHash` is no
                // longer the placeholder. A prior partial run, or any
                // row written post-G1 by the chain-aware service, is
                // already correctly anchored. Adopt their stored hash
                // as the new `previousHash` for the next iteration so
                // the chain stays contiguous.
                if ($row['rowHash'] !== self::PLACEHOLDER_HASH) {
                    $previousHash = $row['rowHash'];
                    continue;
                }

                $canonicalPayload = AuditLogService::canonicalize([
                    'changedByUserId' => $this->_intOrNull($row['changedByUserId']),
                    'dateCreated' => $this->_normaliseDateCreated($row['dateCreated']),
                    'details' => $this->_decodeDetails($row['details']),
                    'event' => $row['event'],
                    'ipHash' => $row['ipHash'],
                    'outcome' => $row['outcome'],
                    'source' => $row['source'],
                    'uid' => $row['uid'],
                    'userId' => $this->_intOrNull($row['userId']),
                    'userIdentifier' => $row['userIdentifier'],
                ]);

                $rowHash = hash('sha256', $canonicalPayload . $previousHash);

                $db->createCommand()
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
        echo "m260507_081852_RecomputeAuditLogChain cannot be reverted.\n";

        return false;
    }

    // Private Methods
    // =========================================================================

    /**
     * Decodes the `details` JSON column to an array, or null when the
     * column is empty. JSON columns come back either as an already-
     * decoded array (Yii 2.0.50+) or as a JSON string — accept both.
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
     * Coerces a database-fetched value to `int|null`. Yii's row-array
     * fetch returns numeric columns as strings on some drivers — the
     * canonical payload contract is bare integers, so the cast must
     * happen before encoding.
     *
     * @param mixed $value
     * @return int|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _intOrNull(mixed $value): ?int
    {
        if ($value === null || $value === '') {
            return null;
        }

        return (int)$value;
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
            ->format(self::CANONICAL_DATE_FORMAT);
    }
}
