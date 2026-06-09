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

use craft\db\Migration;

/**
 * Class m260507_081201_AddRowHashAndPreviousHashToAuditLog
 *
 * Phase G — G1 layer 1. Promotes `passwordpolicy_audit_log` from a flat
 * append table into the head of a SHA-256 forward chain. Adds:
 *
 *  - `rowHash` — `CHAR(64) NOT NULL DEFAULT '0'`. Hex SHA-256 of
 *    `canonicalize(payload) . previousHash`. The default `'0'` is a
 *    placeholder that lets the NOT NULL add succeed against existing
 *    rows; the recompute migration
 *    {@see m260507_081852_RecomputeAuditLogChain} (sibling, ships in the
 *    same commit) walks the table in id-ASC order and rewrites every
 *    row to the real chain hash.
 *  - `previousHash` — `CHAR(64) NOT NULL DEFAULT '0'`. Hex SHA-256 of
 *    the row immediately preceding this one in id order. The genesis
 *    row's `previousHash` is sixty-four zeros — NOT NULL on the column
 *    keeps the verifier's chain-walk free of null-handling branches.
 *  - `forwardedAt` — `DATETIME NULL`. Consumed by the G8 SIEM forwarder
 *    (`WHERE forwardedAt IS NULL` selects the unforwarded slice). Adding
 *    it now in the same migration as the chain columns avoids a follow-
 *    up migration on the same table when G8 lands.
 *  - `forwardAttempts` — `INT NOT NULL DEFAULT 0`. Per-row attempt
 *    counter for the SIEM forwarder retry path. Excluded from the
 *    canonical payload — the payload contract is `excluded: id, rowHash,
 *    previousHash`, plus `forwardedAt` and `forwardAttempts` (mutated
 *    after insert; mutating them must NOT recompute the chain hash).
 *
 * Idempotent — every column add is guarded by `columnExists()`, and the
 * `forwardedAt` index is created inside the same guarded block so a
 * re-run on a fully-applied DB doesn't try to recreate the index. Same
 * idempotency idiom as
 * {@see m260506_174529_AddNotificationLogActivityColumns}.
 *
 * Phase G writes the chain on every edition (Lite included) — capture is
 * universal, edition gates apply to the dashboard / verifier UI / SIEM
 * forwarder / export, never to the underlying writes. See memory rule
 * `project_audit_capture_principle.md`.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class m260507_081201_AddRowHashAndPreviousHashToAuditLog extends Migration
{
    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function safeUp(): bool
    {
        $table = '{{%passwordpolicy_audit_log}}';

        if (!$this->db->columnExists($table, 'rowHash')) {
            $this->addColumn(
                $table,
                'rowHash',
                $this->char(64)->notNull()->defaultValue('0')->after('userIdentifier'),
            );
        }

        if (!$this->db->columnExists($table, 'previousHash')) {
            $this->addColumn(
                $table,
                'previousHash',
                $this->char(64)->notNull()->defaultValue('0')->after('rowHash'),
            );
        }

        if (!$this->db->columnExists($table, 'forwardedAt')) {
            $this->addColumn(
                $table,
                'forwardedAt',
                $this->dateTime()->null()->after('previousHash'),
            );

            // Index for the G8 SIEM forwarder's hot read path
            // (`WHERE forwardedAt IS NULL`). Nested inside the column
            // guard so a re-run on a fully-applied DB doesn't try to
            // recreate the index — same idempotency idiom the per-
            // column FK / index pairs in
            // m260506_174529_AddNotificationLogActivityColumns use.
            $this->createIndex(null, $table, ['forwardedAt'], false);
        }

        if (!$this->db->columnExists($table, 'forwardAttempts')) {
            $this->addColumn(
                $table,
                'forwardAttempts',
                $this->integer()->notNull()->defaultValue(0)->after('forwardedAt'),
            );
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
        echo "m260507_081201_AddRowHashAndPreviousHashToAuditLog cannot be reverted.\n";

        return false;
    }
}
