<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\events;

use DateTime;
use yii\base\Event;

/**
 * Class AuditChainRotatedEvent
 *
 * Fired after `AuditLogService::purgeOldEntries()` deletes one or more
 * rows from the audit log. The chain start moves forward — the new
 * first row's `previousHash` legitimately references a now-deleted row,
 * which the verifier (G2) treats as a chain-start sentinel rather than
 * a tamper.
 *
 * Listeners use this event to record the retention boundary externally
 * (a SIEM forwarder, a compliance dashboard, an off-site archive that
 * snapshots the surviving chain head before the delete cascades). The
 * event payload is structured around the chain-start anchor — the new
 * first row's `id` and `rowHash` — so consumers can pick up exactly
 * where the verifier will start its next walk.
 *
 * @event AuditChainRotatedEvent
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class AuditChainRotatedEvent extends Event
{
    // Public Properties
    // =========================================================================

    /**
     * @var int the highest `id` deleted in this prune. Consumers can
     *     use the `(endId, endRowHash)` pair to anchor an off-site
     *     archive of the rows that just left the database.
     */
    public int $endId;

    /**
     * @var string the `rowHash` of the LAST surviving row at prune
     *     time — the chain head that the new first row's
     *     `previousHash` will reference if both still exist (i.e. the
     *     prune left at least two rows). When the prune left exactly
     *     one row, `endRowHash === startRowHash`.
     */
    public string $endRowHash;

    /**
     * @var DateTime the timestamp at which the rotation occurred
     *     (server UTC).
     */
    public DateTime $rotatedAt;

    /**
     * @var int the `id` of the new first surviving row in the audit
     *     log table — the new chain start. Verifiers walking the
     *     chain after this event must begin at this id; their
     *     `previousHash` argument is `startRowHash`'s previous-hash
     *     (a now-deleted row's hash, which the verifier accepts as
     *     a chain-start sentinel within the configured retention
     *     window).
     */
    public int $startId;

    /**
     * @var string the `rowHash` of the new first surviving row. Pair
     *     this with `startId` for the verifier-facing anchor.
     */
    public string $startRowHash;
}
