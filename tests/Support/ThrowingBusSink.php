<?php
/**
 * Password policy plugin for Craft CMS — test support.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\tests\Support;

use craftpulse\auditkit\audit\AuditEvent;
use craftpulse\auditkit\audit\AuditSinkInterface;
use RuntimeException;

/**
 * A deliberately broken {@see AuditSinkInterface} standing in for a recorder
 * whose storage is unavailable.
 *
 * It exists to pin the fail-soft half of PP's governance emission contract: a
 * throwing sink must never unwind the committed policy save or delete that
 * triggered the emission. The kit's {@see \craftpulse\auditkit\services\Bus::record()}
 * isolates each sink in its own try/catch, so this sink's throw is absorbed
 * there rather than in {@see \craftpulse\passwordpolicy\services\GovernanceAuditService}
 * — asserting it anyway keeps the end-to-end property covered, because a broken
 * recorder registered by any other plugin in the estate must not be able to fail
 * a policy save here.
 *
 * @author    CraftPulse
 * @package   PasswordPolicy
 * @since     5.2.0
 */
class ThrowingBusSink implements AuditSinkInterface
{
    // Public Methods
    // =========================================================================

    /**
     * Always throws.
     *
     * @param AuditEvent $event
     *
     * @throws RuntimeException always.
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function handle(AuditEvent $event): void
    {
        throw new RuntimeException(sprintf(
            'ThrowingBusSink refuses to handle "%s" (test double).',
            $event->name,
        ));
    }
}
