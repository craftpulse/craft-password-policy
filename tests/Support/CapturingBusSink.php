<?php
/**
 * Password policy plugin for Craft CMS — test support.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\tests\Support;

use craftpulse\auditkit\audit\AuditEvent;
use craftpulse\auditkit\audit\AuditSinkInterface;

/**
 * A recording {@see AuditSinkInterface} for asserting what PP emits onto the
 * shared Audit Kit bus. Registered via `Bus::setSinks([...])` in a test, it
 * collects every {@see AuditEvent} the bus fans to it so the test can assert on
 * count, name, category, target, and details — without touching any real
 * recorder's storage (Ledger's table is off-limits in the shared playground).
 *
 * @author    CraftPulse
 * @package   PasswordPolicy
 * @since     5.2.0
 */
class CapturingBusSink implements AuditSinkInterface
{
    // Public Properties
    // =========================================================================

    /**
     * @var AuditEvent[] Every event handed to this sink, in dispatch order.
     */
    public array $events = [];

    // Public Methods
    // =========================================================================

    /**
     * Records the event for later assertion.
     *
     * @param AuditEvent $event
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function handle(AuditEvent $event): void
    {
        $this->events[] = $event;
    }

    /**
     * Returns the captured events whose name matches.
     *
     * @param string $name
     * @return AuditEvent[]
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function eventsNamed(string $name): array
    {
        return array_values(array_filter(
            $this->events,
            static fn(AuditEvent $event): bool => $event->name === $name,
        ));
    }
}
