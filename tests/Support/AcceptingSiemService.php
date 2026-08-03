<?php
/**
 * Password policy plugin for Craft CMS
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\tests\Support;

use craftpulse\passwordpolicy\models\SiemForwarderModel;
use craftpulse\passwordpolicy\services\SiemService;

/**
 * `SiemService` stand-in whose `forward()` always accepts.
 *
 * Exists for the `SiemForwardJob` campaign test. The real service opens a TLS
 * syslog socket, which no test can make succeed without standing up a
 * listener, and a refused connection is the wrong fixture here: a rejected row
 * keeps `forwardedAt = NULL`, so the forwardable result set never shrinks and
 * the offset-versus-predicate drift the test exists to catch never happens.
 *
 * Only the two methods the job consults are overridden. The `forwardedAt`
 * writeback stays where it belongs, in `SiemForwardJob::_recordRowOutcome()`,
 * so the test still exercises the real predicate-shrinking behaviour.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class AcceptingSiemService extends SiemService
{
    // Public Properties
    // =========================================================================

    /**
     * The audit-row ids handed to `forward()`, in call order. Lets a test
     * assert on exactly which rows the campaign reached, and on whether any
     * row was offered twice.
     *
     * @var int[]
     *
     * @since 5.2.0
     */
    public array $forwardedIds = [];

    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function forward(array $auditRow, SiemForwarderModel $forwarder): bool
    {
        $this->forwardedIds[] = (int)$auditRow['id'];

        return true;
    }

    /**
     * @inheritdoc
     *
     * Returns one in-memory forwarder with no id-bearing database row behind
     * it. The job only reads the model to resolve the stream allowlist.
     *
     * @return array<int, SiemForwarderModel>
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getActiveForwarders(): array
    {
        $forwarder = new SiemForwarderModel();
        $forwarder->id = 1;
        $forwarder->name = 'accepting-fixture';
        $forwarder->host = '127.0.0.1';
        $forwarder->port = 6514;
        $forwarder->enabled = true;
        $forwarder->eventClasses = ['audit_log'];

        return [$forwarder];
    }
}
