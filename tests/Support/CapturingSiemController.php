<?php
/**
 * Password policy plugin for Craft CMS
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\tests\Support;

use craftpulse\passwordpolicy\console\controllers\SiemController;

/**
 * Test subclass of `SiemController` that captures `stdout`/`stderr` into
 * in-memory buffers instead of writing to the real STDOUT/STDERR file
 * descriptors.
 *
 * Mirrors {@see CapturingInactiveController} — see {@see CapturingAuditController}
 * for the rationale (output buffering can't intercept `fwrite(\STDOUT, …)`,
 * and a named subclass keeps PHPStan happy where an anonymous class would
 * not).
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class CapturingSiemController extends SiemController
{
    // Public Properties
    // =========================================================================

    /**
     * @var string[] every chunk passed through `stdout()` in call order.
     */
    public array $stdoutBuffer = [];

    /**
     * @var string[] every chunk passed through `stderr()` in call order.
     */
    public array $stderrBuffer = [];

    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function stdout($string): bool|int
    {
        $this->stdoutBuffer[] = $string;

        return strlen($string);
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function stderr($string): bool|int
    {
        $this->stderrBuffer[] = $string;

        return strlen($string);
    }
}
