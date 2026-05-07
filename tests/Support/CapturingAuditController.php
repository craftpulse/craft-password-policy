<?php
/**
 * Password policy plugin for Craft CMS
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\tests\Support;

use craftpulse\passwordpolicy\console\controllers\AuditController;

/**
 * Test subclass of `AuditController` that captures `stdout`/`stderr`
 * into in-memory buffers instead of writing to the real STDOUT/STDERR
 * file descriptors.
 *
 * `Yii\console\Controller::stdout/stderr` write via
 * `fwrite(\STDOUT|\STDERR, …)`, which PHP output buffering does not
 * intercept. Tests that need to assert on emitted text subclass and
 * override both methods to append into capture properties — the
 * production controller path stays untouched.
 *
 * Lives in `tests/Support` (not inline in the Pest test file) so
 * PHPStan can resolve the buffer property accesses without
 * `@property` hints. Anonymous classes confuse the analyser when the
 * containing helper returns the parent type.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class CapturingAuditController extends AuditController
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
