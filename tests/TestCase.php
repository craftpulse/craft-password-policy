<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Pest base TestCase for Integration tests.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\tests;

use Craft;
use PHPUnit\Framework\TestCase as BaseTestCase;
use yii\db\Transaction;

/**
 * Base test case for Integration tests.
 *
 * Wraps every test in a DB transaction that rolls back in `tearDown()`. This
 * keeps state isolated between tests without the cost of truncating every
 * table or re-installing the plugin per-test. The bootstrap installs the
 * schema once; this class hands each test a clean transactional scope on
 * top of that fixed baseline.
 *
 * Tests that need to escape the transaction (e.g. asserting on a committed
 * row from a sub-process) should override `usesTransaction()` to return
 * `false` and clean up after themselves.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
abstract class TestCase extends BaseTestCase
{
    // Private Properties
    // =========================================================================

    /**
     * @var Transaction|null
     */
    private ?Transaction $_transaction = null;

    // Protected Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected function setUp(): void
    {
        parent::setUp();

        if ($this->usesTransaction()) {
            $this->_transaction = Craft::$app->getDb()->beginTransaction();
        }
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected function tearDown(): void
    {
        if ($this->_transaction !== null) {
            $this->_transaction->rollBack();
            $this->_transaction = null;
        }

        parent::tearDown();
    }

    /**
     * Whether the test should run inside a rolled-back DB transaction.
     *
     * Override and return `false` in subclasses (or per-test via
     * `$this->_transaction = null`) when the test depends on committed
     * state — e.g. a queue worker running in a separate process, or a
     * migration that uses DDL the transaction can't roll back cleanly.
     *
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected function usesTransaction(): bool
    {
        return true;
    }
}
