<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\batchers;

use craft\base\Batchable;
use craft\elements\User;

/**
 * Class PasswordResetBatcher
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.0.0
 */
readonly class PasswordResetBatcher implements Batchable
{
    // Public Methods
    // =========================================================================

    /**
     * Constructor.
     *
     * @param User[] $users
     *
     * @author CraftPulse
     */
    public function __construct(
        private array $users,
    ) {
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     */
    public function count(): int
    {
        return count($this->users);
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     */
    public function getSlice(int $offset, int $limit): iterable
    {
        return array_slice($this->users, $offset, $limit);
    }
}
