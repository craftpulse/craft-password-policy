<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\jobs;

use Craft;
use craft\queue\BaseJob;

use craftpulse\passwordpolicy\PasswordPolicy;

/**
 * Class SeedBlocklist
 *
 * Seeds the common password blocklist from the bundled data file.
 * Pushed to the queue when "Block common passwords" is enabled with
 * an empty blocklist, or when triggered from the Blocklist utility.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class SeedBlocklist extends BaseJob
{
    // Protected Methods
    // =========================================================================

    /**
     * Seeds the common passwords blocklist.
     *
     * @param \yii\queue\Queue|\craft\queue\Queue $queue
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function execute($queue): void
    {
        $this->setProgress($queue, 0, Craft::t('password-policy', 'Seeding common passwords…'));

        $count = PasswordPolicy::$plugin->getBlocklist()->seedCommonPasswords();

        $this->setProgress(
            $queue,
            1,
            Craft::t('password-policy', '{count} common passwords seeded.', ['count' => $count]),
        );
    }

    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getDescription(): ?string
    {
        return Craft::t('password-policy', 'Seeding common password blocklist');
    }
}
