<?php
/**
 * Password policy plugin for Craft CMS
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\services;

use Craft;
use craft\db\Query;
use yii\base\Component;

/**
 * Class PasswordHistoryService
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class PasswordHistoryService extends Component
{
    // Constants
    // =========================================================================

    public const TABLE = '{{%passwordpolicy_password_history}}';

    // Public Methods
    // =========================================================================

    /**
     * Saves a password hash to the history for the given user.
     *
     * @param int $userId
     * @param string $passwordHash
     */
    public function savePasswordHash(int $userId, string $passwordHash): void
    {
        Craft::$app->getDb()->createCommand()
            ->insert(self::TABLE, [
                'userId' => $userId,
                'passwordHash' => $passwordHash,
            ])
            ->execute();
    }

    /**
     * Checks whether a plain-text password matches any of the user's recent
     * stored password hashes.
     *
     * @param int $userId
     * @param string $plainPassword
     * @param int $historyCount Number of previous passwords to check
     * @return bool True if the password has been used before
     */
    public function hasPasswordBeenUsed(int $userId, string $plainPassword, int $historyCount = 5): bool
    {
        $hashes = (new Query())
            ->select(['passwordHash'])
            ->from(self::TABLE)
            ->where(['userId' => $userId])
            ->orderBy(['dateCreated' => SORT_DESC])
            ->limit($historyCount)
            ->column();

        foreach ($hashes as $hash) {
            if (Craft::$app->getSecurity()->validatePassword($plainPassword, $hash)) {
                return true;
            }
        }

        return false;
    }
}
