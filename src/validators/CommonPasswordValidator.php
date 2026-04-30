<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\validators;

use Craft;
use craft\db\Query;
use yii\validators\Validator;

/**
 * Class CommonPasswordValidator
 *
 * Validates passwords against the blocklist table (common + custom entries).
 * Uses a cached hash map for O(1) runtime lookups.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class CommonPasswordValidator extends Validator
{
    // Const Properties
    // =========================================================================

    /**
     * Cache key for the blocklist word→source map.
     *
     * @var string
     */
    private const CACHE_KEY = 'passwordpolicy_blocklist_word_sources';

    /**
     * Cache duration in seconds (1 hour).
     *
     * @var int
     */
    private const CACHE_DURATION = 3600;

    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function validateValue($value): ?array
    {
        $word = strtolower(trim($value));
        $blocklist = $this->_getBlocklist();

        if (!isset($blocklist[$word])) {
            return null;
        }

        $message = $blocklist[$word] === 'custom'
            ? Craft::t('password-policy', 'This password is blocked. Please choose a different one.')
            : Craft::t('password-policy', 'This password is too common. Please choose a more unique password.');

        return [$message, []];
    }

    // Private Methods
    // =========================================================================

    /**
     * Returns the cached blocklist as a hash map of word → source for O(1)
     * lookups with source-aware error messages.
     *
     * @return array<string, string> word → source ('common' | 'custom')
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _getBlocklist(): array
    {
        $cache = Craft::$app->getCache();
        $blocklist = $cache->get(self::CACHE_KEY);

        if ($blocklist !== false) {
            return $blocklist;
        }

        $rows = (new Query())
            ->select(['word', 'source'])
            ->from('{{%passwordpolicy_blocklist}}')
            ->all();

        $blocklist = [];
        foreach ($rows as $row) {
            $blocklist[$row['word']] = $row['source'];
        }

        $cache->set(self::CACHE_KEY, $blocklist, self::CACHE_DURATION);

        return $blocklist;
    }
}
