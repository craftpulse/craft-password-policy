<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\validators;

use Craft;
use craft\elements\User;
use yii\validators\Validator;

/**
 * Class ContextualValidator
 *
 * Checks passwords against contextual data: username, email local part,
 * first/last name, system name, and primary site domain.
 *
 * Minimum 3-character substrings to avoid false positives on short names.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class ContextualValidator extends Validator
{
    // Const Properties
    // =========================================================================

    /**
     * Minimum context string length to check against.
     *
     * @var int
     */
    private const MIN_CONTEXT_LENGTH = 3;

    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function validateAttribute($model, $attribute): void
    {
        $password = $model->$attribute;

        if (empty($password)) {
            return;
        }

        $passwordLower = strtolower($password);
        $contextTerms = $this->_gatherContextTerms($model);

        foreach ($contextTerms as $term) {
            if (strlen($term) < self::MIN_CONTEXT_LENGTH) {
                continue;
            }

            if (str_contains($passwordLower, strtolower($term))) {
                $this->addError(
                    $model,
                    $attribute,
                    Craft::t(
                        'password-policy',
                        'Password must not contain your name, username, email, or site name.',
                    ),
                );

                return;
            }
        }
    }

    // Private Methods
    // =========================================================================

    /**
     * Gathers contextual terms from the user and environment.
     *
     * @param mixed $model
     * @return string[]
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _gatherContextTerms(mixed $model): array
    {
        $terms = [];

        if ($model instanceof User) {
            // Username
            if (!empty($model->username)) {
                $terms[] = $model->username;
            }

            // Email local part
            if (!empty($model->email)) {
                $localPart = strstr($model->email, '@', true);
                if ($localPart !== false) {
                    $terms[] = $localPart;
                }
            }

            // First and last name
            if (!empty($model->firstName)) {
                $terms[] = $model->firstName;
            }
            if (!empty($model->lastName)) {
                $terms[] = $model->lastName;
            }
        }

        // System name — split multi-word names into individual terms
        $systemName = Craft::$app->getSystemName();
        if (!empty($systemName)) {
            $terms[] = $systemName;
            foreach (preg_split('/[\s\-_]+/', $systemName) as $word) {
                if (strlen($word) >= self::MIN_CONTEXT_LENGTH) {
                    $terms[] = $word;
                }
            }
        }

        // Primary site domain
        try {
            $primarySite = Craft::$app->getSites()->getPrimarySite();
            $baseUrl = $primarySite->getBaseUrl();

            if ($baseUrl !== null) {
                $host = parse_url($baseUrl, PHP_URL_HOST);
                if ($host) {
                    // Extract domain without TLD (e.g., "mycompany" from
                    // "mycompany.com"). A single-label host (e.g.
                    // "localhost", an internal/intranet hostname with no
                    // TLD) has nothing to strip — the whole label is
                    // itself the identifying term, so it must still be
                    // checked rather than silently skipped.
                    $parts = explode('.', $host);
                    $terms[] = count($parts) >= 2 ? $parts[0] : $host;
                }
            }
        } catch (\Throwable) {
            // Site not configured yet, skip
        }

        return $terms;
    }
}
