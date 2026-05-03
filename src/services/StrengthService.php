<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\services;

use craftpulse\passwordpolicy\models\SettingsModel;
use yii\base\Component;
use ZxcvbnPhp\Zxcvbn;

/**
 * Class StrengthService
 *
 * Computes a strength block for the AJAX validate response. Wraps
 * `bjeavons/zxcvbn-php` (a `require` Composer dep — always loaded) into a
 * stable response shape: `{engine, label, score, crackTime, suggestions,
 * warning}`. The same engine drives the CP strength meter and every
 * front-end Twig render builder; the CP indicator and the consumer-site
 * builders both consume `password-policy/validation/validate` so there's
 * exactly one place that scores passwords.
 *
 * The `engine` key is always `'zxcvbn'`. It stays in the payload as a
 * forward-compat hook in case a future release returns scores from a
 * different engine — costs nothing now and gives consumers a discriminator
 * to switch on if they ever need it.
 *
 * Blocklist hits force `label = 'weak'` and `score = 0` regardless of
 * zxcvbn's natural reading. zxcvbn doesn't know about the plugin's custom
 * dictionary, so without the override a blocklisted long+complex password
 * reads as "excellent" while the back-end correctly rejects it. The
 * override is intentionally narrow — only `label` + `score` get clamped.
 * `crackTime`, `suggestions`, and `warning` carry through from zxcvbn so
 * the user still sees the dictionary breakdown.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class StrengthService extends Component
{
    // Public Methods
    // =========================================================================

    /**
     * Computes the strength block via zxcvbn-php.
     *
     * Thin wrapper around [[analyzeZxcvbn]] kept for forward-compatibility
     * — callers shouldn't have to know which engine is active and the
     * service contract makes adding future engines straightforward without
     * changing the call sites.
     *
     * @param string $password the candidate password
     * @param SettingsModel $settings the resolved policy
     * @param array<string, string> $context optional `username` + `email`
     *     used as the user-input dictionary for zxcvbn
     * @param bool $blocklistHit whether the password matched the blocklist
     *     (forces `label = 'weak'` + `score = 0` regardless of zxcvbn's
     *     reading)
     * @return array<string, mixed>
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function compute(
        #[\SensitiveParameter] string $password,
        SettingsModel $settings,
        array $context = [],
        bool $blocklistHit = false,
    ): array {
        return $this->analyzeZxcvbn($password, $settings, $context, $blocklistHit);
    }

    /**
     * Runs zxcvbn-php against the password and maps the result onto the
     * plugin's stable response shape.
     *
     * @param string $password
     * @param SettingsModel $settings (unused but kept on the signature so
     *     a future engine swap doesn't have to renegotiate the call sites)
     * @param array<string, string> $context
     * @param bool $blocklistHit whether the password matched the blocklist —
     *     forces `label = 'weak'` + `score = 0` regardless of zxcvbn's
     *     reading so the meter stays consistent with the rule list (which
     *     correctly rejects the password)
     * @return array<string, mixed>
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function analyzeZxcvbn(
        #[\SensitiveParameter] string $password,
        SettingsModel $settings,
        array $context = [],
        bool $blocklistHit = false,
    ): array {
        $zxcvbn = new Zxcvbn();
        $userInputs = array_values(array_filter([
            $context['username'] ?? null,
            $context['email'] ?? null,
        ]));

        $result = $zxcvbn->passwordStrength($password, $userInputs);

        // zxcvbn returns score 0-4. Map onto our label vocabulary so the
        // CSS classes are stable regardless of how the engine evolves.
        $score = (int)($result['score'] ?? 0);
        $label = match ($score) {
            0, 1 => 'weak',
            2 => 'fair',
            3 => 'strong',
            4 => 'excellent',
            default => 'weak',
        };

        // Blocklist hit — force the meter to "weak" so what the user sees
        // matches what the rule list already shows. zxcvbn doesn't know
        // about the plugin's custom dictionary; without this override a
        // blocklisted long+complex password reads as "excellent" while
        // the back-end rejects it for being on the list.
        if ($blocklistHit) {
            $label = 'weak';
            $score = 0;
        }

        return [
            'engine' => 'zxcvbn',
            'label' => $label,
            'score' => $score,
            'crackTime' => (string)($result['crack_times_display']['offline_slow_hashing_1e4_per_second'] ?? ''),
            'suggestions' => (array)($result['feedback']['suggestions'] ?? []),
            'warning' => (string)($result['feedback']['warning'] ?? ''),
        ];
    }
}
