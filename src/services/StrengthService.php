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
use craftpulse\passwordpolicy\PasswordPolicy;
use Throwable;
use yii\base\Component;
use ZxcvbnPhp\Zxcvbn;

/**
 * Class StrengthService
 *
 * Computes a strength block for the AJAX validate response. Two engines:
 *
 *  - **Engine A (baseline)** — rule-counting × length-tier label
 *    (`weak/fair/strong/excellent`). Always available; no client-side or
 *    server-side dependencies. Blocklist hits force `weak` regardless of
 *    length so users see consistent feedback when the back-end will reject
 *    the password.
 *
 *  - **Engine B (zxcvbn-php Pro opt-in)** — wraps `bjeavons/zxcvbn-php` to
 *    surface a 0-4 score, suggestions array, and a localized crack-time
 *    estimate. Adds ~200KB to the install but produces materially better
 *    UX. Only runs on Pro AND when the `useZxcvbnStrength` setting is on.
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
     * Computes the strength block.
     *
     * Picks the zxcvbn engine when `useZxcvbnStrength` is on AND we're on
     * Pro AND the zxcvbn-php library is installed; falls back to the
     * baseline engine otherwise. Caller doesn't have to think about which
     * engine is active — the response shape is a strict superset on Engine
     * B so consumers reading the bare label/score keys work in both modes.
     *
     * @param string $password the candidate password
     * @param SettingsModel $settings the resolved policy
     * @param array<string, string> $context optional `username` + `email`
     *     used as the user-input dictionary for zxcvbn; ignored by Engine A
     * @param bool $blocklistHit whether the password matched the blocklist
     *     (forces "weak" on Engine A regardless of length)
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
        $plugin = PasswordPolicy::$plugin;
        $useZxcvbn = $plugin->getIsPro()
            && $settings->useZxcvbnStrength
            && class_exists(Zxcvbn::class);

        if ($useZxcvbn) {
            try {
                return $this->analyzeZxcvbn($password, $settings, $context, $blocklistHit);
            } catch (Throwable) {
                // Fall through to baseline if zxcvbn blows up for any reason
                // (corrupted dictionary, version mismatch, etc.). Better to
                // ship a baseline strength reading than nothing.
            }
        }

        return $this->analyzeBaseline($password, $settings, $blocklistHit);
    }

    /**
     * Engine A — rule-counting × length tier.
     *
     * Length tiers:
     *  - `<8`         → tier 0
     *  - `8-11`       → tier 1
     *  - `12-15`      → tier 2
     *  - `16+`        → tier 3
     *
     * Rule count: 0-4 (lowercase, uppercase, digit, symbol — counted
     * independently of the policy's `cases`/`numbers`/`symbols` toggles
     * because we're describing *the password*, not whether it satisfies
     * the rules).
     *
     * Label:
     *  - tier 0  OR rule count == 0 → `weak`
     *  - tier 1 + ruleCount ≤ 1     → `weak`
     *  - tier 1 + ruleCount ≥ 2     → `fair`
     *  - tier 2 + ruleCount ≤ 2     → `fair`
     *  - tier 2 + ruleCount ≥ 3     → `strong`
     *  - tier 3 + ruleCount ≥ 3     → `excellent`
     *  - tier 3 + ruleCount ≤ 2     → `strong`
     *
     * Blocklist hit overrides everything to `weak`.
     *
     * @param string $password
     * @param SettingsModel $settings
     * @param bool $blocklistHit
     * @return array<string, mixed>
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function analyzeBaseline(
        #[\SensitiveParameter] string $password,
        SettingsModel $settings,
        bool $blocklistHit,
    ): array {
        $length = strlen($password);
        $ruleCount = 0;

        if (preg_match('/[a-z]/', $password)) {
            $ruleCount++;
        }
        if (preg_match('/[A-Z]/', $password)) {
            $ruleCount++;
        }
        if (preg_match('/[0-9]/', $password)) {
            $ruleCount++;
        }
        if (preg_match('/[^a-zA-Z0-9]/', $password)) {
            $ruleCount++;
        }

        $lengthTier = match (true) {
            $length < 8 => 0,
            $length < 12 => 1,
            $length < 16 => 2,
            default => 3,
        };

        $label = $this->_baselineLabel($lengthTier, $ruleCount);

        if ($blocklistHit) {
            $label = 'weak';
        }

        return [
            'engine' => 'baseline',
            'label' => $label,
            'ruleCount' => $ruleCount,
            'lengthTier' => $lengthTier,
        ];
    }

    /**
     * Engine B — zxcvbn-php-driven analysis.
     *
     * @param string $password
     * @param SettingsModel $settings (unused but kept for symmetry with
     *     baseline so callers can swap engines without changing args)
     * @param array<string, string> $context
     * @param bool $blocklistHit whether the password matched the blocklist —
     *     forces "weak" label + score 0 regardless of zxcvbn's reading so
     *     the meter stays consistent with the rule list (which correctly
     *     rejects the password)
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
        // CSS classes are stable across engines.
        $score = (int)($result['score'] ?? 0);
        $label = match ($score) {
            0, 1 => 'weak',
            2 => 'fair',
            3 => 'strong',
            4 => 'excellent',
            default => 'weak',
        };

        // Blocklist hit — force the meter to "weak" so the engine-B meter
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

    // Private Methods
    // =========================================================================

    /**
     * Returns the label string for the given (lengthTier, ruleCount) cell.
     *
     * @param int $lengthTier 0-3
     * @param int $ruleCount 0-4
     * @return string `weak` | `fair` | `strong` | `excellent`
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _baselineLabel(int $lengthTier, int $ruleCount): string
    {
        if ($lengthTier === 0 || $ruleCount === 0) {
            return 'weak';
        }

        if ($lengthTier === 1) {
            return $ruleCount >= 2 ? 'fair' : 'weak';
        }

        if ($lengthTier === 2) {
            return $ruleCount >= 3 ? 'strong' : 'fair';
        }

        // lengthTier === 3
        return $ruleCount >= 3 ? 'excellent' : 'strong';
    }
}
