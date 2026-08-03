<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\enums;

use craftpulse\passwordpolicy\models\GroupPolicyModel;

/**
 * Enum PolicyPreset
 *
 * Pre-configured policy templates based on security standards.
 * Applied as per-group policy overrides.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
enum PolicyPreset: string
{
    /**
     * NIST 800-63B: Passphrase-friendly, no complexity, breach checking.
     * Satisfies all SHALL requirements for memorized secrets.
     */
    case NIST_800_63B = 'nist_800_63b';

    /**
     * OWASP ASVS Level 1: Longer minimum, max 128, breach checking.
     */
    case OWASP_ASVS = 'owasp_asvs';

    /**
     * Strict Enterprise: Maximum enforcement for admin/privileged groups.
     */
    case STRICT_ENTERPRISE = 'strict_enterprise';

    /**
     * PCI-DSS v4.0: Satisfies Req 8.3.5–8.3.9 including 90-day rotation.
     * Note: 90-day rotation conflicts with NIST 800-63B SHOULD NOT guidance.
     */
    case PCI_DSS_V4 = 'pci_dss_v4';

    /**
     * CIS Controls v8: Safeguard 5.2 length floor (14 chars password-only)
     * plus CIS Password Policy Guide history + breach checking + 365-day
     * rotation. Conflicts with NIST 800-63B on the rotation requirement;
     * see the apply method's docblock for the deliberate trade-off.
     */
    case CIS_CONTROLS_V8 = 'cis_controls_v8';

    /**
     * Returns a human-readable label for the preset.
     *
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function label(): string
    {
        return match ($this) {
            self::NIST_800_63B => 'NIST 800-63B',
            self::OWASP_ASVS => 'OWASP ASVS L1',
            self::STRICT_ENTERPRISE => 'Strict Enterprise',
            self::PCI_DSS_V4 => 'PCI-DSS v4.0',
            self::CIS_CONTROLS_V8 => 'CIS Controls v8',
        };
    }

    /**
     * Returns the inactive-account settings overlay this preset applies to
     * the GLOBAL plugin settings (Feature 5).
     *
     * Inactive-account handling is a global setting, not a per-group policy
     * field, so it lives here rather than on {@see GroupPolicyModel}. The
     * PCI-DSS and Strict Enterprise presets opt INTO `suspend` at a 90-day
     * threshold — PCI-DSS v4.0 §8.2.6 mandates disabling inactive accounts
     * within 90 days, and NIST 800-53 AC-2(3) / ISO 27002 A.5.18 require the
     * capability. The NIST 800-63B, OWASP, and CIS presets leave the safe
     * non-destructive default (`report`, disabled) untouched — they return
     * an empty overlay so `SettingsController::actionApplyPreset()` doesn't
     * write the inactive keys at all.
     *
     * @return array<string, bool|int|string> a sparse map of inactive-key
     *     overrides; empty when the preset doesn't opt into suspension
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function inactiveAccountOverlay(): array
    {
        return match ($this) {
            self::PCI_DSS_V4, self::STRICT_ENTERPRISE => [
                'inactiveAccountsEnabled' => true,
                'inactiveAction' => 'suspend',
                'inactiveThresholdDays' => 90,
            ],
            default => [],
        };
    }

    /**
     * Converts the preset to a GroupPolicyModel with pre-configured values.
     *
     * @return GroupPolicyModel
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function toGroupPolicy(): GroupPolicyModel
    {
        $policy = new GroupPolicyModel();
        $policy->preset = $this->value;

        match ($this) {
            self::NIST_800_63B => $this->_applyNist($policy),
            self::OWASP_ASVS => $this->_applyOwasp($policy),
            self::STRICT_ENTERPRISE => $this->_applyStrictEnterprise($policy),
            self::PCI_DSS_V4 => $this->_applyPciDss($policy),
            self::CIS_CONTROLS_V8 => $this->_applyCisControlsV8($policy),
        };

        return $policy;
    }

    /**
     * NIST 800-63B preset: min 15, no composition rules, no rotation,
     * HIBP on, common-password blocklist on.
     *
     * Tracks SP 800-63B Rev. 4 (finalised 31 July 2025). Rev. 4 raised
     * the memorized-secret length floor for single-factor authentication
     * from 8 to 15 characters, kept the multi-factor minimum at 8,
     * explicitly forbids composition rules (`SHALL NOT impose other
     * composition rules`), and explicitly forbids periodic rotation
     * (`SHALL NOT require subscribers to change passwords periodically`).
     *
     * §3.1.1.2 SHALL also requires comparing the prospective secret
     * against a blocklist of "commonly used, expected, or compromised
     * passwords." HIBP covers compromised; `checkCommonPasswords` is
     * required to cover commonly used. Both must be on for the preset
     * to satisfy §3.1.1.2 SHALL.
     *
     * §3.2.2 SHALL also requires rate-limiting consecutive failed
     * attempts to ≤100 per authenticator. The plugin delegates this
     * to Craft core (`maxInvalidLogins` + `cooldownDuration` site
     * config) — the preset doesn't override Craft's defaults. Operators
     * should verify their `config/general.php` aligns; the default
     * `maxInvalidLogins=5` already satisfies the ≤100 ceiling.
     *
     * @param GroupPolicyModel $policy
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _applyNist(GroupPolicyModel $policy): void
    {
        $policy->minLength = 15;
        $policy->cases = false;
        $policy->numbers = false;
        $policy->symbols = false;
        $policy->hibp = true;
        $policy->checkCommonPasswords = true;
        $policy->expiryAmount = null;
    }

    /**
     * OWASP ASVS preset: min 12, max 128, no complexity, HIBP on.
     *
     * @param GroupPolicyModel $policy
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _applyOwasp(GroupPolicyModel $policy): void
    {
        $policy->minLength = 12;
        $policy->maxLength = 128;
        $policy->cases = false;
        $policy->numbers = false;
        $policy->symbols = false;
        $policy->hibp = true;
        $policy->expiryAmount = null;
    }

    /**
     * Strict Enterprise preset: max enforcement for privileged users.
     *
     * @param GroupPolicyModel $policy
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _applyStrictEnterprise(GroupPolicyModel $policy): void
    {
        $policy->minLength = 12;
        $policy->cases = true;
        $policy->numbers = true;
        $policy->symbols = true;
        $policy->hibp = true;
        $policy->hibpFailMode = 'closed';
        $policy->passwordHistoryCount = 5;
        $policy->checkSequentialChars = true;
        $policy->checkRepeatedChars = true;
        $policy->checkContextual = true;
        $policy->checkCommonPasswords = true;
        $policy->expiryAmount = 90;
        $policy->expiryPeriod = 'day';
    }

    /**
     * PCI-DSS v4.0 preset: Req 8.3.5–8.3.9 compliance.
     *
     * Note: 90-day rotation (Req 8.3.9) conflicts with NIST 800-63B
     * SHOULD NOT guidance on periodic password changes.
     *
     * @param GroupPolicyModel $policy
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _applyPciDss(GroupPolicyModel $policy): void
    {
        $policy->minLength = 12;
        $policy->cases = true;
        $policy->numbers = true;
        $policy->hibp = true;
        $policy->passwordHistoryCount = 4;
        $policy->checkCommonPasswords = true;
        $policy->expiryAmount = 90;
        $policy->expiryPeriod = 'day';
    }

    /**
     * CIS Controls v8 preset: 14-char minimum (Safeguard 5.2 for
     * password-only accounts), no composition, last-5 history, HIBP +
     * common-password blocklist, 365-day rotation.
     *
     * Tracks CIS Controls v8 Safeguard 5.2 (IG1/IG2/IG3) plus the CIS
     * Password Policy Guide companion. Safeguard 5.2 specifies 14
     * chars for password-only accounts and 8 chars for MFA-enabled
     * accounts; the plugin cannot reliably detect MFA presence at
     * preset-apply time (a site may run CraftCMS TOTP, may not), so
     * the preset defaults to the safer floor. Sites with MFA enabled
     * get a stricter-than-required policy, which CIS treats as
     * conformant.
     *
     * The CIS Password Policy Guide (referenced by Safeguard 5.2)
     * adds: last-5 password history, continuous breach checking
     * (HIBP-equivalent), internal deny-list of common/poor passwords,
     * and one-year expiration with forced rotation on suspected
     * compromise. CIS explicitly prefers length over composition —
     * `cases`, `numbers`, `symbols` are all false.
     *
     * Note the 365-day rotation deliberately diverges from
     * NIST 800-63B Rev. 4 (`SHALL NOT require subscribers to change
     * passwords periodically`). Operators choosing between NIST and
     * CIS must pick which framework's rotation guidance they align
     * with. CIS-aligned compliance buyers — typical CIS Benchmark
     * shops, US federal contractors using CIS as the actionable
     * companion to NIST — expect the annual rotation here.
     *
     * @param GroupPolicyModel $policy
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _applyCisControlsV8(GroupPolicyModel $policy): void
    {
        $policy->minLength = 14;
        $policy->maxLength = 128;
        $policy->cases = false;
        $policy->numbers = false;
        $policy->symbols = false;
        $policy->hibp = true;
        $policy->checkCommonPasswords = true;
        $policy->passwordHistoryCount = 5;
        $policy->expiryAmount = 365;
        $policy->expiryPeriod = 'day';
    }
}
