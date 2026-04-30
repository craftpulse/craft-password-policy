<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
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
        };

        return $policy;
    }

    /**
     * NIST 800-63B preset: min 8, no complexity, no expiration, HIBP on.
     *
     * @param GroupPolicyModel $policy
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _applyNist(GroupPolicyModel $policy): void
    {
        $policy->minLength = 8;
        $policy->cases = false;
        $policy->numbers = false;
        $policy->symbols = false;
        $policy->hibp = true;
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
}
