<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\twig\tags;

use Craft;

/**
 * Class StrengthMeterTag
 *
 * Renders a `<div data-pp-strength>` wrapper with an inner `<div class="pp-strength-bar">`.
 * JS toggles `pp-strength-weak|fair|strong|excellent` and updates an
 * `aria-live` label as the user types.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class StrengthMeterTag extends BaseTag
{
    // Public Methods
    // =========================================================================

    /**
     * Merges extra attributes into the wrapper.
     *
     * @param array<string, mixed> $attrs
     * @return $this
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function wrapperAttrs(array $attrs): self
    {
        $this->config['wrapperAttrs'] = $attrs;
        return $this;
    }

    /**
     * Merges extra attributes into the inner bar.
     *
     * @param array<string, mixed> $attrs
     * @return $this
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function barAttrs(array $attrs): self
    {
        $this->config['barAttrs'] = $attrs;
        return $this;
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected function _renderHtml(): string
    {
        $wrapperAttrs = (array)($this->config['wrapperAttrs'] ?? []);
        $barAttrs = (array)($this->config['barAttrs'] ?? []);

        $resolvedWrapperAttrs = array_merge([
            'class' => 'pp-strength',
            'data-pp-strength' => '1',
            'role' => 'progressbar',
            'aria-valuemin' => '0',
            'aria-valuemax' => '4',
            'aria-valuenow' => '0',
            'aria-label' => Craft::t('password-policy', 'Password strength'),
        ], $wrapperAttrs);

        $resolvedBarAttrs = array_merge([
            'class' => 'pp-strength-bar',
        ], $barAttrs);

        return '<div' . $this->_renderAttrs($resolvedWrapperAttrs) . '>'
            . '<div' . $this->_renderAttrs($resolvedBarAttrs) . '></div>'
            . '<span class="pp-strength-label" data-pp-strength-label></span>'
            . '</div>';
    }
}
