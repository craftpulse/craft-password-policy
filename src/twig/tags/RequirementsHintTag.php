<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\twig\tags;

use craft\helpers\Html;

/**
 * Class RequirementsHintTag
 *
 * Renders a `<p>` containing the human-readable summary returned by
 * `requirementsText()`. Useful as static helper text below a password input
 * for users who would rather scan one sentence than a checklist.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class RequirementsHintTag extends BaseTag
{
    // Public Methods
    // =========================================================================

    /**
     * Merges extra attributes into the `<p>` element.
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
     * Sets the user group handles for anonymous group-preview resolution.
     *
     * @param string[] $handles
     * @return $this
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function groups(array $handles): self
    {
        $this->config['groups'] = $handles;
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
        $groups = (array)($this->config['groups'] ?? []);

        $resolvedWrapperAttrs = array_merge([
            'class' => 'pp-requirements-hint',
        ], $wrapperAttrs);

        $variable = new \craftpulse\passwordpolicy\variables\PasswordPolicyVariable();
        $text = $variable->requirementsText(['groups' => $groups]);

        return '<p' . $this->_renderAttrs($resolvedWrapperAttrs) . '>' . Html::encode($text) . '</p>';
    }
}
