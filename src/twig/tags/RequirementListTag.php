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

use craft\helpers\Html;
use craftpulse\passwordpolicy\PasswordPolicy;

/**
 * Class RequirementListTag
 *
 * Renders a `<ul>` of `<li data-pp-requirement="<key>">` items mirroring the
 * resolved policy. JS toggles `pp-pass` / `pp-fail` / `pp-pending` classes
 * on each item as the AJAX validate response cycles.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class RequirementListTag extends BaseTag
{
    // Public Methods
    // =========================================================================

    /**
     * Merges extra attributes into the `<ul>` element.
     *
     * @param array<string, mixed> $attrs
     * @return $this
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function listAttrs(array $attrs): self
    {
        $this->config['listAttrs'] = $attrs;
        return $this;
    }

    /**
     * Merges extra attributes into each `<li>` element.
     *
     * @param array<string, mixed> $attrs
     * @return $this
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function itemAttrs(array $attrs): self
    {
        $this->config['itemAttrs'] = $attrs;
        return $this;
    }

    /**
     * Sets the user group handles for anonymous group-preview resolution.
     * Forwarded to `requirementRules()` so the rendered list reflects the
     * per-group merged policy when applicable.
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
        $listAttrs = (array)($this->config['listAttrs'] ?? []);
        $itemAttrs = (array)($this->config['itemAttrs'] ?? []);
        $groups = (array)($this->config['groups'] ?? []);

        $resolvedListAttrs = array_merge([
            'class' => 'pp-requirements',
            'data-pp-requirements' => '1',
        ], $listAttrs);

        $variable = new \craftpulse\passwordpolicy\variables\PasswordPolicyVariable();
        $rules = $variable->requirementRules(['groups' => $groups]);

        $items = '';

        foreach ($rules as $rule) {
            $resolvedItemAttrs = array_merge([
                'class' => 'pp-requirement',
                'data-pp-requirement' => $rule['key'],
            ], $itemAttrs);

            $items .= '<li' . $this->_renderAttrs($resolvedItemAttrs) . '>'
                . Html::encode($rule['label'])
                . '</li>';
        }

        return '<ul' . $this->_renderAttrs($resolvedListAttrs) . '>' . $items . '</ul>';
    }
}
