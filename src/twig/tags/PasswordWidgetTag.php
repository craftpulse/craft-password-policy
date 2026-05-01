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

/**
 * Class PasswordWidgetTag
 *
 * Composite tag — renders a wrapper div containing a `PasswordFieldTag`
 * input plus the strength meter, requirement list, and hint. Sub-components
 * can be toggled via `showStrength`, `showRequirements`, `showHint`.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class PasswordWidgetTag extends BaseTag
{
    // Public Methods
    // =========================================================================

    /**
     * @param string $name
     * @return $this
     */
    public function name(string $name): self
    {
        $this->config['name'] = $name;
        return $this;
    }

    /**
     * @param string $id
     * @return $this
     */
    public function id(string $id): self
    {
        $this->config['id'] = $id;
        return $this;
    }

    /**
     * @param array<string, mixed> $attrs
     * @return $this
     */
    public function wrapperAttrs(array $attrs): self
    {
        $this->config['wrapperAttrs'] = $attrs;
        return $this;
    }

    /**
     * @param array<string, mixed> $attrs
     * @return $this
     */
    public function inputAttrs(array $attrs): self
    {
        $this->config['inputAttrs'] = $attrs;
        return $this;
    }

    /**
     * @param bool $on
     * @return $this
     */
    public function toggleVisibility(bool $on): self
    {
        $this->config['toggleVisibility'] = $on;
        return $this;
    }

    /**
     * @param bool $on
     * @return $this
     */
    public function liveValidation(bool $on): self
    {
        $this->config['liveValidation'] = $on;
        return $this;
    }

    /**
     * @param string $selector
     * @return $this
     */
    public function submitGate(string $selector): self
    {
        $this->config['submitGate'] = $selector;
        return $this;
    }

    /**
     * @param bool $on
     * @return $this
     */
    public function showStrength(bool $on): self
    {
        $this->config['showStrength'] = $on;
        return $this;
    }

    /**
     * @param bool $on
     * @return $this
     */
    public function showRequirements(bool $on): self
    {
        $this->config['showRequirements'] = $on;
        return $this;
    }

    /**
     * @param bool $on
     * @return $this
     */
    public function showHint(bool $on): self
    {
        $this->config['showHint'] = $on;
        return $this;
    }

    /**
     * @param string[] $handles
     * @return $this
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
        $showStrength = (bool)($this->config['showStrength'] ?? true);
        $showRequirements = (bool)($this->config['showRequirements'] ?? true);
        $showHint = (bool)($this->config['showHint'] ?? false);

        $resolvedWrapperAttrs = array_merge([
            'class' => 'pp-widget',
        ], $wrapperAttrs);

        $fieldConfig = [
            'name' => $this->config['name'] ?? 'password',
            'inputAttrs' => $this->config['inputAttrs'] ?? [],
            'toggleVisibility' => $this->config['toggleVisibility'] ?? true,
            'liveValidation' => $this->config['liveValidation'] ?? true,
            'groups' => $groups,
        ];

        // Only forward optional values when the caller explicitly set them —
        // `id` and `submitGate` are strict-typed `string` on the child setter,
        // so forwarding `null` here would TypeError at construct time. The
        // `groups` array is fine to forward unconditionally (`array` accepts
        // empty arrays).
        if (!empty($this->config['id'])) {
            $fieldConfig['id'] = $this->config['id'];
        }

        if (!empty($this->config['submitGate'])) {
            $fieldConfig['submitGate'] = $this->config['submitGate'];
        }

        $field = new PasswordFieldTag($fieldConfig);

        $output = '<div' . $this->_renderAttrs($resolvedWrapperAttrs) . '>';
        $output .= (string)$field;

        if ($showStrength) {
            $output .= (string)(new StrengthMeterTag());
        }

        if ($showRequirements) {
            $output .= (string)(new RequirementListTag(['groups' => $groups]));
        }

        if ($showHint) {
            $output .= (string)(new RequirementsHintTag(['groups' => $groups]));
        }

        $output .= '</div>';

        return $output;
    }
}
