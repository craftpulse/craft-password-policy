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

use Craft;
use craftpulse\passwordpolicy\helpers\PasswordFieldHelper;
use InvalidArgumentException;

/**
 * Class PasswordFieldTag
 *
 * Fluent builder for a `<input type="password">` element with optional
 * show/hide toggle, live AJAX validation, submit-gating, and a11y wiring
 * (live region + describedby + aria-invalid).
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class PasswordFieldTag extends BaseTag
{
    // Public Methods
    // =========================================================================

    /**
     * Sets the input `name` attribute. Required.
     *
     * @param string $name
     * @return $this
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function name(string $name): self
    {
        $this->config['name'] = $name;
        return $this;
    }

    /**
     * Sets the input `id` attribute. When omitted, a stable per-render id
     * is generated so the show/hide toggle and `aria-describedby` linkage
     * still work.
     *
     * @param string $id
     * @return $this
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function id(string $id): self
    {
        $this->config['id'] = $id;
        return $this;
    }

    /**
     * Sets the input `value` attribute. Default: empty (never prefill
     * passwords for security).
     *
     * @param string $value
     * @return $this
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function value(string $value): self
    {
        $this->config['value'] = $value;
        return $this;
    }

    /**
     * Sets the input `autocomplete` attribute. Default: `new-password`.
     *
     * @param string $autocomplete
     * @return $this
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function autocomplete(string $autocomplete): self
    {
        $this->config['autocomplete'] = $autocomplete;
        return $this;
    }

    /**
     * Merges extra attributes into the `<input>` element.
     *
     * @param array<string, mixed> $attrs
     * @return $this
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function inputAttrs(array $attrs): self
    {
        $this->config['inputAttrs'] = $attrs;
        return $this;
    }

    /**
     * Merges extra attributes into the wrapper `<div>` element.
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
     * Toggles the show/hide eye button. Default: true.
     *
     * @param bool $on
     * @return $this
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function toggleVisibility(bool $on): self
    {
        $this->config['toggleVisibility'] = $on;
        return $this;
    }

    /**
     * Merges extra attributes into the show/hide toggle button.
     *
     * @param array<string, mixed> $attrs
     * @return $this
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function toggleAttrs(array $attrs): self
    {
        $this->config['toggleAttrs'] = $attrs;
        return $this;
    }

    /**
     * Enables debounced AJAX live validation against the plugin's validate
     * endpoint. Auto-registers the client JS asset bundle when on.
     *
     * @param bool $on
     * @return $this
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function liveValidation(bool $on): self
    {
        $this->config['liveValidation'] = $on;
        return $this;
    }

    /**
     * Sets the CSS selector for a submit button to enable/disable based on
     * validation state. Only meaningful with `liveValidation(true)`.
     *
     * @param string $selector
     * @return $this
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function submitGate(string $selector): self
    {
        $this->config['submitGate'] = $selector;
        return $this;
    }

    /**
     * Sets the user group handles to use for anonymous group-preview
     * resolution (e.g. a registration form for "Sign up as Editor").
     * Forwarded to the validate endpoint so the response criteria match
     * the resolved per-group policy.
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
     * @throws InvalidArgumentException when required options are missing
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected function _renderHtml(): string
    {
        $this->_validate();

        $name = (string)$this->config['name'];
        $id = $this->config['id'] ?? $this->_autoId('pp-password');
        $value = (string)($this->config['value'] ?? '');
        $autocomplete = (string)($this->config['autocomplete'] ?? 'new-password');
        $toggleVisibility = (bool)($this->config['toggleVisibility'] ?? true);
        $liveValidation = (bool)($this->config['liveValidation'] ?? false);
        $submitGate = $this->config['submitGate'] ?? null;
        $groups = (array)($this->config['groups'] ?? []);

        $inputAttrs = (array)($this->config['inputAttrs'] ?? []);
        $wrapperAttrs = (array)($this->config['wrapperAttrs'] ?? []);
        $toggleAttrs = (array)($this->config['toggleAttrs'] ?? []);

        // Register the client JS bundle for ANY interactivity flag — toggle
        // alone needs the JS too. The earlier `liveValidation`-only gate
        // shipped a non-functional eye button when consumers built a field
        // with `toggleVisibility: true, liveValidation: false`.
        if ($this->_needsClientAsset($this->config)) {
            $this->_registerClientAsset();
        }

        $resolvedInputAttrs = array_merge([
            'type' => 'password',
            'name' => $name,
            'id' => $id,
            'value' => $value,
            'autocomplete' => $autocomplete,
            'data-pp-validate' => $liveValidation ? '1' : null,
            'data-pp-context-groups' => !empty($groups) ? implode(',', array_map('strval', $groups)) : null,
            'data-pp-submit-gate' => $submitGate,
            'aria-describedby' => $liveValidation ? "{$id}-live" : null,
        ], $inputAttrs);

        $resolvedWrapperAttrs = array_merge([
            'class' => 'pp-password-field',
            'data-pp-field' => $id,
        ], $wrapperAttrs);

        $input = '<input' . $this->_renderAttrs($resolvedInputAttrs) . '>';

        $toggle = '';

        if ($toggleVisibility) {
            $resolvedToggleAttrs = array_merge([
                'type' => 'button',
                'class' => 'pp-toggle-visibility',
                'data-pp-toggle-visibility' => $id,
                'aria-label' => Craft::t('password-policy', 'Show password'),
            ], $toggleAttrs);

            $toggle = '<button' . $this->_renderAttrs($resolvedToggleAttrs) . '>'
                . $this->_eyeSvg()
                . '</button>';
        }

        // a11y live region — always rendered when liveValidation is on so
        // screen readers receive state announcements via aria-live polite.
        $liveRegion = '';

        if ($liveValidation) {
            $liveRegion = '<span'
                . $this->_renderAttrs([
                    'id' => "{$id}-live",
                    'class' => 'pp-live-region',
                    'data-pp-live-region' => $id,
                    'aria-live' => 'polite',
                    'aria-atomic' => 'true',
                ])
                . '></span>';
        }

        return '<div' . $this->_renderAttrs($resolvedWrapperAttrs) . '>'
            . $input
            . $toggle
            . $liveRegion
            . '</div>';
    }

    // Private Methods
    // =========================================================================

    /**
     * Renders the eye / eye-slash inline SVG affordance.
     *
     * Delegates to {@see PasswordFieldHelper::eyeToggleSvg()} so the
     * front-end builder and the CP admin change-password modal render the
     * identical glyph from one source (FontAwesome 6 Free solid eye /
     * eye-slash). JS toggles `display` between the two `.pp-eye-open` /
     * `.pp-eye-slash` `<svg>` elements to flip visibility.
     *
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _eyeSvg(): string
    {
        return PasswordFieldHelper::eyeToggleSvg();
    }

    /**
     * Validates required configuration. Throws on misuse.
     *
     * @return void
     *
     * @throws InvalidArgumentException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _validate(): void
    {
        if (empty($this->config['name'])) {
            throw new InvalidArgumentException(
                'PasswordFieldTag requires a `name`. Call ->name(\'password\').',
            );
        }
    }
}
