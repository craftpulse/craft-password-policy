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
use craft\helpers\Html;
use craftpulse\passwordpolicy\assetbundles\passwordpolicyclient\PasswordPolicyClientAsset;
use craftpulse\passwordpolicy\PasswordPolicy;
use InvalidArgumentException;
use Twig\Markup;

/**
 * Class BaseTag
 *
 * Base class for the fluent Twig render builders shipped under
 * `craft.passwordPolicy.*`. Provides the chainable-setter / config-array
 * dual-mode constructor, the common attribute-merge helpers, and the
 * lazy auto-registration of the front-end JS asset bundle.
 *
 * Concrete tags implement `render(): string` and (optionally) `_validate()`
 * for required-field guards.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
abstract class BaseTag
{
    // Protected Properties
    // =========================================================================

    /**
     * @var array<string, mixed> raw config array — internal storage for fluent setters.
     */
    protected array $config = [];

    // Public Methods
    // =========================================================================

    /**
     * @param array<string, mixed> $config initial configuration. Each key
     *     must match a chainable setter on the concrete subclass — invalid
     *     keys throw `InvalidArgumentException` so consumers learn about
     *     typos at render time.
     *
     * @throws InvalidArgumentException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function __construct(array $config = [])
    {
        foreach ($config as $key => $value) {
            if (!method_exists($this, $key)) {
                throw new InvalidArgumentException(
                    sprintf('Unknown option "%s" for %s.', $key, static::class),
                );
            }

            $this->$key($value);
        }
    }

    /**
     * Renders the configured tag to HTML, returned as a `Markup` instance
     * so Twig doesn't double-escape the markup. Subclasses implement
     * `_renderHtml()` returning a plain string; this method wraps it.
     *
     * @return Markup
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function render(): Markup
    {
        return new Markup($this->_renderHtml(), Craft::$app->getView()->getTwig()->getCharset());
    }

    /**
     * Stringifies the rendered HTML for PHP-context concatenation. Used by
     * composite tags that assemble children into a single output string
     * (e.g. `PasswordWidgetTag` calling `(string)$field`).
     *
     * IMPORTANT: do NOT use `{{ tag }}` in Twig templates — Twig's auto-escape
     * filter HTML-encodes the rendered markup because PHP's `__toString()`
     * contract requires a plain `string` return (not `\Twig\Markup`). Always
     * call `{{ tag.render() }}` from Twig, which returns a `Markup` instance
     * that bypasses auto-escape.
     *
     * @return string raw HTML; the consumer is responsible for not re-escaping
     *
     * @see render() for the Twig-safe rendering path
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function __toString(): string
    {
        return $this->_renderHtml();
    }

    // Protected Methods
    // =========================================================================

    /**
     * Concrete subclasses implement this; render() wraps the result in
     * a Twig `Markup` so consumers don't need `|raw`.
     *
     * @return string raw HTML
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    abstract protected function _renderHtml(): string;

    /**
     * Auto-registers the front-end client asset on the current view. Called
     * by tags that emit `data-pp-validate` / `data-pp-toggle-visibility` /
     * other JS-driven affordances.
     *
     * No-op outside web requests (queue jobs, console commands).
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected function _registerClientAsset(): void
    {
        $request = Craft::$app->getRequest();

        if ($request->getIsConsoleRequest()) {
            return;
        }

        try {
            $view = Craft::$app->getView();
            $view->registerAssetBundle(PasswordPolicyClientAsset::class);

            // Expose the CSRF token + param name as CSP-safe <meta> tags so
            // the front-end client (password-policy.js) can authenticate its
            // live-validation XHR. The script's other token source —
            // `window.Craft.csrfTokenValue` — is a CP-only global that is
            // absent on the front-end, so without these tags every validate
            // request is rejected with a 400 CSRF failure and the requirement
            // list / strength meter never update. A <meta> tag is not
            // `script-src` governed, so it survives a strict-nonce CSP — same
            // rationale as the `pp-show-strength-indicator` bootstrap meta.
            $generalConfig = Craft::$app->getConfig()->getGeneral();

            if ($generalConfig->enableCsrfProtection) {
                /** @var \craft\web\Request $request */
                $request = Craft::$app->getRequest();

                $view->registerMetaTag([
                    'name' => 'pp-csrf-param',
                    'content' => $generalConfig->csrfTokenName,
                ], 'pp-csrf-param');

                $view->registerMetaTag([
                    'name' => 'pp-csrf-token',
                    'content' => $request->getCsrfToken(),
                ], 'pp-csrf-token');
            }
        } catch (\Throwable) {
            // Defensive — never let asset registration break Twig rendering.
        }
    }

    /**
     * Returns whether the given config dict requests any feature that needs
     * the client JS bundle (live AJAX validation, show/hide toggle, submit
     * gating). Centralized here so each concrete tag declares which keys it
     * cares about and the gating logic stays consistent.
     *
     * Each flag corresponds to a code path in `password-policy.js`:
     *  - `liveValidation` → `bindValidate()` (debounced AJAX validate calls)
     *  - `toggleVisibility` → `bindToggle()` (eye/eye-slash button)
     *  - `submitGate` → submit-button enable/disable based on validation
     *    state (only meaningful with `liveValidation` on, but harmless to
     *    register the bundle when only a gate is set)
     *
     * @param array<string, mixed> $config
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected function _needsClientAsset(array $config): bool
    {
        if (!empty($config['liveValidation'])) {
            return true;
        }

        if (!empty($config['toggleVisibility'])) {
            return true;
        }

        if (!empty($config['submitGate'])) {
            return true;
        }

        return false;
    }

    /**
     * Renders an HTML attribute string from an array. Used to merge
     * caller-supplied `*Attrs` arrays into the rendered markup.
     *
     * `null` and empty-string values are dropped so consumers can pass
     * `{ class: '' }` to mean "default".
     *
     * @param array<string, mixed> $attrs
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected function _renderAttrs(array $attrs): string
    {
        $filtered = [];

        foreach ($attrs as $name => $value) {
            if ($value === null || $value === '') {
                continue;
            }

            $filtered[$name] = $value;
        }

        return Html::renderTagAttributes($filtered);
    }

    /**
     * Returns a unique DOM id for the current request, scoped to the tag
     * type. Used when the consumer didn't supply an explicit `id`.
     *
     * @param string $prefix
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected function _autoId(string $prefix): string
    {
        static $counter = 0;
        $counter++;

        return $prefix . '-' . substr(md5((string)$counter . microtime(true)), 0, 8);
    }

    /**
     * Returns the plugin instance for downstream policy / strength lookups.
     *
     * @return PasswordPolicy
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected function _plugin(): PasswordPolicy
    {
        return PasswordPolicy::$plugin;
    }
}
