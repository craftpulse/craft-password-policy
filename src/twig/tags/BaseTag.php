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
     * Stringifies the rendered HTML — convenience for callers using
     * `{{ tag }}` directly without `.render()`.
     *
     * @return string
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
            Craft::$app->getView()->registerAssetBundle(PasswordPolicyClientAsset::class);
        } catch (\Throwable) {
            // Defensive — never let asset registration break Twig rendering.
        }
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
