<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

declare(strict_types=1);

namespace craftpulse\passwordpolicy\helpers;

/**
 * Class PasswordFieldHelper
 *
 * Single source of truth for the password-field show/hide "eye"
 * affordance markup. Both the front-end Pro builder
 * ({@see \craftpulse\passwordpolicy\twig\tags\PasswordFieldTag}) and the
 * CP admin change-password modal
 * ({@see \craftpulse\passwordpolicy\elements\actions\ChangeUserPassword})
 * render the glyph from here so the two surfaces can't drift on icon
 * geometry, classes, or markup shape.
 *
 * Glyphs are the FontAwesome 6 Free **solid** `eye` / `eye-slash`
 * icons — the same set Craft 5 bundles at
 * `vendor/craftcms/cms/src/icons/solid/{eye,eye-slash}.svg` (FA icons
 * are CC BY 4.0). The two glyphs ship with DIFFERENT viewBoxes
 * (`0 0 576 512` vs `0 0 640 512`), so they can't share one `<svg>`;
 * `eyeToggleSvg()` emits two complete `<svg>` elements (slash hidden)
 * and the toggle JS flips which one is visible.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
final class PasswordFieldHelper
{
    // Constants
    // =========================================================================

    /**
     * @var string FontAwesome 6 Free solid `eye` path (viewBox 0 0 576 512).
     */
    public const EYE_OPEN_PATH = 'M288 32c-80.8 0-145.5 36.8-192.6 80.6C48.6 156 17.3 208 2.5 243.7c-3.3 7.9-3.3 16.7 0 24.6C17.3 304 48.6 356 95.4 399.4C142.5 443.2 207.2 480 288 480s145.5-36.8 192.6-80.6c46.8-43.5 78.1-95.4 93-131.1c3.3-7.9 3.3-16.7 0-24.6c-14.9-35.7-46.2-87.7-93-131.1C433.5 68.8 368.8 32 288 32zM144 256a144 144 0 1 1 288 0 144 144 0 1 1 -288 0zm144-64c0 35.3-28.7 64-64 64c-7.1 0-13.9-1.2-20.3-3.3c-5.5-1.8-11.9 1.6-11.7 7.4c.3 6.9 1.3 13.8 3.2 20.7c13.7 51.2 66.4 81.6 117.6 67.9s81.6-66.4 67.9-117.6c-11.1-41.5-47.8-69.4-88.6-71.1c-5.8-.2-9.2 6.1-7.4 11.7c2.1 6.4 3.3 13.2 3.3 20.3z';

    /**
     * @var string FontAwesome 6 Free solid `eye-slash` path (viewBox 0 0 640 512).
     */
    public const EYE_SLASH_PATH = 'M38.8 5.1C28.4-3.1 13.3-1.2 5.1 9.2S-1.2 34.7 9.2 42.9l592 464c10.4 8.2 25.5 6.3 33.7-4.1s6.3-25.5-4.1-33.7L525.6 386.7c39.6-40.6 66.4-86.1 79.9-118.4c3.3-7.9 3.3-16.7 0-24.6c-14.9-35.7-46.2-87.7-93-131.1C465.5 68.8 400.8 32 320 32c-68.2 0-125 26.3-169.3 60.8L38.8 5.1zM223.1 149.5C248.6 126.2 282.7 112 320 112c79.5 0 144 64.5 144 144c0 24.9-6.3 48.3-17.4 68.7L408 294.5c8.4-19.3 10.6-41.4 4.8-63.3c-11.1-41.5-47.8-69.4-88.6-71.1c-5.8-.2-9.2 6.1-7.4 11.7c2.1 6.4 3.3 13.2 3.3 20.3c0 10.2-2.4 19.8-6.6 28.3l-90.3-70.8zM373 389.9c-16.4 6.5-34.3 10.1-53 10.1c-79.5 0-144-64.5-144-144c0-6.9 .5-13.6 1.4-20.2L83.1 161.5C60.3 191.2 44 220.8 34.5 243.7c-3.3 7.9-3.3 16.7 0 24.6c14.9 35.7 46.2 87.7 93 131.1C174.5 443.2 239.2 480 320 480c47.8 0 89.9-12.9 126.2-32.5L373 389.9z';

    // Static Methods
    // =========================================================================

    /**
     * Returns the two-glyph eye affordance markup: a visible open eye and
     * a hidden eye-slash. The toggle JS (front-end client asset +
     * CP modal helper) swaps `display` between `.pp-eye-open` and
     * `.pp-eye-slash` on click.
     *
     * `aria-hidden="true"` — the glyph is decorative; the button's
     * `aria-label` carries the accessible name. Both glyphs render in a
     * fixed 20×18 box with the default `xMidYMid meet` aspect handling,
     * so the differing FA viewBoxes letterbox to the same footprint and
     * the toggle doesn't shift layout.
     *
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function eyeToggleSvg(): string
    {
        return self::_glyph('pp-eye-open', '0 0 576 512', self::EYE_OPEN_PATH, false)
            . self::_glyph('pp-eye-slash', '0 0 640 512', self::EYE_SLASH_PATH, true);
    }

    // Private Methods
    // =========================================================================

    /**
     * Renders a single FA glyph `<svg>`.
     *
     * @param string $stateClass the toggle-state class (`pp-eye-open` / `pp-eye-slash`)
     * @param string $viewBox the glyph's native viewBox
     * @param string $path the glyph path data
     * @param bool $hidden whether to start hidden (`display:none`)
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private static function _glyph(string $stateClass, string $viewBox, string $path, bool $hidden): string
    {
        $hiddenStyle = $hidden ? ' style="display:none"' : '';

        return "<svg class=\"pp-eye {$stateClass}\" viewBox=\"{$viewBox}\" width=\"20\" height=\"18\" aria-hidden=\"true\" fill=\"currentColor\"{$hiddenStyle}>"
            . "<path d=\"{$path}\"/>"
            . '</svg>';
    }
}
