<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\exceptions;

use RuntimeException;

/**
 * Class EditionRequiredException
 *
 * Thrown when a caller invokes a feature gated to a higher edition than
 * the current install. Currently the only thrower is
 * `PasswordPolicyVariable::_assertProForBuilders()` — the eight
 * front-end render builders on the `craft.passwordPolicy.*` Twig
 * variable are Pro-only, and calling one on Lite raises this exception
 * which Twig surfaces in dev mode and renders the friendly error
 * template in production.
 *
 * Why a dedicated subclass of `\RuntimeException`:
 *  - Integrators can catch this specific class without false positives
 *    from unrelated runtime errors.
 *  - Log entries carry a class name that reads as "intentional gate"
 *    rather than "uncaught generic runtime error", which matters for
 *    operators triaging exception streams.
 *  - The namespace anchors the throw to the plugin so a `grep` for
 *    `EditionRequiredException` in another project's logs immediately
 *    identifies the source.
 *
 * Extends `\RuntimeException` so existing catch handlers that targeted
 * the previous `\RuntimeException` throws keep working unchanged.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class EditionRequiredException extends RuntimeException
{
}
