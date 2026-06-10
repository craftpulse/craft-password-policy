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
 * Project-wide convention for edition-gate throws in the service and
 * Twig-variable layers. Raised when a caller invokes a feature gated to
 * a higher edition than the current install — calling
 * `craft.passwordPolicy.passwordChangeForm()` on Lite, asking
 * `NotificationService::sendBreachDetected()` to dispatch on Lite, or
 * any future Pro-/Enterprise-gated entry point at the same layers.
 *
 * Layer-specific throwers:
 *  - `PasswordPolicyVariable::_assertProForBuilders()` — the eight
 *    front-end render builders on the `craft.passwordPolicy.*` Twig
 *    variable. Twig surfaces the exception in dev mode and renders the
 *    friendly error template in production.
 *  - `NotificationService::sendBreachDetected()` — Pro-gated breach
 *    notification dispatch.
 *  - `NotificationService::sendNewDeviceAlert()` /
 *    `sendAdminSecurityAlert()` — Enterprise-gated notification dispatch
 *    surfaces. (Device-row capture stays universal; only the alert email
 *    is gated.)
 *
 * HTTP controllers continue to use `yii\web\ForbiddenHttpException` for
 * edition gates because Craft's web layer expects an HttpException to
 * render a proper 403 response. Queue jobs and console controllers skip
 * gracefully with a warning log / non-zero exit rather than throwing.
 * See `.claude/rules/architecture.md` for the layered convention.
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
