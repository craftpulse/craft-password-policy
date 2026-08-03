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
 * The rest of the plugin's layered convention for edition-gate throws:
 *  - HTTP controllers throw `yii\web\NotFoundHttpException` via
 *    {@see \craftpulse\passwordpolicy\base\RequiresEditionTrait} — 404,
 *    never 403. The screen does not exist on that edition and the nav never
 *    offered it, so a bookmarked or hand-typed URL has to behave like any
 *    other nonexistent route; a 403 would confirm the screen is there and
 *    contradict the hidden nav.
 *  - Queue jobs and console controllers skip gracefully — a warning log and
 *    an early return (jobs), or stderr output and a non-zero exit code
 *    (console) — rather than throwing. Async and CLI surfaces can't carry
 *    exception-driven control flow without surfacing user-visible problems.
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
