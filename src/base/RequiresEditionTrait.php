<?php
/**
 * Password policy plugin for Craft CMS
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\base;

use Craft;
use craftpulse\passwordpolicy\PasswordPolicy;
use yii\web\NotFoundHttpException;

/**
 * Gates a web controller's Pro-only or Enterprise-only actions behind the
 * active plugin edition, translating a failed check into a clean
 * {@see NotFoundHttpException}.
 *
 * The plugin's edition-gating doctrine HIDES higher-edition functionality on
 * lower editions: no nav entries, no teaser panes, no disabled controls, no
 * upsell chrome. A URL for a feature the edition doesn't have must therefore
 * behave exactly like any other nonexistent route and 404. A 403 would leak
 * that the route exists and contradict the hidden nav; a 500 (from an
 * uncaught non-HTTP exception) would leak a stack trace in dev mode.
 *
 * Scope: HTTP controllers only. The plugin's layered convention for
 * edition-gate throws is:
 *  - HTTP controllers throw {@see NotFoundHttpException} — 404, never 403.
 *  - Service-layer and Twig-variable gates throw
 *    {@see \craftpulse\passwordpolicy\exceptions\EditionRequiredException},
 *    so integrators can catch the gate explicitly.
 *  - Queue jobs and console controllers skip gracefully — a warning log and
 *    an early return (jobs), or stderr output and a non-zero exit code
 *    (console) — rather than throwing.
 *
 * `ForbiddenHttpException` stays reserved for permission and
 * `allowAdminChanges` denials, which are a different axis: those screens do
 * exist on this edition, the current user just may not use them.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
trait RequiresEditionTrait
{
    // Protected Methods
    // =========================================================================

    /**
     * Requires the Enterprise edition for the current controller action.
     *
     * @return void
     *
     * @throws NotFoundHttpException if the active edition is below Enterprise.
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected function requireEnterpriseEdition(): void
    {
        if (!PasswordPolicy::$plugin->getIsEnterprise()) {
            throw new NotFoundHttpException(Craft::t('yii', 'Page not found.'));
        }
    }

    /**
     * Requires the Pro edition or higher for the current controller action.
     *
     * @return void
     *
     * @throws NotFoundHttpException if the active edition is below Pro.
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected function requireProEdition(): void
    {
        if (!PasswordPolicy::$plugin->getIsPro()) {
            throw new NotFoundHttpException(Craft::t('yii', 'Page not found.'));
        }
    }
}
