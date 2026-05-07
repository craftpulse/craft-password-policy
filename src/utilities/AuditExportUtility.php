<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\utilities;

use Craft;
use craft\base\Utility;
use craftpulse\passwordpolicy\PasswordPolicy;

/**
 * Class AuditExportUtility
 *
 * Renders the operator surface for triggering audit-log exports (G10).
 * Pairs with the `password-policy/audit/export --queue` console command
 * — same job, different surface, both produce identical export files
 * with one-time-use download tokens.
 *
 * Surface placement: a CP utility sits naturally next to
 * {@see AuditSchemaUtility} (the registry viewer) until G3's compliance
 * dashboard establishes a top-level audit subnav. G3 may rearrange
 * placement; the utility is portable.
 *
 * Edition gate: Enterprise-only — registration in
 * {@see PasswordPolicy::_registerUtilities()} guards on
 * `getIsEnterprise()` so a Lite or Pro install never sees the utility
 * class registered. Permission gate: `pp:audit-export` — registration
 * additionally checks the calling user can grant the permission so an
 * admin without it doesn't see a useless utility.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class AuditExportUtility extends Utility
{
    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function contentHtml(): string
    {
        return Craft::$app->getView()->renderTemplate(
            'password-policy/_utilities/audit-export',
            [
                'auditExportFilesystem' => PasswordPolicy::$plugin->getSettings()->auditExportFilesystem,
            ],
        );
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function displayName(): string
    {
        return Craft::t('password-policy', 'Audit Export');
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function icon(): ?string
    {
        return Craft::getAlias('@craftpulse/passwordpolicy/icon-mask.svg');
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function id(): string
    {
        return 'pp-audit-export';
    }
}
