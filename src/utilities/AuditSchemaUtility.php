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
use craftpulse\passwordpolicy\services\AuditLogService;

/**
 * Class AuditSchemaUtility
 *
 * Renders the per-event PII allowlist registry from
 * {@see AuditLogService::ALLOWED_DETAILS_BY_EVENT} as a read-only
 * auditor-facing table in the CP. Pairs with the
 * `password-policy/audit/schema` console command — same registry,
 * different surface, both are static evidence of the privacy contract.
 *
 * Edition gate: Enterprise-only. Permission gate: `pp:audit-view`. Both
 * gates are wired in `PasswordPolicy::_registerUtilities()` — a Lite
 * or Pro install never sees the utility class registered.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class AuditSchemaUtility extends Utility
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
        $registry = AuditLogService::ALLOWED_DETAILS_BY_EVENT;
        ksort($registry, SORT_STRING);

        return Craft::$app->getView()->renderTemplate(
            'password-policy/_utilities/audit-schema',
            [
                'registry' => $registry,
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
        return Craft::t('password-policy', 'Audit Schema');
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
        return 'password-policy-audit-schema';
    }
}
