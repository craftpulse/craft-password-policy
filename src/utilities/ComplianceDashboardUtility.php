<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\utilities;

use Craft;
use craft\base\Utility;
use craftpulse\passwordpolicy\PasswordPolicy;

/**
 * Class ComplianceDashboardUtility
 *
 * Enterprise read-only operator surface that surfaces the Phase G
 * audit infrastructure's state in one place: chain health, alert
 * activity, pending SIEM forwards, retention cadence. Pairs with the
 * G3 {@see \craftpulse\passwordpolicy\controllers\ReportController}
 * for HTML / CSV report exports (per-aggregate "Run report" links).
 *
 * Edition gate: Enterprise-only — registration in
 * {@see PasswordPolicy::_registerUtilities()} guards on
 * `getIsEnterprise()` so a Lite or Pro install never sees the utility
 * class registered.
 *
 * Permission gate: `pp:audit-view` — registration additionally checks
 * the calling user can grant the permission so an admin without it
 * doesn't see a useless utility. The dashboard itself is read-only; an
 * auditor with the view permission alone should be able to render it.
 *
 * Capture-vs-exposure: the aggregate service runs on every edition
 * (universal capture per `project_audit_capture_principle.md`). This
 * utility is the visible-exposure surface — the Enterprise gate lives
 * here, not on the aggregator.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class ComplianceDashboardUtility extends Utility
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
        $plugin = PasswordPolicy::$plugin;

        return Craft::$app->getView()->renderTemplate(
            'password-policy/_utilities/compliance-dashboard',
            ['aggregates' => $plugin->getComplianceAggregates()],
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
        return Craft::t('password-policy', 'Compliance dashboard');
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
        return 'pp-compliance-dashboard';
    }
}
