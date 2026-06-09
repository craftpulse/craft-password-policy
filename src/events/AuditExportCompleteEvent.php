<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\events;

use DateTime;
use yii\base\Event;

/**
 * Class AuditExportCompleteEvent
 *
 * Fired after `AuditExportJob` finishes writing every batch and the
 * file is fully materialised. Listeners observe the completion — they
 * don't gate it. The export decision was made earlier (the operator
 * triggered the utility / console command); by the time this event
 * fires the file already exists, the one-time-use download token is
 * cached, and the email notification is queued.
 *
 * Use cases:
 *
 *  - SIEM-side mirroring of completed exports for audit-trail-of-
 *    exports compliance — auditors want a record of every export
 *    operation visible in the same off-site evidence system that
 *    receives the audit log itself.
 *  - Compliance dashboard counting "exports run this week" /
 *    "average export size" as a single read.
 *  - Custom integration recording the export in a third-party
 *    incident or evidence queue (e.g. Jira issue with the download
 *    URL embedded for the auditor's review window).
 *
 * Privacy: the event payload intentionally does NOT include the file
 * contents. Listeners that want the rows themselves dispatch their
 * own filesystem read against `$filePath` — that decision is theirs,
 * and keeping the bytes out of the event keeps the path narrow for
 * listeners that only need the operational signal.
 *
 * Edition: Enterprise — `AuditExportJob` is itself Enterprise-only,
 * so this event only fires on Enterprise installs. Listeners
 * registered on lower editions never see it because the underlying
 * job exits silently before reaching `after()`.
 *
 * @event AuditExportCompleteEvent
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class AuditExportCompleteEvent extends Event
{
    // Public Properties
    // =========================================================================

    /**
     * @var DateTime UTC timestamp when the one-time-use download token
     *     expires. After this point the download URL returns 404
     *     regardless of whether the file still exists on disk.
     */
    public DateTime $expiresAt;

    /**
     * @var string absolute filesystem path (local fallback) or
     *     filesystem-relative path (when a custom FsInterface handle
     *     is configured) to the materialised export file. Listeners
     *     that need the bytes resolve this against the configured
     *     filesystem; the plugin's own download path looks it up via
     *     the cached token.
     */
    public string $filePath;

    /**
     * @var string output format — `csv` or `jsonl`.
     */
    public string $format;

    /**
     * @var int the userId of the admin who requested the export. Used
     *     by listeners to correlate the export operation with an
     *     actor in their evidence system.
     */
    public int $requestedById;

    /**
     * @var int the number of rows written to the export file.
     *     Includes every row in the configured date window.
     */
    public int $rowCount;

    /**
     * @var string the 64-char URL-safe random token. Doubles as the
     *     filename and the cache key suffix the download controller
     *     uses to look up the file.
     */
    public string $token;

    /**
     * @var string|null the handle of the configured filesystem the
     *     export was written to, or `null` on the local-fallback path
     *     (where `$filePath` is an absolute local path). Listeners that
     *     mirror the artefact off-site resolve `$filePath` against this
     *     filesystem so they read the same bytes the download controller
     *     serves.
     *
     * @since 5.2.0
     */
    public ?string $filesystemHandle = null;
}
