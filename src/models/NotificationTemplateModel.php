<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\models;

use Craft;
use craft\base\Model;
use craft\helpers\DateTimeHelper;
use craft\helpers\Json;
use craft\helpers\UrlHelper;
use craft\web\View;
use craftpulse\passwordpolicy\records\NotificationTemplateRecord;
use DateTime;

/**
 * Class NotificationTemplateModel
 *
 * Per-(notificationKey, siteId) email template, hydrated from the JSON
 * `content` column. Typed properties at the model layer give type safety
 * over the schemaless storage shape.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class NotificationTemplateModel extends Model
{
    // Public Properties
    // =========================================================================

    /**
     * @var int|null the row ID
     */
    public ?int $id = null;

    /**
     * @var string the notification key (e.g. `expiry-reminder`)
     */
    public string $notificationKey = '';

    /**
     * @var int the site ID this template applies to
     */
    public int $siteId = 0;

    /**
     * @var string the email subject (Twig source)
     */
    public string $subject = '';

    /**
     * @var string the plaintext email body (Twig source)
     */
    public string $body = '';

    /**
     * @var string|null optional sender name override; null falls back to system mailer
     */
    public ?string $senderName = null;

    /**
     * @var string|null optional sender email override; null falls back to system mailer
     */
    public ?string $senderEmail = null;

    /**
     * @var string|null optional reply-to override; null means no Reply-To header
     */
    public ?string $replyTo = null;

    /**
     * @var string|null optional path to a site Twig template that renders
     *     the email body in place of the DB-stored `$body` field. Enterprise
     *     edition only — see `NotificationService::composeFromTemplate()`
     *     for the renderer-side gate and `NotificationTemplateController::
     *     actionSave()` for the input-side strip. Subject continues to
     *     render from the DB `$subject` field even when this is set —
     *     admins want to edit subject without touching a Twig file.
     *
     *     The path is validated at save time via
     *     `Craft::$app->getView()->resolveTemplate()` so a typo fails the
     *     save loudly instead of silently dispatching empty bodies. The
     *     Enterprise gate is enforced at the renderer, not at field load,
     *     so a downgrade from Enterprise to Pro silently falls back to the
     *     DB body without rewriting any rows.
     */
    public ?string $templatePath = null;

    /**
     * @var DateTime|null
     */
    public ?DateTime $dateCreated = null;

    /**
     * @var DateTime|null
     */
    public ?DateTime $dateUpdated = null;

    /**
     * @var string|null
     */
    public ?string $uid = null;

    // Static Methods
    // =========================================================================

    /**
     * Hydrates a model from a NotificationTemplateRecord, decoding the JSON
     * `content` column onto typed properties.
     *
     * The `content` column may come back double-encoded depending on driver
     * (string-of-JSON vs. native JSON column) — `Json::decodeIfJson` peels
     * one layer; if the result is still a string it means the value was
     * stored as a quoted JSON string and we decode again.
     *
     * @param NotificationTemplateRecord $record the source record
     * @return self
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function fromRecord(NotificationTemplateRecord $record): self
    {
        $model = new self();
        $model->id = (int)$record->id;
        $model->notificationKey = (string)$record->notificationKey;
        $model->siteId = (int)$record->siteId;
        $model->dateCreated = $record->dateCreated !== null
            ? DateTimeHelper::toDateTime($record->dateCreated) ?: null
            : null;
        $model->dateUpdated = $record->dateUpdated !== null
            ? DateTimeHelper::toDateTime($record->dateUpdated) ?: null
            : null;
        $model->uid = $record->uid;

        $rawContent = $record->content;
        $decoded = is_string($rawContent) ? Json::decodeIfJson($rawContent) : $rawContent;

        // Double-encoded path: first decode yielded a string, second yields the array.
        if (is_string($decoded)) {
            $decoded = Json::decodeIfJson($decoded);
        }

        if (is_array($decoded)) {
            $model->subject = (string)($decoded['subject'] ?? '');
            $model->body = (string)($decoded['body'] ?? '');
            $model->senderName = isset($decoded['senderName']) && $decoded['senderName'] !== ''
                ? (string)$decoded['senderName']
                : null;
            $model->senderEmail = isset($decoded['senderEmail']) && $decoded['senderEmail'] !== ''
                ? (string)$decoded['senderEmail']
                : null;
            $model->replyTo = isset($decoded['replyTo']) && $decoded['replyTo'] !== ''
                ? (string)$decoded['replyTo']
                : null;
            $model->templatePath = isset($decoded['templatePath']) && $decoded['templatePath'] !== ''
                ? (string)$decoded['templatePath']
                : null;
        }

        return $model;
    }

    // Public Methods
    // =========================================================================

    /**
     * Validates that `$templatePath`, when set, resolves to a real site
     * Twig template. Save fails loudly on typos / missing files instead
     * of silently dispatching empty bodies at send time.
     *
     * Resolves under `View::TEMPLATE_MODE_SITE` — these are site
     * templates (admin-written, brand-owned), not CP-internal templates.
     *
     * Edition is not gated here. The Enterprise strip in
     * `NotificationTemplateController::actionSave()` nulls the value
     * before this rule runs on a non-Enterprise install, so the rule
     * only fires on Enterprise input. (Validating on every edition would
     * be fine too — the rule is correct in either gate — but the strip
     * order makes a Pro save with a crafted `templatePath` POST a no-op,
     * which is the desired defense-in-depth shape.)
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function validateTemplatePath(): void
    {
        if ($this->templatePath === null || $this->templatePath === '') {
            return;
        }

        $resolved = Craft::$app->getView()
            ->resolveTemplate($this->templatePath, View::TEMPLATE_MODE_SITE);

        if ($resolved === false) {
            $this->addError('templatePath', Craft::t(
                'password-policy',
                'Twig template not found at "{templatePath}".',
                ['templatePath' => $this->templatePath],
            ));
        }
    }

    /**
     * Returns the CP edit URL for this template (notification key + site).
     *
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getCpEditUrl(): string
    {
        return UrlHelper::cpUrl(
            "password-policy/notifications/{$this->notificationKey}",
            ['siteId' => $this->siteId],
        );
    }

    /**
     * Returns the editable content fields as an associative array suitable
     * for JSON-encoding into the `content` column.
     *
     * Sender override fields persist as `null` when empty so the runtime
     * fallback to system mailer defaults works without empty-string vs
     * null ambiguity.
     *
     * @return array<string, string|null>
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function toContentJson(): array
    {
        return [
            'subject' => $this->subject,
            'body' => $this->body,
            'senderName' => $this->senderName === '' ? null : $this->senderName,
            'senderEmail' => $this->senderEmail === '' ? null : $this->senderEmail,
            'replyTo' => $this->replyTo === '' ? null : $this->replyTo,
            'templatePath' => $this->templatePath === '' ? null : $this->templatePath,
        ];
    }

    // Protected Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected function defineRules(): array
    {
        return array_merge(parent::defineRules(), [
            [['notificationKey', 'subject', 'body'], 'required'],
            [['siteId'], 'required'],
            [['siteId'], 'integer'],
            [['notificationKey'], 'string', 'max' => 64],
            [['subject'], 'string', 'max' => 255],
            [['senderName'], 'string', 'max' => 255],
            [['senderEmail', 'replyTo'], 'email'],
            [['senderEmail', 'replyTo'], 'string', 'max' => 255],
            [['templatePath'], 'string', 'max' => 255],
            [['templatePath'], 'validateTemplatePath'],
        ]);
    }
}
