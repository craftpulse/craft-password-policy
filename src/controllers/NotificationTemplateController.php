<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\controllers;

use Craft;
use craft\elements\User;
use craft\helpers\Json;
use craft\helpers\StringHelper;
use craft\helpers\UrlHelper;
use craft\web\assets\admintable\AdminTableAsset;
use craft\web\Controller;
use craftpulse\passwordpolicy\data\EmailDefaults;
use craftpulse\passwordpolicy\models\NotificationTemplateModel;
use craftpulse\passwordpolicy\PasswordPolicy;
use DateTime;
use Throwable;
use yii\web\BadRequestHttpException;
use yii\web\ForbiddenHttpException;
use yii\web\NotFoundHttpException;
use yii\web\Response;

/**
 * Class NotificationTemplateController
 *
 * Handles CRUD + test-send for the editable per-(notificationKey, siteId)
 * email templates. Pro-gated (403 on Lite). Permission-gated on
 * `pp:notification-templates-manage`.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class NotificationTemplateController extends Controller
{
    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @throws ForbiddenHttpException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function beforeAction($action): bool
    {
        if (!parent::beforeAction($action)) {
            return false;
        }

        $this->requireCpRequest();

        if (!PasswordPolicy::$plugin->getIsPro()) {
            throw new ForbiddenHttpException('Email notification templates require the Pro edition.');
        }

        $this->requirePermission('pp:notification-templates-manage');

        return true;
    }

    /**
     * Renders the notifications index — one row per notification key, with
     * primary-site subject + a count of sites whose content diverges from
     * the primary site's row.
     *
     * @return Response
     *
     * @throws Throwable
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionIndex(): Response
    {
        $service = PasswordPolicy::$plugin->getNotificationTemplates();
        $primarySiteId = Craft::$app->getSites()->getPrimarySite()->id;
        $totalSites = count(Craft::$app->getSites()->getAllSites());

        $rows = [];
        foreach (array_keys(EmailDefaults::all()) as $key) {
            $primary = $service->getTemplate($key, $primarySiteId);
            $allForKey = $service->getAllForKey($key);

            $primaryContentJson = $primary !== null
                ? Json::encode($primary->toContentJson())
                : null;

            $overrides = 0;
            foreach ($allForKey as $template) {
                if ($template->siteId === $primarySiteId) {
                    continue;
                }
                if (Json::encode($template->toContentJson()) !== $primaryContentJson) {
                    $overrides++;
                }
            }

            $rows[] = [
                'key' => $key,
                'name' => $this->_displayNameForKey($key),
                'subject' => $primary?->subject ?? '',
                'overrides' => $overrides,
                'totalOtherSites' => max(0, $totalSites - 1),
            ];
        }

        // P3-09 — `AdminTableAsset` registers here so the controller
        // owns the bundle dependency (was inline in the template).
        Craft::$app->getView()->registerAssetBundle(AdminTableAsset::class);

        // Breadcrumbs back to the plugin landing — P2-08. Match the
        // shape used by `SiemForwarderController` /
        // `WebhookEndpointController` so every CP index in the
        // password-policy surface roots back to the same landing
        // crumb.
        $pluginName = 'Password Policy';
        return $this->renderTemplate('password-policy/_notifications/_index', [
            'rows' => $rows,
            'crumbs' => [
                [
                    'label' => $pluginName,
                    'url' => UrlHelper::cpUrl('password-policy'),
                ],
            ],
        ]);
    }

    /**
     * Renders the per-(key, site) edit screen using `asCpScreen()`.
     *
     * @param string $key the notification key
     * @param int|null $siteId target site (defaults to primary)
     * @param NotificationTemplateModel|null $template route-injected by asModelFailure
     * @return Response
     *
     * @throws ForbiddenHttpException
     * @throws NotFoundHttpException
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionEdit(string $key, ?int $siteId = null, ?NotificationTemplateModel $template = null): Response
    {
        if (!isset(EmailDefaults::all()[$key])) {
            // Log the attacker-controlled value to the plugin log channel
            // (operationally useful for spotting crafted URLs) while
            // returning the generic 404 message to the client. Same
            // shape used by `actionSave()` / `actionTestSend()`.
            Craft::warning(
                "NotificationTemplate: unknown notification key requested (key={$key})",
                'password-policy',
            );
            throw new NotFoundHttpException();
        }

        $sites = Craft::$app->getSites()->getAllSites();
        $primarySiteId = Craft::$app->getSites()->getPrimarySite()->id;
        $siteId = $siteId ?? $primarySiteId;

        // Confirm the target site exists / is enabled.
        $targetSite = Craft::$app->getSites()->getSiteById($siteId);
        if ($targetSite === null) {
            Craft::warning(
                "NotificationTemplate: unknown site requested (siteId={$siteId})",
                'password-policy',
            );
            throw new NotFoundHttpException();
        }

        $service = PasswordPolicy::$plugin->getNotificationTemplates();

        if ($template === null) {
            $template = $service->getTemplate($key, $siteId);

            if ($template === null) {
                // Defensive: row was deleted out of band. Hydrate from defaults
                // so the admin can save and re-create the row.
                $template = $this->_seedDefaultsModel($key, $siteId);
            }
        }

        $tokens = [
            '{{ user.friendlyName }}',
            '{{ user.username }}',
            '{{ user.email }}',
            '{{ daysUntilExpiry }}',
            '{{ siteName }}',
        ];

        // Mirror the `SettingsController` read-only convention so the
        // template fields and test-send affordance render disabled when
        // `allowAdminChanges` is off. `actionSave()` and `actionTestSend()`
        // already enforce a 403 server-side — this is the visible-affordance
        // half of the read-only contract.
        $readOnly = !Craft::$app->getConfig()->getGeneral()->allowAdminChanges;

        return $this->asCpScreen()
            ->title($this->_displayNameForKey($key))
            ->selectedSubnavItem('notifications')
            ->addCrumb(
                Craft::t('password-policy', 'Password Policy'),
                'password-policy',
            )
            ->addCrumb(
                Craft::t('password-policy', 'Notifications'),
                'password-policy/notifications',
            )
            ->action("password-policy/notifications/$key/save")
            ->redirectUrl("password-policy/notifications/$key?siteId=$siteId")
            ->tabs([
                'general' => [
                    'label' => Craft::t('password-policy', 'General'),
                    'url' => '#general',
                ],
                'advanced' => [
                    'label' => Craft::t('password-policy', 'Advanced'),
                    'url' => '#advanced',
                ],
            ])
            ->contentTemplate('password-policy/_notifications/_edit', [
                'template' => $template,
                'key' => $key,
                'sites' => $sites,
                'currentSite' => $targetSite,
                'primarySiteId' => $primarySiteId,
                'tokens' => $tokens,
                'displayName' => $this->_displayNameForKey($key),
                'readOnly' => $readOnly,
            ]);
    }

    /**
     * Saves a template from POST.
     *
     * @return Response|null
     *
     * @throws BadRequestHttpException
     * @throws ForbiddenHttpException
     * @throws NotFoundHttpException
     * @throws Throwable
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionSave(): ?Response
    {
        $this->requirePostRequest();

        // Mirror `SettingsController::actionSave` — when admin changes
        // are disabled (typical production posture), the entire write
        // surface is off, regardless of the user's plugin permissions.
        $general = Craft::$app->getConfig()->getGeneral();
        if (!$general->allowAdminChanges) {
            throw new ForbiddenHttpException(
                'Unable to edit notification templates because admin changes are disabled in this environment.',
            );
        }

        $request = Craft::$app->getRequest();
        $key = (string)$request->getRequiredBodyParam('notificationKey');
        $siteId = (int)$request->getRequiredBodyParam('siteId');

        if (!isset(EmailDefaults::all()[$key])) {
            Craft::warning(
                "NotificationTemplate: unknown notification key on save (key={$key})",
                'password-policy',
            );
            throw new BadRequestHttpException();
        }

        if (Craft::$app->getSites()->getSiteById($siteId) === null) {
            Craft::warning(
                "NotificationTemplate: unknown site on save (siteId={$siteId})",
                'password-policy',
            );
            throw new NotFoundHttpException();
        }

        $service = PasswordPolicy::$plugin->getNotificationTemplates();
        $template = $service->getTemplate($key, $siteId)
            ?? $this->_seedDefaultsModel($key, $siteId);

        $template->subject = (string)$request->getBodyParam('subject', '');
        $template->body = (string)$request->getBodyParam('body', '');
        $template->senderName = $this->_nullable($request->getBodyParam('senderName'));
        $template->senderEmail = $this->_nullable($request->getBodyParam('senderEmail'));
        $template->replyTo = $this->_nullable($request->getBodyParam('replyTo'));

        // G11 — custom Twig template path is Enterprise-only. The CP UI
        // renders the field disabled on Lite/Pro, but a crafted POST
        // could still carry the param. Strip unconditionally when the
        // plugin isn't running Enterprise. Defense-in-depth: log a
        // warning when a value was stripped so operators can spot the
        // crafted-POST signal.
        $template->templatePath = $this->_nullable($request->getBodyParam('templatePath'));
        if (!PasswordPolicy::$plugin->getIsEnterprise() && $template->templatePath !== null) {
            Craft::warning(
                "Stripped templatePath from notification template save on non-Enterprise edition (key={$template->notificationKey}, siteId={$template->siteId})",
                'password-policy',
            );
            $template->templatePath = null;
        }

        if (!$service->saveTemplate($template)) {
            return $this->asModelFailure(
                $template,
                Craft::t('password-policy', "Couldn't save notification template."),
                'template',
            );
        }

        return $this->asModelSuccess(
            $template,
            Craft::t('password-policy', 'Notification template saved.'),
            'template',
        );
    }

    /**
     * Renders the template against a per-key sample render context (see
     * `_sampleVarsForKey()`) and sends through the real mailer pipeline.
     *
     * The sample context is switched on the notification key so each
     * template's tokens resolve — `strict_variables` is ON in devMode, so
     * a fixed context that omitted a key's tokens (e.g. `detectedAt`,
     * `deviceLabel`, `event`) would throw "Variable does not exist" and the
     * test-send would always fail in dev. Rendering runs once via
     * `composeFromTemplate()`'s out-param, inside the try/catch, so a broken
     * admin-edited template returns friendly JSON instead of a 500.
     *
     * Returns JSON for the inline test-send panel: success or failure
     * with the rendered subject + a body excerpt for visual confirmation.
     *
     * @return Response
     *
     * @throws BadRequestHttpException
     * @throws Throwable
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionTestSend(): Response
    {
        $this->requirePostRequest();
        $this->requireAcceptsJson();

        // Test-send mutates nothing in the DB but the UX intent matches
        // `actionSave()` — when admin changes are disabled, the entire
        // write/test surface is off.
        $general = Craft::$app->getConfig()->getGeneral();
        if (!$general->allowAdminChanges) {
            throw new ForbiddenHttpException(
                'Unable to test notification templates because admin changes are disabled in this environment.',
            );
        }

        $request = Craft::$app->getRequest();
        $key = (string)$request->getRequiredBodyParam('notificationKey');
        $siteId = (int)$request->getRequiredBodyParam('siteId');

        if (!isset(EmailDefaults::all()[$key])) {
            Craft::warning(
                "NotificationTemplate: unknown notification key on test-send (key={$key})",
                'password-policy',
            );
            throw new BadRequestHttpException();
        }

        $admin = Craft::$app->getUser()->getIdentity();
        if ($admin === null || $admin->email === null) {
            return $this->asJson([
                'success' => false,
                'message' => Craft::t('password-policy', 'Could not resolve a recipient email for the current user.'),
            ]);
        }

        $service = PasswordPolicy::$plugin->getNotificationTemplates();
        $template = $service->getTemplate($key, $siteId)
            ?? $this->_seedDefaultsModel($key, $siteId);

        // Use posted subject/body so the admin can test edits *before* saving.
        $previewSubject = (string)$request->getBodyParam('subject', $template->subject);
        $previewBody = (string)$request->getBodyParam('body', $template->body);
        $template->subject = $previewSubject;
        $template->body = $previewBody;

        // G11 — strip a posted templatePath on non-Enterprise editions so a
        // crafted POST can't reach the Twig-file renderer. On Enterprise we
        // still honour the saved DB value (admins testing existing config);
        // a fresh value typed into a disabled field has no field on this AJAX
        // surface anyway — kept as defense-in-depth.
        $postedTemplatePath = $this->_nullable($request->getBodyParam('templatePath'));
        if (!PasswordPolicy::$plugin->getIsEnterprise()) {
            if ($postedTemplatePath !== null) {
                Craft::warning(
                    "Stripped templatePath from notification test-send on non-Enterprise edition (key={$key}, siteId={$siteId})",
                    'password-policy',
                );
            }
            $template->templatePath = null;
        } elseif ($postedTemplatePath !== null) {
            $template->templatePath = $postedTemplatePath;
        }

        $site = Craft::$app->getSites()->getSiteById($siteId);
        $siteName = $site?->getName() ?? Craft::$app->getSystemName();

        // Build a per-key sample-var context. Every notification key
        // references a different set of Twig tokens (breach-detected →
        // `detectedAt`; new-device-alert → `deviceLabel` / `maskedIp`;
        // admin-security-alert → `event` / `context` and NO `user`). Craft
        // renders templates with `strict_variables` ON in devMode, so a
        // fixed context that omits a key's tokens throws an "undefined
        // variable" error — the test-send would always fail in dev. The
        // sample map mirrors the real `_dispatch()` render context per key.
        $vars = $this->_sampleVarsForKey($key, $admin, $siteName);

        // Admin-recipient templates (admin-security-alert) omit the `user`
        // var — the recipient is the operator, not an end-user. Pass the
        // sample user through only when the per-key context includes it.
        $renderUser = ($vars['user'] ?? null) instanceof User ? $vars['user'] : null;

        // Capture the rendered subject + body via `composeFromTemplate()`'s
        // out-param so we render Twig exactly once and reuse the strings for
        // the JSON response. Rendering happens inside the try/catch — a
        // broken admin-edited template throws here, and previously the
        // separate post-send `renderString()` calls (outside the catch)
        // would 500 the request instead of returning the friendly JSON.
        $rendered = [];

        try {
            $message = PasswordPolicy::$plugin->getNotification()
                ->composeFromTemplate($template, $renderUser, $vars, $rendered);
            $message->setTo($admin->email)->send();
        } catch (Throwable $e) {
            // Don't leak the underlying exception message to the client
            // — `$e->getMessage()` can carry mailer transport details
            // (SMTP host, auth failures, internal paths from a Twig
            // render error). Operators get the full message via the
            // plugin log channel; the client gets a static breadcrumb
            // pointing them at the log.
            Craft::error(
                "Test-send failed: " . $e->getMessage(),
                'password-policy',
            );
            return $this->asJson([
                'success' => false,
                'message' => Craft::t(
                    'password-policy',
                    'Send failed — see the password-policy log for details.',
                ),
            ]);
        }

        $renderedSubject = $rendered['subject'] ?? $previewSubject;
        $renderedBody = $rendered['body'] ?? $previewBody;

        return $this->asJson([
            'success' => true,
            'message' => Craft::t('password-policy', 'Test email sent to {email}.', [
                'email' => $admin->email,
            ]),
            'renderedSubject' => $renderedSubject,
            'renderedBodyExcerpt' => StringHelper::truncate($renderedBody, 240, '…'),
        ]);
    }

    // Private Methods
    // =========================================================================

    /**
     * Returns the human-readable display name for a notification key.
     *
     * @param string $key
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _displayNameForKey(string $key): string
    {
        return match ($key) {
            'expiry-reminder' => Craft::t('password-policy', 'Password expiry reminder'),
            default => StringHelper::titleize(str_replace('-', ' ', $key)),
        };
    }

    /**
     * Builds the sample Twig render context for a test-send of the given
     * notification key.
     *
     * Each key references a distinct set of tokens, and Craft renders with
     * `strict_variables` ON in devMode — a context that omits a referenced
     * token throws "Variable does not exist". The map mirrors the real
     * `NotificationService::_dispatch()` context per key: user-scoped keys
     * include `{{ user }}`; the admin-security-alert key omits `{{ user }}`
     * (the recipient is the operator, not an end-user) and instead provides
     * `event` + an iterable `context`.
     *
     * @param string $key the notification key
     * @param User $admin the current admin user (used as the sample recipient)
     * @param string $siteName resolved site name for the `{{ siteName }}` token
     * @return array<string, mixed>
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _sampleVarsForKey(string $key, User $admin, string $siteName): array
    {
        $base = ['siteName' => $siteName];

        return match ($key) {
            'breach-detected' => $base + [
                'user' => $admin,
                'detectedAt' => new DateTime('now'),
            ],
            'new-device-alert' => $base + [
                'user' => $admin,
                'deviceLabel' => 'Chrome on macOS',
                'maskedIp' => '192.168.x.x',
            ],
            'admin-security-alert' => $base + [
                // Admin-recipient template — no `{{ user }}` token. Provide
                // a sample event + iterable context matching the default body.
                'event' => 'breach_detected',
                'context' => ['userId' => 7, 'email' => 'compromised@example.test'],
            ],
            // expiry-reminder (and any future user-scoped key) — `user` +
            // `daysUntilExpiry` matching the seeded default template.
            default => $base + [
                'user' => $admin,
                'daysUntilExpiry' => 7,
            ],
        };
    }

    /**
     * Hydrates a fresh model from EmailDefaults — used as a defensive
     * fallback when the underlying row is missing for an admin who clicked
     * straight to a per-site edit URL.
     *
     * @param string $key
     * @param int $siteId
     * @return NotificationTemplateModel
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _seedDefaultsModel(string $key, int $siteId): NotificationTemplateModel
    {
        $factory = EmailDefaults::all()[$key];
        $defaults = call_user_func($factory);

        $model = new NotificationTemplateModel();
        $model->notificationKey = $key;
        $model->siteId = $siteId;
        $model->subject = (string)($defaults['subject'] ?? '');
        $model->body = (string)($defaults['body'] ?? '');
        $model->senderName = $defaults['senderName'] ?? null;
        $model->senderEmail = $defaults['senderEmail'] ?? null;
        $model->replyTo = $defaults['replyTo'] ?? null;

        return $model;
    }

    /**
     * Trims a posted string and returns null when empty.
     *
     * @param mixed $value
     * @return string|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _nullable(mixed $value): ?string
    {
        if (!is_string($value)) {
            return null;
        }

        $trimmed = trim($value);
        return $trimmed === '' ? null : $trimmed;
    }
}
