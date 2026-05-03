<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\elements\actions;

use Craft;
use craft\base\ElementAction;
use craft\elements\db\ElementQueryInterface;
use craft\helpers\Json;
use craft\helpers\UrlHelper;

/**
 * Class ChangeUserPassword
 *
 * Single-user element action that lets a permitted admin set another
 * user's password directly through a modal on the Users index. The modal
 * collects a new password + confirmation; the action's controller
 * (`UserPasswordController::actionChange()`) re-runs the per-user policy
 * via `User::EVENT_DEFINE_RULES`, sets the password through Craft's
 * standard `Elements::saveElement()` flow, and pins an explicit
 * `AuditContext::adminChange()` so the central history-write listener
 * records `changeReason = admin_change` + `changedByUserId =
 * <currentAdminId>` on the new history row. Capture is non-negotiable
 * across editions — every edition writes the audit context; gates apply
 * to UI/API/SIEM exposure downstream (memory rule
 * `project_audit_capture_principle.md`).
 *
 * Bulk-by-design *off*: setting the same password on N users is a
 * security anti-pattern (one leak compromises all). The action's
 * trigger HTML asserts `selectedItems.length === 1`; the controller
 * also rejects multi-id POSTs as a defense-in-depth check. Admins who
 * need to onboard many users at once should use
 * `SendPasswordResetEmail` (which is bulk-friendly) instead.
 *
 * Read-only mode: when `allowAdminChanges = false`, `getTriggerHtml()`
 * returns null so the action never appears in the index actions menu.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class ChangeUserPassword extends ElementAction
{
    // Public Methods
    // =========================================================================

    /**
     * Returns the action's trigger label.
     *
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getTriggerLabel(): string
    {
        return Craft::t('password-policy', 'Change password');
    }

    /**
     * Returns the trigger HTML rendered into the index actions menu.
     *
     * The JS-side `Craft.ElementActionTrigger` opens a small modal with
     * password + confirm fields and posts to the action's controller.
     * `validateSelection` rejects bulk selections so the modal only
     * surfaces when exactly one user is selected; the controller
     * separately rejects multi-id POSTs.
     *
     * Returns `null` when the host install is in read-only mode
     * (`allowAdminChanges = false`) so the action never registers on
     * the index — admins still see the row, but can't mutate.
     *
     * @return string|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getTriggerHtml(): ?string
    {
        if (!Craft::$app->getConfig()->getGeneral()->allowAdminChanges) {
            return null;
        }

        $type = Json::encode(static::class);
        $actionUrl = Json::encode(UrlHelper::actionUrl('password-policy/user-password/change'));
        $modalTitle = Json::encode(Craft::t('password-policy', 'Change password'));
        $newLabel = Json::encode(Craft::t('app', 'New Password'));
        $confirmLabel = Json::encode(Craft::t('password-policy', 'Confirm New Password'));
        $submitLabel = Json::encode(Craft::t('password-policy', 'Change password'));
        $cancelLabel = Json::encode(Craft::t('app', 'Cancel'));
        $genericError = Json::encode(Craft::t('password-policy', 'Couldn’t update password.'));

        // Modal opener — defined once per CP page render. Garnish is
        // already loaded on every CP page (CpAsset dependency); the
        // modal itself is a vanilla `Garnish.Modal` constructed from a
        // string of HTML, no separate template required.
        //
        // The modal posts as JSON. The controller responds via
        // `asJson()` — `{message, errors}` on failure (HTTP 400),
        // `{success, message}` on success. Post-success we close the
        // modal and notify the operator via Craft's flash mechanism
        // (Craft.cp.displayNotice).
        $js = <<<JS
(() => {
    Craft.PasswordPolicy = Craft.PasswordPolicy || {};

    // Define once — re-rendering the index re-runs this script, so
    // guard against redefining the helper on every render.
    if (!Craft.PasswordPolicy.openChangePasswordModal) {
        Craft.PasswordPolicy.openChangePasswordModal = function(options) {
            const html = ''
                + '<form class="modal pp-change-password-modal" method="post" accept-charset="UTF-8">'
                +   '<div class="body">'
                +     '<h2 class="first"></h2>'
                +     '<div class="field">'
                +       '<div class="heading"><label for="pp-change-newPassword"></label></div>'
                +       '<div class="input"><input type="password" id="pp-change-newPassword" name="newPassword" class="text fullwidth" autocomplete="new-password" /></div>'
                +     '</div>'
                +     '<div class="field">'
                +       '<div class="heading"><label for="pp-change-confirm"></label></div>'
                +       '<div class="input"><input type="password" id="pp-change-confirm" name="newPasswordConfirm" class="text fullwidth" autocomplete="new-password" /></div>'
                +     '</div>'
                +     '<div class="pp-errors errors" style="display:none;"></div>'
                +   '</div>'
                +   '<div class="footer">'
                +     '<div class="buttons right">'
                +       '<button type="button" class="btn pp-cancel"></button>'
                +       '<button type="submit" class="btn submit"></button>'
                +     '</div>'
                +   '</div>'
                + '</form>';
            const \$form = \$(html);
            \$form.find('h2.first').text(options.modalTitle);
            \$form.find('label[for=pp-change-newPassword]').text(options.newLabel);
            \$form.find('label[for=pp-change-confirm]').text(options.confirmLabel);
            \$form.find('button.submit').text(options.submitLabel);
            \$form.find('button.pp-cancel').text(options.cancelLabel);
            const modal = new Garnish.Modal(\$form, { resizable: false });
            \$form.find('button.pp-cancel').on('click', () => modal.hide());
            \$form.on('submit', (ev) => {
                ev.preventDefault();
                const data = {
                    userId: options.userId,
                    newPassword: \$form.find('[name=newPassword]').val(),
                    newPasswordConfirm: \$form.find('[name=newPasswordConfirm]').val(),
                };
                Craft.sendActionRequest('POST', options.actionUrl, { data: data })
                    .then((response) => {
                        modal.hide();
                        if (Craft.cp && typeof Craft.cp.displayNotice === 'function') {
                            Craft.cp.displayNotice(response.data.message || options.successFallback);
                        }
                    })
                    .catch((err) => {
                        const data = err && err.response && err.response.data ? err.response.data : {};
                        const errs = data.errors || {};
                        const messages = [];
                        for (const key of Object.keys(errs)) {
                            const v = errs[key];
                            if (Array.isArray(v)) {
                                messages.push(...v);
                            } else if (typeof v === 'string') {
                                messages.push(v);
                            }
                        }
                        const \$err = \$form.find('.pp-errors');
                        \$err.empty();
                        if (messages.length) {
                            for (const m of messages) {
                                \$err.append(\$('<p>').text(m));
                            }
                        } else {
                            \$err.append(\$('<p>').text(data.message || options.genericError));
                        }
                        \$err.show();
                    });
            });
        };
    }

    new Craft.ElementActionTrigger({
        type: $type,
        bulk: false,
        validateSelection: (selectedItems) => selectedItems.length === 1,
        activate: (selectedItems) => {
            const userId = selectedItems.eq(0).find('.element').data('id');
            if (!userId) {
                return;
            }
            Craft.PasswordPolicy.openChangePasswordModal({
                userId: userId,
                actionUrl: $actionUrl,
                modalTitle: $modalTitle,
                newLabel: $newLabel,
                confirmLabel: $confirmLabel,
                submitLabel: $submitLabel,
                cancelLabel: $cancelLabel,
                genericError: $genericError,
            });
        },
    });
})();
JS;

        Craft::$app->getView()->registerJs($js);

        return null;
    }

    /**
     * Performs the action.
     *
     * The action's user-facing flow runs entirely through the modal +
     * controller seam — `Craft.PasswordPolicy.openChangePasswordModal()`
     * collects the new password and POSTs to the controller, which
     * does the actual save. This `performAction()` exists only to
     * satisfy `ElementAction`'s abstract contract for the (rare) path
     * where Craft invokes the action without going through the trigger.
     * It rejects every such call: there's no UX path that would land
     * here, and silently no-oping would be misleading.
     *
     * @param ElementQueryInterface $query
     * @return bool always false — see method description
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function performAction(ElementQueryInterface $query): bool
    {
        $this->setMessage(Craft::t(
            'password-policy',
            'Change password is a single-user action — use the modal trigger from the index.',
        ));

        return false;
    }
}
