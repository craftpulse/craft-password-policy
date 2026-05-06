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
use craft\web\View;

/**
 * Class ChangeUserPassword
 *
 * Single-user element action that lets a permitted admin set another
 * user's password directly through a modal. The modal collects a new
 * password + confirmation; the action's controller
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
 * security anti-pattern (one leak compromises all). The action is no
 * longer registered on the Users index bulk-action menu — only on the
 * per-user edit screen action menu via
 * `Element::EVENT_DEFINE_ACTION_MENU_ITEMS`. The controller also
 * rejects multi-id POSTs as defense-in-depth. Admins who need to
 * onboard many users at once should use `SendPasswordResetEmail`
 * (which is bulk-friendly).
 *
 * Read-only mode: when `allowAdminChanges = false`, the action menu
 * listener short-circuits before registering the trigger so the modal
 * never surfaces.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class ChangeUserPassword extends ElementAction
{
    // Static Methods
    // =========================================================================

    /**
     * Registers the `Craft.PasswordPolicy.openChangePasswordModal(options)`
     * JS helper on the active CP view. Idempotent — guarded by an
     * `if (!Craft.PasswordPolicy.openChangePasswordModal)` check on the
     * client side so re-registration across surface reloads doesn't
     * stack handlers. Called by both this action's `getTriggerHtml()`
     * (for any future bulk re-registration) and the per-user action
     * menu listener in `PasswordPolicy::_registerUserEditActionMenu()`.
     *
     * The modal posts as JSON. The controller responds via `asJson()` —
     * `{message, errors}` on failure (HTTP 400), `{success, message}`
     * on success. Post-success we close the modal and notify the
     * operator via Craft's flash mechanism (`Craft.cp.displayNotice`).
     *
     * @param View $view
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function registerModalHelper(View $view): void
    {
        $js = <<<JS
(() => {
    Craft.PasswordPolicy = Craft.PasswordPolicy || {};

    if (Craft.PasswordPolicy.openChangePasswordModal) {
        return;
    }

    // Inner opener — opens the styled modal. Always invoked through
    // the public wrapper below so callers don't have to worry about
    // elevated-session re-auth themselves.
    const _open = function(options) {
        const html = ''
            + '<form class="modal pp-change-password-modal fitted" method="post" accept-charset="UTF-8" style="width: 480px;">'
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
        // Wire the show/hide-eye affordance Craft uses on every CP
        // password input — keeps the modal consistent with the
        // standard "Change your Password" pane on the My Account
        // screen.
        new Craft.PasswordInput('#pp-change-newPassword');
        new Craft.PasswordInput('#pp-change-confirm');
        // Initial focus — the operator landed here ready to type.
        setTimeout(() => \$form.find('#pp-change-newPassword').trigger('focus'), 0);
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

    // Public wrapper — gates modal-open behind an elevated-session
    // re-auth so the operator doesn't type a new password into a form
    // that's about to bounce them to the elevation prompt anyway.
    // The controller's `beforeAction()` enforces the same gate
    // server-side regardless.
    Craft.PasswordPolicy.openChangePasswordModal = function(options) {
        Craft.elevatedSessionManager.requireElevatedSession(() => _open(options));
    };
})();
JS;

        $view->registerJs($js);
    }

    /**
     * Returns the JSON-encoded label bag the modal helper consumes.
     * Single source of truth shared between any caller that opens the
     * modal — keeps surface-specific call sites from drifting on
     * label keys.
     *
     * @return array<string, string> JSON-encoded values keyed by option name
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public static function modalLabels(): array
    {
        return [
            'actionUrl' => Json::encode(UrlHelper::actionUrl('password-policy/user-password/change')),
            'modalTitle' => Json::encode(Craft::t('password-policy', 'Change password')),
            'newLabel' => Json::encode(Craft::t('app', 'New Password')),
            'confirmLabel' => Json::encode(Craft::t('password-policy', 'Confirm New Password')),
            'submitLabel' => Json::encode(Craft::t('password-policy', 'Change password')),
            'cancelLabel' => Json::encode(Craft::t('app', 'Cancel')),
            'genericError' => Json::encode(Craft::t('password-policy', 'Couldn’t update password.')),
        ];
    }

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
     * Performs the action.
     *
     * The action's user-facing flow runs entirely through the modal +
     * controller seam — `Craft.PasswordPolicy.openChangePasswordModal()`
     * (registered by `_registerUserEditActionMenu()`) collects the
     * new password and POSTs to the controller, which does the actual
     * save. This `performAction()` exists only to satisfy
     * `ElementAction`'s abstract contract for the (rare) path where
     * Craft invokes the action without going through the menu trigger.
     * It rejects every such call: there's no UX path that would land
     * here (the action class is intentionally NOT registered on
     * `User::EVENT_REGISTER_ACTIONS`), and silently no-oping would be
     * misleading.
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
