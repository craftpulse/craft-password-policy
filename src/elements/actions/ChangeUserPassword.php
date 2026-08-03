<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\elements\actions;

use Craft;
use craft\base\ElementAction;
use craft\elements\db\ElementQueryInterface;
use craft\helpers\Json;
use craft\helpers\UrlHelper;
use craft\web\View;
use craftpulse\passwordpolicy\helpers\PasswordFieldHelper;

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
        // Inline CSS for the eye-toggle affordance. Mirrors the
        // `.pp-password-field` / `.pp-toggle-visibility` styling shipped by
        // the front-end client asset (`passwordpolicyclient/password-policy
        // .css`); duplicated here because the front-end asset isn't
        // registered on CP pages and we want a self-contained modal. ~30
        // lines, keep in sync with the front-end CSS if either side changes.
        $view->registerCss(<<<CSS
.pp-change-password-modal .pp-password-field {
    position: relative;
    display: block;
}
.pp-change-password-modal .pp-password-field input[type="password"],
.pp-change-password-modal .pp-password-field input[type="text"] {
    padding-right: 2.5rem;
    width: 100%;
    box-sizing: border-box;
}
.pp-change-password-modal .pp-toggle-visibility {
    position: absolute;
    right: 0.5rem;
    top: 50%;
    transform: translateY(-50%);
    background: transparent;
    border: 0;
    padding: 0.25rem;
    cursor: pointer;
    color: currentColor;
    opacity: 0.6;
}
.pp-change-password-modal .pp-toggle-visibility:hover,
.pp-change-password-modal .pp-toggle-visibility:focus {
    opacity: 1;
}
CSS, [], 'pp-change-password-modal-css');

        // Eye affordance markup — sourced from the shared
        // `PasswordFieldHelper` so the modal and the front-end Pro
        // builders render the identical FontAwesome eye / eye-slash
        // glyph from one place (no drift). JSON-encoded for safe
        // embedding as a JS string literal in the heredoc below.
        $eyeSvgJs = Json::encode(PasswordFieldHelper::eyeToggleSvg());

        $js = <<<JS
(() => {
    Craft.PasswordPolicy = Craft.PasswordPolicy || {};

    if (Craft.PasswordPolicy.openChangePasswordModal) {
        return;
    }

    // Shared eye affordance — two FA glyph <svg> elements (open eye +
    // eye-slash, slash hidden) sourced from PasswordFieldHelper and
    // JSON-encoded in PHP, so it lands here as a safe JS string literal.
    const eyeSvg = {$eyeSvgJs};

    /**
     * Binds the show/hide-eye toggle to a single password input within
     * the modal. Mirrors the front-end client asset's `bindToggle()`
     * behavior (`passwordpolicyclient/password-policy.js`) so the CP
     * modal and the Pro front-end builders surface the same affordance.
     *
     * The initial `aria-label` is set HERE via `setAttribute` rather than
     * baked into the field markup string — i18n labels must never be
     * concatenated into an HTML attribute value (a translation carrying
     * `">` would be an injection vector). `setAttribute` is escape-safe.
     */
    const bindEyeToggle = function(\$container, inputId, showLabel, hideLabel) {
        const input = \$container.find('#' + inputId)[0];
        const button = \$container.find('button[data-pp-toggle-visibility="' + inputId + '"]')[0];
        if (!input || !button) return;
        button.setAttribute('aria-label', showLabel);
        button.addEventListener('click', function(ev) {
            ev.preventDefault();
            const isPassword = input.type === 'password';
            input.type = isPassword ? 'text' : 'password';
            button.setAttribute('aria-label', isPassword ? hideLabel : showLabel);
            const open = button.querySelector('.pp-eye-open');
            const slash = button.querySelector('.pp-eye-slash');
            if (open && slash) {
                open.style.display = isPassword ? 'none' : '';
                slash.style.display = isPassword ? '' : 'none';
            }
        });
    };

    // Inner opener — opens the styled modal. Always invoked through
    // the public wrapper below so callers don't have to worry about
    // elevated-session re-auth themselves.
    const _open = function(options, triggerElement) {
        // No aria-label in the markup string — bindEyeToggle sets it via
        // setAttribute (escape-safe). See bindEyeToggle's docblock.
        const newField = ''
            + '<div class="pp-password-field" data-pp-field="pp-change-newPassword">'
            +   '<input type="password" id="pp-change-newPassword" name="newPassword" class="text fullwidth" autocomplete="new-password" />'
            +   '<button type="button" class="pp-toggle-visibility" data-pp-toggle-visibility="pp-change-newPassword">' + eyeSvg + '</button>'
            + '</div>';
        const confirmField = ''
            + '<div class="pp-password-field" data-pp-field="pp-change-confirm">'
            +   '<input type="password" id="pp-change-confirm" name="newPasswordConfirm" class="text fullwidth" autocomplete="new-password" />'
            +   '<button type="button" class="pp-toggle-visibility" data-pp-toggle-visibility="pp-change-confirm">' + eyeSvg + '</button>'
            + '</div>';
        const html = ''
            + '<form class="modal pp-change-password-modal fitted" method="post" accept-charset="UTF-8" style="width: 480px;">'
            +   '<div class="body">'
            +     '<h2 class="first"></h2>'
            +     '<div class="field">'
            +       '<div class="heading"><label for="pp-change-newPassword"></label></div>'
            +       '<div class="input">' + newField + '</div>'
            +     '</div>'
            +     '<div class="field">'
            +       '<div class="heading"><label for="pp-change-confirm"></label></div>'
            +       '<div class="input">' + confirmField + '</div>'
            +     '</div>'
            +     '<ul class="pp-errors errors" style="display:none;"></ul>'
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
        // `triggerElement` — Garnish returns focus here on hide (Cancel or
        // successful submit), so the operator lands back on the control
        // they opened the modal from instead of document.body. Captured
        // in the public wrapper BEFORE the elevated-session hop, because
        // the re-auth prompt can move focus before `_open` runs. Garnish
        // auto-captures the focused element when none is passed, but that
        // would be stale after elevation — so we pass it explicitly.
        const modal = new Garnish.Modal(\$form, { resizable: false, triggerElement: triggerElement || null });
        // Eye-toggle affordance — replaces Craft's default `new
        // Craft.PasswordInput()` "Show" text widget with the same
        // SVG eye the plugin's front-end Pro builders surface. The
        // strength meter on the new-password input is bound by the
        // CP-side indicator.ts MutationObserver — no extra wiring
        // needed here.
        bindEyeToggle(\$form, 'pp-change-newPassword', options.showLabel, options.hideLabel);
        bindEyeToggle(\$form, 'pp-change-confirm', options.showLabel, options.hideLabel);
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
                    // Craft's `.errors` CSS styles `<ul class="errors"><li>`
                    // markup (red list with marker). Plain `<p>` children skip
                    // the styling entirely — caught during the 5.2.0 Phase H
                    // smoke walk. Use the canonical pattern so error messages
                    // pick up Craft's standard CP error treatment.
                    const \$err = \$form.find('.pp-errors');
                    \$err.empty();
                    if (messages.length) {
                        for (const m of messages) {
                            \$err.append(\$('<li>').text(m));
                        }
                    } else {
                        \$err.append(\$('<li>').text(data.message || options.genericError));
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
        // Capture the trigger NOW, before the elevation prompt can steal
        // focus — so the modal can hand focus back to it on close.
        const triggerElement = document.activeElement;
        Craft.elevatedSessionManager.requireElevatedSession(() => _open(options, triggerElement));
    };
})();
JS;

        $view->registerJs($js, View::POS_READY, 'pp-change-password-modal-js');
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
            'showLabel' => Json::encode(Craft::t('password-policy', 'Show password')),
            'hideLabel' => Json::encode(Craft::t('password-policy', 'Hide password')),
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
            'Change password is a single-user action. Use the modal trigger from the index.',
        ));

        return false;
    }
}
