<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\twig\tags;

use Craft;
use craft\helpers\Html;

/**
 * Class PasswordChangeFormTag
 *
 * Renders a `<form>` for a logged-in user to change their password.
 * Three fields: current password (required), new password (validated), confirm.
 * POSTs to `password-policy/front/password-change/save`.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class PasswordChangeFormTag extends BaseTag
{
    // Public Methods
    // =========================================================================

    /**
     * @param array<string, mixed> $attrs
     * @return $this
     */
    public function formAttrs(array $attrs): self
    {
        $this->config['formAttrs'] = $attrs;
        return $this;
    }

    /**
     * @param array<string, mixed> $attrs
     * @return $this
     */
    public function submitButtonAttrs(array $attrs): self
    {
        $this->config['submitButtonAttrs'] = $attrs;
        return $this;
    }

    /**
     * @param string $label
     * @return $this
     */
    public function submitLabel(string $label): self
    {
        $this->config['submitLabel'] = $label;
        return $this;
    }

    /**
     * @param string $url
     * @return $this
     */
    public function successRedirect(string $url): self
    {
        $this->config['successRedirect'] = $url;
        return $this;
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected function _renderHtml(): string
    {
        $formAttrs = array_merge([
            'method' => 'post',
            'action' => '',
            'class' => 'pp-form pp-change-form',
            'novalidate' => true,
        ], (array)($this->config['formAttrs'] ?? []));

        $submitAttrs = array_merge([
            'type' => 'submit',
            'class' => 'pp-submit',
            'id' => 'pp-change-submit',
        ], (array)($this->config['submitButtonAttrs'] ?? []));

        $submitLabel = (string)($this->config['submitLabel'] ?? Craft::t('app', 'Update password'));

        // Per-field error map flashed by `PasswordChangeController::_failure()`
        // on the previous (failed) request. Single channel — the user's own
        // error map under `pp:errors`.
        $errors = $this->_flashedErrors();

        $output = '<form' . $this->_renderAttrs($formAttrs) . '>';
        $output .= Html::hiddenInput('action', 'password-policy/front/password-change/save');
        $output .= Html::csrfInput();

        if (!empty($this->config['successRedirect'])) {
            $output .= Html::hiddenInput(
                'redirect',
                Craft::$app->getSecurity()->hashData((string)$this->config['successRedirect']),
            );
        }

        // Error summary — `role="alert"` + `aria-live="assertive"` so a
        // screen reader announces it on the re-rendered form (WCAG 3.3.1
        // Error Identification, 4.1.3 Status Messages). The container is
        // always present in the DOM so dynamic injection (if a consumer
        // wires AJAX submit) is announced too; it's only populated when
        // there are errors to report.
        $output .= $this->_renderErrorSummary($errors);

        // Current password
        $output .= $this->_renderField(
            'currentPassword',
            'pp-current-password',
            Craft::t('password-policy', 'Current password'),
            'current-password',
            $errors,
            ['liveValidation' => false],
        );

        // New password — full live validation
        $output .= $this->_renderField(
            'newPassword',
            'pp-new-password',
            Craft::t('password-policy', 'New password'),
            'new-password',
            $errors,
            [
                'liveValidation' => true,
                'submitGate' => '#' . $submitAttrs['id'],
            ],
        );

        // Confirm
        $output .= $this->_renderField(
            'newPasswordConfirm',
            'pp-new-password-confirm',
            Craft::t('password-policy', 'Confirm new password'),
            'new-password',
            $errors,
            ['liveValidation' => false],
        );

        $output .= '<button' . $this->_renderAttrs($submitAttrs) . '>' . Html::encode($submitLabel) . '</button>';

        $output .= '</form>';

        return $output;
    }

    // Protected Methods
    // =========================================================================

    /**
     * Returns the per-field error map flashed by
     * `PasswordChangeController::_failure()` on the previous request, or an
     * empty array when there was no failure. Each value is the framework's
     * standard `string[]` of messages per attribute.
     *
     * No-op (empty array) outside web requests where no session exists —
     * the console-request guard and the surrounding try/catch keep Twig
     * rendering from blowing up in CLI / queue / preview contexts where the
     * session component throws `MissingComponentException`.
     *
     * `protected` so tests can override the session read without standing up
     * a web session in the console-bootstrapped suite.
     *
     * @return array<string, string[]>
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected function _flashedErrors(): array
    {
        $request = Craft::$app->getRequest();

        if ($request->getIsConsoleRequest()) {
            return [];
        }

        try {
            /** @var array<string, string[]>|null $flashed */
            $flashed = Craft::$app->getSession()->getFlash('pp:errors');
        } catch (\Throwable) {
            return [];
        }

        return is_array($flashed) ? $flashed : [];
    }

    // Private Methods
    // =========================================================================

    /**
     * Renders the error-summary region. Always emits the `role="alert"` /
     * `aria-live="assertive"` container so the live region exists in the DOM
     * before any (consumer-wired AJAX) injection; the list inside is only
     * populated when there are flashed errors to report.
     *
     * Each summary item links to its field so keyboard / screen-reader users
     * can jump straight to the offending input (WCAG 3.3.1, 4.1.3).
     *
     * @param array<string, string[]> $errors
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _renderErrorSummary(array $errors): string
    {
        $fieldIds = [
            'currentPassword' => 'pp-current-password',
            'newPassword' => 'pp-new-password',
            'newPasswordConfirm' => 'pp-new-password-confirm',
        ];

        $items = '';

        foreach ($errors as $attribute => $messages) {
            foreach ((array)$messages as $message) {
                $targetId = $fieldIds[$attribute] ?? null;
                $label = (string)$message;

                $items .= $targetId !== null
                    ? '<li><a href="#' . Html::encode($targetId) . '">' . Html::encode($label) . '</a></li>'
                    : '<li>' . Html::encode($label) . '</li>';
            }
        }

        $body = $items !== ''
            ? '<p class="pp-error-summary__title">'
                . Html::encode(Craft::t('password-policy', 'There’s a problem with your submission.'))
                . '</p><ul class="pp-error-summary__list">' . $items . '</ul>'
            : '';

        return '<div'
            . $this->_renderAttrs([
                'class' => 'pp-error-summary',
                'role' => 'alert',
                'aria-live' => 'assertive',
                'aria-atomic' => 'true',
                'tabindex' => $items !== '' ? '-1' : null,
            ])
            . '>' . $body . '</div>';
    }

    /**
     * Renders a labelled password field plus its inline error region,
     * wiring `aria-invalid` + `aria-describedby` to the error element when
     * the field carries flashed errors. Preserves the field's own live
     * region `aria-describedby` linkage (set by `PasswordFieldTag` when
     * `liveValidation` is on) by composing both ids.
     *
     * @param string $name the input `name` / error-map key
     * @param string $id the input `id`
     * @param string $label the visible field label
     * @param string $autocomplete the `autocomplete` token
     * @param array<string, string[]> $errors the flashed per-field error map
     * @param array<string, mixed> $extraConfig additional `PasswordFieldTag`
     *     config (e.g. `liveValidation`, `submitGate`)
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _renderField(
        string $name,
        string $id,
        string $label,
        string $autocomplete,
        array $errors,
        array $extraConfig = [],
    ): string {
        $fieldErrors = array_values(array_filter(
            array_map(static fn($message): string => (string)$message, (array)($errors[$name] ?? [])),
            static fn(string $message): bool => $message !== '',
        ));
        $hasError = $fieldErrors !== [];
        $errorId = "{$id}-error";

        $inputAttrs = ['required' => true, 'class' => 'pp-input'];

        if ($hasError) {
            $inputAttrs['aria-invalid'] = 'true';

            // Compose describedby: keep the live region id (added by the
            // field tag when liveValidation is on) so we don't clobber it.
            $describedBy = !empty($extraConfig['liveValidation'])
                ? "{$id}-live {$errorId}"
                : $errorId;
            $inputAttrs['aria-describedby'] = $describedBy;
        }

        $fieldConfig = array_merge([
            'name' => $name,
            'id' => $id,
            'autocomplete' => $autocomplete,
            'inputAttrs' => $inputAttrs,
            'toggleVisibility' => true,
            'liveValidation' => false,
        ], $extraConfig);

        $output = '<label for="' . Html::encode($id) . '" class="pp-label">'
            . Html::encode($label)
            . '</label>';
        $output .= (string)(new PasswordFieldTag($fieldConfig));

        if ($hasError) {
            $messages = '';

            foreach ($fieldErrors as $message) {
                $messages .= ($messages !== '' ? ' ' : '') . Html::encode($message);
            }

            $output .= '<span'
                . $this->_renderAttrs([
                    'id' => $errorId,
                    'class' => 'pp-field-error',
                ])
                . '>' . $messages . '</span>';
        }

        return $output;
    }
}
