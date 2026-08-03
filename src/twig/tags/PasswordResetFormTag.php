<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\twig\tags;

use Craft;
use craft\helpers\Html;
use InvalidArgumentException;

/**
 * Class PasswordResetFormTag
 *
 * Renders a `<form>` for token-based password reset (the user clicked a
 * "reset your password" email link). Posts to Craft's
 * `users/set-password` action so the existing token-validation flow runs;
 * the new-password field still goes through plugin validation via
 * `User::EVENT_DEFINE_RULES` on the server side.
 *
 * The caller must pass `code` and `id` values (typically from the URL
 * query params Craft sends in the reset email).
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class PasswordResetFormTag extends BaseTag
{
    // Public Methods
    // =========================================================================

    /**
     * Sets the reset code from the URL.
     *
     * @param string $code
     * @return $this
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function code(string $code): self
    {
        $this->config['code'] = $code;
        return $this;
    }

    /**
     * Sets the user identifier from the reset email URL. Craft renders the
     * reset link as `?code=…&id=…` — the `id` URL param IS the user UID.
     *
     * Canonical setter; mirrors the URL param name so consumers can write
     * `.id(craft.app.request.queryParam('id'))` without mental translation.
     *
     * @param string $id
     * @return $this
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function id(string $id): self
    {
        $this->config['userUid'] = $id;
        return $this;
    }

    /**
     * Sets the user UID from the URL.
     *
     * @param string $userUid
     * @return $this
     *
     * @deprecated since 5.2.0 use [[id()]] instead — Craft's reset email URL
     *     param is named `id`, not `userUid`. The legacy setter is preserved
     *     indefinitely for backward compatibility but new code should call
     *     `->id($value)`.
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function userUid(string $userUid): self
    {
        return $this->id($userUid);
    }

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
     * @throws InvalidArgumentException when `code` or `id` are missing
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected function _renderHtml(): string
    {
        if (empty($this->config['code']) || empty($this->config['userUid'])) {
            throw new InvalidArgumentException(
                'PasswordResetFormTag requires `code` and `id`. Pass them from the URL query string '
                . "(e.g. `.code(craft.app.request.queryParam('code')).id(craft.app.request.queryParam('id'))`).",
            );
        }

        $formAttrs = array_merge([
            'method' => 'post',
            'action' => '',
            'class' => 'pp-form pp-reset-form',
            'novalidate' => true,
        ], (array)($this->config['formAttrs'] ?? []));

        $submitAttrs = array_merge([
            'type' => 'submit',
            'class' => 'pp-submit',
            'id' => 'pp-reset-submit',
        ], (array)($this->config['submitButtonAttrs'] ?? []));

        $submitLabel = (string)($this->config['submitLabel'] ?? Craft::t('app', 'Set new password'));

        $output = '<form' . $this->_renderAttrs($formAttrs) . '>';
        $output .= Html::hiddenInput('action', 'users/set-password');
        $output .= Html::csrfInput();
        $output .= Html::hiddenInput('code', (string)$this->config['code']);
        $output .= Html::hiddenInput('id', (string)$this->config['userUid']);

        if (!empty($this->config['successRedirect'])) {
            $output .= Html::hiddenInput(
                'redirect',
                Craft::$app->getSecurity()->hashData((string)$this->config['successRedirect']),
            );
        }

        $newField = new PasswordFieldTag([
            'name' => 'newPassword',
            'id' => 'pp-reset-password',
            'autocomplete' => 'new-password',
            'inputAttrs' => ['required' => true, 'class' => 'pp-input'],
            'toggleVisibility' => true,
            'liveValidation' => true,
            'submitGate' => '#' . $submitAttrs['id'],
        ]);

        $output .= '<label for="pp-reset-password" class="pp-label">'
            . Html::encode(Craft::t('password-policy', 'New password'))
            . '</label>';
        $output .= (string)$newField;

        $output .= '<button' . $this->_renderAttrs($submitAttrs) . '>' . Html::encode($submitLabel) . '</button>';

        $output .= '</form>';

        return $output;
    }
}
