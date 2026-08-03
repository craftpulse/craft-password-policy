<?php
/**
 * Pest coverage for `PasswordChangeFormTag` — the front-end change-password
 * form builder. Pins the C-phase review fix that added an accessible error
 * region (WCAG 3.3.1 Error Identification, 4.1.3 Status Messages):
 *
 *  - An always-present `role="alert"` / `aria-live="assertive"` summary
 *    container so dynamic injection is announced and a re-rendered failed
 *    submit reports errors to assistive tech.
 *  - Per-field inline errors with `aria-invalid="true"` +
 *    `aria-describedby` wiring on the offending input.
 *  - Errors are read off a single channel — the `pp:errors` session flash
 *    written by `PasswordChangeController::_failure()`.
 *
 * The session read (`_flashedErrors()`) is `protected` so these tests can
 * feed a deterministic error map without standing up a web session — the
 * suite boots a console application whose `getSession()` throws. The error
 * rendering branches are the behaviour under test; the flash plumbing is
 * exercised at the controller layer.
 *
 * The tag is rendered via `__toString()` (the PHP-context path the form
 * uses to assemble its children) and the markup asserted with substring
 * checks — no DOM-parser dependency.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craft\web\Response;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\tests\Support\WebRequestStub;
use craftpulse\passwordpolicy\twig\tags\PasswordChangeFormTag;

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;

    $this->originalRequest = Craft::$app->getRequest();
    $this->originalResponse = Craft::$app->getResponse();

    // `PasswordChangeFormTag::_renderHtml()` calls `Html::csrfInput()`, which
    // reads `Craft::$app->getRequest()->csrfParam` and calls
    // `Craft::$app->getResponse()->setNoCacheHeaders()`. Both methods are
    // absent on the console request/response objects that the test bootstrap
    // creates. Swap in a WebRequestStub (site-shaped — the change form is a
    // front-end surface) and a `craft\web\Response` so those calls succeed
    // without standing up a real HTTP lifecycle.
    $webRequest = new WebRequestStub();
    $webRequest->stubIsCpRequest = false;
    Craft::$app->set('request', $webRequest);
    Craft::$app->set('response', new Response());
});

afterEach(function() {
    Craft::$app->set('request', $this->originalRequest);
    Craft::$app->set('response', $this->originalResponse);
});

/**
 * Builds a `PasswordChangeFormTag` whose `_flashedErrors()` returns the
 * supplied map — sidestepping the web session the console suite lacks.
 *
 * @param array<string, string[]> $errors
 */
function changeFormWithErrors(array $errors): PasswordChangeFormTag
{
    return new class($errors) extends PasswordChangeFormTag {
        /** @var array<string, string[]> */
        private array $stubErrors;

        /**
         * @param array<string, string[]> $errors
         */
        public function __construct(array $errors)
        {
            parent::__construct();
            $this->stubErrors = $errors;
        }

        /**
         * @return array<string, string[]>
         */
        protected function _flashedErrors(): array
        {
            return $this->stubErrors;
        }
    };
}

// =============================================================================
// Error region — always-present summary container
// =============================================================================

it('always renders an aria-live alert summary container', function() {
    $html = (string)changeFormWithErrors([]);

    expect($html)
        ->toContain('role="alert"')
        ->toContain('aria-live="assertive"')
        ->toContain('class="pp-error-summary"');
});

it('marks no input invalid when there are no errors', function() {
    $html = (string)changeFormWithErrors([]);

    expect($html)->not->toContain('aria-invalid="true"');
    expect($html)->not->toContain('class="pp-field-error"');
});

// =============================================================================
// Error region — populated from the flashed error map
// =============================================================================

it('renders flashed per-field errors in the summary and inline', function() {
    $html = (string)changeFormWithErrors([
        'currentPassword' => ['Current password is incorrect.'],
        'newPassword' => ['Password is too short.'],
    ]);

    // Summary links each error to its field anchor.
    expect($html)
        ->toContain('Current password is incorrect.')
        ->toContain('Password is too short.')
        ->toContain('href="#pp-current-password"')
        ->toContain('href="#pp-new-password"');

    // Inline error spans wired by id.
    expect($html)
        ->toContain('id="pp-current-password-error"')
        ->toContain('id="pp-new-password-error"');

    // Offending inputs marked invalid + described by their error element.
    expect($html)
        ->toContain('aria-invalid="true"')
        ->toContain('aria-describedby="pp-current-password-error"');
});

it('composes the live-region id into describedby for the new-password field', function() {
    // The new-password field has liveValidation on, so its own live region
    // (`pp-new-password-live`) must not be clobbered by the error linkage.
    $html = (string)changeFormWithErrors([
        'newPassword' => ['Password is too short.'],
    ]);

    expect($html)->toContain('aria-describedby="pp-new-password-live pp-new-password-error"');
});

it('renders no inline error span for fields without errors', function() {
    $html = (string)changeFormWithErrors([
        'currentPassword' => ['Current password is incorrect.'],
    ]);

    // The confirm field carried no error — no inline error span for it.
    expect($html)->not->toContain('id="pp-new-password-confirm-error"');
});
