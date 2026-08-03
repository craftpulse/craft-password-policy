<?php
/**
 * Password policy plugin for Craft CMS
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\tests\Support;

use Craft;
use craft\web\Request;

/**
 * Lightweight stub of `craft\web\Request` for tests that need to flip
 * `Craft::$app->getRequest()->getIsConsoleRequest()` to `false` while the
 * test process is still bootstrapped as a console application.
 *
 * The stub forces `getIsConsoleRequest()` to `false` and exposes
 * `setBodyParams()` so controller-flow tests can populate POST data
 * without standing up a full HTTP request lifecycle. Acceptance
 * (`getAcceptsJson`), POST detection (`getIsPost`), and CSRF
 * (`getCsrfToken`) all return defaults that keep `craft\web\Controller`
 * happy without needing real HTTP plumbing.
 *
 * Use via `Craft::$app->set('request', new WebRequestStub())` inside a
 * `beforeEach()`; the singleton swap restores when the test process
 * exits or another `set()` overwrites it. Tests that don't need the
 * web-context flip stick with the bootstrap's console request.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class WebRequestStub extends Request
{
    // Public Properties
    // =========================================================================

    /**
     * @var array<string, mixed>
     */
    public array $stubBodyParams = [];

    /**
     * Stubbed query-string params, keyed by name. Lets token-authed GET
     * endpoints (`ApiController`) read `from` / `to` / `limit` / `offset` /
     * `userUid` without a real query string.
     *
     * @var array<string, mixed>
     *
     * @since 5.2.0
     */
    public array $stubQueryParams = [];

    /**
     * Stubbed request headers, keyed by (case-insensitive) name. Lets
     * Bearer-token tests set `Authorization` without a real HTTP layer.
     *
     * @var array<string, string>
     *
     * @since 5.2.0
     */
    public array $stubHeaders = [];

    /**
     * @var bool
     */
    public bool $stubIsPost = true;

    /**
     * @var bool
     */
    public bool $stubAcceptsJson = true;

    /**
     * Stubbed return value for `getIsCpRequest()`. The default
     * (`false`) keeps front-end-controller tests working as before;
     * D3 controller tests flip to `true` so the controller's
     * `requireCpRequest()` gate passes.
     *
     * @var bool
     *
     * @since 5.2.0
     */
    public bool $stubIsCpRequest = false;

    /**
     * Stub IP returned from `getUserIP()`. Lets `AuditContext::fromRequest()`
     * round-trip a known value into the password-history row without
     * standing up a real `$_SERVER['REMOTE_ADDR']` pin.
     *
     * @var string|null
     *
     * @since 5.2.0
     */
    public ?string $stubUserIp = '203.0.113.7';

    /**
     * Stub user-agent returned from `getUserAgent()`. Same rationale as
     * `$stubUserIp` — lets audit-context tests assert without manipulating
     * `$_SERVER['HTTP_USER_AGENT']`.
     *
     * @var string|null
     *
     * @since 5.2.0
     */
    public ?string $stubUserAgent = 'Pest/Test (audit-context)';

    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function init(): void
    {
        // Skip parent init — Craft's Request::init reads from $_SERVER /
        // $_REQUEST and resolves a Site, neither of which makes sense in
        // a console-bootstrapped test process.
        //
        // But pin the typed `generalConfig` property so methods that
        // access it (`getSiteToken()`, `validateCsrfToken()` internals)
        // don't trip over uninitialized-property errors. Parent init
        // would normally populate this; we replicate that bit here.
        $this->generalConfig = Craft::$app->getConfig()->getGeneral();

        // Pin a host info so `UrlHelper::cpUrl()` / `actionUrl()` (used
        // by Craft's mailer and CP redirect machinery) can resolve a
        // canonical absolute URL even though the test process is
        // console-shaped. Without this, `getHostInfo()` returns null
        // and the URL helpers throw on the typed return.
        $this->setHostInfo('https://test.craftcms.test');
        $this->setBaseUrl('');
    }

    /**
     * @return false
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getIsConsoleRequest(): bool
    {
        return false;
    }

    /**
     * @inheritdoc
     */
    public function getIsCpRequest(): bool
    {
        return $this->stubIsCpRequest;
    }

    /**
     * @inheritdoc
     */
    public function getIsSiteRequest(): bool
    {
        return !$this->stubIsCpRequest;
    }

    /**
     * @inheritdoc
     *
     * Returns a stub CP-shaped path. The default `_path` is left
     * uninitialised on `craft\web\Request`, so any code that calls
     * `getPathInfo()` (which the CP layout's global sidebar does
     * unconditionally) trips an "uninitialized typed property" error.
     * Tests that render full CP templates need this method to return a
     * stable string. Front-end controller tests don't hit this path.
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getPathInfo(bool $returnRealPathInfo = false): string
    {
        return 'pest-stub';
    }

    /**
     * @inheritdoc
     *
     * Returns a stub URL. Yii's `Request::getUrl()` reads from
     * `$_SERVER['REQUEST_URI']` and throws when the key is absent,
     * which is the case in console-bootstrapped tests. CP templates
     * routinely call `craft.app.request.url` (e.g. for
     * `redirectInput(craft.app.request.url)`); the stub returns a
     * deterministic string so those reads don't blow up the render.
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getUrl(): string
    {
        return '/pest-stub';
    }

    /**
     * @inheritdoc
     */
    public function getIsLivePreview(): bool
    {
        return false;
    }

    /**
     * @inheritdoc
     */
    public function getIsPreview(): bool
    {
        return false;
    }

    /**
     * @inheritdoc
     */
    public function hasValidSiteToken(): bool
    {
        return false;
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getIsPost(): bool
    {
        return $this->stubIsPost;
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getAcceptsJson(): bool
    {
        return $this->stubAcceptsJson;
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getIsOptions(): bool
    {
        return false;
    }

    /**
     * @inheritdoc
     *
     * Builds a fresh `HeaderCollection` from `$stubHeaders` on each call so
     * mid-test header changes are reflected. Yii's collection is
     * case-insensitive on `get()`, matching real HTTP behaviour.
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getHeaders(): \yii\web\HeaderCollection
    {
        $collection = new \yii\web\HeaderCollection();

        foreach ($this->stubHeaders as $name => $value) {
            $collection->set($name, $value);
        }

        return $collection;
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getQueryParam($name, $defaultValue = null): mixed
    {
        return $this->stubQueryParams[$name] ?? $defaultValue;
    }

    /**
     * @inheritdoc
     */
    public function getBodyParams(): array
    {
        return $this->stubBodyParams;
    }

    /**
     * @inheritdoc
     */
    public function setBodyParams($values): void
    {
        $this->stubBodyParams = $values;
    }

    /**
     * @inheritdoc
     */
    public function getBodyParam($name, $defaultValue = null): mixed
    {
        return $this->stubBodyParams[$name] ?? $defaultValue;
    }

    /**
     * @inheritdoc
     */
    public function getRequiredBodyParam($name): mixed
    {
        if (!array_key_exists($name, $this->stubBodyParams)) {
            throw new \yii\web\BadRequestHttpException(sprintf(
                'Required body param `%s` not present.',
                $name,
            ));
        }

        return $this->stubBodyParams[$name];
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getUserIP($ipHeaders = null): ?string
    {
        return $this->stubUserIp;
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getUserAgent(): ?string
    {
        return $this->stubUserAgent;
    }

    /**
     * @inheritdoc
     */
    public function getCsrfToken($regenerate = false): string
    {
        return 'stub-csrf-token';
    }

    /**
     * @inheritdoc
     */
    public function validateCsrfToken($clientSuppliedToken = null): bool
    {
        return true;
    }
}
