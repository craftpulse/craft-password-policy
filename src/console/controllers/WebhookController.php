<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\console\controllers;

use craft\console\Controller;
use craft\helpers\Queue;
use craftpulse\passwordpolicy\jobs\WebhookForwardJob;
use craftpulse\passwordpolicy\models\WebhookEndpointModel;
use craftpulse\passwordpolicy\PasswordPolicy;
use Throwable;
use yii\console\ExitCode;

/**
 * Manages webhook endpoints and enqueues the webhook delivery sweep.
 *
 * `create`, `list`, and `rotate-secret` are console parity for the
 * webhook endpoint control panel screen. Operators with IaC pipelines
 * provision endpoints from cron, so these actions match the CP CRUD
 * shape and a Terraform module or Ansible playbook doesn't need to drive
 * a CP click.
 *
 * `run` is the delivery trigger. Deliveries run as a batched queue job
 * and the plugin never enqueues that job implicitly, so
 * `password-policy/webhook/run` belongs in cron on any install where
 * delivery matters. The Cron setup page in the plugin docs carries
 * ready-made crontab, Forge, and Kubernetes entries.
 *
 * Edition gate: every action returns
 * `ExitCode::UNSPECIFIED_ERROR` with a stderr message on a sub-
 * Enterprise install. The webhook *registry* is exposure: the table
 * exists empty on Lite / Pro but write operations stay gated.
 *
 * Secret-handling contract: the new plaintext secret is printed to
 * stdout EXACTLY ONCE per create / rotate-secret action. Operators
 * capture it from the CI log; the plugin's encrypted-at-rest store
 * never echoes it back. Pair the action invocation with whatever
 * secrets manager the operator runs (Vault, AWS Secrets Manager,
 * etc.): capture the stdout line, push it into the secret store,
 * configure the consumer to read from there.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class WebhookController extends Controller
{
    // Public Properties
    // =========================================================================

    /**
     * @var string|null comma-separated event-class allowlist for
     * `actionCreate`. Empty = use the global setting.
     */
    public ?string $events = null;

    /**
     * @var string|null human-readable display name for `actionCreate`.
     */
    public ?string $name = null;

    /**
     * @var string the destination URL for `actionCreate`. Required for
     * create. Supports `$ENV_VAR` references, resolved at dispatch.
     */
    public string $url = '';

    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function options($actionID): array
    {
        $options = parent::options($actionID);

        if ($actionID === 'create') {
            $options[] = 'events';
            $options[] = 'name';
            $options[] = 'url';
        }

        return $options;
    }

    /**
     * Creates a new webhook endpoint and prints the generated secret to
     * stdout exactly once. The plaintext is gone from the controller
     * layer immediately afterward; the database stores ciphertext only.
     *
     * Usage:
     *
     *     ddev craft password-policy/webhook/create \
     *         --url=https://hooks.example.test/audit \
     *         --events=audit_log \
     *         --name="Compliance dashboard"
     *
     * @return int
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionCreate(): int
    {
        if (!$this->_requireEnterprise()) {
            return ExitCode::UNSPECIFIED_ERROR;
        }

        if ($this->url === '') {
            $this->stderr("--url is required\n");

            return ExitCode::USAGE;
        }

        $endpoint = new WebhookEndpointModel();
        $endpoint->name = $this->name;
        $endpoint->url = $this->url;
        $endpoint->eventClasses = $this->_parseEventList($this->events);
        $endpoint->enabled = true;

        try {
            if (!PasswordPolicy::$plugin->getWebhook()->saveEndpoint($endpoint)) {
                $this->stderr("Couldn't save endpoint:\n");
                foreach ($endpoint->getErrorSummary(true) as $error) {
                    $this->stderr("  - {$error}\n");
                }

                return ExitCode::UNSPECIFIED_ERROR;
            }
        } catch (Throwable $e) {
            $this->stderr("Couldn't save endpoint: {$e->getMessage()}\n");

            return ExitCode::UNSPECIFIED_ERROR;
        }

        $this->stdout("Webhook endpoint created (id={$endpoint->id}).\n");
        $this->stdout("Secret (shown ONCE — capture this for your consumer config):\n");
        $this->stdout($endpoint->secretCurrent . "\n");

        return ExitCode::OK;
    }

    /**
     * Lists every configured webhook endpoint.
     *
     * @return int
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionList(): int
    {
        if (!$this->_requireEnterprise()) {
            return ExitCode::UNSPECIFIED_ERROR;
        }

        $endpoints = PasswordPolicy::$plugin->getWebhook()->listEndpoints();

        if (empty($endpoints)) {
            $this->stdout("No webhook endpoints registered.\n");

            return ExitCode::OK;
        }

        $this->stdout(sprintf(
            "%-4s  %-9s  %-12s  %s\n",
            'ID',
            'ENABLED',
            'CURSOR',
            'URL',
        ));

        foreach ($endpoints as $endpoint) {
            $this->stdout(sprintf(
                "%-4d  %-9s  %-12s  %s\n",
                (int)$endpoint->id,
                $endpoint->enabled ? 'yes' : 'no',
                $endpoint->lastDeliveredRowId !== null
                    ? (string)$endpoint->lastDeliveredRowId
                    : '-',
                $endpoint->url,
            ));
        }

        return ExitCode::OK;
    }

    /**
     * Rotates a webhook endpoint's HMAC secret and prints the new
     * plaintext to stdout exactly once.
     *
     * Usage:
     *
     *     ddev craft password-policy/webhook/rotate-secret 42
     *
     * @param int $endpointId
     * @return int
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionRotateSecret(int $endpointId): int
    {
        if (!$this->_requireEnterprise()) {
            return ExitCode::UNSPECIFIED_ERROR;
        }

        $service = PasswordPolicy::$plugin->getWebhook();
        $endpoint = $service->getEndpointById($endpointId);

        if ($endpoint === null) {
            $this->stderr("Endpoint {$endpointId} not found\n");

            return ExitCode::UNSPECIFIED_ERROR;
        }

        try {
            $newSecret = $service->rotateSecret($endpoint);
        } catch (Throwable $e) {
            $this->stderr("Couldn't rotate secret: {$e->getMessage()}\n");

            return ExitCode::UNSPECIFIED_ERROR;
        }

        $this->stdout("Webhook endpoint {$endpointId} secret rotated.\n");
        $this->stdout("New secret (shown ONCE):\n");
        $this->stdout($newSecret . "\n");

        return ExitCode::OK;
    }

    /**
     * Enqueues the batched job that delivers pending audit rows to every active webhook endpoint.
     *
     * Each endpoint carries its own delivery cursor
     * (`lastDeliveredRowId`), so the job resumes per endpoint rather than
     * redelivering, and an endpoint that fails does not hold up the
     * others.
     *
     * Nothing is enqueued when no endpoint is currently active: a
     * disabled endpoint, or one inside its circuit-breaker cooldown,
     * would give the job no destination, and a cron running every few
     * minutes would otherwise fill the queue table with no-op jobs. That
     * case still exits zero, because "nothing configured yet" is not an
     * operator-actionable failure.
     *
     * @return int
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionRun(): int
    {
        if (!$this->_requireEnterprise()) {
            return ExitCode::UNSPECIFIED_ERROR;
        }

        $endpointCount = count(PasswordPolicy::$plugin->getWebhook()->getActiveEndpoints());

        if ($endpointCount === 0) {
            $this->stdout("No active webhook endpoints. Nothing enqueued.\n");

            return ExitCode::OK;
        }

        Queue::push(new WebhookForwardJob());

        $this->stdout("Webhook delivery sweep enqueued for {$endpointCount} active endpoint(s).\n");
        PasswordPolicy::$plugin->log('Webhook delivery sweep queued [endpoints={endpoints}]', [
            'endpoints' => $endpointCount,
        ]);

        return ExitCode::OK;
    }

    // Private Methods
    // =========================================================================

    /**
     * Parses a comma-separated event-class list into an array. Empty
     * input = null (use global setting). Whitespace tolerant.
     *
     * @param string|null $raw
     * @return array<int, string>|null
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _parseEventList(?string $raw): ?array
    {
        if ($raw === null || trim($raw) === '') {
            return null;
        }

        $items = array_values(array_filter(
            array_map('trim', explode(',', $raw)),
            fn(string $v): bool => $v !== '',
        ));

        return $items !== [] ? $items : null;
    }

    /**
     * Returns true on Enterprise. On a sub-Enterprise install, prints
     * a stderr message and returns false so the caller can short-
     * circuit with `ExitCode::UNSPECIFIED_ERROR`.
     *
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _requireEnterprise(): bool
    {
        if (PasswordPolicy::$plugin->getIsEnterprise()) {
            return true;
        }

        $this->stderr("Webhook management requires the Enterprise edition.\n");

        return false;
    }
}
