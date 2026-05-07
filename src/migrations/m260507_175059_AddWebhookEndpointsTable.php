<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\migrations;

use craft\db\Migration;

/**
 * Class m260507_175059_AddWebhookEndpointsTable
 *
 * Phase G — G9. Adds the `passwordpolicy_webhook_endpoints` table — the
 * registry of HTTP webhook endpoints the plugin POSTs HMAC-signed audit
 * payloads to.
 *
 * Schema (per § 4 of the Phase G plan, locked):
 *
 *  - `id` — primary key.
 *  - `name` — admin-supplied display label (nullable). The index falls
 *    back to the URL when empty.
 *  - `url` — the webhook endpoint URL. Env-var-resolved at use via
 *    `App::parseEnv()` so operators store the literal env reference (e.g.
 *    `$PP_WEBHOOK_URL`) here. NOT NULL — every endpoint targets an
 *    address.
 *  - `secretCurrent` — the HMAC signing secret in active use. Encrypted
 *    at rest via `Craft::$app->getSecurity()->encryptByKey()` at the
 *    model boundary; the column stores opaque ciphertext. Stored as
 *    `text` because the encrypted blob exceeds 255 chars (Craft's
 *    encrypt envelope adds key-version prefix + IV + tag).
 *  - `secretPrevious` — the prior secret during a rotation grace
 *    window. Same encryption envelope as `secretCurrent`. Null when no
 *    rotation is active or after `RotateWebhookSecretJob` reaped it.
 *  - `secretRotatedAt` — UTC timestamp the most recent rotation
 *    happened. Drives the grace-window expiry that nulls
 *    `secretPrevious`.
 *  - `eventClasses` — JSON array, nullable. When non-null + non-empty,
 *    overrides the global `webhookForwardEventClasses` setting per
 *    endpoint. NULL means "use the global setting" (default
 *    `['audit_log']`).
 *  - `enabled` — bool. Disabled endpoints are skipped by the queue job
 *    entirely — distinct from circuit-open, which is automatic and
 *    self-recovering.
 *  - `lastDeliveredRowId` — durable per-endpoint dispatch cursor. Each
 *    endpoint tracks its own watermark independently. The job
 *    dispatches audit rows where `id > lastDeliveredRowId`; on success
 *    the cursor advances; on failure it stays put so the row gets
 *    retried next pass. Differs from G8's at-least-once-to-one
 *    semantics — webhooks treat each endpoint as an independent
 *    subscriber so endpoint A's success doesn't paper over endpoint
 *    B's failure.
 *  - `consecutiveFailures` — int, defaults 0. Durable mirror of the
 *    cache-resident counter in
 *    `pp:webhook-endpoint-circuit:{endpointId}` so a cache flush
 *    doesn't reset circuit state.
 *  - `circuitOpenAt` — datetime, nullable. Set when the consecutive-
 *    failure threshold opens the circuit; cleared on successful
 *    delivery.
 *  - Standard Craft `dateCreated` / `dateUpdated` / `uid` columns.
 *
 * No FK constraints — endpoints are independent of any Craft entity
 * (sites, users, groups). Deleting any of those does not cascade here.
 *
 * Idempotent — guarded by `tableExists()` so a re-run on a fully-applied
 * DB is a no-op (`migrations.md` rule).
 *
 * Capture is universal per memory rule
 * `project_audit_capture_principle.md`. Audit row writes happen on every
 * edition (G1 ships unconditionally). The endpoint *registry* is
 * exposure — only Enterprise installs see the CP subnav, can register
 * endpoints, and run the queue job that consumes them. This table
 * exists empty on Lite / Pro and that's the correct state.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class m260507_175059_AddWebhookEndpointsTable extends Migration
{
    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function safeUp(): bool
    {
        $table = '{{%passwordpolicy_webhook_endpoints}}';

        if ($this->db->tableExists($table)) {
            return true;
        }

        $this->createTable($table, [
            'id' => $this->primaryKey(),
            'name' => $this->string()->null(),
            'url' => $this->string(2048)->notNull(),
            'secretCurrent' => $this->text()->notNull(),
            'secretPrevious' => $this->text()->null(),
            'secretRotatedAt' => $this->dateTime()->null(),
            'eventClasses' => $this->json()->null(),
            'enabled' => $this->boolean()->notNull()->defaultValue(true),
            'lastDeliveredRowId' => $this->bigInteger()->null(),
            'consecutiveFailures' => $this->integer()->notNull()->defaultValue(0),
            'circuitOpenAt' => $this->dateTime()->null(),
            'dateCreated' => $this->dateTime()->notNull(),
            'dateUpdated' => $this->dateTime()->notNull(),
            'uid' => $this->uid(),
        ]);

        // `enabled` is the hot path for the queue job's
        // `getActiveEndpoints()` query; index it so a Pro install with
        // many disabled endpoints doesn't full-scan.
        $this->createIndex(null, $table, ['enabled'], false);
        $this->createIndex(null, $table, ['circuitOpenAt'], false);
        $this->createIndex(null, $table, ['lastDeliveredRowId'], false);

        return true;
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function safeDown(): bool
    {
        echo "m260507_175059_AddWebhookEndpointsTable cannot be reverted.\n";

        return false;
    }
}
