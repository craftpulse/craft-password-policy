<?php
/**
 * Pest coverage for `UnforwardedAuditRowBatcher` driven across a MULTI-BATCH
 * campaign, which is the only shape in which its defect was visible.
 *
 * The forwardable predicate is self-consuming: `SiemForwardJob` writes
 * `forwardedAt` on every row it delivers, so each processed row leaves the
 * result set, while `craft\queue\BaseBatchedJob` advances `itemOffset`
 * monotonically across the batches it spawns. Paginating that query by offset
 * skips exactly as many rows as the campaign processed. With the seven-row
 * fixture and a batch size of three below, the offset-paginated version
 * forwarded four of seven rows in two batches and reported clean completion;
 * the watermark version forwards all seven in three.
 *
 * A single-batch test cannot see any of that, which is why there was no
 * coverage under `src/batchers/` and why the bug survived. Every assertion here
 * is therefore about the campaign as a whole rather than about one slice.
 *
 * `CapturingQueue` feeds each spawned batch back the way a queue worker would,
 * including the real serialize/unserialize round trip, so the test also pins
 * that the campaign cursor survives the queue hop.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use Carbon\Carbon;
use craft\db\Query;
use craft\db\Table;
use craft\helpers\StringHelper;
use craftpulse\passwordpolicy\elements\AuditLogElement;
use craftpulse\passwordpolicy\jobs\SiemForwardJob;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\services\SiemService;
use craftpulse\passwordpolicy\tests\Support\AcceptingSiemService;
use craftpulse\passwordpolicy\tests\Support\CapturingQueue;

// =============================================================================
// Setup
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->originalEdition = $this->plugin->edition;
    $this->plugin->edition = PasswordPolicy::EDITION_ENTERPRISE;

    Craft::$app->getDb()->createCommand()
        ->delete('{{%passwordpolicy_audit_log}}')
        ->execute();

    // Swap in a forwarder that accepts, so `forwardedAt` is actually written
    // and the forwardable result set actually shrinks. A refused socket would
    // leave every row pending and the campaign would never drift.
    $this->siem = new AcceptingSiemService();
    $this->plugin->set('siem', $this->siem);
});

afterEach(function() {
    // Restore the real component. A stub left in place would leak into every
    // later file in the process, since the plugin module memoizes components.
    $this->plugin->set('siem', SiemService::class);
    $this->plugin->edition = $this->originalEdition;
});

// =============================================================================
// Helpers
// =============================================================================

/**
 * Inserts an unforwarded audit-log row, bypassing the chain writer. These tests
 * care about the batcher's pagination, not about chain integrity, and every
 * audit row pairs with a `craft_elements` row via `id`, so the element row is
 * allocated first to satisfy the FK.
 */
function makeUnforwardedAuditRow(): int
{
    $now = Carbon::now('UTC')->format('Y-m-d H:i:s');

    Craft::$app->getDb()->createCommand()
        ->insert(Table::ELEMENTS, [
            'type' => AuditLogElement::class,
            'enabled' => 1,
            'archived' => 0,
            'dateCreated' => $now,
            'dateUpdated' => $now,
            'uid' => StringHelper::UUID(),
        ])
        ->execute();

    $elementId = (int)Craft::$app->getDb()->getLastInsertID(Table::ELEMENTS);

    Craft::$app->getDb()->createCommand()
        ->insert('{{%passwordpolicy_audit_log}}', [
            'id' => $elementId,
            'event' => 'campaign_fixture',
            'outcome' => 'success',
            'source' => 'admin',
            'rowHash' => str_repeat('a', 64),
            'previousHash' => str_repeat('0', 64),
            'forwardedAt' => null,
            'forwardAttempts' => 0,
            'dateCreated' => $now,
            'uid' => StringHelper::UUID(),
        ])
        ->execute();

    return $elementId;
}

/**
 * Counts audit rows still awaiting forwarding.
 */
function unforwardedAuditRowCount(): int
{
    return (int)(new Query())
        ->from('{{%passwordpolicy_audit_log}}')
        ->where(['forwardedAt' => null])
        ->count();
}

// =============================================================================
// Multi-batch campaign — every eligible row must be forwarded
// =============================================================================

it('forwards every pending audit row across a campaign that spans several batches', function() {
    $ids = [];

    for ($i = 0; $i < 7; $i++) {
        $ids[] = makeUnforwardedAuditRow();
    }

    $batches = CapturingQueue::runCampaign(new SiemForwardJob(), batchSize: 3);

    // Three batches for seven rows at three per batch. Two would mean the
    // campaign terminated early, which is precisely how the offset-paginated
    // version failed: its shrinking `count()` fell below the growing offset.
    // The assertion that matters: nothing is left behind.
    expect(unforwardedAuditRowCount())->toBe(0);

    expect($batches)->toBe(3);

    // And every row was offered exactly once. A watermark that failed to
    // advance would show duplicates here even while the count above passed.
    expect($this->siem->forwardedIds)->toHaveCount(7)
        ->and($this->siem->forwardedIds)->toBe($ids);
});

it('forwards every row when the fixture does not divide evenly into batches', function() {
    // The remainder batch is where an off-by-one in the watermark or in the
    // count compensation surfaces.
    for ($i = 0; $i < 10; $i++) {
        makeUnforwardedAuditRow();
    }

    $batches = CapturingQueue::runCampaign(new SiemForwardJob(), batchSize: 4);

    expect($batches)->toBe(3)
        ->and(unforwardedAuditRowCount())->toBe(0)
        ->and($this->siem->forwardedIds)->toHaveCount(10);
});

// =============================================================================
// Termination — a row nothing can forward must not spin the campaign forever
// =============================================================================

it('terminates when a row stays unforwarded rather than re-offering it forever', function() {
    // With no active forwarder every row keeps `forwardedAt = NULL`, so the
    // result set never shrinks. Ignoring the offset without a watermark would
    // hand out the same first slice on every batch and grow `count()` on each
    // one, so the campaign would never end. `runCampaign()` throws past its
    // batch guard, which is what would fail this test.
    $this->plugin->set('siem', SiemService::class);

    for ($i = 0; $i < 7; $i++) {
        makeUnforwardedAuditRow();
    }

    $batches = CapturingQueue::runCampaign(new SiemForwardJob(), batchSize: 3);

    expect($batches)->toBe(3)
        ->and(unforwardedAuditRowCount())->toBe(7);
});
