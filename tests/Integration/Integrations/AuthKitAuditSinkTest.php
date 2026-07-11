<?php
/**
 * Pest coverage for `integrations\AuthKitAuditSink` — Password Policy's
 * adapter for Auth Kit's audit-event contract (Integration 1).
 *
 * Four contracts pinned by this fixture:
 *
 *  1. Mapping — every neutral `AuthEvent` name in `EVENT_MAP` lands on the
 *     right PP event class, with the documented `details` (login `method`
 *     derived from the name suffix, `provider` / `scope` / `trigger` carried
 *     through), the emitter as both the row `source` column and a
 *     `details.source` key, and the neutral `outcome`.
 *  2. Identity — the subject `userId` and acting `actorId` pass through to the
 *     row's `userId` / `changedByUserId` columns.
 *  3. Forward-compatibility — an unknown neutral name is dropped silently: no
 *     row, and (unlike an unregistered event class hitting `logEvent()`) no
 *     fail-closed warning, because the sink returns before it ever calls
 *     `logEvent()`.
 *  4. End-to-end — registering PP's sink through the *real* Auth Kit
 *     `Audit::EVENT_REGISTER_AUDIT_SINKS` event and calling `Audit::record()`
 *     lands the row on the hash-chained log, proving the bootstrap wiring.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craft\db\Query;
use craft\helpers\Json;
use craftpulse\authkit\audit\AuthEvent;
use craftpulse\authkit\services\Audit;
use craftpulse\passwordpolicy\integrations\AuthKitAuditSink;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;
use yii\log\Logger;

// =============================================================================
// Setup — audit capture on, Pro edition (capture is universal anyway), clear
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->originalEdition = $this->plugin->edition;
    $this->originalEnableAuditLog = $this->plugin->getSettings()->enableAuditLog;

    $this->plugin->edition = PasswordPolicy::EDITION_PRO;
    $this->plugin->getSettings()->enableAuditLog = true;

    Craft::$app->getDb()->createCommand()
        ->delete('{{%passwordpolicy_audit_log}}')
        ->execute();
});

afterEach(function() {
    $this->plugin->edition = $this->originalEdition;
    $this->plugin->getSettings()->enableAuditLog = $this->originalEnableAuditLog;
});

// =============================================================================
// Helpers
// =============================================================================

/**
 * Returns the newest audit row for the given event class, or null.
 *
 * @return array<string, mixed>|null
 */
function ppAuditRow(string $event): ?array
{
    $row = (new Query())
        ->from('{{%passwordpolicy_audit_log}}')
        ->where(['event' => $event])
        ->orderBy(['id' => SORT_DESC])
        ->one();

    return is_array($row) ? $row : null;
}

/**
 * Decodes the JSON `details` column into an array (or null).
 *
 * @param array<string, mixed> $row
 * @return array<string, mixed>|null
 */
function ppAuditDetails(array $row): ?array
{
    if (!isset($row['details']) || !is_string($row['details'])) {
        return is_array($row['details'] ?? null) ? $row['details'] : null;
    }

    $decoded = Json::decodeIfJson($row['details']);

    return is_array($decoded) ? $decoded : null;
}

// =============================================================================
// Mapping — every EVENT_MAP name lands the right class + details + source
// =============================================================================

it('maps a neutral AuthEvent onto the right PP event class with the right details', function(
    string $name,
    string $emitter,
    array $inputDetails,
    string $expectedEvent,
    array $expectedDetails,
) {
    $sink = new AuthKitAuditSink();

    $sink->handle(new AuthEvent(
        name: $name,
        emitter: $emitter,
        outcome: AuthEvent::OUTCOME_SUCCESS,
        details: $inputDetails,
    ));

    $row = ppAuditRow($expectedEvent);

    expect($row)->not->toBeNull();
    expect($row['event'])->toBe($expectedEvent);
    expect($row['outcome'])->toBe('success');
    // The emitter is the row `source` column (via the `$source` param).
    expect($row['source'])->toBe($emitter);
    // ...and mirrored into the allowlisted `details.source` key.
    expect(ppAuditDetails($row))->toEqualCanonicalizing($expectedDetails);
})->with([
    'magic-link login' => ['login.magic_link', 'warp', [], 'auth_login', ['method' => 'magic_link', 'source' => 'warp']],
    'otp login' => ['login.otp', 'warp', [], 'auth_login', ['method' => 'otp', 'source' => 'warp']],
    'passkey login' => ['login.passkey', 'warp', [], 'auth_login', ['method' => 'passkey', 'source' => 'warp']],
    'sso login' => ['login.sso', 'warden', ['provider' => 'okta'], 'auth_login', ['method' => 'sso', 'provider' => 'okta', 'source' => 'warden']],
    'registration' => ['registration.fulfilled', 'warp', ['method' => 'magic_link'], 'auth_registration', ['method' => 'magic_link', 'source' => 'warp']],
    'passkey enrolled' => ['passkey.enrolled', 'warp', [], 'passkey_enrolled', ['source' => 'warp']],
    'passkey deleted' => ['passkey.deleted', 'warden', [], 'passkey_deleted', ['source' => 'warden']],
    'session revoked' => ['session.revoked', 'warden', ['scope' => 'backchannel'], 'session_revoked', ['scope' => 'backchannel', 'source' => 'warden']],
    'scim provisioned' => ['scim.provisioned', 'warden', ['trigger' => 'scim'], 'scim_provisioned', ['trigger' => 'scim', 'source' => 'warden']],
    'scim deprovisioned' => ['scim.deprovisioned', 'warden', ['trigger' => 'jit'], 'scim_deprovisioned', ['trigger' => 'jit', 'source' => 'warden']],
]);

it('strips a neutral details key not on the mapped class allowlist', function() {
    $sink = new AuthKitAuditSink();

    // `scope` is not allowed on `auth_login` — only method/provider/source are.
    $sink->handle(new AuthEvent(
        name: AuthEvent::LOGIN_SSO,
        emitter: 'warden',
        details: ['provider' => 'okta', 'scope' => 'should-be-stripped'],
    ));

    $details = ppAuditDetails(ppAuditRow('auth_login'));

    expect($details)->toHaveKey('provider');
    expect($details)->not->toHaveKey('scope');
});

// =============================================================================
// Outcome — the neutral outcome maps straight through
// =============================================================================

it('maps the failure outcome onto the row outcome column', function() {
    $sink = new AuthKitAuditSink();

    $sink->handle(new AuthEvent(
        name: AuthEvent::LOGIN_PASSKEY,
        emitter: 'warp',
        outcome: AuthEvent::OUTCOME_FAILURE,
    ));

    expect(ppAuditRow('auth_login')['outcome'])->toBe('failure');
});

// =============================================================================
// Identity — subject userId + acting actorId land on the right columns
// =============================================================================

it('maps userId to the subject and actorId to changedByUserId', function() {
    $subject = UserFactory::admin(['email' => 'sink-subject@craftpulse.test']);
    $actor = UserFactory::admin(['email' => 'sink-actor@craftpulse.test']);

    $sink = new AuthKitAuditSink();

    $sink->handle(new AuthEvent(
        name: AuthEvent::SCIM_DEPROVISIONED,
        emitter: 'warden',
        userId: (int)$subject->id,
        details: ['trigger' => 'scim'],
        actorId: (int)$actor->id,
    ));

    $row = ppAuditRow('scim_deprovisioned');

    expect((int)$row['userId'])->toBe((int)$subject->id);
    expect((int)$row['changedByUserId'])->toBe((int)$actor->id);
});

// =============================================================================
// Forward-compatibility — unknown name dropped silently, no row, no warning
// =============================================================================

it('drops an unknown neutral name silently with no row and no warning', function() {
    $before = (int)(new Query())->from('{{%passwordpolicy_audit_log}}')->count();
    $loggedBefore = count(Craft::getLogger()->messages);

    $sink = new AuthKitAuditSink();

    $sink->handle(new AuthEvent(
        name: 'login.future_method_not_yet_known',
        emitter: 'warp',
    ));

    $after = (int)(new Query())->from('{{%passwordpolicy_audit_log}}')->count();

    expect($after)->toBe($before);

    // The sink returns before touching `logEvent()`, so PP's fail-closed
    // registry never fires its "row dropped" warning for an unknown name.
    $warnings = array_filter(
        array_slice(Craft::getLogger()->messages, $loggedBefore),
        fn(array $m): bool => $m[1] === Logger::LEVEL_WARNING && $m[2] === 'password-policy',
    );

    expect($warnings)->toBeEmpty();
});

it('never throws, even for an unknown name', function() {
    $sink = new AuthKitAuditSink();

    expect(fn() => $sink->handle(new AuthEvent(
        name: 'totally.unknown',
        emitter: 'warp',
    )))->not->toThrow(Throwable::class);
});

// =============================================================================
// End-to-end — register through the real Auth Kit event, record(), assert row
// =============================================================================

it('records end-to-end through the real Auth Kit audit service', function() {
    // A fresh Audit instance assembles its sinks by triggering the
    // class-level EVENT_REGISTER_AUDIT_SINKS — PP's bootstrap registered its
    // listener there via `Event::on(Audit::class, ...)`, so the sink appears
    // without any explicit wiring here. This is the real contract path.
    $audit = new Audit();

    $ppSinks = array_filter(
        $audit->getSinks(),
        static fn($sink): bool => $sink instanceof AuthKitAuditSink,
    );

    expect($ppSinks)->not->toBeEmpty();

    $audit->record(new AuthEvent(
        name: AuthEvent::LOGIN_SSO,
        emitter: 'warden',
        outcome: AuthEvent::OUTCOME_SUCCESS,
        details: ['provider' => 'entra'],
    ));

    $row = ppAuditRow('auth_login');

    expect($row)->not->toBeNull();
    expect($row['source'])->toBe('warden');

    $details = ppAuditDetails($row);
    expect($details['method'])->toBe('sso');
    expect($details['provider'])->toBe('entra');
    expect($details['source'])->toBe('warden');
});
