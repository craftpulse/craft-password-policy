<?php
/**
 * Pest coverage for the per-cell HTML rendering surface of
 * `UserIndexService::renderAttributeHtml()`. Per memory rule
 * `feedback_native_callout_components.md` we render via Craft's
 * native `<span class="status">` / `<span class="status red">` /
 * etc. semantics rather than hand-rolled markup; the tests assert
 * structure (class names, key text) and avoid pinning exact strings
 * so locale- or formatter-driven cosmetic shifts don't churn fixtures.
 *
 * Each test seeds a deliberate user state via the existing factories,
 * preloads the cache, and asserts the rendered cell.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use Carbon\Carbon;
use craft\db\Table;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\services\UserIndexService;
use craftpulse\passwordpolicy\tests\Support\Factories\UserFactory;

// =============================================================================
// Setup / teardown
// =============================================================================

beforeEach(function() {
    $this->plugin = PasswordPolicy::$plugin;
    $this->service = $this->plugin->getUserIndex();
    $this->settings = $this->plugin->getSettings();

    $this->originalEdition = $this->plugin->edition;
    $this->originalCraftEdition = Craft::$app->edition;
    $this->originalExpiryAmount = $this->settings->expiryAmount;
    $this->originalExpiryPeriod = $this->settings->expiryPeriod;

    $this->plugin->edition = PasswordPolicy::EDITION_LITE;
});

afterEach(function() {
    $this->plugin->edition = $this->originalEdition;
    Craft::$app->edition = $this->originalCraftEdition;
    $this->settings->expiryAmount = $this->originalExpiryAmount;
    $this->settings->expiryPeriod = $this->originalExpiryPeriod;
    $this->service->resetCache();
});

// =============================================================================
// Last change cell
// =============================================================================

it('renders the lastChange cell as "Never" when no password change is recorded', function() {
    $user = UserFactory::admin();
    seedLastChange($user, null);

    $this->service->preloadForUsers([$user->id]);
    $html = $this->service->renderAttributeHtml($user, UserIndexService::ATTR_LAST_CHANGE);

    expect($html)
        ->toContain('class="light"')
        ->and($html)->toContain('Never');
});

it('renders the lastChange cell as a formatted datetime when set', function() {
    $user = UserFactory::admin();
    $when = Carbon::now('UTC')->subDays(5);
    seedLastChange($user, $when);

    $this->service->preloadForUsers([$user->id]);
    $html = $this->service->renderAttributeHtml($user, UserIndexService::ATTR_LAST_CHANGE);

    expect($html)->toBeString()
        ->and($html)->not->toContain('Never');
});

// =============================================================================
// Days until expiry cell
// =============================================================================

it('renders the daysUntilExpiry cell as a muted dash when expiry is not configured', function() {
    $user = UserFactory::admin();
    $this->settings->expiryAmount = null;
    seedLastChange($user, Carbon::now('UTC')->subDays(3));

    $this->service->preloadForUsers([$user->id]);
    $html = $this->service->renderAttributeHtml($user, UserIndexService::ATTR_DAYS_UNTIL_EXPIRY);

    expect($html)->toContain('—')
        ->and($html)->toContain('class="light"');
});

it('renders the daysUntilExpiry cell green when remaining days exceed seven', function() {
    $user = UserFactory::admin();
    $this->settings->expiryAmount = 90;
    $this->settings->expiryPeriod = 'day';
    seedLastChange($user, Carbon::now('UTC')->subDays(10));

    $this->service->preloadForUsers([$user->id]);
    $html = $this->service->renderAttributeHtml($user, UserIndexService::ATTR_DAYS_UNTIL_EXPIRY);

    expect($html)->toContain('status green');
});

it('renders the daysUntilExpiry cell red when the password is past expiry', function() {
    $user = UserFactory::admin();
    $this->settings->expiryAmount = 10;
    $this->settings->expiryPeriod = 'day';
    seedLastChange($user, Carbon::now('UTC')->subDays(60));

    $this->service->preloadForUsers([$user->id]);
    $html = $this->service->renderAttributeHtml($user, UserIndexService::ATTR_DAYS_UNTIL_EXPIRY);

    expect($html)->toContain('status red');
});

it('renders the daysUntilExpiry cell orange within the seven-day soon-to-expire window', function() {
    $user = UserFactory::admin();
    $this->settings->expiryAmount = 30;
    $this->settings->expiryPeriod = 'day';
    seedLastChange($user, Carbon::now('UTC')->subDays(28));

    $this->service->preloadForUsers([$user->id]);
    $html = $this->service->renderAttributeHtml($user, UserIndexService::ATTR_DAYS_UNTIL_EXPIRY);

    expect($html)->toContain('status orange');
});

// =============================================================================
// Expired cell
// =============================================================================

it('renders the expired cell as red Expired when past the threshold', function() {
    $user = UserFactory::admin();
    $this->settings->expiryAmount = 10;
    $this->settings->expiryPeriod = 'day';
    seedLastChange($user, Carbon::now('UTC')->subDays(60));

    $this->service->preloadForUsers([$user->id]);
    $html = $this->service->renderAttributeHtml($user, UserIndexService::ATTR_EXPIRED);

    expect($html)
        ->toContain('status red')
        ->and($html)->toContain('Expired');
});

it('renders the expired cell as muted No when within the threshold', function() {
    $user = UserFactory::admin();
    $this->settings->expiryAmount = 30;
    $this->settings->expiryPeriod = 'day';
    seedLastChange($user, Carbon::now('UTC')->subDays(2));

    $this->service->preloadForUsers([$user->id]);
    $html = $this->service->renderAttributeHtml($user, UserIndexService::ATTR_EXPIRED);

    expect($html)->toContain('No');
});

it('renders the expired cell as muted dash when expiry is not configured', function() {
    $user = UserFactory::admin();
    $this->settings->expiryAmount = null;
    seedLastChange($user, Carbon::now('UTC')->subDays(60));

    $this->service->preloadForUsers([$user->id]);
    $html = $this->service->renderAttributeHtml($user, UserIndexService::ATTR_EXPIRED);

    expect($html)->toContain('—');
});

// =============================================================================
// Reset required cell
// =============================================================================

it('renders the resetRequired cell as orange Yes when set', function() {
    $user = UserFactory::admin();
    seedResetRequired($user, true);

    $this->service->preloadForUsers([$user->id]);
    $html = $this->service->renderAttributeHtml($user, UserIndexService::ATTR_RESET_REQUIRED);

    expect($html)
        ->toContain('status orange')
        ->and($html)->toContain('Yes');
});

it('renders the resetRequired cell as muted No when not set', function() {
    $user = UserFactory::admin();
    seedResetRequired($user, false);

    $this->service->preloadForUsers([$user->id]);
    $html = $this->service->renderAttributeHtml($user, UserIndexService::ATTR_RESET_REQUIRED);

    expect($html)->toContain('No');
});

// =============================================================================
// Last change reason cell
// =============================================================================

it('renders the lastChangeReason cell using the enum label when history exists', function() {
    $user = UserFactory::admin();
    seedHistoryRow($user, reason: 'admin_force_reset');

    $this->service->preloadForUsers([$user->id]);
    $html = $this->service->renderAttributeHtml($user, UserIndexService::ATTR_LAST_CHANGE_REASON);

    expect($html)->toContain('Admin forced reset');
});

it('renders the lastChangeReason cell as muted dash when no history exists', function() {
    $user = UserFactory::admin();

    $this->service->preloadForUsers([$user->id]);
    $html = $this->service->renderAttributeHtml($user, UserIndexService::ATTR_LAST_CHANGE_REASON);

    expect($html)->toContain('—');
});

// =============================================================================
// Status cell — composite badge spot checks
// =============================================================================

it('renders the status cell as red Expired when past expiry', function() {
    $user = UserFactory::admin();
    $this->settings->expiryAmount = 10;
    $this->settings->expiryPeriod = 'day';
    seedLastChange($user, Carbon::now('UTC')->subDays(60));

    $this->service->preloadForUsers([$user->id]);
    $html = $this->service->renderAttributeHtml($user, UserIndexService::ATTR_STATUS);

    expect($html)
        ->toContain('status red')
        ->and($html)->toContain('Expired');
});

it('renders the status cell as green OK when nothing applies', function() {
    $user = UserFactory::admin();
    $this->settings->expiryAmount = 90;
    $this->settings->expiryPeriod = 'day';
    seedLastChange($user, Carbon::now('UTC')->subDays(2));

    $this->service->preloadForUsers([$user->id]);
    $html = $this->service->renderAttributeHtml($user, UserIndexService::ATTR_STATUS);

    expect($html)
        ->toContain('status green')
        ->and($html)->toContain('OK');
});

// =============================================================================
// Unrelated attribute — service short-circuits
// =============================================================================

it('returns null for attributes outside the plugin namespace', function() {
    $user = UserFactory::admin();

    $this->service->preloadForUsers([$user->id]);

    expect($this->service->renderAttributeHtml($user, 'email'))->toBeNull();
});

// =============================================================================
// Helpers — direct DB writes match the production access pattern
// =============================================================================

/**
 * Sets `users.lastPasswordChangeDate` directly in DB. UserQuery
 * doesn't select the column, and saving the User element wouldn't
 * touch it either, so the test path mirrors how the production
 * write site (the password-history listener) updates the column.
 */
function seedLastChange(craft\elements\User $user, ?Carbon $when): void
{
    Craft::$app->getDb()->createCommand()
        ->update(
            Table::USERS,
            ['lastPasswordChangeDate' => $when?->format('Y-m-d H:i:s')],
            ['id' => $user->id],
        )
        ->execute();
}

/**
 * Sets `users.passwordResetRequired` directly in DB. Mirrors the
 * `lastPasswordChangeDate` rationale.
 */
function seedResetRequired(craft\elements\User $user, bool $value): void
{
    Craft::$app->getDb()->createCommand()
        ->update(
            Table::USERS,
            ['passwordResetRequired' => $value ? 1 : 0],
            ['id' => $user->id],
        )
        ->execute();
}

/**
 * Inserts a single password history row with a known `changeReason`
 * so the cell renderers see the expected enum case via the preloader.
 */
function seedHistoryRow(craft\elements\User $user, string $reason, ?string $policySnapshot = null): void
{
    Craft::$app->getDb()->createCommand()
        ->insert('{{%passwordpolicy_password_history}}', [
            'userId' => $user->id,
            'passwordHash' => '$2y$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ012',
            'changeReason' => $reason,
            'policySnapshot' => $policySnapshot,
            'dateCreated' => Carbon::now('UTC')->format('Y-m-d H:i:s'),
            'uid' => craft\helpers\StringHelper::UUID(),
        ])
        ->execute();
}
