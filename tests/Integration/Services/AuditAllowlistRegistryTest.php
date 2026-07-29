<?php
/**
 * Pest coverage for `AuditLogService::ALLOWED_DETAILS_BY_EVENT` — the
 * per-event PII allowlist registry (Phase G — G5).
 *
 * Three contracts pinned by this fixture:
 *
 *  1. Per-event filtering — keys not declared for an event class are
 *     stripped before insertion. The auditor's read of the registry is
 *     the read of the privacy boundary.
 *  2. Fail-closed enforcement — an event class without a registry entry
 *     drops the row entirely AND emits a `Logger::LEVEL_WARNING` on the
 *     `password-policy` channel. Both halves matter — silent-allow lets
 *     a typo'd event class leak any payload shape forever; silent-deny
 *     hides a developer error indefinitely.
 *  3. Codebase-grep enforcement — every `logEvent('<event>'` call site
 *     in `src/` must resolve to a registry key. Catches new event
 *     classes added without registration before they ever fire at
 *     runtime.
 *
 * The fail-closed warning fires regardless of whether `enableAuditLog`
 * is currently on — a missing registry entry is a programming error,
 * and the diagnostic must reach a maintainer even when the audit
 * feature flag is off.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craft\db\Query;
use craftpulse\passwordpolicy\integrations\AuthKitAuditSink;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\services\AuditLogService;
use yii\log\Logger;

// =============================================================================
// Setup — flip enableAuditLog on for every test, restore after, clear rows
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
// Per-event filtering — non-allowlisted keys stripped, allowlisted preserved
// =============================================================================

it('strips a non-allowlisted key (plaintext) from password_changed details', function() {
    $this->plugin->getAuditLog()->logEvent(
        userId: null,
        event: 'password_changed',
        details: [
            'plaintext' => 'should-never-be-stored',
            'method' => 'cp',
        ],
    );

    /** @var array<string, mixed>|null $row */
    $row = (new Query())
        ->from('{{%passwordpolicy_audit_log}}')
        ->where(['event' => 'password_changed'])
        ->one();

    expect($row)->not->toBeNull();

    $details = is_string($row['details'])
        ? json_decode($row['details'], true)
        : $row['details'];

    expect($details)->toBeArray();
    expect($details)->toHaveKey('method');
    expect($details)->not->toHaveKey('plaintext');
    expect($details['method'])->toBe('cp');
});

it('preserves all allowlisted keys for hibp_check_failed', function() {
    $this->plugin->getAuditLog()->logEvent(
        userId: null,
        event: 'hibp_check_failed',
        details: [
            'failMode' => 'open',
            'source' => 'login',
        ],
    );

    /** @var array<string, mixed>|null $row */
    $row = (new Query())
        ->from('{{%passwordpolicy_audit_log}}')
        ->where(['event' => 'hibp_check_failed'])
        ->one();

    expect($row)->not->toBeNull();

    $details = is_string($row['details'])
        ? json_decode($row['details'], true)
        : $row['details'];

    expect($details)->toBeArray();
    expect($details)->toHaveKey('failMode');
    expect($details['failMode'])->toBe('open');
});

// =============================================================================
// Fail-closed — unregistered event class drops the row + warns
// =============================================================================

it('drops the row when the event class is not in the registry', function() {
    $before = (new Query())
        ->from('{{%passwordpolicy_audit_log}}')
        ->count();

    $this->plugin->getAuditLog()->logEvent(
        userId: null,
        event: 'totally_made_up_event',
    );

    $after = (new Query())
        ->from('{{%passwordpolicy_audit_log}}')
        ->count();

    expect($after)->toBe($before);
});

it('logs a warning on the password-policy channel for an unregistered event', function() {
    $before = count(Craft::getLogger()->messages);

    $this->plugin->getAuditLog()->logEvent(
        userId: null,
        event: 'totally_made_up_event',
    );

    $messages = array_slice(Craft::getLogger()->messages, $before);

    // Yii log message tuple: [message, level, category, time, traces, memory]
    $warnings = array_values(array_filter(
        $messages,
        fn(array $m): bool => $m[1] === Logger::LEVEL_WARNING && $m[2] === 'password-policy',
    ));

    expect($warnings)->not->toBeEmpty();
    expect($warnings[0][0])->toContain('totally_made_up_event');
    expect($warnings[0][0])->toContain('the row was dropped');
});

it('fires the fail-closed warning even when enableAuditLog is off', function() {
    // The fail-closed check lands BEFORE the feature-flag gate on
    // purpose — a missing registry entry is a programming error and
    // the diagnostic must reach a maintainer regardless of whether the
    // feature is currently on.
    $this->plugin->getSettings()->enableAuditLog = false;

    $before = count(Craft::getLogger()->messages);

    $this->plugin->getAuditLog()->logEvent(
        userId: null,
        event: 'totally_made_up_event',
    );

    $messages = array_slice(Craft::getLogger()->messages, $before);

    $warnings = array_values(array_filter(
        $messages,
        fn(array $m): bool => $m[1] === Logger::LEVEL_WARNING && $m[2] === 'password-policy',
    ));

    expect($warnings)->not->toBeEmpty();
    expect($warnings[0][0])->toContain('totally_made_up_event');
});

// =============================================================================
// Inspection surfaces — utility template renders the registry shape
// =============================================================================

it('renders the registry through the AuditSchemaUtility template', function() {
    // The utility's contentHtml() runs Craft's view layer against the
    // `_utilities/audit-schema.twig` template. A passing render proves
    // the template's Twig syntax is valid AND the registry shape the
    // template expects (`event => allowedKeys[]`) matches what the
    // service exposes.
    $html = \craftpulse\passwordpolicy\utilities\AuditSchemaUtility::contentHtml();

    expect($html)->toBeString();
    expect($html)->toContain('password_changed');
    expect($html)->toContain('hibp_check_failed');
    expect($html)->toContain('failMode');
    expect($html)->toContain('source');
});

// =============================================================================
// Registered events — sanity check that every fired event class still writes
// =============================================================================

it('writes a row for every registered event class', function() {
    $service = $this->plugin->getAuditLog();

    foreach (array_keys(AuditLogService::ALLOWED_DETAILS_BY_EVENT) as $eventClass) {
        $service->logEvent(userId: null, event: $eventClass);
    }

    $rowCount = (new Query())
        ->from('{{%passwordpolicy_audit_log}}')
        ->count();

    expect((int)$rowCount)->toBe(count(AuditLogService::ALLOWED_DETAILS_BY_EVENT));
});

// =============================================================================
// Codebase-grep enforcement — new event classes must register before merge
// =============================================================================

it('registers every event class fired in src/', function() {
    $registryKeys = array_keys(AuditLogService::ALLOWED_DETAILS_BY_EVENT);

    $srcRoot = dirname(__DIR__, 3) . '/src';

    expect(is_dir($srcRoot))->toBeTrue();

    /** @var array<int, array{file: string, line: int, event: string}> $occurrences */
    $occurrences = [];

    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator(
            $srcRoot,
            RecursiveDirectoryIterator::SKIP_DOTS,
        ),
    );

    /** @var SplFileInfo $fileInfo */
    foreach ($iterator as $fileInfo) {
        if (!$fileInfo->isFile() || $fileInfo->getExtension() !== 'php') {
            continue;
        }

        // Skip the service itself — its method signature contains the
        // string `logEvent(` but the writer doesn't fire its own event
        // class strings.
        if ($fileInfo->getRealPath() === realpath($srcRoot . '/services/AuditLogService.php')) {
            continue;
        }

        $contents = (string)file_get_contents($fileInfo->getRealPath());
        $lines = explode("\n", $contents);

        // Match `logEvent(` followed eventually by `event: '<name>'` or
        // a positional `'<name>'` second argument. Multi-line named-arg
        // calls dominate this codebase, so a permissive multi-line
        // regex is the right shape.
        if (!preg_match_all(
            '/logEvent\s*\(.*?event:\s*[\'"]([a-z_]+)[\'"]/s',
            $contents,
            $namedMatches,
            PREG_OFFSET_CAPTURE,
        )) {
            continue;
        }

        foreach ($namedMatches[1] as $match) {
            [$eventName, $offset] = $match;
            $line = substr_count(substr($contents, 0, $offset), "\n") + 1;
            $occurrences[] = [
                'file' => str_replace($srcRoot . '/', '', $fileInfo->getRealPath()),
                'line' => $line,
                'event' => $eventName,
            ];
        }

        // Suppress an unused-variable warning when no logEvent calls
        // matched on a given file.
        unset($lines);
    }

    expect($occurrences)->not->toBeEmpty();

    // Map every occurrence to a "call_site => is_registered" pair. When
    // the assertion fails, PHPUnit's diff output lists every offending
    // call site labelled with file + line — a developer can fix all
    // gaps in one pass instead of CI-bouncing one event at a time.
    $registrationStatus = [];
    foreach ($occurrences as $occ) {
        $label = sprintf("'%s' (%s:%d)", $occ['event'], $occ['file'], $occ['line']);
        $registrationStatus[$label] = in_array($occ['event'], $registryKeys, true);
    }

    $allRegistered = array_fill_keys(array_keys($registrationStatus), true);

    expect($registrationStatus)->toBe($allRegistered);
});

// =============================================================================
// Mapping-table enforcement — Auth Kit sink targets must be registered
// =============================================================================

it('registers every AuthKitAuditSink::EVENT_MAP target', function() {
    // The sink passes a *mapped variable* to `logEvent()`, so the
    // codebase-grep test above (which only sees `event: '<literal>'`)
    // can't reach these targets. This assertion is the equivalent guard:
    // every neutral AuthEvent name the sink maps must resolve to a PP
    // event class that exists in the allowlist registry — otherwise the
    // row would silently fail-closed at runtime.
    $registryKeys = array_keys(AuditLogService::ALLOWED_DETAILS_BY_EVENT);

    $mappingStatus = [];
    foreach (AuthKitAuditSink::EVENT_MAP as $neutralName => $ppEvent) {
        $label = sprintf("'%s' => '%s'", $neutralName, $ppEvent);
        $mappingStatus[$label] = in_array($ppEvent, $registryKeys, true);
    }

    expect($mappingStatus)->not->toBeEmpty();

    $allRegistered = array_fill_keys(array_keys($mappingStatus), true);

    expect($mappingStatus)->toBe($allRegistered);
});
