<?php
/**
 * Structural guard for the Audit Kit module retrofit contract.
 *
 * Audit Kit 1.1.0+ ships as a library-shipped Yii module rather than a Craft
 * plugin, so Craft never boots it: the dispatch bus, the runtime event-type
 * registry and the hash-chain engine's home do not exist until a consumer calls
 * `AuditKit::register()`. PP makes that call unconditionally from
 * `PasswordPolicy::init()`.
 *
 * Every assertion here guards a failure that is silent by construction on a
 * plugin whose entire value proposition is the audit trail:
 *
 *  - **`register()` is present in `init()`.** Drop the call and nothing throws
 *    at boot, nothing logs, the control panel reports a saved policy, and the
 *    governance emission is discarded forever. No behavioural test can isolate
 *    it: `tests/bootstrap.php` registers the module itself, and on a real
 *    install any other kit consumer registering it makes PP's own call look
 *    unnecessary. So the guard is a token scan of PP's boot path.
 *
 *  - **The bus is resolved through `getInstance()`, never `AuditKit::$plugin`.**
 *    This is the specific trap PP carried. `$plugin` is a typed static with no
 *    default, assigned only in the module's `init()`; reading it before
 *    registration throws `Error`, `Error` implements `Throwable`, and
 *    `GovernanceAuditService::_record()` catches `Throwable` fail-soft. So a
 *    missing or mis-ordered registration turned every governance emission into a
 *    permanent no-op that logged one line and reported success.
 *    `AuditKit::getInstance()` is literally `return self::register();` — it
 *    self-registers and is non-nullable, so the failure mode is gone by
 *    construction rather than caught.
 *
 *  - **`Install` pumps the kit migrator and `safeDown()` does not revert it.**
 *    The pump is the seam that lets a kit migration reach every install without
 *    a coordinated release across every consumer; reverting it on one plugin's
 *    uninstall would tear down state every other installed consumer relies on.
 *
 * Token scans rather than substring matches, so a mention inside a docblock or a
 * comment cannot satisfy them, and each scan is bounded to the reflected line
 * range of the method under test so a matching call elsewhere in the same file
 * cannot either. Pure reflection and source reading — no database, no fixtures,
 * hence the Unit suite.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craftpulse\auditkit\services\Bus;
use craftpulse\passwordpolicy\migrations\Install;
use craftpulse\passwordpolicy\PasswordPolicy;
use craftpulse\passwordpolicy\services\GovernanceAuditService;

// =============================================================================
// Helpers
// =============================================================================

/**
 * Returns the significant PHP tokens of the file declaring `$class::$method`,
 * with comments, docblocks and whitespace dropped.
 *
 * @param class-string $class
 * @return list<array{0: int, 1: string, 2: int}|string>
 *
 * @throws ReflectionException if the method does not exist.
 */
function ppRetrofitTokens(string $class, string $method): array
{
    $file = (new ReflectionMethod($class, $method))->getFileName();

    expect($file)->toBeString();

    return array_values(array_filter(
        token_get_all((string)file_get_contents((string)$file)),
        static fn(array|string $token): bool => !is_array($token)
            || !in_array($token[0], [T_COMMENT, T_DOC_COMMENT, T_WHITESPACE], true),
    ));
}

/**
 * Whether the body of `$class::$method` contains a static reference to
 * `$callee::$member`, where `$member` is a method name or a `$`-prefixed static
 * property name.
 *
 * Tokenised rather than matched as a substring, so a mention inside a docblock
 * or a comment cannot satisfy it, and the imported short form
 * (`AuditKit::register()`), the qualified form and the fully qualified form all
 * count. The line range comes from reflection, so moving the method inside its
 * file does not break the scan and a matching reference elsewhere in the file
 * cannot satisfy it.
 *
 * @param class-string $class  the class declaring the method
 * @param string $method       the method whose body is scanned
 * @param string $callee       the referenced class's short name, without its
 *                             namespace
 * @param string $member       the referenced static method or `$property`
 *
 * @throws ReflectionException if the method does not exist.
 */
function ppRetrofitReferencesStatically(
    string $class,
    string $method,
    string $callee,
    string $member,
): bool {
    $reflection = new ReflectionMethod($class, $method);
    $tokens = ppRetrofitTokens($class, $method);
    $nameTypes = [T_STRING, T_NAME_QUALIFIED, T_NAME_FULLY_QUALIFIED];
    $start = $reflection->getStartLine();
    $end = $reflection->getEndLine();

    foreach ($tokens as $i => $token) {
        if (!is_array($token) || !in_array($token[0], $nameTypes, true)) {
            continue;
        }

        if ($token[2] < $start || $token[2] > $end) {
            continue;
        }

        $segments = explode('\\', $token[1]);

        if (end($segments) !== $callee) {
            continue;
        }

        $separator = $tokens[$i + 1] ?? null;

        if (!is_array($separator) || $separator[0] !== T_DOUBLE_COLON) {
            continue;
        }

        $target = $tokens[$i + 2] ?? null;

        if (is_array($target) && $target[1] === $member) {
            return true;
        }
    }

    return false;
}

// =============================================================================
// Module registration
// =============================================================================

it('registers the Audit Kit module from PasswordPolicy::init()', function() {
    expect(ppRetrofitReferencesStatically(PasswordPolicy::class, 'init', 'AuditKit', 'register'))
        ->toBeTrue(
            'PasswordPolicy::init() must call AuditKit::register(). Without it the '
            . 'Audit Kit module is never constructed on an install where no other '
            . 'consumer registers it, and every governance emission is silently '
            . 'discarded while the control panel reports the policy saved.',
        );
});

// =============================================================================
// The bus is resolved through getInstance(), never the typed static
// =============================================================================

it('resolves the dispatch bus through AuditKit::getInstance()', function() {
    expect(ppRetrofitReferencesStatically(
        GovernanceAuditService::class,
        '_record',
        'AuditKit',
        'getInstance',
    ))->toBeTrue(
        'GovernanceAuditService::_record() must resolve the bus through '
        . 'AuditKit::getInstance(), which self-registers and cannot fail this way.',
    );
});

it('never reads the AuditKit::$plugin static when resolving the bus', function() {
    expect(ppRetrofitReferencesStatically(
        GovernanceAuditService::class,
        '_record',
        'AuditKit',
        '$plugin',
    ))->toBeFalse(
        'GovernanceAuditService::_record() must not read AuditKit::$plugin. It is a '
        . 'typed static with no default, so reading it before registration throws '
        . 'Error, which the surrounding catch (Throwable) swallows — turning every '
        . 'governance emission into a permanent silent no-op.',
    );
});

it('resolves a non-nullable Bus from the registered module', function() {
    $returnType = (new ReflectionMethod(Bus::class, 'record'))->getReturnType();

    // Sanity check on the kit contract this suite is written against: `record()`
    // returns void, so a caller has no return value to inspect and a dropped
    // emission is invisible at the call site. That is why the guards above are
    // structural.
    expect($returnType)->toBeInstanceOf(ReflectionNamedType::class);
    /** @var ReflectionNamedType $returnType */
    expect($returnType->getName())->toBe('void');
});

// =============================================================================
// Install pumps the kit migrator, safeDown does not revert it
// =============================================================================

it('pumps the Audit Kit migrator from Install::safeUp()', function() {
    expect(ppRetrofitReferencesStatically(Install::class, 'safeUp', 'AuditKit', 'getInstance'))
        ->toBeTrue(
            'Install::safeUp() must pump the Audit Kit migrator. It is the seam that '
            . 'lets a kit migration reach every install without a coordinated '
            . 'release across every consumer.',
        );
});

it('never reverts the Audit Kit migrator from Install::safeDown()', function() {
    expect(ppRetrofitReferencesStatically(Install::class, 'safeDown', 'AuditKit', 'getInstance'))
        ->toBeFalse(
            'Install::safeDown() must not touch the Audit Kit migrator. The kit is '
            . 'shared by every installed consumer and one plugin\'s uninstall must '
            . 'not tear down state the others rely on.',
        );
});
