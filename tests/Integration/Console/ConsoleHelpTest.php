<?php
/**
 * Pest coverage for the operator-facing help text of every console controller.
 *
 * Yii renders console docblocks VERBATIM as terminal help, and it does so by
 * physical line rather than by sentence: `Controller::parseDocCommentSummary()`
 * returns line 2 of the class docblock as the command-group summary printed by
 * `craft help`, and the same method reads line 2 of an action method's docblock
 * as that action's description. A class docblock that opens with
 * `Class GcController` therefore makes `craft help password-policy` advertise a
 * PHP class name where the command's purpose belongs, and an action docblock
 * that merely restates its own method name is the same defect one level down.
 *
 * The assertions run against Yii's own `getHelpSummary()` / `getHelp()` /
 * `getActionHelpSummary()` rather than shelling out to `craft help`, because
 * those are the methods `craft help` calls and they need no installed,
 * enabled plugin in a playground to answer.
 *
 * The dash test covers the same terminal surface from the other side: the estate
 * copy rule bans em-dashes and en-dashes from anything a human reads, and console
 * `stdout()` / `stderr()` output is exactly that. It tokenises each controller so
 * only real string literals are inspected, which keeps code comments and PHPDoc
 * (both exempt) out of the result.
 *
 * Pins:
 *
 *  - Every console controller's help summary is a sentence about the command
 *    group, never a class name.
 *  - Every action's help summary is a sentence about the action, never a
 *    restatement of its method name.
 *  - No console output string carries an em-dash or an en-dash.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craftpulse\passwordpolicy\console\controllers\AuditController;
use craftpulse\passwordpolicy\console\controllers\BlocklistController;
use craftpulse\passwordpolicy\console\controllers\GcController;
use craftpulse\passwordpolicy\console\controllers\InactiveController;
use craftpulse\passwordpolicy\console\controllers\NotificationController;
use craftpulse\passwordpolicy\console\controllers\RetentionController;
use craftpulse\passwordpolicy\console\controllers\SiemController;
use craftpulse\passwordpolicy\console\controllers\WebhookController;
use craftpulse\passwordpolicy\PasswordPolicy;
use yii\helpers\Inflector;

// =============================================================================
// Helpers
// =============================================================================

/**
 * Every console controller the plugin ships, keyed by the controller id that
 * appears in `craft help password-policy`.
 *
 * @return array<string, class-string<\craft\console\Controller>>
 */
function consoleControllerMap(): array
{
    return [
        'audit' => AuditController::class,
        'blocklist' => BlocklistController::class,
        'gc' => GcController::class,
        'inactive' => InactiveController::class,
        'notification' => NotificationController::class,
        'retention' => RetentionController::class,
        'siem' => SiemController::class,
        'webhook' => WebhookController::class,
    ];
}

/**
 * Returns the action ids a controller exposes, derived the way Yii derives
 * them: every public `action*()` method, hyphenated.
 *
 * @param class-string<\craft\console\Controller> $class
 * @return array<int, string>
 */
function consoleActionIds(string $class): array
{
    $ids = [];

    foreach ((new ReflectionClass($class))->getMethods(ReflectionMethod::IS_PUBLIC) as $method) {
        if ($method->isStatic() || !str_starts_with($method->name, 'action')) {
            continue;
        }

        // Yii's own rule: `action` followed by an upper-case character. Without
        // the case check, `actions()` would be mistaken for an `s` action.
        $suffix = substr($method->name, 6);

        if ($suffix === '' || $suffix !== ucfirst($suffix)) {
            continue;
        }

        $ids[] = Inflector::camel2id($suffix);
    }

    sort($ids);

    return $ids;
}

/**
 * Counts whitespace-separated words in a rendered help string.
 */
function helpWordCount(string $text): int
{
    return count(preg_split('/\s+/', trim($text), -1, PREG_SPLIT_NO_EMPTY) ?: []);
}

/**
 * Dataset over every console controller, named by controller id so a failure
 * report names the command rather than a dataset index.
 *
 * @return Generator<string, array{string, class-string<\craft\console\Controller>}>
 */
function consoleControllerDataset(): Generator
{
    foreach (consoleControllerMap() as $id => $class) {
        yield $id => [$id, $class];
    }
}

/**
 * Returns every string literal in a PHP file, comments and docblocks excluded.
 * `token_get_all()` is used rather than a regex so a dash inside a line comment
 * or a docblock can't be mistaken for output copy.
 *
 * @return array<int, string>
 */
function phpStringLiterals(string $path): array
{
    $literals = [];
    $interesting = [T_CONSTANT_ENCAPSED_STRING, T_ENCAPSED_AND_WHITESPACE];

    foreach (token_get_all((string)file_get_contents($path)) as $token) {
        if (is_array($token) && in_array($token[0], $interesting, true)) {
            $literals[] = $token[1];
        }
    }

    return $literals;
}

// =============================================================================
// Command-group summaries — `craft help` reads line 2 of the class docblock
// =============================================================================

it('renders a command summary rather than a class name', function(string $id, string $class) {
    $controller = new $class($id, PasswordPolicy::$plugin);
    $shortName = (new ReflectionClass($class))->getShortName();

    $summary = $controller->getHelpSummary();

    expect($summary)->not->toBe('')
        ->and($summary)->not->toStartWith('Class ')
        ->and($summary)->not->toContain($shortName)
        ->and($summary)->toEndWith('.')
        ->and(helpWordCount($summary))->toBeGreaterThanOrEqual(3);

    // `getHelp()` is the body `craft help <command>` prints. Yii builds it from
    // the same docblock, so a class name on line 2 leaks into it as well.
    $help = $controller->getHelp();

    expect($help)->not->toBe('')
        ->and($help)->not->toStartWith('Class ')
        ->and($help)->not->toContain($shortName);
})->with(consoleControllerDataset());

// =============================================================================
// Action summaries — the same line-2 read, one level down
// =============================================================================

it('renders an action summary rather than a method name', function(string $id, string $class) {
    $controller = new $class($id, PasswordPolicy::$plugin);
    $actionIds = consoleActionIds($class);

    expect($actionIds)->not->toBeEmpty();

    foreach ($actionIds as $actionId) {
        $action = $controller->createAction($actionId);

        expect($action)->not->toBeNull("{$id}/{$actionId} has no resolvable action");

        $summary = $controller->getActionHelpSummary($action);
        $methodName = 'action' . Inflector::id2camel($actionId);

        expect($summary)->not->toBe('', "{$id}/{$actionId} has an empty help summary")
            ->and($summary)->not->toStartWith('Class ')
            ->and($summary)->not->toContain($methodName)
            ->and($summary)->toEndWith('.')
            // A one-word restatement of the method name tells an operator
            // nothing. Five words is the floor for a real sentence.
            ->and(helpWordCount($summary))
            ->toBeGreaterThanOrEqual(5, "{$id}/{$actionId} help summary is too thin: {$summary}");
    }
})->with(consoleControllerDataset());

// =============================================================================
// Copy rule — no em-dashes or en-dashes in anything the operator reads
// =============================================================================

it('carries no em-dash or en-dash in any console output string', function() {
    $offenders = [];

    foreach (glob(dirname(__DIR__, 3) . '/src/console/controllers/*.php') ?: [] as $path) {
        foreach (phpStringLiterals($path) as $literal) {
            if (str_contains($literal, '—') || str_contains($literal, '–')) {
                $offenders[] = basename($path) . ': ' . trim($literal);
            }
        }
    }

    expect($offenders)->toBe([]);
});
