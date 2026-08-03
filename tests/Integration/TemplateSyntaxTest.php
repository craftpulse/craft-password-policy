<?php
/**
 * Compiles every CP template the plugin ships and fails on a syntax error.
 *
 * The suite renders a handful of content-only templates (see
 * PasswordSecurityTabTest), but most plugin templates extend the CP layout,
 * which a console-bootstrapped process can't render. That leaves whole-file
 * restructures (unwrapping an `{% if %}`, re-indenting a block, moving a
 * `{% set %}`) with no automated guard: an unbalanced tag would only surface
 * the next time someone opened the page in a browser.
 *
 * Parsing catches exactly that class of mistake without needing CP chrome.
 * `Twig\Environment::parse(tokenize(...))` resolves the file's own syntax and
 * leaves `extends` / `include` targets to runtime, so this is a pure syntax
 * check over the whole `src/templates` tree, macros and partials included.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 *
 * @author    CraftPulse
 * @since     5.2.0
 */

use craft\web\View;
use Twig\Error\SyntaxError;
use Twig\Source;

// =============================================================================
// Helpers
// =============================================================================

/**
 * Absolute paths of every Twig file the plugin ships, relative-path keyed so a
 * failure names the template rather than an index.
 *
 * @return array<string, string>
 */
function ppTemplateFiles(): array
{
    $root = dirname(__DIR__, 2) . '/src/templates';

    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
    );

    $files = [];

    /** @var SplFileInfo $file */
    foreach ($iterator as $file) {
        if ($file->getExtension() !== 'twig') {
            continue;
        }

        $files[substr($file->getPathname(), strlen($root) + 1)] = $file->getPathname();
    }

    ksort($files);

    return $files;
}

// =============================================================================
// Syntax
// =============================================================================

it('compiles every CP template without a syntax error', function() {
    $view = Craft::$app->getView();
    $oldMode = $view->getTemplateMode();
    $view->setTemplateMode(View::TEMPLATE_MODE_CP);

    $errors = [];

    try {
        $twig = $view->getTwig();

        foreach (ppTemplateFiles() as $name => $path) {
            try {
                $twig->parse($twig->tokenize(new Source((string)file_get_contents($path), $name)));
            } catch (SyntaxError $e) {
                $errors[] = sprintf('%s: %s (line %d)', $name, $e->getRawMessage(), $e->getTemplateLine());
            }
        }
    } finally {
        $view->setTemplateMode($oldMode);
    }

    expect($errors)->toBe([]);
});

it('finds templates to compile', function() {
    // Guards the guard: an empty sweep would make the assertion above pass
    // without compiling anything.
    expect(ppTemplateFiles())->not->toBeEmpty();
});
