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
use craftpulse\passwordpolicy\PasswordPolicy;
use yii\console\ExitCode;
use yii\db\Exception;

/**
 * Reseeds the bundled common-password list, imports custom words, and reports totals.
 *
 * The blocklist has two halves. `update` refreshes the bundled common-password
 * list from the data file that ships with the plugin, which is what you run
 * after a plugin update. `import` loads a newline-delimited word list into the
 * custom half, the same store the control panel blocklist editor writes to, and
 * requires the Pro edition. `stats` reports the size of both halves and when the
 * common list was last seeded.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class BlocklistController extends Controller
{
    // Public Properties
    // =========================================================================

    /**
     * @var string|null path to a text file with one word per line for import
     */
    public ?string $file = null;

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

        if ($actionID === 'import') {
            $options[] = 'file';
        }

        return $options;
    }

    /**
     * Re-seeds common passwords from the bundled data file.
     *
     * Run after plugin updates to refresh the common passwords list.
     *
     * @return int
     *
     * @throws Exception
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionUpdate(): int
    {
        $this->stdout("Seeding common passwords from bundled data file...\n");

        $count = PasswordPolicy::$plugin->getBlocklist()->seedCommonPasswords();

        $this->stdout("Done. {$count} common passwords loaded.\n");

        return ExitCode::OK;
    }

    /**
     * Imports custom words from a text file (one word per line).
     *
     * @return int
     *
     * @throws Exception
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionImport(): int
    {
        // The custom blocklist editor is a Pro feature. The console surface
        // can't tolerate exception-driven control flow, so it gates with a
        // graceful stderr + non-zero exit rather than letting the throw in
        // `BlocklistService::addCustomWord()` surface mid-import.
        if (!PasswordPolicy::$plugin->getIsPro()) {
            $this->stderr("Error: Custom blocklist import requires the Pro edition.\n");
            return ExitCode::UNSPECIFIED_ERROR;
        }

        if ($this->file === null) {
            $this->stderr("Error: --file option is required.\n");
            return ExitCode::USAGE;
        }

        if (!file_exists($this->file)) {
            $this->stderr("Error: File not found: {$this->file}\n");
            return ExitCode::IOERR;
        }

        $lines = file($this->file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

        if ($lines === false) {
            $this->stderr("Error: Could not read file: {$this->file}\n");
            return ExitCode::IOERR;
        }

        $added = 0;
        $skipped = 0;
        $service = PasswordPolicy::$plugin->getBlocklist();

        foreach ($lines as $word) {
            if ($service->addCustomWord($word)) {
                $added++;
            } else {
                $skipped++;
            }
        }

        $this->stdout("Done. {$added} words added, {$skipped} duplicates skipped.\n");

        return ExitCode::OK;
    }

    /**
     * Shows blocklist statistics by source.
     *
     * @return int
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function actionStats(): int
    {
        $service = PasswordPolicy::$plugin->getBlocklist();

        $commonCount = $service->getCommonCount();
        $customResult = $service->getCustomWords(1, 1);
        $customCount = $customResult['total'];
        $lastUpdated = $service->getLastUpdated();

        $this->stdout("Blocklist Statistics:\n");
        $this->stdout("  Common passwords: {$commonCount}\n");
        $this->stdout("  Custom words: {$customCount}\n");
        $this->stdout("  Total: " . ($commonCount + $customCount) . "\n");

        if ($lastUpdated !== null) {
            $this->stdout("  Last updated: " . $lastUpdated->format('Y-m-d H:i:s') . "\n");
        }

        return ExitCode::OK;
    }
}
