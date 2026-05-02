<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Non-transactional Pest TestCase for multi-site tests that need to fire
 * `Sites::EVENT_AFTER_SAVE_SITE` and `EVENT_AFTER_DELETE_SITE` against a
 * real Craft `Sites` service.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\tests\Support;

use Craft;
use craftpulse\passwordpolicy\tests\TestCase;
use Throwable;

/**
 * Base TestCase for multi-site tests (T9.7).
 *
 * Site creation and deletion go through `craft\services\Sites::saveSite()`
 * and `deleteSite()`, which write to `Craft::$app->getProjectConfig()`.
 * Project-config writes commit immediately and bypass the standard test
 * transaction wrapper. This subclass therefore opts out of the transaction
 * and takes responsibility for cleanup in `tearDown`.
 *
 * `tearDown` walks every site that isn't the primary site and deletes it
 * via `deleteSiteById()`. The cleanup is best-effort — a deleted site that
 * already gone (because the test deleted it itself) is silently skipped.
 *
 * `Sites::refreshSites()` is called both before each test (to make the
 * service drop any stale cached results from a prior test) and after each
 * cleanup so the next test boots from a single-site baseline.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
abstract class MultiSiteTestCase extends TestCase
{
    // Protected Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected function setUp(): void
    {
        parent::setUp();

        // Belt-and-braces: clear any stale `Sites::$_allSitesById` state
        // left by a prior test that mutated sites without cleaning up.
        Craft::$app->getSites()->refreshSites();
    }

    /**
     * @inheritdoc
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected function tearDown(): void
    {
        $this->deleteAllNonPrimarySites();

        parent::tearDown();
    }

    /**
     * Multi-site tests run outside the standard transaction wrap because
     * site saves trigger project-config writes that bypass DB transactions.
     *
     * @return bool
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected function usesTransaction(): bool
    {
        return false;
    }

    /**
     * Walks every site that isn't the primary and deletes it, swallowing
     * exceptions so a partial failure doesn't poison adjacent tests.
     *
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    protected function deleteAllNonPrimarySites(): void
    {
        $sites = Craft::$app->getSites();
        $sites->refreshSites();

        $primaryId = $sites->getPrimarySite()->id;

        foreach ($sites->getAllSites(true) as $site) {
            if ($site->id === $primaryId) {
                continue;
            }

            try {
                $sites->deleteSiteById($site->id);
            } catch (Throwable) {
                // Swallow — best-effort cleanup. A failed delete is logged
                // by Craft and the next test starts fresh anyway because
                // the site IDs increment.
            }
        }

        $sites->refreshSites();
    }
}
