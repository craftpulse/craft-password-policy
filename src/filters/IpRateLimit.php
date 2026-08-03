<?php
/**
 * Password policy plugin for Craft CMS
 *
 * Enforce a password policy on your users. This plugin is aimed to make sure users use a password that is secure.
 *
 * @link      https://craftpulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

namespace craftpulse\passwordpolicy\filters;

use Craft;
use yii\base\Action;
use yii\base\BaseObject;
use yii\filters\RateLimitInterface;
use yii\web\Request;

/**
 * Class IpRateLimit
 *
 * Per-IP rate-limit identity for Yii's {@see \yii\filters\RateLimiter} filter,
 * which needs a `RateLimitInterface` implementation to have anything to meter
 * against and does nothing at all without one. Yii resolves that from
 * `Yii::$app->user->getIdentity()` by default, so an anonymous endpoint has no
 * identity and no limit; this class supplies one keyed on the caller's IP.
 *
 * Allowance is tracked in Craft's cache, so the limit is shared across web
 * workers and expires on its own without a garbage-collection pass.
 *
 * ## Why the plugin ships this rather than using Craft's
 *
 * `craft\filters\IpRateLimitIdentity` is the same thing and landed in Craft
 * **5.9.15**. This plugin's `craftcms/cms` constraint is `^5.0.0` and it has
 * paying customers, so depending on that class would raise the floor by nine
 * minor versions to obtain roughly fifty lines whose entire body is a cache
 * read and a cache write. An operator on 5.4 would then be unable to take a
 * security fix without first moving Craft.
 *
 * This is not working around a framework mechanism: `RateLimitInterface` is
 * Yii's documented extension point for exactly this, stable since 2.0, and
 * Craft's own class is one more implementation of it. Prefer Craft's once the
 * plugin's floor is above 5.9.15 for other reasons.
 *
 * @author      CraftPulse
 * @package     PasswordPolicy
 * @since       5.2.0
 */
class IpRateLimit extends BaseObject implements RateLimitInterface
{
    // Public Properties
    // =========================================================================

    /**
     * The caller's IP address. Rate-limiting an unresolvable IP under a single
     * shared bucket is the intended failure mode: one caller the plugin cannot
     * distinguish is safer metered than unmetered.
     *
     * @var string
     *
     * @since 5.2.0
     */
    public string $ip = 'unknown';

    /**
     * Cache-key prefix, so one limited action can't consume another's
     * allowance.
     *
     * @var string
     *
     * @since 5.2.0
     */
    public string $keyPrefix = 'pp:rate-limit';

    /**
     * Burst capacity: the most requests one IP may make before the bucket is
     * empty.
     *
     * @var int
     *
     * @since 5.2.0
     */
    public int $limit = 60;

    /**
     * Seconds the bucket takes to refill from empty, which also sets the
     * sustained rate at `limit / window` requests per second.
     *
     * @var int
     *
     * @since 5.2.0
     */
    public int $window = 60;

    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     *
     * @param Request $request
     * @param Action $action
     * @return array{0: int, 1: int}
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function getRateLimit($request, $action): array
    {
        return [$this->limit, $this->window];
    }

    /**
     * @inheritdoc
     *
     * A cache miss reads as a full bucket, so a cold cache never locks callers
     * out.
     *
     * @param Request $request
     * @param Action $action
     * @return array{0: int, 1: int}
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function loadAllowance($request, $action): array
    {
        $data = Craft::$app->getCache()->get($this->_cacheKey($action));

        if (!is_array($data) || count($data) !== 2) {
            return [$this->limit, time()];
        }

        return [(int)$data[0], (int)$data[1]];
    }

    /**
     * @inheritdoc
     *
     * TTL is the window, so an IP that stops calling drops out of the cache
     * rather than holding a row forever.
     *
     * @param Request $request
     * @param Action $action
     * @param int $allowance
     * @param int $timestamp
     * @return void
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    public function saveAllowance($request, $action, $allowance, $timestamp): void
    {
        Craft::$app->getCache()->set(
            $this->_cacheKey($action),
            [$allowance, $timestamp],
            $this->window,
        );
    }

    // Private Methods
    // =========================================================================

    /**
     * Returns the cache key holding this (action, IP) pair's allowance.
     *
     * @param Action $action
     * @return string
     *
     * @author CraftPulse
     * @since 5.2.0
     */
    private function _cacheKey(Action $action): string
    {
        return sprintf('%s:%s:%s', $this->keyPrefix, $action->getUniqueId(), $this->ip);
    }
}
