<?php
/**
 * Yii application config for the Pest test suite.
 *
 * @link      https://craft-pulse.com
 * @copyright Copyright (c) 2024 CraftPulse
 */

return [
    'id' => 'CraftCMS--password-policy-test',
    'components' => [
        // Pin the asset manager to a writable test-runtime path so
        // `View::registerJs()` (which triggers `JqueryAsset::register()`
        // on POS_READY) doesn't fail with "directory does not exist"
        // when CP element actions register their trigger JS during a
        // unit-level test. The default `@webroot/assets` doesn't exist
        // in the headless test layout.
        'assetManager' => [
            'basePath' => '@root/storage/runtime/assets',
            'baseUrl' => '/assets',
        ],
    ],
];
