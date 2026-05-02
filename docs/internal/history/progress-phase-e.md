# Phase E — Pest test infrastructure (closed 2026-05-02)

P2.5 scope-expanded. Build order swap (signed off 2026-05-02) put Pest before Phase D — adding new CP surfaces on top of an untested codebase compounds the testing debt that the C2 bug fix sweep had just demonstrated. 18 commits across six sub-phases (E1–E6) plus a `fix(hibp)` and a `docs(ideas)` commit. Suite went from 0 tests to 329 passing / 0 skipped / 634 assertions. ECS clean, PHPStan clean (3-entry baseline unchanged from E1).

## Sub-phases

### E1 — Bootstrap + HibpClient extraction (2026-05-02)

Three commits: `df26265`, `08c0702`, `8f49223`.

- Custom Pest bootstrap that boots Craft as a console application. **No Codeception** — `craft\test\TestSetup` helpers transitively autoload `craft\test\Craft` (extends `Codeception\Module\Yii2`), so a Pest-only setup must inline-replicate `configureCraft()` + `createTestCraftObjectConfig()` (~40 lines). Memory gap #15.
- Test DB strategy: dedicated `db_test` MySQL database, plugin `Install::safeUp()` runs once per process, per-test transaction wrapper rolls back state.
- `composer test` chains ECS → PHPStan → Pest (stops on first failure). CI calls the same target.
- `HibpClientInterface` + `GuzzleHibpClient` extracted from `PasswordService`. Wired via `ServicesTrait::getHibpClient()`. Tests swap via `$plugin->set('hibpClient', $fake)`. Same pattern positions Phase 12's SIEM + webhook services for testability.
- Smoke test (`tests/Unit/SmokeTest.php`) + Craft bootstrap proof (`tests/Integration/CraftBootstrapTest.php` — verifies Craft boots, plugin installed, all 7 plugin tables present, `hibpClient` resolves).
- `UserFactory::admin()` — first factory; others added incrementally.

39 tests post-E1.

### E2 — Pure validators (2026-05-02)

One commit: `5156cdc`.

Coverage:
- `SequentialCharsValidator` — 22 tests (ascending + descending ASCII, `pqr` quirk from T3.1, keyboard rows, embedded matches, case folding)
- `RepeatedCharsValidator` — 14 tests (case-sensitivity, byte-level UTF-8 — `ααα` passes because no byte repeats 3× in a row)
- `ContextualValidator` — 14 tests (username/email/first/last branches, 3-char `MIN_CONTEXT_LENGTH` boundary, email-domain isolation)
- `MinimumCharacterTypesValidator` — 14 tests (each character class threshold; `é` counts as symbol because regex is ASCII-locked `[^a-zA-Z0-9]`)
- `PasswordService::generatePattern/generateMessage` — 11 tests (validator helpers; cosmetic `,  and  ` double-space quirk codified)

All in `tests/Integration/Validators/` because every rejection path calls `Craft::t()`. 97 tests post-E2.

### E3 — DB-touching services + factories (2026-05-02)

Five commits: `a0a2fcb` (factories), `bb9f7d1` (blocklist), `72332d5` (history), `fec8a68` (group policy), `cfeb14d` (resolver).

**Critical bootstrap fix folded into E3.1:** the entire E1+E2 suite had been silently hitting the playground's `db` schema, not `db_test`. PHPUnit 12's `<env force="true"/>` calls `putenv()` + `$_ENV[]` but does NOT overwrite `$_SERVER[]`. DDEV exports `CRAFT_DB_DATABASE=db` into `$_SERVER`; `craft\helpers\App::env()` reads `$_SERVER` first, so the PHPUnit override lost. Pure validators didn't notice (no DB writes); the moment E3.1's blocklist tests inserted rows the duplicate-entry collision surfaced. Fix: pin `$_SERVER[CRAFT_DB_*]` + `$_ENV[CRAFT_DB_*]` + `putenv(...)` in `tests/bootstrap.php` before any Craft code runs. Memory gap #16.

**Solo edition cap fix folded into E3.2:** fresh Craft installs default to `CmsEdition::Solo`, capped at 1 user. After the bootstrap admin (id=1), every `UserFactory::admin()` follow-up hit `User::beforeSave()`'s `canCreateUsers()` veto and silently returned false. Fix: `UserFactory::admin` elevates `Craft::$app->edition` to `CmsEdition::Pro` on first call. Direct property mutation, not project config. Memory gap #17.

Coverage:
- `BlocklistService` — 22 tests (CRUD, lookup variants, cache-flush handshake, common-password seed)
- `CommonPasswordValidator` — 12 tests (source-aware messaging, `policyId` scoping codified as not-yet-honored — flips when Phase G ships per-policy editor)
- `PasswordHistoryValidator` — 12 tests (bcrypt re-use detection, count-window boundary, Pro-edition gate behavior)
- `GroupPolicyModel` — 22 tests (was 10 + 2 skipped) — boolean tri-state matrix (true / false / null) for every boolean field. **Two previously-skipped tests now passing** — codifies the post-2026-04-29-refactor "booleans bypass `mergeWithGlobal`, resolved at `PolicyResolverService` layer" contract.
- `PolicyResolverService` — 27 tests (single-group, multi-group merge, auto-correction, `enablePerGroupPolicies = false` global-fallback, no per-user cache, expiry merge guard requires both `expiryAmount` AND `expiryPeriod`)

Factories added: `GroupFactory`, `PolicyFactory`, `BlocklistFactory`, `PasswordHistoryFactory` (with `enableLogging`/`enableProfiling` toggle around bcrypt seed loop per security.md).

192 tests post-E3.

### E4 — HIBP + Strength + Settings (2026-05-02)

Three commits: `f96f890`, `4d512a0`, `49e0023`.

- `GuzzleHibpClient` direct tests via `MockHandler` spliced through Craft's `config/guzzle.php` + `TestGuzzleConfig` static holder. Each canned 200/4xx/5xx/429 response branch covered.
- `PasswordService::isHibpBackoffActive()` proxy + listener-shaped short-circuit verified.
- `HibpClientFake` (implements `HibpClientInterface`) for consumer-side tests — reusable in E5.
- `StrengthService::analyzeZxcvbn` blocklist propagation: engine B forces `weak` label + clamps `score` to 0 on blocklist hit; `crackTime` / `suggestions` / `warning` survive. Mirrors engine A.
- `SettingsModel` four-hook legacy alias (`attributes`, `canGet/SetProperty`, `__get`, `__set`): `pwned: true` flows to `hibp: true` with deprecation warning. Pinned for the alias removal in 5.4.

**Quirks codified, flagged in commit bodies:**
- `GuzzleHibpClient` non-2xx-non-429 logged at `LEVEL_ERROR`, contradicting `security.md`'s `WARNING` prescription. Fixed in follow-up commit `fd8149b`.
- `_parseRetryAfter()` doesn't parse RFC 7231 HTTP-date form — falls back to `DEFAULT_BACKOFF_SECONDS`.
- `isBackoffActive()` reads via `cache->get(...) !== false` (memory gap #11 idiom). Sentinel `'1'` makes it inert; pinned so a refactor swapping to `false` fails loudly.

254 tests post-E4.

### `fix(hibp)` log-level downgrade (2026-05-02)

Commit `fd8149b`. Out of E-phase scope but landed in-stream after E5 completed. Both `Logger::LEVEL_ERROR` calls in `GuzzleHibpClient::query()` (the `ClientException` non-429 path and the `GuzzleException` catch-all) downgraded to `Logger::LEVEL_WARNING`. Test gains a Yii logger-buffer snapshot+slice assertion confirming the WARNING entry surfaces. Aligns code with `security.md`'s prescription: a transient HIBP outage is fail-open by design, ERROR-level entries route to ops alerting, every CDN burp shouldn't page someone.

`docs(ideas)` commit `2efabbe` captures two 5.2.x cleanup candidates:
1. **Validator Unicode-awareness gaps** — `RepeatedCharsValidator` byte-level regex (`ααα` passes), `MinimumCharacterTypesValidator` ASCII-locked symbol class (`é` counts as symbol). Tests in E2 codify the wrong-as-coded behavior; flip assertions when the fix lands.
2. **Audit log levels against security.md** — the GuzzleHibpClient one-off opened up the broader question. Likely more divergences hide in queue jobs, ValidationController, etc.

302 tests post-fix.

### E5 — Controllers + Twig tags (2026-05-02)

Three commits: `38914c4` (Twig tag), `ca18af7` (sessions), `19e557e` (validation).

**Path A confirmed for request mocking:** swap a `WebRequestStub` instance into `Craft::$app->set('request', $stub)`; Yii's `Instance::ensure('request', Request::class)` in `Controller::init()` resolves from the app component. No bootstrap surgery — keep the console-app bootstrap, mock the request at the test boundary. Path B (per-test web-app re-bootstrap) considered and rejected as too heavy.

Coverage:
- `PasswordWidgetTag` composite null-gating — 23 tests. Forwards only non-null `submitGate` / `groups` to children. `BaseTag::render()` returns `\Twig\Markup` (memory gap #14); `__toString()` returns plain string for PHP-context concatenation.
- `PasswordService::destroyOtherSessions()` — 9 tests across web + console paths. Console boot is the bootstrap default; helper short-circuits the token branch when `getIsConsoleRequest()=true`. `craft\console\User` lacks `getToken()`; web-context guard chains `!getIsConsoleRequest()` AND `getIsCurrent()` AND `getToken() !== null`.
- `ValidationController::actionValidate` — 16 tests covering anonymous vs authenticated context resolution. Anonymous can't pass `username`/`email` POST params (defense against attacker-supplied context); authenticated pulls from session identity. POST values truncated to 254 chars defensively. Internal rule keys remap to client keys via `_clientKey()` (`minLength` → `length`, etc.). HIBP rule with `pass: null` is the fail-open contract.

Reusable stubs added: `WebRequestStub`, `UserStub`, `SessionFactory`. Used in E6.

302 tests post-E5 (matching count from after `fix(hibp)`).

### E6 — Migrations + multi-site (2026-05-02)

Three commits: `503455a` (bases), `c164646` (migrations), `6a69664` (multi-site).

- `MigrationTestCase` and `MultiSiteTestCase` non-transactional bases. **DDL auto-commits in MySQL** — `DROP TABLE` / `CREATE TABLE` happen outside the transaction wrapper and don't roll back. Project config writes also commit immediately. Both bases override `usesTransaction(): bool { return false; }` and clean up in `tearDown` (idempotent — runs even on test failure).
- `MigrationTestCase::restorePluginSchema()` re-applies `Install::safeUp()` (every `_create*Table()` is `tableExists`-guarded) plus re-records each migration's history row by name + track via `MigrationManager::addMigrationHistory()`. Suite runs cleanly twice in a row from cold boot.
- `MultiSiteTestCase` — `setUp()` flushes the Sites cache; `tearDown()` walks every non-primary site and `deleteSiteById()`s it, swallowing `Throwable` for best-effort cleanup.

Coverage:
- T1.2 — 5.1.1 → 5.2.0 upgrade replay: tear `db_test` down to 5.1.1 schema, run `m260429_*` + `m260430_*`, assert post-upgrade state. 14 tests including idempotency, history-row count, hash equivalence to `users.password`, seed-loop logging suppression, defensive `groupPolicies` legacy-key cleanup.
- TX.2 — zero behavior change folded in (paired with `SettingsModelLegacyAliasTest` from E4.3).
- T9.7 — multi-site propagation + FK CASCADE. 9 tests in `SitePropagationTest` + 4 in `SiteDeletionCascadeTest`. **Brief had FK CASCADE behavior slightly wrong**: Craft's `Sites::handleDeletedSite()` soft-deletes (sets `dateDeleted`), so CASCADE doesn't fire on `deleteSiteById()`. Hard-delete via direct `createCommand()->delete(Table::SITES, ...)` does cascade — the FK is correctly wired for the GC sweep. Both behaviors codified. Memory gap #19.

**Pest `uses()` ordering finding:** `TestRepository::make()` iterates rules in registration order; first match wins, second match for the same file throws `TestCaseAlreadyInUse`. The intuitive "blanket `Integration` + per-subfolder override" pattern fails. Register most-specific paths first, then enumerate remaining sub-dirs explicitly. Documented in `tests/Pest.php`. Memory gap #18.

329 tests post-E6.

## Skill gaps captured (this phase)

Five new entries added to `feedback_skill_gaps.md` (#15–19):

15. `craft\test\TestSetup` helpers transitively autoload Codeception (E1)
16. PHPUnit 12 `<env force="true"/>` doesn't overwrite `$_SERVER` — DDEV's `CRAFT_DB_DATABASE` wins (E3)
17. Solo edition caps user creation at 1 — factories must elevate to Pro (E3)
18. Pest `uses()` rules iterate in registration order — first match wins (E6)
19. Craft `Sites::deleteSiteById()` soft-deletes — FK CASCADE doesn't fire (E6)

All five are non-obvious testing gotchas any future Pest setup in another Craft plugin will hit. Useful seed for a `craft-pest-testing` skill if one ever gets built.

## Architectural decisions (locked during the phase)

1. **Custom Pest bootstrap, no Codeception.** Inline-replicate `craft\test\TestSetup` helpers (~40 lines) to avoid the transitive Codeception load. Documented in `tests/bootstrap.php`.
2. **Dedicated `db_test` MySQL DB on DDEV.** Per-test transaction wrapper for state isolation; non-transactional `MigrationTestCase` / `MultiSiteTestCase` bases for DDL + project-config tests.
3. **Factory helpers in `tests/Support/Factories/`.** Plain PHP, no third-party factory lib. Static methods (`UserFactory::admin()`, `PolicyFactory::nist()`, etc.).
4. **Two-layer mocking strategy for HIBP.** `HibpClientFake` for consumer-side tests (PasswordService::hibp() + listener gate). `MockHandler`-backed Guzzle for transport-side tests (GuzzleHibpClient itself). Layers stay independent.
5. **Path A for controller tests.** Mock the request via `WebRequestStub`, swap into `Craft::$app->set('request', $stub)`. Console-app bootstrap stays; web-context tests get the request boundary they need without re-bootstrapping.
6. **`composer test` chains ECS → PHPStan → Pest.** First failure stops the chain. CI calls the same target.

## Reusable artifacts for Phase D and beyond

- `tests/Pest.php` — `uses()` rules with most-specific-first ordering
- `tests/TestCase.php` — transaction wrapper base
- `tests/Support/MigrationTestCase.php` — non-transactional + DDL teardown
- `tests/Support/MultiSiteTestCase.php` — non-transactional + site-cleanup teardown
- `tests/Support/Factories/` — UserFactory, GroupFactory, PolicyFactory, BlocklistFactory, PasswordHistoryFactory, SessionFactory
- `tests/Support/HibpClientFake.php` — implements `HibpClientInterface`
- `tests/Support/WebRequestStub.php` — request-mocking stub for controller tests
- `tests/Support/UserStub.php` — adds stubbable `getToken()` on `craft\console\User`
- `tests/Support/TestGuzzleConfig.php` — static handler holder for Guzzle MockHandler injection

When Phase D adds the password history `changedByUserId` migration, extend `UpgradeTo520MigrationTest` (or a sibling test file) to cover the new migration. The existing infrastructure handles fixture teardown + replay.

## Files touched (full Phase E)

```
composer.json
phpunit.xml.dist
phpstan.neon
phpstan-baseline.neon
src/services/HibpClientInterface.php (new)
src/services/GuzzleHibpClient.php (new — extracted; later log-level fix in fd8149b)
src/services/PasswordService.php (refactored to consume HibpClient via service)
src/services/ServicesTrait.php (added hibpClient)
tests/bootstrap.php (new — $_SERVER pin block + inline TestSetup replication)
tests/Pest.php (new — most-specific-first uses() rules)
tests/TestCase.php (new — transaction wrapper)
tests/_craft/ (new — minimal Craft project skeleton: config, storage with .gitignore, templates, migrations, translations)
tests/_craft/config/guzzle.php (new — fixture for MockHandler injection in E4)
tests/Support/Factories/UserFactory.php (E1; expanded E3 with edition elevation)
tests/Support/Factories/GroupFactory.php (E3)
tests/Support/Factories/PolicyFactory.php (E3)
tests/Support/Factories/BlocklistFactory.php (E3)
tests/Support/Factories/PasswordHistoryFactory.php (E3)
tests/Support/Factories/SessionFactory.php (E5)
tests/Support/HibpClientFake.php (E4)
tests/Support/TestGuzzleConfig.php (E4)
tests/Support/WebRequestStub.php (E5)
tests/Support/UserStub.php (E5)
tests/Support/MigrationTestCase.php (E6)
tests/Support/MultiSiteTestCase.php (E6)
tests/Unit/SmokeTest.php (E1)
tests/Unit/Enums/PolicyPresetTest.php (existed pre-E1; pwned → hibp rename)
tests/Integration/CraftBootstrapTest.php (E1)
tests/Integration/Validators/SequentialCharsValidatorTest.php (existed; expanded E2)
tests/Integration/Validators/RepeatedCharsValidatorTest.php (existed; expanded E2)
tests/Integration/Validators/ContextualValidatorTest.php (E2)
tests/Integration/Validators/MinimumCharacterTypesValidatorTest.php (E2)
tests/Integration/Validators/CommonPasswordValidatorTest.php (E3)
tests/Integration/Validators/PasswordHistoryValidatorTest.php (E3)
tests/Integration/Services/PasswordServicePatternTest.php (E2)
tests/Integration/Services/BlocklistServiceTest.php (E3)
tests/Integration/Services/PolicyResolverServiceTest.php (E3)
tests/Integration/Services/HibpBackoffTest.php (E4)
tests/Integration/Services/GuzzleHibpClientTest.php (E4; updated in fd8149b)
tests/Integration/Services/StrengthServiceTest.php (E4)
tests/Integration/Services/DestroyOtherSessionsTest.php (E5)
tests/Integration/Models/GroupPolicyModelTest.php (existed; expanded E3)
tests/Integration/Models/SettingsModelLegacyAliasTest.php (E4)
tests/Integration/Controllers/ValidationControllerTest.php (E5)
tests/Integration/TwigTags/PasswordWidgetTagTest.php (E5)
tests/Integration/Migrations/UpgradeTo520MigrationTest.php (E6)
tests/Integration/MultiSite/SitePropagationTest.php (E6)
tests/Integration/MultiSite/SiteDeletionCascadeTest.php (E6)
docs/internal/ideas.md (validator Unicode + log levels candidates — committed in 2efabbe)
```

## What didn't get touched

- `5.1.x` branch — still parked, three backport commits unpushed and untagged
- Phase D items (P2.1, P2.2, half-built `_users/password-security.twig` user-edit tab)
- Phase F (P2.8 — Phase G build plan draft)
- Enterprise (Phase G — Phase 10/11/12)
- Release prep (Phase H — tag, Plugin Store, marketing copy, deployment docs)
- The two product-quality 5.2.x cleanup candidates from `ideas.md` (validator Unicode awareness, broader log-level audit)
