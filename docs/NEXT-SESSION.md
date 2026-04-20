# Next Session — Action List

## Context

10 branches built (`5.2.0-alpha.1` through `5.2.0-beta.5`), covering Phases 0-9 (Phase 7 built last). All passing ECS, PHPStan, and unit tests. Plugin installs and runs on `plugin-playground.ddev.site`.

Current branch: `5.2.0-beta.5`

## Priority 1 — Manual Testing (barely started)

We only completed T0.2 (settings UI renders) and T7.1 (sidebar subnav). That single test surfaced 6 bugs — all fixed, but nothing else has been tested live. The full test matrix in `docs/TESTING.md` is untouched:

**Not yet tested — work through these in order:**
- [ ] T0.1 — Edition helpers return correct values
- [ ] T0.3 — HIBP breach detection rejects known-breached passwords
- [ ] T0.4 — Sensitive keys never appear in logs
- [ ] T1.1 — Fresh install creates all 4 tables (done during initial install)
- [ ] T1.2 — Upgrade migration seeds password history
- [ ] T2.1 — Password change stores history (needs Pro edition)
- [ ] T2.2 — Password reuse rejected (needs Pro)
- [ ] T2.3 — History check disabled on Lite
- [ ] T2.4 — Force change on first login
- [ ] T2.5 — Recursion guard
- [ ] T3.1–T3.6 — All advanced validators (needs Pro)
- [ ] T4.1–T4.6 — Audit logging (needs Enterprise)
- [ ] T5.1–T5.5 — Per-group policy resolution (needs Pro + multiple groups)
- [ ] T6.1–T6.2 — User index condition rules + bulk action
- [ ] T8.1–T8.3 — Developer events, session invalidation, group force reset
- [ ] T9.1–T9.4 — Twig variables, AJAX validation, GC, notification dedup
- [ ] T7.x — Remaining settings UI checks (sidebar badges, edition gating visual, fail-closed JS warning, settings persistence across sections)

**Settings UI fixes that need visual verification:**
- [ ] Sidebar badges ("Pro" / "Enterprise") render with Craft's `badge` class
- [ ] Edition-gated sections show `p.notice.has-icon` banner with proper spacing
- [ ] Fail-closed warning appears/disappears on dropdown change (JS-driven)
- [ ] Compliance notice shows on retention page when expiry is set
- [ ] Settings persist across sections (the merge fix)

Most tests beyond T0.x/T1.x require Pro or Enterprise edition to be active. Testing strategy: either temporarily set edition in code, or use Craft's `plugin-editions` config.

## Priority 2 — Continue Manual Testing

Work through `docs/TESTING.md` systematically. Each test that fails gets fixed immediately on `5.2.0-beta.5` before moving to the next. The first test (T0.2) found 6 bugs — expect more.

To test Pro/Enterprise features, add to `cms/config/app.php` in the playground:
```php
return [
    'modules' => [],
    'bootstrap' => [],
    'components' => [
        'plugins' => [
            'pluginConfigs' => [
                'password-policy' => ['edition' => 'pro'], // or 'enterprise'
            ],
        ],
    ],
];
```

## Priority 3 — Integration Tests (need Craft bootstrap)

12 integration tests written but need Craft's test framework to run:
- `tests/integration/validators/SequentialCharsValidatorTest.php` (10 tests)
- `tests/integration/validators/RepeatedCharsValidatorTest.php` (7 tests)
- `tests/integration/models/GroupPolicyModelTest.php` (12 tests)

Set up Craft's Pest integration: `craft\test\TestCase` base, bootstrap file, DB fixtures.

## Priority 4 — Remaining Backend Phases

Three phases remain, all Enterprise-tier:

### Phase 10 — Device Tracking + Login Anomaly Detection
- `DeviceTrackingService`, `KnownDeviceRecord`, `known_devices` migration
- ua-parser/uap-php integration (add to composer.json)
- Login event listener: `yii\web\User::EVENT_AFTER_LOGIN`
- `NotificationService::sendNewDeviceAlert()` integration
- `DeviceController` CLI for pruning

### Phase 12 — SIEM Forwarding + Webhooks + API Tokens
- `SiemService`, `WebhookService`, `ApiTokenService`
- `ApiController` (token-authenticated, CSRF-exempt)
- `SiemForwardJob` queue job (stores entry ID only, fetches at execution)
- `ApiTokenRecord`, `api_tokens` migration
- Circuit breaker for SIEM failure loops
- HMAC-SHA256 webhook signatures

### Phase 11 — Compliance Dashboard
- `ComplianceDashboardUtility` with aggregated metrics
- `ReportController` for per-user audit trail export (HTML/PDF/CSV)
- Compliance mapping template (framework → green/amber/red)
- PCI-DSS tension surfacing

## Priority 5 — Open Items from Review

- [ ] Common passwords data file: expand from 195 to 10,000 entries before stable
- [ ] `passwordField()` Twig render function (Phase 9 plan — not yet built)
- [ ] CP password field show/hide toggle via JS injection (Phase 9 plan — not yet built)
- [ ] Email templates: `_emails/expiry-reminder.twig`, `new-device-alert.twig`, `admin-security-alert.twig`
- [ ] `NotificationController` CLI: `send-expiry-reminders`, `prune`
- [ ] Group deletion cleanup listener (remove orphaned groupPolicies)
- [ ] `allowAdminChanges` read-only mode: verify `readOnlyNotice()` banner renders

## Prompt for New Session

```
Read docs/NEXT-SESSION.md and docs/TESTING.md in the plugin directory,
then read the plan files at ~/dev/plans/password-policy-pro-plan.md and
~/dev/plans/password-policy-security-architecture.md.

We're building the v5.2.0 Pro/Enterprise expansion for the password
policy plugin. 10 branches are built (alpha.1 through beta.5), all
passing ECS/PHPStan/unit tests. The plugin is installed and running
on plugin-playground.

We barely started manual testing — only T0.2 and T7.1 are done. That
single test found 6 bugs. The entire test matrix in TESTING.md is
untouched. Manual testing IS the priority. Work through TESTING.md
systematically, fix bugs as they surface. Do not build new features
until the existing build is tested.

Branch: 5.2.0-beta.5
Playground: https://plugin-playground.ddev.site/cp
Login: development@craftpulse.com / letmein-craftpulse
```
