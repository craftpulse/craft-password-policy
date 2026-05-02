<!-- craftcms-claude-skills -->
# Testing — craftpulse/craft-password-policy

## Manual testing

Single source of truth: `docs/internal/manual-tests.md`.

- **Active test pass** — top of the file. Orchestrated walkthrough for the current verification cycle (Phase C2 + Layer 4b + bug fix sweep). 6 blocks: front-end demos, CP strength, HIBP-on-login, email notifications, bug-fix-specific, edition matrix.
- **Per-test register** — phase-numbered T-rows (T0.x → T13.x). PASS / FAIL / PENDING / DEFERRED status per individual scenario.

When manually testing, the active pass is your roadmap. The T-rows are where you record outcomes for individual scenarios as you go.

## Playground

- Path: `/Users/michtio/dev/craft-plugin-playground/cms_v5`
- URL: `https://plugin-playground-v5.ddev.site/admin`
- Admin: `development@craftpulse.com` / `Letmein-Craftpulse1!`
- Mailpit URL: `ddev describe` shows it.
- Demo templates for the front-end Twig surface live in `cms/templates/_demo/password-policy/`. Routed via `cms/config/routes.php`.

## Pest

Scaffolded but no test files yet (P2.5 backlog). When Pest lands, three deferred manual tests absorb into Pest fixtures:

- T1.2 — upgrade migration seeds history.
- TX.2 — zero behavior change on upgrade from 5.1.1.
- T9.7 — site propagation listener + CASCADE (single-site playground can't exercise).

Run via `ddev composer test` once tests exist. Edge cases for P2.5 are captured in `docs/internal/reference.md` § 7.4.

## CI

GitHub Actions for ECS + PHPStan + Pest (when it lands). Use `gh run list` / `gh run view` / `gh run watch` to check status.

## Debugging

```bash
ddev xdebug on                                              # toggle Xdebug
ddev craft queue/info                                       # queue state
ddev craft queue/run --verbose                              # run pending jobs synchronously
ddev craft password-policy/notification/send-expiry-reminders --user=<id>   # one-shot
tail -f cms/storage/logs/password-policy-*.log              # plugin log
ddev mailpit                                                # email inspection (or via ddev describe URL)
```
