<!-- craftcms-claude-skills -->
# Git workflow — craftpulse/craft-password-policy

## Branches

- `5.x` — active 5.2.0 development. All Phase A → H work lands here.
- `5.1.x` — backport branch from `5.1.1` tag. Holds 5.1.x patches (TLS verify, log level bump, sensitive-key strip backports). Don't tag a 5.1.2 release without explicit user direction.
- `main` — points at the latest stable; track upstream when a release is tagged.

## Release strategy

5.2.0 is a single coordinated release covering Lite + Pro + Enterprise. **Nothing tags until Enterprise (Phase G) is built and tested.** Features either land at the right edition tier in 5.2.0 or get dropped to `docs/internal/ideas.md`. Don't defer features as "v5.2.x" or "v5.3" — 5.2.x is reserved for security patches only.

## Commits

- **Conventional Commits** prefixes: `feat`, `fix`, `refactor`, `docs`, `test`, `chore`. Match scope to the layer touched (`feat(notifications)`, `fix(twig-tags)`, `refactor(strength)`).
- **HEREDOC** commit messages for proper formatting via `git commit -m "$(cat <<'EOF' ... EOF )"`.
- **Extensive bodies** — *why* + *what* + *how to undo* + subtle gotchas. Match the depth of `7b9d7b7` (UX polish) and `04178bf` (P1.4 batched job).
- **Imperative mood**: "fix HIBP TLS verify", not "fixed" or "fixes".
- **No AI attribution.** No `Co-Authored-By: Claude` trailers. No "Claude" / "Claude Code" / "AI" mentions in commit messages, code comments, or doc updates.
- **No `--no-verify`** / `--no-gpg-sign` unless explicitly asked. Fix the underlying issue if a hook fails.

## Pushing

- **Don't push on agent runs.** Local commits only — user pushes on their own cadence.
- **No force push** to release branches (`5.x`, `5.1.x`, `main`). Global settings deny `git push --force *` and `git push -f *`.
- **Don't tag on agent runs.** Tagging is a release decision.

## GitHub

- Use `gh` for all GitHub ops — already authenticated. `gh run list`, `gh pr`, `gh issue`, `gh api`.
- PR descriptions: no "Test plan" sections.
- No AI attribution in PR descriptions, comments, or issue comments.

## Migrations

Always generate via `ddev craft migrate/create <Name> --plugin=password-policy`. **Never hand-pick filenames or timestamps.** The container clock authors them; the host clock can drift.
