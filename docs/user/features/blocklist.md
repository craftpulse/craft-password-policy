# Blocklist

The plugin ships a **Blocklist** subnav on Pro and Enterprise installs at **Password Policy → Blocklist**. Two lists, one editor:

- **Bundled common passwords**: 10,000 entries from the SecLists Common-Credentials list. Updated via a cron-driven seed action.
- **Custom dictionary**: admin-managed list of words you want to block in addition to the bundled list (employee surnames, company codenames, breached internal passwords, etc.).

On Enterprise, you can also scope custom words to specific named policies, useful when different teams need different exclusions.

This page covers configuring the blocklist, the bundled list source, the custom dictionary editor, the per-policy blocklist (Enterprise), and the "Check a word" diagnostic tool.

## Enabling the blocklist

Open **Settings → Password Policy → Validation** and toggle **Check common passwords**. The blocklist validator is now active: every password change is checked against the union of the bundled list and the custom dictionary.

Lookups go through a cached hash-map (`Craft::$app->getCache()`) for O(1) runtime, so adding the validator doesn't add measurable latency to password changes.

## Bundled common passwords

The bundled list ships 10,000 entries from the [SecLists Common-Credentials](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/10k-most-common.txt) project, lowercased and deduplicated. These cover the credentials most commonly used in credential-stuffing attacks across decades of breach corpora.

The bundle is **seeded on plugin install** and re-seeded on demand. To refresh after a Composer update brings in a newer SecLists vintage:

**From the CP:** Click **Update common passwords** on the Blocklist page. The button enqueues a `SeedBlocklist` queue job.

**From the CLI:** Run the bundled command:

```bash
./craft password-policy/blocklist/update
```

Re-seeding deletes every row with `source = 'common'` and inserts the current bundled list. Custom words (`source = 'custom'`) are untouched.

## Custom dictionary editor

Add words specific to your install: employee surnames, company codenames, internal product names, breached internal passwords that aren't in the bundled list, etc. Edits use Craft's standard `forms.editableTableField` with diff-on-save semantics:

- **Adding** a row inserts a new `source = 'custom'` entry.
- **Removing** a row deletes the entry by ID.
- **Editing** a row leaves the ID stable; the database row's `word` column is updated.

Words are case-normalised on save (lowercase + trimmed). The validator does case-insensitive matching, so the case you type during entry doesn't matter.

### Error messages

The validator emits source-aware error messages so admins can distinguish bundled hits from custom hits without inspecting the database:

| Source | Error message shown to user |
|---|---|
| `common` | "This password is too common. Choose a more unique password." |
| `custom` | "This password has been blocked. Choose a different password." |

The bundled-list message frames the rejection as a quality issue (the password is widely-used); the custom-list message frames it as a policy decision (the password matches an organisation-specific block).

## Check a word

Use the **Check a word** tool at the bottom of the Blocklist page to verify whether a specific value is currently blocked, handy for debugging "why is this password being rejected?" tickets.

Type the word + click **Check**. The tool AJAX-queries the same cache-backed lookup the validator uses and renders the result inline:

| Result | Visual |
|---|---|
| Not blocked | Green tip callout. |
| Bundled match | Amber warning: "Blocked: this word is in the bundled common-passwords list." |
| Custom match | Amber warning: "Blocked: this word matches a custom-dictionary entry." (and, on Enterprise, the policies it's scoped to) |

The tool is case-insensitive and matches the validator's behaviour exactly. There's no "fuzzy match", only exact (case-folded) matches register as blocked.

## Per-policy blocklist (Enterprise)

Enterprise installs can scope custom words to specific named policies. Useful for:

- **Sales reps with a "Customers" policy**: block customer company names (so a sales rep can't use "AcmeCorp2024!" as their password).
- **Engineers with an "Engineering" policy**: block project codenames + internal product names.
- **Admins with a "Strict" policy**: block breached internal passwords specific to admin accounts.

On the **Policy edit screen** (Enterprise), there's a **Blocklist** tab next to **General / Rules / Lifecycle**. Each policy can have its own custom-dictionary entries via the same editable-table UI as the global custom dictionary.

The validator merges:

1. The bundled common-password list (`source = 'common'`, `policyId IS NULL`).
2. The global custom dictionary (`source = 'custom'`, `policyId IS NULL`).
3. The custom entries scoped to the user's applicable policies (`source = 'custom'`, `policyId IN (...)`).

A user belonging to multiple groups whose policies have different custom-dictionary entries gets the union: every policy's blocked words apply.

### Edition-strip on save

The CP edit screen renders the per-policy blocklist tab on Enterprise only. The save action also strips `policyId` from posted custom-word inserts if a crafted POST tries to scope a word to a policy on a Pro install, defense in depth. The strip logs a `Craft::warning()` when triggered so operators can spot crafted POSTs in the plugin log.

## Permissions

| Permission | What it grants |
|---|---|
| `pp:blocklist-view` | Read-only access to the Blocklist page (stats + custom dictionary table render). |
| `pp:blocklist-manage` (nested) | Write access: add/remove custom words, trigger common-password seed, check a word. |

The two nest, so granting `pp:blocklist-manage` grants `pp:blocklist-view` with it. Write access implies read access; the reverse does not hold, so you can give someone the ability to review the deny list without the ability to change it.

## Console commands

```bash
# Re-seed the bundled common-password list from the shipped data file
./craft password-policy/blocklist/update

# Bulk-import custom words from a plaintext file (one word per line)
./craft password-policy/blocklist/import --file=path/to/words.txt

# Count entries by source
./craft password-policy/blocklist/stats
```

The `--file` import is useful for migrations. If you're moving from another password-policy tool that exported a wordlist, drop it into a text file and import.

## Cache invalidation

The blocklist is cached in `Craft::$app->getCache()` under `pp:blocklist:words` for fast runtime lookups. The cache is invalidated automatically on:

- `addCustomWord()`: the editor save path
- `removeCustomWord()`: the editor delete path
- `seedCommonPasswords()`: the bundled re-seed path
- Any direct `BlocklistService::clearCache()` call

If you've directly modified the `passwordpolicy_blocklist` table outside the service (database migration, manual SQL), call:

```bash
./craft cache/flush
```

…to flush all Craft caches, or hit the service method from a one-shot script:

```php
\craftpulse\passwordpolicy\PasswordPolicy::$plugin->getBlocklist()->clearCache();
```

## Data file location

The bundled common-password list lives at `src/data/common-passwords.php` as a PHP array. The file is **seed material only**: it's imported into the database on install or re-seed, not read at runtime. Modifying the PHP file doesn't change runtime behaviour until you re-seed.

To update the bundled list:

1. Replace `src/data/common-passwords.php` with a newer SecLists vintage.
2. Run `./craft password-policy/blocklist/update`.

The plugin's CI verifies the file's row count against a known minimum (8,000+) to catch accidental truncation.

## See also

- [Validators](./validators.md): the `checkCommonPasswords` toggle that activates the blocklist.
- [Per-Group Policies](./per-group-policies.md): the policy edit screen where the Enterprise per-policy blocklist tab appears.
- [Audit logging](./audit-logging.md): blocklist hits are captured as `password_changed` events with `details.outcome = denied` and `details.violationType = 'common_password'` on Enterprise.
