# Bundled IP geolocation database

This directory ships the geolocation database used by the plugin's IP
geolocation feature (Feature 4, Enterprise edition).

## File

- `dbip-country-lite.mmdb` — the DB-IP IP-to-Country Lite database in
  MaxMind `.mmdb` format. Read at runtime via the pure-PHP
  `geoip2/geoip2` Composer package (no PECL extension, no external API,
  no operator download).

If `dbip-country-lite.mmdb` is absent (e.g. a partial checkout, or a
`.gitattributes export-ignore` rule that dropped the binary from a
dist archive), the provider degrades gracefully: every lookup returns
`null` and login + audit logging continue unaffected. Re-fetch the file
with the procedure below to restore geolocation.

## Attribution (required)

**IP Geolocation by DB-IP** — <https://db-ip.com>

The bundled database is the **DB-IP IP-to-Country Lite** database,
licensed under **Creative Commons Attribution 4.0 International
(CC BY 4.0)** — <https://creativecommons.org/licenses/by/4.0/>. The
attribution line above is the licence-required notice and must remain
discoverable (it is also surfaced in the CP audit settings page and in
the `DbIpFileProvider` class docblock).

## Coverage

Country-level only. `GeoResult::$region` is therefore almost always
`null`. The value-object + audit schema already carry a `region` column
so a future city-level database can populate it without a code or schema
change.

## Refreshing the database

DB-IP publishes a fresh Lite database monthly. To update:

```bash
# From this directory. Try the current month; fall back to last month
# if the current month has not been published yet (404).
curl -fsSL "https://download.db-ip.com/free/dbip-country-lite-$(date +%Y-%m).mmdb.gz" \
  | gunzip > dbip-country-lite.mmdb
```

Then commit the refreshed binary. There is no schema or code change —
the reader opens whatever `.mmdb` is present at this path.
