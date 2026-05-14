# Security

This project is designed for small shared-hosting deployments, so security hardening is built in.

## Fixes applied (high level)
- All SQL uses PDO prepared statements; no user input is concatenated into SQL strings.
- Added `htmlEscape()` helper (and kept `h()` as an alias) to ensure consistent output escaping.
- CSRF enforced for state-changing POSTs (including logout, which is POST-only).
- Passwords use `password_hash()` / `password_verify()` and `session_regenerate_id(true)` is called on login.
- Session idle timeout enforced (`SESSION_IDLE_TIMEOUT_SECONDS`) to reduce risk from abandoned sessions.
- Added SQLite-backed rate limiting for login and write-heavy endpoints (returns HTTP 429 with `Retry-After`).
- Added security headers: CSP, HSTS (HTTPS only), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
- Validated “dangerous” style inputs (e.g., store accent color) to prevent CSS/HTML injection via stored settings.
- Centralized exception/error handling to avoid stack traces reaching users; errors are logged server-side.

## Rotating keys / secrets
- Rotate `CRON_TOKEN`: edit `.env` and update cPanel cron URLs accordingly.
- Rotate admin password: change the password in-app (recommended) or reset the DB user row hash.
- Keep `.env` out of version control (see `.gitignore`).

## Logging
- Server-side errors are appended to `neighbourpos.log` (configurable via `LOG_FILE`).
- To reduce logging, point `LOG_FILE` to a non-writable path or rotate via hosting log tools.

## Production hardening recommendations
- Use HTTPS everywhere (HSTS is enabled automatically when HTTPS is detected).
- Put the app behind a WAF / bot protection if exposed publicly.
- Move from SQLite → Postgres/MySQL for higher concurrency and safer operational tooling.
- Run regular backups of `neighbourpos.db` and store them off-host.
- Consider adding a proper customer auth token for the portal (today it is phone lookup only).

## Quick local scan (optional)
Search for risky SQL patterns and direct superglobal usage:

- `rg "SELECT.*\\$_(GET|POST)" -n neighbourpos.php`
- `rg "\\.\\s*\\$_(GET|POST)" -n neighbourpos.php`
- `rg "echo\\s+\\$_(GET|POST)" -n neighbourpos.php`
