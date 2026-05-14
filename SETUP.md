# Setup (Namecheap / cPanel / shared hosting)

1) Upload `neighbourpos.php` (and these docs) to `public_html/` (or a subfolder).
2) Ensure PHP can write in that folder so it can create `neighbourpos.db` and `neighbourpos.log`.
3) In cPanel → MultiPHP Manager: select PHP 8.1+ for the domain/folder.
4) Visit `https://YOUR-DOMAIN/neighbourpos.php` once to initialize the SQLite schema.
5) Log in with `admin@example.com` / `ChangeMe123!` and change credentials immediately.
6) Optional: open DevTools Console and run `loadSample()` to load demo products/customers/orders (admin only).
7) Create `.env` from `.env.example`, set `CRON_TOKEN` and rotate default admin password.
8) Backups: download `neighbourpos.db` regularly (cPanel backups / FTP).

## File permissions
- Typical safe permissions: files `0644`, folders `0755`.
- If SQLite creation fails, the folder needs to be writable by the PHP user (sometimes `0755` is enough; sometimes `0775` depending on hosting).

## Cron (optional but recommended)
Use a long random `CRON_TOKEN` in `.env`. Add cPanel cron jobs:

- Daily campaigns:
  - URL: `https://YOUR-DOMAIN/neighbourpos.php?action=cron_campaigns&token=YOUR_CRON_TOKEN`
- Nightly log retention purge:
  - URL: `https://YOUR-DOMAIN/neighbourpos.php?action=cron_purge_logs&token=YOUR_CRON_TOKEN`

If cPanel cron supports CLI PHP, you can call:
`php /home/USER/public_html/neighbourpos.php action=cron_campaigns token=YOUR_CRON_TOKEN`

## Notes
- Customer portal is public: `?action=portal` (phone lookup only).
- For production, enable HTTPS (AutoSSL / Let’s Encrypt) and keep the app behind TLS.
