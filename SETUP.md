# Setup (Namecheap / cPanel / shared hosting)

1) Upload `neighbourpos.php` (and these docs) to `public_html/` (or a subfolder).
2) Ensure PHP can write in that folder so it can create `neighbourpos.db` and `neighbourpos.log`.
3) In cPanel → MultiPHP Manager: select PHP 8.1+ for the domain/folder.
4) Visit `https://YOUR-DOMAIN/neighbourpos.php` once to initialize the SQLite schema.
5) Log in with `admin@example.com` / `ChangeMe123!` and change credentials immediately.
6) Optional: open DevTools Console and run `loadSample()` to load demo products/customers/orders (admin only).
7) Create `.env` from `.env.example`, set `CRON_TOKEN` and rotate default admin password.
8) Backups: use Admin -> Download backup regularly, plus hosting/cPanel backups.

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

## Backup and restore

- Download backups from Admin -> Download backup. The app streams a SQLite snapshot, not a raw live database file.
- Keep several dated backup copies off the hosting account.
- To verify a backup before relying on it, run:
  `php -r "$pdo=new PDO('sqlite:'.$argv[1]); echo $pdo->query('PRAGMA integrity_check')->fetchColumn(), PHP_EOL;" neighbourpos-backup.db`
- To restore, put the site in maintenance mode or briefly stop writes, rename the current `neighbourpos.db` to a dated safety copy, upload the backup as `neighbourpos.db`, then visit the app and log in.
- After restore, run the same `PRAGMA integrity_check` command against the restored `neighbourpos.db` and keep the old safety copy until the store owner confirms recent orders/customers look right.

## Notes
- Customer portal is public: `?action=portal` (phone lookup only).
- Campaign recipient CSV exports are available from queued campaign rows after staff login.
- Sales reports, low-stock CSV exports, and admin database backup are built in; protect downloaded files because they may contain customer/order data.
- For production, enable HTTPS (AutoSSL / Let’s Encrypt) and keep the app behind TLS.
