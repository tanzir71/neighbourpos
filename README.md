# NeighbourPOS

Minimal, mobile-first POS + CRM MVP built for shared hosting (single-file PHP + SQLite).

- App entry: `neighbourpos.php` (creates `neighbourpos.db` on first run).
- Default admin (change immediately): `admin@example.com` / `ChangeMe123!`
- Customer portal: `/neighbourpos.php?action=portal`
- Docs: [SETUP.md](SETUP.md) | [SECURITY.md](SECURITY.md)
- Repo: https://github.com/tanzir71/neighbourpos

## What makes it different (CRM moat)
Orders feed customer recency/frequency/spend. Staff builds reusable segments (filters), queues campaigns, and downloads recipient CSV exports while defaulting to opt-in-only delivery and auditing overrides.

## Tiny feature-rich surfaces
Dashboard KPIs, low-stock CSV exports, product add/edit, order search, sales reports, coupon redemption tracking, campaign presets, customer timelines, audit logs, password tools, portal opt-in updates, and admin database backup all stay inside the single PHP + SQLite app.
