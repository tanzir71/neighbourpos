# NeighbourPOS

Minimal, mobile-first POS + CRM MVP built for shared hosting (single-file PHP + SQLite).

- App entry: `neighbourpos.php` (creates `neighbourpos.db` on first run).
- Default admin (change immediately): `admin@example.com` / `ChangeMe123!`
- Customer portal: `/neighbourpos.php?action=portal`
- Docs: [SETUP.md](SETUP.md) • [SECURITY.md](SECURITY.md)
- Repo: https://github.com/tanzir71/<REPO-NAME>

## What makes it different (CRM moat)
Orders feed customer recency/frequency/spend. Staff builds reusable segments (filters) and runs campaigns (export/queue) while defaulting to opt-in-only delivery and auditing overrides.
