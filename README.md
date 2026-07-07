# NeighbourPOS

Minimal, mobile-first POS + CRM for tiny neighborhood stores, built for shared hosting (single-file PHP + SQLite).

- App entry: `neighbourpos.php` (creates `neighbourpos.db` on first run).
- Current version: `0.4.0`
- Default admin (change immediately): `admin@example.com` / `ChangeMe123!`
- Customer portal: `/neighbourpos.php?action=portal`
- Docs: [SETUP.md](SETUP.md) | [EXPORTS.md](EXPORTS.md) | [SECURITY.md](SECURITY.md)
- Repo: https://github.com/tanzir71/neighbourpos

## What makes it different (CRM moat)
Orders feed customer recency/frequency/spend. Staff builds reusable segments (filters), queues campaigns, and downloads recipient CSV exports while defaulting to opt-in-only delivery and auditing overrides.

## Feature surfaces
- Fast cashier checkout with search, categories, quick amount sales, cash/card/online/on-credit recording, customer attach, coupons, receipts, and stock decrement on completion.
- Customer CRM with phone-first profiles, consent, order timeline, tags, saved segments, duplicate segments, and customer CSV export.
- Credit ledger for cash-first shops: on-credit sales, running balances, payment recording, debtor filters, outstanding-credit KPI, and SMS reminder exports with `{balance}`.
- Campaign exports for Mailchimp, Brevo, SMS, WhatsApp, and full archive profiles; coupon merge fields render per recipient and exports stay opt-in by default.
- Inventory tools with product add/edit, low-stock exports, CSV import preview/commit, row-level import errors, and template download.
- Sales reports include date-window summaries, category/product exports, and a printable Today's close card for gross, tender totals, coupons redeemed, and new customers.
- Admin tools include audit logs, password management, a self-test endpoint, and SQLite snapshot backup downloads with restore/integrity-check docs.

No payment processing or message sending is built in. NeighbourPOS records payment status and exports sending lists so the shop keeps ownership of the data and chooses its own tools.
