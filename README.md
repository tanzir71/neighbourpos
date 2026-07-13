# NeighbourPOS

> A minimal, mobile-first POS + CRM for tiny neighborhood stores — **one PHP file, one SQLite file, any $2 shared host.**

- App entry: `neighbourpos.php` (creates `neighbourpos.db` on first run)
- Current version: `0.4.0`
- Default admin (change immediately): `admin@example.com` / `ChangeMe123!`
- Customer portal: `/neighbourpos.php?action=portal`
- Docs: [SETUP.md](SETUP.md) | [EXPORTS.md](EXPORTS.md) | [SECURITY.md](SECURITY.md)
- Repo: <https://github.com/tanzir71/neighbourpos>

## What is this?

A point-of-sale that a corner shop can actually afford to run: no monthly SaaS fee, no tablet lock-in, no cloud dependency. Upload one PHP file to the cheapest shared hosting, open it in any phone browser, and you have checkout, inventory, customer records, credit ledger, and marketing exports.

**The CRM moat:** every order feeds customer recency/frequency/spend. Staff build reusable segments (filters), queue campaigns, and download recipient CSVs — defaulting to opt-in-only delivery, with overrides audited. The shop owns its customer data and picks its own sending tools.

## Feature surfaces

- **Cashier** — fast checkout with search, categories, quick-amount sales, cash/card/online/on-credit recording, customer attach, coupons, receipts, stock decrement on completion.
- **CRM** — phone-first profiles, consent tracking, order timeline, tags, saved/duplicated segments, customer CSV export.
- **Credit ledger** — on-credit sales, running balances, payment recording, debtor filters, outstanding-credit KPI, SMS reminder exports with `{balance}` merge field.
- **Campaign exports** — Mailchimp, Brevo, SMS, WhatsApp, and full-archive profiles; per-recipient coupon merge fields; opt-in by default.
- **Inventory** — product add/edit, low-stock exports, CSV import with preview/commit and row-level errors, template download.
- **Reports** — date-window summaries, category/product exports, printable "Today's close" card (gross, tender totals, coupons redeemed, new customers).
- **Admin** — audit logs, password management, self-test endpoint, SQLite snapshot backup downloads with restore/integrity-check docs.

No payment processing or message sending is built in — the app records payment status and exports sending lists, so the shop keeps ownership of data and tooling.

## Architecture

Deliberately the simplest thing that can serve a real store:

```
Phone / tablet / PC browser (staff)        Customer's phone
        │ HTTPS                                  │ portal link
        ▼                                        ▼
┌──────────────────── shared hosting ─────────────────────┐
│                                                          │
│   neighbourpos.php  ←  the ENTIRE application            │
│   ├─ router (?action=…): cashier, crm, credit,           │
│   │   campaigns, inventory, reports, admin, portal       │
│   ├─ auth & roles, CSRF, sessions, audit log             │
│   └─ HTML rendering (mobile-first)                       │
│           │                                              │
│           ▼                                              │
│   neighbourpos.db  (SQLite, auto-created on first run)   │
│   products · orders · customers · segments ·             │
│   credit ledger · coupons · audit rows                   │
│                                                          │
│   demo.html — static browsable demo of the UI            │
└──────────────────────────────────────────────────────────┘
```

Why single-file PHP + SQLite: the target user has cPanel, not Kubernetes. One file to upload, one file to back up (the `.db`), nothing to keep running. Prepared statements, `password_hash()`, CSRF tokens, and session hardening cover the security basics — see [SECURITY.md](SECURITY.md).

## Getting started (from zero)

### Shared hosting (the intended path — no terminal needed)

1. Log in to cPanel / your host's control panel and open **File Manager**.
2. Upload `neighbourpos.php` (and `assets/` if present) into `public_html` or a subfolder.
3. Make sure PHP is set to **8.1+** with `pdo_sqlite` and `sqlite3` enabled (Select PHP Version in cPanel).
4. Visit `https://your-domain/neighbourpos.php` — the database creates itself on first run.
5. Log in with the default admin and **immediately** create your real admin account and disable the default one.

Full runbook with screenshots-level detail: [SETUP.md](SETUP.md).

### Local (for trying it out or development)

```bash
php -S 127.0.0.1:8080
# then open http://127.0.0.1:8080/neighbourpos.php
```

Requires any PHP 8.1+ with SQLite extensions (on Windows, `php.exe` from php.net works out of the box). To just look at the UI without running anything, open `demo.html` in a browser.

### Tests

```bash
ls tests/   # test scripts live here; see SETUP.md for the runner
```

## Backups

Admin → backups lets you download SQLite snapshots. Since all state is one `.db` file, backup/restore is copy-a-file simple; integrity-check steps are in the docs.

## Troubleshooting

- **500 error on first load** → PHP version below 8.1 or `pdo_sqlite` missing; fix in your host's PHP settings.
- **"Database is locked"** → SQLite allows one writer; this shows up only under unusual concurrent writes on very slow hosts. Retry, and keep the database on local disk (not NFS).
- **Forgot the admin password** → see the recovery notes in [SECURITY.md](SECURITY.md).
