# Changelog

## 2026-07-07
- [P5.3] Refreshed README feature claims, bumped the app/landing version to 0.4.0, and reran final static-page and fresh-install verification.
- [P5.2] Switched admin database backup downloads to `VACUUM INTO` SQLite snapshots and documented restore/integrity checks.
- [P5.1] Expanded the admin self-test endpoint with E.164 checks, in-memory segment filter fixtures, and export-profile header assertions.
- [P4.5] Added a printable Reports "Today's close" card with completed-order gross, payment-method totals, coupons redeemed, and new customer counts.
- [P4.4] Added one-click loyalty-lite campaign presets for rewarding top spenders and winning back lapsed customers, with auto-queued coupon recipients and focused export panels.
- [P4.3] Added product CSV imports with template download, preview/commit APIs, row-level error storage, Inventory UI controls, audit logging, and a 500-row cap.
- [P4.2] Added POS quick amount sales with custom labels, product-free order items, line-ID cart controls, and `(quick sale)` sales report grouping.
- [P4.1] Added the customer credit ledger with on-credit POS tendering, customer balances, payment recording, debtor segments, outstanding-credit dashboard KPI, and debtor reminder exports with `{balance}`.
- [P3.7] Added provider-specific export documentation with CSV headers, examples, import click paths, consent notes, and links from README plus the app export panels.
- [P3.6] Added saved segment live counts, duplicate segment workflow, direct tag filter support, and a hidden has-balance filter hook for the future credit ledger.
- [P3.5] Added CRM customer exports for saved segments or current search filters using the same provider CSV profiles, opt-in defaults, audited override, and Excel-friendly downloads.
- [P3.4] Replaced campaign row exports with a provider-format panel, preview-count API, Excel-friendly BOM option, and slugged dated filenames for explicit exports.
- [P3.3] Added campaign merge-field rendering for customer name, first name, coupon code, and store name across exports and simulator preview messages.
- [P3.2] Added Mailchimp, Brevo, SMS, and WhatsApp campaign export profiles with E.164 phone normalization, provider-specific headers, dedupe, and rendered coupon messages.
- [P3.1] Added store default country calling code, Admin editing, E.164 phone normalization, and CLI/admin self-tests for Bangladesh, US, and invalid phone cases.
- [P2.5] Removed render-blocking remote font CSS from static pages, added accessible demo control labels, fixed landing contrast, and recorded Lighthouse mobile observed-throttling scores: landing 100 performance / 100 accessibility; demo 100 performance / 100 accessibility.
- [P2.4] Upgraded the static demo with a reset/hosting banner, SVG icon chrome, preserved 12-item catalog and sample customers, and a receipt modal after checkout.
- [P2.3] Added landing-page credibility signals: synced version badge, changelog/security links, last-updated and license notes, and OpenGraph/Twitter metadata.
- [P2.2] Rewrote the landing page narrative around owned POS + customer data, cash-first workflows, export-based campaigns, limits, FAQ, and live-demo CTAs.
- [P2.1] Added handcrafted landing-page product mockups for checkout and campaign export, including a hero checkout preview and Mailchimp CSV export preview.
- [P1.10] Standardized Orders, Inventory, CRM, and Audit lists on shared sticky-header data tables with numeric alignment and mobile-safe overflow.
- [P1.9] Upgraded the dashboard with KPI deltas, a 14-day sales sparkline, and needs-attention cards for stock, unpaid orders, and queued exports.
- [P1.8] Polished login, register, customer portal, and receipt pages with shared public-page styling, receipt sharing, and 80mm print CSS.
- [P1.7] Added shared money/date formatters, Admin currency-symbol editing, locale thousands separators, and relative dates in the SPA.
- [P1.6] Added POS scanner-style SKU entry, keyboard shortcuts, cash change due, and mobile tap-target sizing.
- [P1.5] Added section skeletons, retry cards, and a global connection banner for failed fetches.
- Restored larger checkout product tile names while keeping the lighter UI font weight.
- [P1.4] Added toast and modal prompt/confirm UI, replacing all SPA native alert/prompt/confirm usage.
- [P1.3] Added shared app page headers and designed empty states across Dashboard, POS, Orders, Inventory, CRM, Campaigns, Reports, and Admin.
- [P1.2] Added elevation tokens, borders, card radii, sale-tile hover lift, and removed the dead legacy POS renderer.
- [P1.1] Replaced SPA letter-glyph navigation and checkout controls with a shared inline SVG sprite; API unauth responses now return JSON 401 for verification smoke tests.

## 2026-05-14
- Hardened session handling (idle timeout) and made logout POST-only with CSRF protection.
- Added SQLite-backed rate limiting (login + write endpoints) with HTTP 429 responses.
- Added CSP/HSTS and related security headers; centralized error handling and server-side logging.
- Validated accent color to prevent style injection; fixed customer search query logic.
- Added landing page + deployment/security docs and repo hygiene files (`.env.example`, `.gitignore`).
