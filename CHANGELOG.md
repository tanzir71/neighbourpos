# Changelog

## 2026-07-07
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
