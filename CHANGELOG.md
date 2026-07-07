# Changelog

## 2026-07-07
- [P1.3] Added shared app page headers and designed empty states across Dashboard, POS, Orders, Inventory, CRM, Campaigns, Reports, and Admin.
- [P1.2] Added elevation tokens, borders, card radii, sale-tile hover lift, and removed the dead legacy POS renderer.
- [P1.1] Replaced SPA letter-glyph navigation and checkout controls with a shared inline SVG sprite; API unauth responses now return JSON 401 for verification smoke tests.

## 2026-05-14
- Hardened session handling (idle timeout) and made logout POST-only with CSRF protection.
- Added SQLite-backed rate limiting (login + write endpoints) with HTTP 429 responses.
- Added CSP/HSTS and related security headers; centralized error handling and server-side logging.
- Validated accent color to prevent style injection; fixed customer search query logic.
- Added landing page + deployment/security docs and repo hygiene files (`.env.example`, `.gitignore`).
