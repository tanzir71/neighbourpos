# Changelog

## 2026-05-14
- Hardened session handling (idle timeout) and made logout POST-only with CSRF protection.
- Added SQLite-backed rate limiting (login + write endpoints) with HTTP 429 responses.
- Added CSP/HSTS and related security headers; centralized error handling and server-side logging.
- Validated accent color to prevent style injection; fixed customer search query logic.
- Added landing page + deployment/security docs and repo hygiene files (`.env.example`, `.gitignore`).
