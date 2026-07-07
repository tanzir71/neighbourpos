# CODEX_HANDOFF.md — NeighbourPOS Refinement Plan (loop-runnable)

> **How to use this file (Codex loop protocol)**
>
> 1. Read `## Invariants` and `## Verification` first. They apply to EVERY iteration.
> 2. Find the first unchecked `- [ ]` task in the lowest-numbered phase that still has unchecked tasks. Work strictly in phase order.
> 3. Implement ONLY that task. Do not batch multiple tasks in one iteration.
> 4. Run every command in `## Verification`. All must pass.
> 5. Check the box `- [x]`, append a one-line entry to `CHANGELOG.md` (date + task ID), commit with message `[P<phase>.<task>] <summary>`.
> 6. Stop. The next loop iteration picks up the next task.
>
> If a task turns out to be impossible without violating an invariant, do NOT violate the invariant. Instead mark the task `- [x] (SKIPPED: reason)` in this file and move on.

---

## Invariants (never violate)

1. **Single file app.** `neighbourpos.php` remains ONE deployable PHP file. No Composer, no npm, no build step, no separate CSS/JS files for the app. Inline everything. PHP 8.1+, PDO SQLite only.
2. **Static marketing site.** `index.html` and `demo.html` remain self-contained static files (inline CSS/JS; Google Fonts CDN is the only allowed external request). No frameworks.
3. **Security stays.** Never remove or weaken: CSRF tokens, POST-only logout, session idle timeout, SQLite rate limiting, CSP/HSTS headers, prepared statements, `csv_safe_cell()` formula-injection escaping, audit logging, opt-in enforcement on campaign exports (override must stay audited).
4. **No payment processing, no vendor messaging.** The app records payments and produces sending lists; it never sends SMS/email itself and never touches card networks. This is a product boundary, not a TODO.
5. **Cash-only merchants are first-class.** Every feature must be usable by a shop that takes only cash and may not have customer emails. Phone is the primary customer key (it already is: `customers.phone` UNIQUE).
6. **Localization-neutral.** No hardcoded `$`/`USD` in new code. Always use the store's `currency_symbol`/`currency` settings. New: default phone country code setting (Phase 3).
7. **Data ownership promise.** Everything remains exportable as CSV / SQLite backup with no gate.
8. **No fabricated social proof.** The landing page must never contain invented testimonials, fake logos, fake user counts, or fake press mentions. Credibility comes from screenshots, the live demo, docs, and honest limits.
9. **Migrations are additive.** Schema changes go through `CREATE TABLE IF NOT EXISTS` / guarded `ALTER TABLE ADD COLUMN` (check `PRAGMA table_info` first) so existing `neighbourpos.db` files upgrade in place on first request.

---

## Verification (run every iteration)

```bash
# 1. Syntax
php -l neighbourpos.php

# 2. Fresh-boot smoke test (deletes nothing of the user's; uses a temp copy)
rm -rf /tmp/np_smoke && mkdir /tmp/np_smoke && cp neighbourpos.php /tmp/np_smoke/
php -S 127.0.0.1:8098 -t /tmp/np_smoke & SRV=$!; sleep 1
curl -sf -o /dev/null -w "%{http_code}\n" "http://127.0.0.1:8098/neighbourpos.php"                     # expect 200 (login page)
curl -sf -o /dev/null -w "%{http_code}\n" "http://127.0.0.1:8098/neighbourpos.php?action=portal"       # expect 200
curl -s  -o /dev/null -w "%{http_code}\n" "http://127.0.0.1:8098/neighbourpos.php?action=api_me"       # expect 401/403 JSON, NOT 500
kill $SRV

# 3. Upgrade-in-place test: run the same smoke against a db created by the PREVIOUS commit
#    (keep /tmp/np_prev.db between iterations; if missing, create it from HEAD~1)

# 4. Static pages parse
python3 -c "import html.parser,sys; p=html.parser.HTMLParser(); p.feed(open('index.html').read()); p.feed(open('demo.html').read()); print('html ok')"

# 5. If the task touched exports: run the CSV assertions in Phase 3 acceptance criteria.
```

The existing `tests/*.ps1` are PowerShell and may not run in your environment; port any assertion you need into inline `curl` checks rather than depending on them.

---

## Context: what this app is

Minimal POS + CRM for tiny neighborhood shops, deployed as one PHP file + one SQLite db on shared hosting. Staff SPA has 8 tabs: Dashboard, POS, Orders, Inventory, CRM, Campaigns, Reports, Admin (`renderDashboard()` … `renderAdmin()`, router in `render()` around line ~3691). Non-SPA routes: `staff_login`, `staff_register`, `portal` (customer opt-in page), `receipt`, CSV exports (`campaign_export`, `inventory_low_stock_export`, `sales_report_export`), `database_backup`, cron endpoints. JSON API routes are all `?action=api_*`.

Schema (all in the bootstrap block, ~line 393+): `users, stores, products, customers, orders, order_items, segments, campaigns, campaign_recipients, audit_log, imports (currently UNUSED — no code writes to it), rate_limits`.

Segment filters supported today (`segment_query()`, ~line 648): opt-in only, total spent min/max, order count min/max, inactive_days, recency_days, purchased product/category. Customers have `tags_text` but there is NO tag filter yet.

**The two problems this plan exists to fix:**
1. **Confidence gap.** The landing page and app UI look like a prototype: letter-glyph "icons", flat borderless cards on flat washes, no shadows/depth, no empty states, no loading states, alert-style error boxes, abrupt `prompt()`/`confirm()` dialogs, no product screenshots on the landing page, `assets/` is empty.
2. **The export is not actually usable.** `campaign_export` produces ONE wide 20-column CSV with internal fields (`total_spent_cents`, `payload_json`-derived flags). No email tool or SMS tool can ingest it without manual surgery. The whole product thesis is "we don't send; you export a sending list into Mailchimp/Brevo/SimpleTexting/WhatsApp" — so the export must be import-ready for those tools. See Phase 3.

---

## Competitor analysis → what it implies

| Competitor | What they do well | What it costs the merchant | Lesson for NeighbourPOS |
|---|---|---|---|
| **Square POS** (free tier) | Polished checkout, item grid, receipts, basic CRM | Requires their payment processing + account; US-centric; data lives with vendor | Match the *checkout ergonomics* (fast grid, quick amounts, receipts), not the payments stack |
| **Loyverse** (free) | Free POS + loyalty + inventory + employee mgmt; strong mobile UI | Cloud account required; paid add-ons for inventory depth | Loyalty expectation exists even at the free tier → ship "loyalty-lite" via existing coupon campaigns; UI bar is set by their level of polish |
| **Kyte** (freemium) | Mobile-first, digital catalog, digital + printed receipts, works offline | Subscription upsell; vendor cloud | Receipt *sharing* (a link/text the customer keeps) is table stakes; graceful offline messaging matters |
| **Vyapar** (India, kirana-focused) | Cash/UPI/card recording, payment reminders, offline-first, local-language | India/GST-specific | Cash-first recording + "payment reminder" workflow = our credit ledger + export loop |
| **Khatabook / Hishabee** (BD/IN ledger apps) | Digital *udhar/khata* (customer credit tab) + SMS reminders — massively adopted by cash-only shops | Ledger only; no real POS/inventory | **Biggest gap in NeighbourPOS today: no customer credit ledger.** For cash-only shops, tracking "who owes me" is more important than campaigns. Phase 4 adds it |

Positioning that survives this table: *the only POS+CRM a cash-only shop can run on $2 shared hosting, that they fully own, that turns their order history into ready-to-send campaign lists.* Nobody else combines: no subscription, no vendor account, credit ledger, and import-ready campaign exports.

---

## Phase 1 — App UI overhaul (staff SPA inside neighbourpos.php)

Goal: the app should look like a finished commercial tool at first paint. All changes are CSS/HTML/JS inside the single file.

**Design tokens (apply consistently, replace ad-hoc values):**
- Depth: reintroduce a real elevation system. `--shadow-sm: 0 1px 2px rgb(9 11 16 / .06); --shadow-md: 0 4px 12px rgb(9 11 16 / .08)`. Cards get `--shadow-sm` + `1px solid var(--line)`. Kill the current `--shadow:none` flatness.
- Radius scale: 6 / 10 / 14px (control / card / modal). Stop mixing 7 and 8.
- Type scale: 12 / 13 / 15 / 18 / 24px with defined weights; page titles exist (currently tabs have no visible page heading).
- Spacing: 4px base grid; card padding 16–20px, not 14.

Tasks:

- [x] **P1.1 Icon system.** Replace every letter-glyph "icon" (`.navIcon` letters, `.iconBtn` text glyphs, `.productVisual` initials fallback stays) with a single inline SVG sprite (`<svg><symbol id="i-pos">…`) defined once in the SPA HTML; ~16 icons (pos, dashboard, orders, inventory, crm, campaigns, reports, admin, search, plus, minus, trash, export, print, user, alert). Stroke style, 1.75px, `currentColor`. Acceptance: no nav/toolbar element renders a letter as an icon; sprite referenced via `<use>`.
- [x] **P1.2 Elevation + card polish.** Apply the token block above across `.card, .k, .stationPanel, .cartPanel, .nav, .saleTile, .totals`. Sale tiles get hover lift (`transform:translateY(-1px)` + shadow-md) and a visible pressed state. Acceptance: zero occurrences of `box-shadow:none` on card-level surfaces; visual diff shows borders+shadows on all panels.
- [x] **P1.3 Page headers + empty states.** Every tab starts with a header row: page title (18px/700), one-line description, and the tab's primary action button. Every list/table gets an empty state (icon + one sentence + primary CTA, e.g. Inventory empty → "Add your first product" / "Load sample data"). Acceptance: with a fresh db, every tab shows a designed empty state, never a bare "no rows" or blank area.
- [x] **P1.4 Toasts + modal confirms.** Add a tiny toast system (top-right, auto-dismiss 3.5s, success/error/info) and a promise-based modal `uiConfirm(title, body, danger?)` + `uiPrompt(...)`. Replace ALL `alert()`, `confirm()`, `prompt()` call sites (line-note prompt in POS, deletes, campaign send confirms, etc.). Acceptance: `grep -cE "\balert\(|\bconfirm\(|\bprompt\(" neighbourpos.php` → 0 in the SPA `<script>` block.
- [x] **P1.5 Loading + error states.** Every fetch-rendered region shows a skeleton (shimmering blocks) while loading and an inline retry card on failure. Add a global offline banner: on `fetch` failure or `navigator.onLine === false`, show "Connection lost — changes can't save" bar; recheck every 5s. Acceptance: throttling the network shows skeletons; killing the server shows the banner, no unhandled promise rejections in console.
- [x] **P1.6 POS ergonomics.** (a) Barcode/keyboard-wedge: when the sale search input receives an exact SKU match + Enter, add that item to cart immediately and clear the input. (b) Keyboard shortcuts: `/` focuses search, `F2` place order, `+`/`-` adjust qty of last-touched line. (c) Amount tendered → change-due calculator in the cash tender row. (d) Tap targets ≥44px on ≤980px viewports. Acceptance: a USB scanner (or typing a SKU + Enter) adds the item; change-due updates live; Lighthouse mobile tap-target audit passes.
- [x] **P1.7 Money & date formatting.** One `fmtMoney(cents)` and `fmtDate(iso)` used everywhere; money uses store `currency_symbol` and thousands separators; dates render as relative ("2h ago") under 48h, else short date. Kill any remaining hardcoded `$`. Acceptance: `grep -n '"\$"' `-style literals in JS render paths → 0; switching currency symbol in Admin updates every screen.
- [x] **P1.8 Login/register/portal/receipt polish.** These four non-SPA pages get the same tokens: centered card on soft gradient, brand mark, proper form states, error styling. Receipt page gets print CSS (80mm-friendly: no nav, monospace totals block) and a "Share" button using `navigator.share` with clipboard fallback (shares the existing public receipt URL). Acceptance: `?action=receipt&code=…` prints cleanly to 80mm width; login page visually matches the app.
- [x] **P1.9 Dashboard upgrade.** Add a 14-day sales sparkline (inline SVG, no chart lib) and "needs attention" cards (low stock count, unpaid orders count, campaigns queued but not exported). KPI cards get icons + delta vs previous period. Acceptance: sparkline renders from `api_sales_report` data; zero-data day renders a flat baseline, not a broken path.
- [x] **P1.10 Table/list consistency.** Orders/Inventory/CRM/Audit lists: consistent row height, right-aligned numeric columns, sticky header on scroll, hover row highlight, and a shared badge component for statuses. Acceptance: all four screens use the same table classes; no horizontal overflow at 360px width.

## Phase 2 — Landing page full redesign (index.html) + demo credibility

Goal: a visitor should believe within 5 seconds that this is a real, working, maintained product.

- [x] **P2.1 Real product visuals.** Build two hand-crafted, pixel-accurate HTML/CSS mockups inside index.html (NOT screenshots, NOT images): (a) the POS checkout screen with a filled cart, (b) the campaign export screen with a segment preview + "Download Mailchimp CSV" button. They must mirror the ACTUAL post-Phase-1 app UI (same tokens/colors/layout) — update them if Phase 1 changed the look. Hero shows mockup (a) in a browser-chrome frame, slightly rotated/elevated. Acceptance: hero contains a recognizable product UI, not just headline text; mockups match app styling.
- [x] **P2.2 Rewrite hero + narrative.** New structure: (1) Hero: headline states the outcome ("The POS + customer list your corner shop actually owns"), subhead names the stack honestly (one PHP file, your hosting, no subscription), primary CTA "Try the live demo", secondary "Deploy in 10 minutes". (2) "Built for cash-first shops" section: explicitly say *no card reader required, record cash/mobile-money/card, phone number is the customer ID*. (3) The store loop (sell → remember → bring back) with the three mockups/mini-UIs. (4) Campaign export walkthrough: 3-step visual — build segment → queue campaign → download CSV for Mailchimp/Brevo/SMS/WhatsApp (name the tools; this is the differentiator). (5) Honest comparison table (keep, restyle). (6) Limits section (keep — it builds trust). (7) FAQ (5–7 real questions: hosting requirements, backups, multi-device, security, what "no sending" means). (8) Final CTA. Acceptance: page names at least 3 external campaign tools; the word "own"/"ownership" appears in hero; no fabricated proof (Invariant 8).
- [x] **P2.3 Credibility signals.** Header/footer get: version badge (read from a single `const APP_VERSION` you also add to neighbourpos.php and keep in sync), "Changelog" link to CHANGELOG.md on GitHub, "Security" link to SECURITY.md, license note, last-updated date. Add OpenGraph/Twitter meta + a proper social card as inline-SVG-based favicon upgrade. Acceptance: OG tags validate; version badge matches `APP_VERSION` in the PHP file.
- [x] **P2.4 Demo upgrade.** demo.html: add a persistent top banner ("Static demo — data resets on refresh; the real app runs on your hosting" + link back), pre-load sample catalog with 12+ realistic items and 3 sample customers, and make the full checkout loop work (attach customer, coupon, place order shows a receipt modal). Bring demo styling to Phase-1 parity. Acceptance: a first-time visitor can complete a sale in the demo in <30s with zero instructions; demo visually matches the real app.
- [ ] **P2.5 Performance/a11y pass.** Both static pages: Lighthouse ≥95 performance / ≥95 accessibility on mobile; self-host or `font-display:swap` fonts; all interactive elements keyboard-reachable; contrast AA. Acceptance: Lighthouse scores recorded in CHANGELOG entry.

## Phase 3 — Campaign export overhaul (the core differentiator)

Goal: "Download → import into your sending tool → send" with zero manual CSV editing. Research facts to honor: Mailchimp requires an `Email Address` column and E.164 phones for SMS; Brevo requires at least one of `EMAIL`/`SMS` and expects country-coded numbers; SMS tools (SimpleTexting/TextMagic) require phone-with-country-code and consented contacts only.

- [ ] **P3.1 Store setting: default country calling code.** Add `default_country_code` (e.g. `+880`, `+1`) to stores (guarded ALTER, Invariant 9), editable in Admin, surfaced in `api_settings_update`/`api_me`. Add `normalize_e164(string $phone, string $cc): ?string` in PHP: strip spaces/dashes/parens, convert leading `00` to `+`, prefix bare national numbers (drop one leading `0`) with the store code; return null if result isn't `+[1-9][0-9]{6,14}`. Acceptance: unit-style assertions via a `?action=api_dev_selftest` (admin-only, or CLI) covering `01712-345678`+`+880` → `+8801712345678`, `(555) 010-1234`+`+1` → `+15550101234`, garbage → null.
- [ ] **P3.2 Export profiles.** Extend `campaign_export` with `&format=` producing these profiles (default `full` = current 20-column CSV, unchanged for backward compat):
  - `mailchimp`: columns `Email Address,First Name,Last Name,Phone,Tags` — rows WITH email only; Tags = `campaign:<name>` + customer tags; phone in E.164 when normalizable else blank.
  - `brevo`: columns `EMAIL,SMS,FIRSTNAME,LASTNAME,COUPON_CODE` — row included if email OR normalizable phone exists; SMS strictly E.164.
  - `sms`: columns `phone,name,coupon_code,message` — E.164 only, rows without normalizable phone are EXCLUDED (and counted, see P3.4); `message` is the fully rendered per-recipient text.
  - `whatsapp`: columns `phone,name,message,wa_link` — `wa_link` = `https://wa.me/<digits>?text=<urlencoded rendered message>` so a cash-only shop can send one-by-one from a spreadsheet.
  Name splitting: first token → First Name, remainder → Last Name (empty allowed). All profiles: dedupe (by email for mailchimp; by phone for sms/whatsapp; by email-then-phone for brevo), keep `csv_safe_cell()`, opt-in filtering identical to current behavior including the audited override, money fields (if any) in currency units not cents. Acceptance: scripted check — create campaign with recipients incl. a duplicate phone, a no-email customer, an unparseable phone; assert each profile's header row byte-exact, row counts, and that the sms profile has no blank/invalid phone.
- [ ] **P3.3 Merge-field rendering.** Support `{name}`, `{first_name}`, `{coupon_code}`, `{store_name}` in `message_template`; render per-recipient at export time (and in `api_campaign_simulate` preview). Unknown `{tokens}` pass through untouched. Acceptance: template `"Hi {first_name}, use {coupon_code}"` exports fully substituted in `sms`/`whatsapp` profiles.
- [ ] **P3.4 Export UX in Campaigns tab.** Replace the single export button with a small export panel: format picker (with one-line "works with: Mailchimp / Brevo / any SMS tool / WhatsApp manual"), UTF-8 BOM toggle ("Excel-friendly"), and a pre-export summary fetched from a new `api_campaign_export_preview`: total queued, opted-in, with-email, with-valid-phone, excluded-and-why. Filename: `<campaign-slug>-<format>-YYYYMMDD.csv`. Acceptance: summary numbers match actual exported row counts for every profile.
- [ ] **P3.5 Customer list export (no campaign needed).** CRM tab: "Export customers" using the SAME profile engine on the current filter/segment (opt-in-only enforced by default, override audited, same formats). Cash-only shops often just want their full opted-in phone book. Endpoint `customer_export` mirrors `campaign_export` behavior incl. rate limiting + audit. Acceptance: exporting segment "spend > X" as `sms` yields the same customers as the segment preview, filtered/normalized identically.
- [ ] **P3.6 Segment upgrades.** Add two filters to `segment_query()` + UI: `tag` (match against `tags_text`, comma-tokenized) and `has_balance` (only meaningful after P4.1; hide until then). Add "duplicate segment" and show live count next to each saved segment. Acceptance: tag filter returns correct rows; counts refresh after orders.
- [ ] **P3.7 Docs.** New `EXPORTS.md`: one section per profile with header spec, a 3-row example, and click-path import instructions for Mailchimp, Brevo, SimpleTexting/TextMagic, and the WhatsApp wa.me workflow; consent/compliance note (export includes only opted-in contacts by default; overrides are audited; local law is the merchant's responsibility). Link it from README and the Campaigns tab. Acceptance: file exists, linked in both places.

## Phase 4 — Cash-first features (competitor-driven backlog)

- [ ] **P4.1 Customer credit ledger ("tab / khata / udhar").** New table `ledger_entries (id, customer_id, order_id NULL, type 'credit'|'payment', amount_cents, note, created_by, created_at)`. POS: new tender option "On credit" (order marked unpaid, ledger credit entry auto-created). Customer profile: running balance, entry list, "Record payment" button. CRM list: balance column + "owes money" quick filter; segment filter `has_balance` (activates P3.6 leftover). Dashboard: "Outstanding credit" KPI. Exports: optional `balance` column in `full` profile; a dedicated `sms` export of debtors with `{balance}` merge field enables Khatabook-style payment reminders through any SMS tool. Acceptance: credit sale → balance up; payment → balance down, audit logged; reminder export renders balances in currency units.
- [ ] **P4.2 Quick sale (amount-only).** POS gets a "Quick amount" tile (first position, always visible): enter amount (+ optional label), adds a custom line item with no product/stock linkage (`order_items.product_id NULL` already allowed). Many cash shops ring totals without a catalog. Acceptance: an order of only quick-amount lines completes, reports include it under category "(quick sale)".
- [ ] **P4.3 Product CSV import.** The `imports` table exists but nothing writes to it — wire it up: Inventory tab "Import CSV" (columns `sku,name,price,stock,category`; price in currency units), preview-then-commit flow, per-row error report stored in `imports.errors_json`, template CSV downloadable. Rate-limited, admin-audited, 500-row cap per file. Acceptance: importing the template + 2 bad rows imports good rows and reports both errors with row numbers; `imports` row is written.
- [ ] **P4.4 Loyalty-lite via campaign presets.** Two new one-click presets in Campaigns: "Reward top spenders" (spend ≥ X, coupon auto-generated) and "Win back lapsed" (inactive ≥ N days). Presets create segment + campaign + queue recipients in one action, then land the user on the export panel. Acceptance: one click from empty state to downloadable CSV on sample data.
- [ ] **P4.5 End-of-day summary.** Reports tab: "Today's close" card — orders, gross, by payment method (cash/card/mobile/credit), coupons redeemed, new customers; printable (same 80mm print CSS as receipts). Cash-only shops reconcile the drawer against this. Acceptance: matches sum of the day's orders; prints on one narrow page.

## Phase 5 — Hardening & release

- [ ] **P5.1 Self-test endpoint.** `?action=api_dev_selftest` (admin-only): runs the E.164 assertions, a segment-filter matrix on fixture data in a temp in-memory SQLite, and export-profile header checks; returns JSON pass/fail list. Wire into Verification step 5. Acceptance: returns all-pass on clean checkout.
- [ ] **P5.2 Backup/restore round-trip doc + guard.** Verify `database_backup` streams a consistent snapshot (use SQLite backup API or `VACUUM INTO` temp file, not raw fread of a live db). Document restore in SETUP.md. Acceptance: backup taken during concurrent writes opens clean (`PRAGMA integrity_check` = ok).
- [ ] **P5.3 Final sweep.** Update README (feature list incl. ledger + export profiles), bump `APP_VERSION`, re-run Lighthouse on both static pages, fresh-install walkthrough following SETUP.md verbatim on a clean PHP 8.1 environment. Acceptance: all Verification steps + P5.1 selftest pass; README screenshots/claims match reality.

---

## Explicit non-goals (do not build, even if tempting)

- In-app SMS/email sending or API integrations with sending providers (export-only is the moat and the compliance stance).
- Offline write queue / PWA sync (SQLite server writes make this false comfort; the P1.5 banner is the honest version).
- Multi-store, staff roles/permissions beyond current admin/staff, purchase orders, supplier management.
- Payment processing of any kind. Gift cards, points-balance loyalty engines.
- Rewriting into a framework, or splitting the app file (Invariant 1).

## Notes for the implementer

- The SPA's JS lives in one `<script>` block at the bottom of `neighbourpos.php`; keep new JS in the existing module pattern (`renderX()` functions + `render()` router).
- `renderPOSOld()` (~line 2916) appears superseded by `renderPOS()` (~line 3061) — confirm it's dead and delete it in P1.2 (counts as card-polish cleanup; log it in CHANGELOG).
- `assets/` is currently empty; it may hold OG images for P2.3 — that's fine (static site is exempt from Invariant 1, but keep it lean).
- When in doubt between adding a feature and improving the finish of an existing one: finish wins. The product's pitch is small-but-credible.
