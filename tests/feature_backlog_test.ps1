$ErrorActionPreference = 'Stop'

function Assert-SourceContains {
  param(
    [string]$Source,
    [string]$Pattern,
    [string]$Message
  )
  if ($Source -notmatch $Pattern) {
    throw $Message
  }
}

function Assert-SourceDoesNotContain {
  param(
    [string]$Source,
    [string]$Pattern,
    [string]$Message
  )
  if ($Source -match $Pattern) {
    throw $Message
  }
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
$source = Get-Content -Raw -LiteralPath (Join-Path $repoRoot 'neighbourpos.php')
$demo = Get-Content -Raw -LiteralPath (Join-Path $repoRoot 'demo.html')
$landing = Get-Content -Raw -LiteralPath (Join-Path $repoRoot 'index.html')
$readme = Get-Content -Raw -LiteralPath (Join-Path $repoRoot 'README.md')
$setup = Get-Content -Raw -LiteralPath (Join-Path $repoRoot 'SETUP.md')
$exportsPath = Join-Path $repoRoot 'EXPORTS.md'
if (-not (Test-Path -LiteralPath $exportsPath)) { throw 'EXPORTS.md export guide is missing' }
$exports = Get-Content -Raw -LiteralPath $exportsPath

$phpVersionMatch = [regex]::Match($source, "const APP_VERSION = '([^']+)'")
$landingVersionMatch = [regex]::Match($landing, "const APP_VERSION = '([^']+)'")
if (-not $phpVersionMatch.Success) { throw 'Production APP_VERSION constant is missing' }
if (-not $landingVersionMatch.Success) { throw 'Landing APP_VERSION constant is missing' }
if ($phpVersionMatch.Groups[1].Value -ne $landingVersionMatch.Groups[1].Value) {
  throw "Landing version badge does not match production APP_VERSION"
}

$demoProductSeedCount = ([regex]::Matches($demo, 'sku:"[^"]+"')).Count
$demoCustomerSeedCount = ([regex]::Matches($demo, 'phone:"555-')).Count
if ($demoProductSeedCount -lt 12) { throw 'Static demo should seed at least 12 realistic catalog items' }
if ($demoCustomerSeedCount -lt 3) { throw 'Static demo should seed at least 3 sample customers' }

Assert-SourceContains $source 'inventory_low_stock_export' 'Low-stock CSV export route is missing'
Assert-SourceContains $source 'product_import_template' 'Product CSV import template route is missing'
Assert-SourceContains $source 'function renderDashboard' 'Today snapshot dashboard UI is missing'
Assert-SourceContains $source "api_today_snapshot" 'Today snapshot API is missing'
Assert-SourceContains $source "api_product_save" 'Product create/edit API is missing'
Assert-SourceContains $source 'api_product_import_preview' 'Product CSV import preview API is missing'
Assert-SourceContains $source 'api_product_import_commit' 'Product CSV import commit API is missing'
Assert-SourceContains $source 'api_product_imports_list' 'Product CSV import history API is missing'
Assert-SourceContains $source 'PRODUCT_IMPORT_MAX_ROWS' 'Product CSV import row cap is missing'
Assert-SourceContains $source "api_sales_report" 'Sales report API is missing'
Assert-SourceContains $source "sales_report_export" 'Sales report CSV export route is missing'
Assert-SourceContains $source "coupon_code_text" 'Order coupon capture field is missing'
Assert-SourceContains $source "redeemed_order_id" 'Campaign recipient redemption schema is missing'
Assert-SourceContains $source "api_campaign_preset_create" 'Campaign preset API is missing'
Assert-SourceContains $source 'reward_top_spenders' 'Reward top spenders preset is missing'
Assert-SourceContains $source 'win_back_lapsed' 'Win back lapsed preset is missing'
Assert-SourceContains $source 'focus_campaign_id' 'Preset-created campaign focus state is missing'
Assert-SourceContains $source 'Created and queued' 'One-click preset queue confirmation is missing'
Assert-SourceContains $source "api_customer_timeline" 'Customer timeline API is missing'
Assert-SourceContains $source "api_orders_search" 'Order search API is missing'
Assert-SourceContains $source "api_audit_log" 'Audit log viewer API is missing'
Assert-SourceContains $source "api_password_change" 'Password change API is missing'
Assert-SourceContains $source "api_admin_password_reset" 'Admin password reset API is missing'
Assert-SourceContains $source "default_country_code" 'Store default country code setting is missing'
Assert-SourceContains $source "function normalize_e164" 'E.164 phone normalizer is missing'
Assert-SourceContains $source "api_dev_selftest" 'Developer self-test route is missing'
Assert-SourceContains $source "function campaign_export_profile" 'Campaign export profile engine is missing'
Assert-SourceContains $source "Email Address" 'Mailchimp export profile header is missing'
Assert-SourceContains $source "COUPON_CODE" 'Brevo export profile coupon header is missing'
Assert-SourceContains $source "https://wa.me/" 'WhatsApp export link builder is missing'
Assert-SourceContains $source "preview_messages" 'Campaign simulator merge-field preview is missing'
Assert-SourceContains $source "{first_name}" 'Campaign merge-field renderer is missing first_name support'
Assert-SourceContains $source "{store_name}" 'Campaign merge-field renderer is missing store_name support'
Assert-SourceContains $source "api_campaign_export_preview" 'Campaign export preview API is missing'
Assert-SourceContains $source "data-export-preview" 'Campaign export preview control is missing'
Assert-SourceContains $source "Excel-friendly" 'Campaign export BOM toggle is missing'
Assert-SourceContains $source "Works with: Mailchimp / Brevo / any SMS tool / WhatsApp manual" 'Campaign export helper copy is missing'
Assert-SourceContains $source "customer_export" 'Customer export route is missing'
Assert-SourceContains $source "crm_export_format" 'CRM customer export format control is missing'
Assert-SourceContains $source "Download customers" 'CRM customer export download control is missing'
Assert-SourceContains $source "EXPORTS.md" 'Campaigns tab export guide link is missing'
Assert-SourceContains $source "Export guide" 'Campaigns tab export guide label is missing'
Assert-SourceContains $source "api_segment_duplicate" 'Segment duplicate API is missing'
Assert-SourceContains $source "data-dup-seg" 'Segment duplicate control is missing'
Assert-SourceContains $source "has_balance" 'Segment has_balance filter hook is missing'
Assert-SourceContains $source "CREATE TABLE IF NOT EXISTS ledger_entries" 'Credit ledger table is missing'
Assert-SourceContains $source "api_ledger_payment" 'Ledger payment API is missing'
Assert-SourceContains $source "ledger.credit" 'Ledger credit audit action is missing'
Assert-SourceContains $source "ledger.payment" 'Ledger payment audit action is missing'
Assert-SourceContains $source "payment_method: state.pos.payMethod" 'POS payment method payload is missing'
Assert-SourceContains $source "On credit" 'POS on-credit tender option is missing'
Assert-SourceContains $source "Outstanding credit" 'Dashboard outstanding credit KPI is missing'
Assert-SourceContains $source "Owes money" 'CRM owes-money quick filter is missing'
Assert-SourceContains $source "Record payment" 'CRM record-payment control is missing'
Assert-SourceContains $source "Debtor reminders" 'CRM debtor reminder export is missing'
Assert-SourceContains $source "{balance}" 'Balance merge field is missing'
Assert-SourceContains $source "include_balance" 'Full export include-balance option is missing'
Assert-SourceContains $source "portal_opt_in_update" 'Customer portal opt-in update route is missing'
Assert-SourceContains $source "database_backup" 'Database backup route is missing'

Assert-SourceContains $source 'data-tab="dashboard"' 'Dashboard navigation tab is missing'
Assert-SourceContains $source 'Export low-stock CSV' 'Low-stock export button is missing'
Assert-SourceContains $source 'Save product' 'Product save control is missing'
Assert-SourceContains $source 'Sales reports' 'Sales report UI is missing'
Assert-SourceContains $source 'Coupon code' 'POS coupon input is missing'
Assert-SourceContains $source 'Campaign presets' 'Campaign presets UI is missing'
Assert-SourceContains $source 'Timeline' 'Customer timeline UI is missing'
Assert-SourceContains $source 'Order search' 'Order search UI is missing'
Assert-SourceContains $source 'Audit log' 'Audit log UI is missing'
Assert-SourceContains $source 'Change password' 'Password management UI is missing'
Assert-SourceContains $source 'Download database backup' 'Database backup UI is missing'
Assert-SourceContains $source 'store_country_code' 'Admin default country code setting control is missing'

Assert-SourceContains $demo 'checkoutShell' 'Static demo cashier station shell is missing'
Assert-SourceContains $demo 'saleSearch' 'Static demo checkout search/scan control is missing'
Assert-SourceContains $demo 'categoryTabs' 'Static demo checkout category tabs are missing'
Assert-SourceContains $demo 'customerLookup' 'Static demo checkout customer lookup is missing'
Assert-SourceContains $demo 'paymentMethod' 'Static demo payment method state/control is missing'
Assert-SourceContains $demo 'markPaid' 'Static demo mark-paid control is missing'
Assert-SourceContains $demo 'tinyStatus' 'Static demo checkout status strip is missing'
Assert-SourceContains $demo 'brandMark' 'Static demo premium brand mark is missing'
Assert-SourceContains $demo 'navCollapsed' 'Static demo collapsible sidebar state is missing'
Assert-SourceContains $demo 'sideToggle' 'Static demo sidebar collapse toggle is missing'
Assert-SourceContains $demo 'navIcon' 'Static demo icon rail labels are missing'
Assert-SourceContains $demo 'rel="icon" type="image/svg\+xml"' 'Static demo SVG favicon is missing'
Assert-SourceContains $demo 'Static demo - data resets on refresh' 'Static demo reset/hosting banner is missing'
Assert-SourceContains $demo '<use href="#i-pos">' 'Static demo POS SVG nav icon is missing'
Assert-SourceContains $demo '<use href="#i-barcode">' 'Static demo barcode icon button is missing'
Assert-SourceContains $demo 'receiptModal' 'Static demo receipt modal styling is missing'
Assert-SourceContains $demo 'showReceiptModal' 'Static demo receipt modal renderer is missing'
Assert-SourceContains $demo 'receiptRoot' 'Static demo receipt modal root is missing'
Assert-SourceContains $demo 'data-view-orders' 'Static demo receipt view-orders action is missing'
Assert-SourceDoesNotContain $demo 'fonts.googleapis.com' 'Static demo should not use render-blocking remote font CSS'

Assert-SourceContains $source 'checkoutShell' 'Production cashier station shell is missing'
Assert-SourceContains $source 'pos_category' 'Production checkout category filter is missing'
Assert-SourceContains $source 'attachedCustomer' 'Production checkout attached customer state is missing'
Assert-SourceContains $source 'lookupCustomerByPhone' 'Production checkout phone lookup helper is missing'
Assert-SourceContains $source 'payment_received' 'Production checkout payment received payload is missing'
Assert-SourceContains $source 'api_customer_get' 'Production checkout does not use existing customer lookup API'
Assert-SourceContains $source 'brand_favicon_href' 'Production SVG favicon helper is missing'
Assert-SourceContains $source 'brandMark' 'Production premium brand mark is missing'
Assert-SourceContains $source 'navCollapsed' 'Production collapsible sidebar state is missing'
Assert-SourceContains $source 'navToggle' 'Production sidebar collapse toggle is missing'
Assert-SourceContains $source 'navIcon' 'Production icon rail labels are missing'
Assert-SourceContains $source 'skeletonRow' 'Production loading skeleton rows are missing'
Assert-SourceContains $source 'retryCard' 'Production inline retry cards are missing'
Assert-SourceContains $source 'data-retry' 'Production retry action binding is missing'
Assert-SourceContains $source 'offlineBanner' 'Production offline banner is missing'
Assert-SourceContains $source 'Connection lost' 'Production offline warning copy is missing'
Assert-SourceContains $source 'addExactSkuFromSearch' 'Production exact-SKU scan helper is missing'
Assert-SourceContains $source 'setupKeyboardShortcuts' 'Production POS keyboard shortcuts are missing'
Assert-SourceContains $source 'lastTouchedProductId' 'Production last-touched cart line state is missing'
Assert-SourceContains $source 'Quick amount' 'Production quick amount tile is missing'
Assert-SourceContains $source 'addQuickSaleLine' 'Production quick sale cart helper is missing'
Assert-SourceContains $source "'product_id' => null" 'Production quick sale order item should store product_id NULL'
Assert-SourceContains $source '\(quick sale\)' 'Production quick sale report category is missing'
Assert-SourceContains $source 'Import CSV' 'Inventory product import panel is missing'
Assert-SourceContains $source 'Template CSV' 'Inventory product import template link is missing'
Assert-SourceContains $source 'Preview import' 'Inventory product import preview control is missing'
Assert-SourceContains $source 'Import valid rows' 'Inventory product import commit control is missing'
Assert-SourceContains $source 'pos_amount_received' 'Production cash received input is missing'
Assert-SourceContains $source 'change_due' 'Production change-due display is missing'
Assert-SourceContains $source 'min-height:44px' 'Production mobile tap target sizing is missing'
Assert-SourceContains $source 'sku LIKE' 'Production product search does not include SKU matching'
Assert-SourceContains $source 'function fmtMoney' 'Production shared money formatter is missing'
Assert-SourceContains $source 'toLocaleString' 'Production money formatter lacks thousands separators'
Assert-SourceContains $source 'function fmtDate' 'Production shared date formatter is missing'
Assert-SourceDoesNotContain $source 'function money\(' 'Legacy JS money formatter should be removed'
Assert-SourceContains $source '\.saleTile strong,\.saleTile \.name\{font-size:18px' 'Production checkout product names should keep the larger tile sizing'
Assert-SourceContains $demo '\.saleTile strong,\.saleTile \.name\{font-size:18px' 'Static demo checkout product names should keep the larger tile sizing'
Assert-SourceContains $source 'function public_page_css' 'Public login/register/portal shell styles are missing'
Assert-SourceContains $source 'function receipt_page_css' 'Receipt print/share styles are missing'
Assert-SourceContains $source '@page\{size:80mm' 'Receipt 80mm print page rule is missing'
Assert-SourceContains $source 'navigator\.share' 'Receipt Web Share button is missing'
Assert-SourceContains $source 'navigator\.clipboard && navigator\.clipboard\.writeText' 'Receipt clipboard fallback is missing'
Assert-SourceContains $source 'action=receipt&code' 'Public receipt code URL is missing'
Assert-SourceContains $source 'SELECT \* FROM orders WHERE order_code = \?' 'Receipt route must support code lookup'
Assert-SourceDoesNotContain $source 'action=receipt&id' 'In-app receipt links should use public receipt codes'
Assert-SourceContains $source "daily' =>" 'Sales report daily sparkline series is missing'
Assert-SourceContains $source 'function salesTrendSparkline' 'Dashboard 14-day sales sparkline renderer is missing'
Assert-SourceContains $source 'function sparklinePath' 'Dashboard sparkline path helper is missing'
Assert-SourceContains $source 'unpaid_orders_count' 'Dashboard unpaid-orders attention count is missing'
Assert-SourceContains $source 'COUNT\(DISTINCT campaign_id\)' 'Dashboard queued campaign attention count is missing'
Assert-SourceContains $source 'deltas' 'Dashboard KPI deltas are missing'
Assert-SourceContains $source 'function dataTable' 'Shared data table helper is missing'
Assert-SourceContains $source 'dataTableWrap' 'Shared data table wrapper class is missing'
Assert-SourceContains $source 'position:sticky;top:0' 'Shared data table sticky header is missing'
Assert-SourceContains $source 'className:''num''' 'Shared data table numeric alignment is missing from render paths'
Assert-SourceContains $source 'statusBadge' 'Shared status badge component/class is missing'
Assert-SourceContains $source 'v<\?=h\(APP_VERSION\)\?>' 'Production app version badge is missing'

Assert-SourceContains $landing 'brandMark' 'Landing page premium brand mark is missing'
Assert-SourceDoesNotContain $landing 'heroLogo|heroPanel|heroImage' 'Landing page hero should stay logo/image-free'
Assert-SourceContains $landing 'rel="icon" type="image/svg\+xml"' 'Landing page SVG favicon is missing'
Assert-SourceContains $landing 'The POS \+ customer list your corner shop actually owns' 'Landing page ownership hero copy is missing'
Assert-SourceContains $landing 'Try the live demo' 'Landing page live demo CTA is missing'
Assert-SourceContains $landing 'Deploy in 10 minutes' 'Landing page deploy-in-10 CTA is missing'
Assert-SourceContains $landing 'No card reader required' 'Landing page cash-first copy is missing'
Assert-SourceContains $landing 'phone number is the customer ID' 'Landing page phone-as-customer-ID copy is missing'
Assert-SourceContains $landing 'Mailchimp' 'Landing page Mailchimp export workflow copy is missing'
Assert-SourceContains $landing 'Brevo' 'Landing page Brevo export workflow copy is missing'
Assert-SourceContains $landing 'SimpleTexting' 'Landing page SMS tool export workflow copy is missing'
Assert-SourceContains $landing 'WhatsApp' 'Landing page WhatsApp export workflow copy is missing'
Assert-SourceContains $landing 'id="faq"' 'Landing page FAQ section is missing'
Assert-SourceContains $landing 'Open demo' 'Landing page primary demo CTA is missing'
Assert-SourceContains $landing 'Deploy guide' 'Landing page deploy guide link is missing'
Assert-SourceContains $landing 'View source' 'Landing page source link is missing'
Assert-SourceContains $landing 'No payment processing' 'Landing page payment-processing limit is missing'
Assert-SourceContains $landing 'checkoutMockup' 'Landing page checkout product mockup is missing'
Assert-SourceContains $landing 'campaignMockup' 'Landing page campaign export mockup is missing'
Assert-SourceContains $landing 'Download Mailchimp CSV' 'Landing page campaign export CTA mockup is missing'
Assert-SourceContains $landing 'segmentPreview' 'Landing page segment preview mockup is missing'
Assert-SourceContains $landing 'browserFrame' 'Landing page browser-frame product preview styling is missing'
Assert-SourceContains $landing 'data-app-version' 'Landing page version badge target is missing'
Assert-SourceContains $landing 'property="og:title"' 'Landing page OpenGraph title is missing'
Assert-SourceContains $landing 'property="og:image"' 'Landing page OpenGraph social card is missing'
Assert-SourceContains $landing 'name="twitter:card" content="summary_large_image"' 'Landing page Twitter card metadata is missing'
Assert-SourceContains $landing 'CHANGELOG.md' 'Landing page changelog link is missing'
Assert-SourceContains $landing 'SECURITY.md' 'Landing page security link is missing'
Assert-SourceContains $landing 'Last updated: 2026-07-07' 'Landing page last-updated date is missing'
Assert-SourceContains $landing 'License: not declared yet' 'Landing page license note is missing'
Assert-SourceDoesNotContain $landing 'fonts.googleapis.com' 'Landing page should not use render-blocking remote font CSS'

Assert-SourceContains $readme 'sales reports' 'README does not mention sales reports'
Assert-SourceContains $readme 'EXPORTS.md' 'README export guide link is missing'
Assert-SourceContains $setup 'database backup' 'SETUP does not mention database backup'

Assert-SourceContains $exports '# NeighbourPOS Export Guide' 'EXPORTS guide title is missing'
Assert-SourceContains $exports 'Email Address,First Name,Last Name,Phone,Tags' 'EXPORTS Mailchimp header spec is missing'
Assert-SourceContains $exports 'EMAIL,SMS,FIRSTNAME,LASTNAME,COUPON_CODE' 'EXPORTS Brevo header spec is missing'
Assert-SourceContains $exports 'phone,name,coupon_code,message' 'EXPORTS SMS header spec is missing'
Assert-SourceContains $exports 'phone,name,message,wa_link' 'EXPORTS WhatsApp header spec is missing'
Assert-SourceContains $exports 'Mailchimp' 'EXPORTS Mailchimp section is missing'
Assert-SourceContains $exports 'Brevo' 'EXPORTS Brevo section is missing'
Assert-SourceContains $exports 'SimpleTexting' 'EXPORTS SimpleTexting instructions are missing'
Assert-SourceContains $exports 'TextMagic|Textmagic' 'EXPORTS TextMagic instructions are missing'
Assert-SourceContains $exports 'WhatsApp' 'EXPORTS WhatsApp instructions are missing'
Assert-SourceContains $exports 'https://wa.me/' 'EXPORTS WhatsApp wa.me workflow is missing'
Assert-SourceContains $exports 'Debtor reminders' 'EXPORTS debtor reminder workflow is missing'
Assert-SourceContains $exports '\{balance\}' 'EXPORTS balance merge-field note is missing'
Assert-SourceContains $exports 'opted-in' 'EXPORTS consent default note is missing'
Assert-SourceContains $exports 'override' 'EXPORTS audited override note is missing'
Assert-SourceContains $exports 'merchant' 'EXPORTS merchant compliance responsibility note is missing'

Write-Host 'feature_backlog source checks passed.'
