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

Assert-SourceContains $source 'inventory_low_stock_export' 'Low-stock CSV export route is missing'
Assert-SourceContains $source 'function renderDashboard' 'Today snapshot dashboard UI is missing'
Assert-SourceContains $source "api_today_snapshot" 'Today snapshot API is missing'
Assert-SourceContains $source "api_product_save" 'Product create/edit API is missing'
Assert-SourceContains $source "api_sales_report" 'Sales report API is missing'
Assert-SourceContains $source "sales_report_export" 'Sales report CSV export route is missing'
Assert-SourceContains $source "coupon_code_text" 'Order coupon capture field is missing'
Assert-SourceContains $source "redeemed_order_id" 'Campaign recipient redemption schema is missing'
Assert-SourceContains $source "api_campaign_preset_create" 'Campaign preset API is missing'
Assert-SourceContains $source "api_customer_timeline" 'Customer timeline API is missing'
Assert-SourceContains $source "api_orders_search" 'Order search API is missing'
Assert-SourceContains $source "api_audit_log" 'Audit log viewer API is missing'
Assert-SourceContains $source "api_password_change" 'Password change API is missing'
Assert-SourceContains $source "api_admin_password_reset" 'Admin password reset API is missing'
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
Assert-SourceContains $source 'pos_amount_received' 'Production cash received input is missing'
Assert-SourceContains $source 'change_due' 'Production change-due display is missing'
Assert-SourceContains $source 'min-height:44px' 'Production mobile tap target sizing is missing'
Assert-SourceContains $source 'sku LIKE' 'Production product search does not include SKU matching'
Assert-SourceContains $source 'function fmtMoney' 'Production shared money formatter is missing'
Assert-SourceContains $source 'toLocaleString' 'Production money formatter lacks thousands separators'
Assert-SourceContains $source 'function fmtDate' 'Production shared date formatter is missing'
Assert-SourceDoesNotContain $source 'function money\(' 'Legacy JS money formatter should be removed'
Assert-SourceContains $source '\.saleTile strong,\.saleTile \.name\{font-size:16px' 'Production checkout product names should keep the larger tile sizing'
Assert-SourceContains $demo '\.saleTile strong,\.saleTile \.name\{font-size:16px' 'Static demo checkout product names should keep the larger tile sizing'
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

Assert-SourceContains $landing 'brandMark' 'Landing page premium brand mark is missing'
Assert-SourceDoesNotContain $landing 'heroLogo|heroPanel|heroImage' 'Landing page hero should stay logo/image-free'
Assert-SourceContains $landing 'rel="icon" type="image/svg\+xml"' 'Landing page SVG favicon is missing'
Assert-SourceContains $landing 'Sell fast, remember customers, bring them back' 'Landing page owner-first hero copy is missing'
Assert-SourceContains $landing 'Open demo' 'Landing page primary demo CTA is missing'
Assert-SourceContains $landing 'Deploy guide' 'Landing page deploy guide link is missing'
Assert-SourceContains $landing 'View source' 'Landing page source link is missing'
Assert-SourceContains $landing 'No payment processing' 'Landing page payment-processing limit is missing'

Assert-SourceContains $readme 'sales reports' 'README does not mention sales reports'
Assert-SourceContains $setup 'database backup' 'SETUP does not mention database backup'

Write-Host 'feature_backlog source checks passed.'
