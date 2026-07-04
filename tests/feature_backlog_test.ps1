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

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
$source = Get-Content -Raw -LiteralPath (Join-Path $repoRoot 'neighbourpos.php')
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

Assert-SourceContains $readme 'sales reports' 'README does not mention sales reports'
Assert-SourceContains $setup 'database backup' 'SETUP does not mention database backup'

Write-Host 'feature_backlog source checks passed.'
