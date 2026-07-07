$ErrorActionPreference = 'Stop'

function Assert-True {
  param(
    [bool]$Condition,
    [string]$Message
  )
  if (-not $Condition) {
    throw $Message
  }
}

function Invoke-AppJson {
  param(
    [string]$BaseUrl,
    [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
    [string]$Csrf,
    [string]$Action,
    [object]$Body
  )

  $json = $Body | ConvertTo-Json -Depth 10 -Compress
  try {
    $response = Invoke-WebRequest `
      -Uri "${BaseUrl}?action=$Action" `
      -Method Post `
      -WebSession $Session `
      -Headers @{ 'Accept' = 'application/json'; 'X-CSRF-Token' = $Csrf } `
      -ContentType 'application/json' `
      -Body $json `
      -UseBasicParsing
  } catch {
    $content = ''
    if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $content = $_.ErrorDetails.Message }
    throw "API action $Action request failed with body $json`: $($_.Exception.Message) $content"
  }

  $payload = $response.Content | ConvertFrom-Json
  Assert-True $payload.ok "API action $Action did not return ok=true"
  return $payload.data
}

function Invoke-AppGetJson {
  param(
    [string]$Uri,
    [Microsoft.PowerShell.Commands.WebRequestSession]$Session
  )

  $response = Invoke-WebRequest -Uri $Uri -WebSession $Session -Headers @{ 'Accept' = 'application/json' } -UseBasicParsing
  $payload = $response.Content | ConvertFrom-Json
  Assert-True $payload.ok "GET $Uri did not return ok=true"
  return $payload.data
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
$appSource = Join-Path $repoRoot 'neighbourpos.php'
$source = Get-Content -Raw -LiteralPath $appSource
$phpCommand = if ($env:NEIGHBOURPOS_PHP) { $env:NEIGHBOURPOS_PHP } else { 'php' }
$phpArgs = @()
if ($env:NEIGHBOURPOS_PHP_EXT_DIR) {
  $phpArgs = @('-d', "extension_dir=$env:NEIGHBOURPOS_PHP_EXT_DIR", '-d', 'extension=pdo_sqlite', '-d', 'extension=sqlite3')
}

$phpModules = & $phpCommand @phpArgs -m
if (-not ($phpModules -contains 'pdo_sqlite')) {
  Assert-True ($source -match 'Quick amount') 'Quick amount tile/control is missing'
  Assert-True ($source -match '\(quick sale\)') 'Quick sale report category is missing'
  Write-Host 'quick_sale source checks passed; skipping HTTP integration because PHP pdo_sqlite is not loaded.'
  return
}

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("neighbourpos-quick-sale-test-" + [guid]::NewGuid().ToString('N'))
$server = $null

try {
  New-Item -ItemType Directory -Path $tempRoot | Out-Null
  Copy-Item -LiteralPath $appSource -Destination (Join-Path $tempRoot 'neighbourpos.php')

  $port = Get-Random -Minimum 29100 -Maximum 39999
  $stdout = Join-Path $tempRoot 'server.out.log'
  $stderr = Join-Path $tempRoot 'server.err.log'
  $server = Start-Process `
    -FilePath $phpCommand `
    -ArgumentList ($phpArgs + @('-S', "127.0.0.1:$port", '-t', $tempRoot)) `
    -WorkingDirectory $tempRoot `
    -RedirectStandardOutput $stdout `
    -RedirectStandardError $stderr `
    -WindowStyle Hidden `
    -PassThru

  $baseUrl = "http://127.0.0.1:$port/neighbourpos.php"
  $loginPage = $null
  for ($i = 0; $i -lt 40; $i++) {
    try {
      $loginPage = Invoke-WebRequest -Uri "${baseUrl}?action=staff_login" -SessionVariable session -UseBasicParsing
      break
    } catch {
      Start-Sleep -Milliseconds 250
    }
  }
  Assert-True ($null -ne $loginPage) 'PHP development server did not become ready'
  Assert-True ($loginPage.Content -match "name='csrf' value='([^']+)'") 'Could not find login CSRF token'
  $csrf = $Matches[1]

  Invoke-WebRequest `
    -Uri "${baseUrl}?action=staff_login" `
    -Method Post `
    -WebSession $session `
    -Body @{ csrf = $csrf; email = 'admin@example.com'; password = 'ChangeMe123!' } `
    -UseBasicParsing | Out-Null

  Invoke-AppJson -BaseUrl $baseUrl -Session $session -Csrf $csrf -Action 'api_settings_update' -Body @{
    name = 'Neighbour Store'
    enable_delivery = 1
    tax_rate = 0
    accent = '#2563eb'
    currency_symbol = '$'
    default_country_code = '+1'
  } | Out-Null

  $order = Invoke-AppJson -BaseUrl $baseUrl -Session $session -Csrf $csrf -Action 'api_orders_create' -Body @{
    items = @(@{
      product_id = $null
      name = 'Counter total'
      price_cents = 1850
      qty = 1
      category = '(quick sale)'
      notes = 'amount-only sale'
    })
    order_type = 'pickup'
    expected_eta_minutes = 15
    tip_cents = 0
    coupon_code = ''
    payment_method = 'cash'
    payment_received = 1
    walkin = 1
    phone = ''
    customer_name = ''
    customer_address = ''
    marketing_opt_in = 0
  }
  Assert-True ([int]$order.order_id -gt 0) 'Quick sale order did not return an order id'

  $createdOrder = Invoke-AppGetJson -Uri "${baseUrl}?action=api_order_get&id=$([int]$order.order_id)" -Session $session
  Assert-True (@($createdOrder.items).Count -eq 1) 'Quick sale order should store one item'
  Assert-True ($null -eq $createdOrder.items[0].product_id) 'Quick sale item should not have product linkage'
  Assert-True ($createdOrder.items[0].name -eq 'Counter total') 'Quick sale item name was not preserved'
  Assert-True ([int]$createdOrder.items[0].price_cents -eq 1850) 'Quick sale item amount was not preserved'
  Assert-True ($createdOrder.items[0].category -eq '(quick sale)') 'Quick sale item category was not normalized'

  Invoke-AppJson -BaseUrl $baseUrl -Session $session -Csrf $csrf -Action 'api_order_status_update' -Body @{
    id = [int]$order.order_id
    status = 'completed'
  } | Out-Null

  $today = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd')
  $report = Invoke-AppGetJson -Uri "${baseUrl}?action=api_sales_report&from=$today&to=$today" -Session $session
  $quickCategory = @($report.category_mix | Where-Object { $_.category -eq '(quick sale)' })[0]
  Assert-True ($null -ne $quickCategory) 'Sales report should include quick sale category'
  Assert-True ([int]$quickCategory.revenue_cents -eq 1850) "Quick sale category revenue should be 1850, got $($quickCategory.revenue_cents)"

  $quickProduct = @($report.top_products | Where-Object { $_.product_name -eq 'Counter total' -and $_.category -eq '(quick sale)' })[0]
  Assert-True ($null -ne $quickProduct) 'Top products should include quick sale line under quick sale category'

  Assert-True ($source -match 'Quick amount') 'Quick amount tile/control is missing'
  Assert-True ($source -match 'addQuickSaleLine') 'Quick sale cart helper is missing'
  Assert-True ($source -match '\(quick sale\)') 'Quick sale report category is missing'

  Write-Host 'quick_sale_test passed.'
} finally {
  if ($server -and -not $server.HasExited) {
    Stop-Process -Id $server.Id -Force
  }
  if (Test-Path -LiteralPath $tempRoot) {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force
  }
}
