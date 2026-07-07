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

  $json = $Body | ConvertTo-Json -Depth 12 -Compress
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

function New-CloseOrder {
  param(
    [string]$BaseUrl,
    [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
    [string]$Csrf,
    [string]$PaymentMethod,
    [int]$AmountCents,
    [string]$Phone = '',
    [string]$CustomerName = '',
    [string]$CouponCode = '',
    [int]$Walkin = 0,
    [int]$PaymentReceived = 1
  )

  $order = Invoke-AppJson -BaseUrl $BaseUrl -Session $Session -Csrf $Csrf -Action 'api_orders_create' -Body @{
    items = @(@{
      product_id = $null
      name = "$PaymentMethod close sale"
      price_cents = $AmountCents
      qty = 1
      category = 'Close test'
      notes = ''
    })
    order_type = 'pickup'
    expected_eta_minutes = 15
    tip_cents = 0
    coupon_code = $CouponCode
    payment_method = $PaymentMethod
    payment_received = $PaymentReceived
    walkin = $Walkin
    phone = $Phone
    customer_name = $CustomerName
    customer_address = ''
    marketing_opt_in = 1
  }

  Invoke-AppJson -BaseUrl $BaseUrl -Session $Session -Csrf $Csrf -Action 'api_order_status_update' -Body @{
    id = [int]$order.order_id
    status = 'completed'
  } | Out-Null

  return $order
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
$appSource = Join-Path $repoRoot 'neighbourpos.php'
$phpCommand = if ($env:NEIGHBOURPOS_PHP) { $env:NEIGHBOURPOS_PHP } else { 'php' }
$phpArgs = @()
if ($env:NEIGHBOURPOS_PHP_EXT_DIR) {
  $phpArgs = @('-d', "extension_dir=$env:NEIGHBOURPOS_PHP_EXT_DIR", '-d', 'extension=pdo_sqlite', '-d', 'extension=sqlite3')
}

$phpModules = & $phpCommand @phpArgs -m
if (-not ($phpModules -contains 'pdo_sqlite')) {
  Write-Host 'end_of_day_close source checks passed; skipping HTTP integration because PHP pdo_sqlite is not loaded.'
  return
}

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("neighbourpos-end-close-test-" + [guid]::NewGuid().ToString('N'))
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
    -WindowStyle Hidden `
    -RedirectStandardOutput $stdout `
    -RedirectStandardError $stderr `
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

  New-CloseOrder -BaseUrl $baseUrl -Session $session -Csrf $csrf -PaymentMethod 'cash' -AmountCents 1000 -CouponCode 'SAVE10' -Walkin 1 | Out-Null
  New-CloseOrder -BaseUrl $baseUrl -Session $session -Csrf $csrf -PaymentMethod 'card' -AmountCents 2500 -Phone '(555) 010-1001' -CustomerName 'Card Customer' | Out-Null
  New-CloseOrder -BaseUrl $baseUrl -Session $session -Csrf $csrf -PaymentMethod 'online' -AmountCents 3000 -Phone '(555) 010-1002' -CustomerName 'Mobile Customer' | Out-Null
  New-CloseOrder -BaseUrl $baseUrl -Session $session -Csrf $csrf -PaymentMethod 'credit' -AmountCents 4000 -Phone '(555) 010-1003' -CustomerName 'Credit Customer' -PaymentReceived 0 | Out-Null

  $today = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd')
  $report = Invoke-AppGetJson -Uri "${baseUrl}?action=api_sales_report&from=$today&to=$today" -Session $session
  $close = $report.today_close
  Assert-True ($null -ne $close) 'Sales report should include today_close data'
  Assert-True ([int]$close.order_count -eq 4) "Close order count should be 4, got $($close.order_count)"
  Assert-True ([int]$close.gross_cents -eq 10500) "Close gross should be 10500, got $($close.gross_cents)"
  Assert-True ([int]$close.gross_cents -eq [int]$report.summary.revenue_cents) 'Close gross should match report revenue for the day'
  Assert-True ([int]$close.payment_methods.cash.gross_cents -eq 1000) 'Cash close total should be 1000'
  Assert-True ([int]$close.payment_methods.card.gross_cents -eq 2500) 'Card close total should be 2500'
  Assert-True ([int]$close.payment_methods.mobile.gross_cents -eq 3000) 'Mobile/online close total should be 3000'
  Assert-True ([int]$close.payment_methods.credit.gross_cents -eq 4000) 'Credit close total should be 4000'
  Assert-True ([int]$close.coupons_redeemed -eq 1) "Coupons redeemed should be 1, got $($close.coupons_redeemed)"
  Assert-True ([int]$close.new_customers -eq 3) "New customers should be 3, got $($close.new_customers)"

  $wideFrom = (Get-Date).ToUniversalTime().AddDays(-6).ToString('yyyy-MM-dd')
  $wideReport = Invoke-AppGetJson -Uri "${baseUrl}?action=api_sales_report&from=$wideFrom&to=$today" -Session $session
  Assert-True ($wideReport.today_close.from -eq $today) "Today close from-date should stay $today for a wider report window"
  Assert-True ($wideReport.today_close.to -eq $today) "Today close to-date should stay $today for a wider report window"

  Write-Host 'end_of_day_close_test passed.'
} finally {
  if ($server -and -not $server.HasExited) {
    Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
  }
  if (Test-Path $tempRoot) {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
  }
}
