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

function Get-CsvHeader {
  param([string]$Content)
  $clean = $Content.TrimStart([char]0xFEFF)
  return ([regex]::Split($clean, "\r\n|\n|\r"))[0]
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
$appSource = Join-Path $repoRoot 'neighbourpos.php'
$source = Get-Content -Raw -LiteralPath $appSource
$phpCommand = if ($env:NEIGHBOURPOS_PHP) { $env:NEIGHBOURPOS_PHP } else { 'php' }
$phpArgs = @()
if ($env:NEIGHBOURPOS_PHP_EXT_DIR) {
  $phpArgs = @('-d', "extension_dir=$env:NEIGHBOURPOS_PHP_EXT_DIR", '-d', 'extension=pdo_sqlite', '-d', 'extension=sqlite3')
}

Assert-True ($source -match 'CREATE TABLE IF NOT EXISTS ledger_entries') 'Ledger entries table is missing'
Assert-True ($source -match 'api_ledger_payment') 'Ledger payment API is missing'
Assert-True ($source -match 'Outstanding credit') 'Dashboard outstanding credit KPI is missing'
Assert-True ($source -match 'On credit') 'POS on-credit tender option is missing'
Assert-True ($source -match '\{balance\}') 'Balance merge field is missing'
Assert-True ($source -match 'Record payment') 'CRM record-payment control is missing'

$phpModules = & $phpCommand @phpArgs -m
if (-not ($phpModules -contains 'pdo_sqlite')) {
  Write-Host 'credit_ledger source checks passed; skipping HTTP integration because PHP pdo_sqlite is not loaded.'
  return
}

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("neighbourpos-ledger-test-" + [guid]::NewGuid().ToString('N'))
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

  $product = Invoke-AppJson -BaseUrl $baseUrl -Session $session -Csrf $csrf -Action 'api_product_save' -Body @{
    sku = 'LEDGER-BEANS'
    name = 'Ledger Beans'
    price_cents = 1200
    stock_qty = 20
    category = 'Grocery'
    active = 1
  }

  $order = Invoke-AppJson -BaseUrl $baseUrl -Session $session -Csrf $csrf -Action 'api_orders_create' -Body @{
    items = @(@{ product_id = [int]$product.id; qty = 2; notes = '' })
    order_type = 'pickup'
    expected_eta_minutes = 15
    tip_cents = 0
    coupon_code = ''
    payment_method = 'credit'
    payment_received = 0
    walkin = 0
    phone = '(555) 010-4444'
    customer_name = 'Credit Customer'
    customer_address = ''
    marketing_opt_in = 1
  }
  Assert-True ([int]$order.order_id -gt 0) 'Credit order did not return an order id'

  $customer = Invoke-AppGetJson -Uri "${baseUrl}?action=api_customer_get&phone=$([uri]::EscapeDataString('(555) 010-4444'))" -Session $session
  $customerId = [int]$customer.customer.id
  Assert-True ($customerId -gt 0) 'Credit order did not attach a customer'
  Assert-True ([int]$customer.customer.balance_cents -eq 2400) "Credit order should create a 2400-cent balance, got $($customer.customer.balance_cents)"
  Assert-True (@($customer.ledger_entries).Count -eq 1) 'Customer profile should include one ledger entry after credit sale'
  Assert-True ($customer.ledger_entries[0].type -eq 'credit') 'First ledger entry should be credit'
  Assert-True ([int]$customer.ledger_entries[0].amount_cents -eq 2400) 'Credit ledger entry amount is incorrect'

  $timeline = Invoke-AppGetJson -Uri "${baseUrl}?action=api_customer_timeline&id=$customerId" -Session $session
  Assert-True (@($timeline | Where-Object { $_.type -eq 'ledger_credit' }).Count -eq 1) 'Customer timeline should include ledger credit event'

  $dashboard = Invoke-AppGetJson -Uri "${baseUrl}?action=api_today_snapshot" -Session $session
  Assert-True ([int]$dashboard.outstanding_credit_cents -eq 2400) "Outstanding credit should be 2400, got $($dashboard.outstanding_credit_cents)"

  $search = Invoke-AppGetJson -Uri "${baseUrl}?action=api_customers_search&q=Credit" -Session $session
  $searchCustomer = @($search | Where-Object { $_.phone -eq '+15550104444' })[0]
  Assert-True ($null -ne $searchCustomer) 'CRM search should return the credit customer'
  Assert-True ([int]$searchCustomer.balance_cents -eq 2400) 'CRM search row should include balance_cents'

  $segment = Invoke-AppJson -BaseUrl $baseUrl -Session $session -Csrf $csrf -Action 'api_segment_create' -Body @{
    name = 'Debtors'
    filters = @{ has_balance = $true; marketing_opt_in_only = $true }
  }
  $preview = Invoke-AppJson -BaseUrl $baseUrl -Session $session -Csrf $csrf -Action 'api_segment_preview' -Body @{
    segment_id = [int]$segment.id
    filters = @{ has_balance = $true; marketing_opt_in_only = $true }
  }
  Assert-True ([int]$preview.count -eq 1) "has_balance segment should return one debtor, got $($preview.count)"

  $message = [uri]::EscapeDataString('Hi {first_name}, you owe {balance}.')
  $debtorSms = Invoke-WebRequest -Uri "${baseUrl}?action=customer_export&format=sms&debtors=1&message_template=$message" -WebSession $session -UseBasicParsing
  Assert-True ((Get-CsvHeader $debtorSms.Content) -eq 'phone,name,coupon_code,message') 'Debtor SMS export header is incorrect'
  $debtorRows = @($debtorSms.Content | ConvertFrom-Csv)
  Assert-True ($debtorRows.Count -eq 1) "Debtor SMS export should include one row, got $($debtorRows.Count)"
  Assert-True ($debtorRows[0].message -eq 'Hi Credit, you owe $24.00.') "Debtor SMS message did not render balance: $($debtorRows[0].message)"

  $fullDebtors = Invoke-WebRequest -Uri "${baseUrl}?action=customer_export&format=full&debtors=1&include_balance=1" -WebSession $session -UseBasicParsing
  Assert-True ((Get-CsvHeader $fullDebtors.Content) -match 'balance') 'Full debtor export should include balance when requested'
  $fullRows = @($fullDebtors.Content | ConvertFrom-Csv)
  Assert-True ($fullRows[0].balance -eq '$24.00') "Full debtor export balance is incorrect: $($fullRows[0].balance)"

  $payment = Invoke-AppJson -BaseUrl $baseUrl -Session $session -Csrf $csrf -Action 'api_ledger_payment' -Body @{
    customer_id = $customerId
    amount_cents = 900
    note = 'partial cash payment'
  }
  Assert-True ([int]$payment.balance_cents -eq 1500) "Payment should reduce balance to 1500, got $($payment.balance_cents)"

  $customerAfterPayment = Invoke-AppGetJson -Uri "${baseUrl}?action=api_customer_get&id=$customerId" -Session $session
  Assert-True ([int]$customerAfterPayment.customer.balance_cents -eq 1500) 'Customer balance after payment is incorrect'
  Assert-True (@($customerAfterPayment.ledger_entries | Where-Object { $_.type -eq 'payment' }).Count -eq 1) 'Customer profile should include payment ledger entry'

  $audit = Invoke-AppGetJson -Uri "${baseUrl}?action=api_audit_log&q=ledger" -Session $session
  Assert-True (@($audit | Where-Object { $_.action -eq 'ledger.credit' }).Count -ge 1) 'Ledger credit audit entry is missing'
  Assert-True (@($audit | Where-Object { $_.action -eq 'ledger.payment' }).Count -ge 1) 'Ledger payment audit entry is missing'

  Write-Host 'credit_ledger_test passed.'
} finally {
  if ($server -and -not $server.HasExited) {
    Stop-Process -Id $server.Id -Force
  }
  if (Test-Path -LiteralPath $tempRoot) {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force
  }
}
