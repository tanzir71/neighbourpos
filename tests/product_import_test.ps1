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

  $json = $Body | ConvertTo-Json -Depth 20 -Compress
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

function Invoke-AppJsonExpectError {
  param(
    [string]$BaseUrl,
    [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
    [string]$Csrf,
    [string]$Action,
    [object]$Body
  )

  $json = $Body | ConvertTo-Json -Depth 20 -Compress
  try {
    Invoke-WebRequest `
      -Uri "${BaseUrl}?action=$Action" `
      -Method Post `
      -WebSession $Session `
      -Headers @{ 'Accept' = 'application/json'; 'X-CSRF-Token' = $Csrf } `
      -ContentType 'application/json' `
      -Body $json `
      -UseBasicParsing | Out-Null
  } catch {
    $content = ''
    if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $content = $_.ErrorDetails.Message }
    if ($content -eq '' -and $_.Exception.Response) {
      $stream = $_.Exception.Response.GetResponseStream()
      if ($stream) {
        $reader = [System.IO.StreamReader]::new($stream)
        $content = $reader.ReadToEnd()
        $reader.Dispose()
      }
    }
    return $content
  }
  throw "API action $Action unexpectedly succeeded"
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
  Assert-True ($source -match 'api_product_import_preview') 'Product import preview API is missing'
  Assert-True ($source -match 'api_product_import_commit') 'Product import commit API is missing'
  Assert-True ($source -match 'product_import_template') 'Product import template download is missing'
  Assert-True ($source -match 'PRODUCT_IMPORT_MAX_ROWS') 'Product import row cap is missing'
  Write-Host 'product_import source checks passed; skipping HTTP integration because PHP pdo_sqlite is not loaded.'
  return
}

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("neighbourpos-product-import-test-" + [guid]::NewGuid().ToString('N'))
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

  $template = Invoke-WebRequest -Uri "${baseUrl}?action=product_import_template" -WebSession $session -UseBasicParsing
  Assert-True ($template.Content.Trim().StartsWith('sku,name,price,stock,category')) 'Product import template header is incorrect'

  $csv = @'
sku,name,price,stock,category
BEAN,Imported Beans,3.50,12,Grocery
BAD-NAME,,2.00,5,Grocery
TEA,Imported Tea,$4.25,8,Pantry
BAD-STOCK,Broken Stock,1.25,nope,Pantry
'@

  $preview = Invoke-AppJson -BaseUrl $baseUrl -Session $session -Csrf $csrf -Action 'api_product_import_preview' -Body @{
    filename = 'products.csv'
    csv = $csv
  }
  Assert-True ([int]$preview.rows_total -eq 4) "Preview rows_total should be 4, got $($preview.rows_total)"
  Assert-True ([int]$preview.valid_count -eq 2) "Preview valid_count should be 2, got $($preview.valid_count)"
  Assert-True (@($preview.errors).Count -eq 2) "Preview should report 2 bad rows, got $(@($preview.errors).Count)"
  Assert-True ([int]$preview.errors[0].row -eq 3) "First bad row should be row 3, got $($preview.errors[0].row)"
  Assert-True ([int]$preview.errors[1].row -eq 5) "Second bad row should be row 5, got $($preview.errors[1].row)"
  Assert-True ([int]$preview.rows[0].price_cents -eq 350) 'Preview should parse 3.50 as 350 cents'
  Assert-True ([int]$preview.rows[1].price_cents -eq 425) 'Preview should parse $4.25 as 425 cents'

  $commit = Invoke-AppJson -BaseUrl $baseUrl -Session $session -Csrf $csrf -Action 'api_product_import_commit' -Body @{
    filename = 'products.csv'
    csv = $csv
  }
  Assert-True ([int]$commit.rows_total -eq 4) "Commit rows_total should be 4, got $($commit.rows_total)"
  Assert-True ([int]$commit.rows_imported -eq 2) "Commit should import 2 rows, got $($commit.rows_imported)"
  Assert-True ([int]$commit.import_id -gt 0) 'Commit should return an import id'
  Assert-True (@($commit.errors).Count -eq 2) 'Commit should return the 2 row errors'

  $products = Invoke-AppGetJson -Uri "${baseUrl}?action=api_products_list&q=Imported&include_inactive=1&per=30" -Session $session
  $beans = @($products.items | Where-Object { $_.sku -eq 'BEAN' })[0]
  $tea = @($products.items | Where-Object { $_.sku -eq 'TEA' })[0]
  Assert-True ($null -ne $beans) 'Imported Beans product was not created'
  Assert-True ($null -ne $tea) 'Imported Tea product was not created'
  Assert-True ([int]$beans.price_cents -eq 350) 'Imported Beans price is incorrect'
  Assert-True ([int]$beans.stock_qty -eq 12) 'Imported Beans stock is incorrect'
  Assert-True ([int]$tea.price_cents -eq 425) 'Imported Tea price is incorrect'
  Assert-True ([int]$tea.stock_qty -eq 8) 'Imported Tea stock is incorrect'

  $imports = Invoke-AppGetJson -Uri "${baseUrl}?action=api_product_imports_list" -Session $session
  $importRow = @($imports | Where-Object { [int]$_.id -eq [int]$commit.import_id })[0]
  Assert-True ($null -ne $importRow) 'Import log row is missing'
  Assert-True ([int]$importRow.rows_total -eq 4) 'Import log rows_total is incorrect'
  Assert-True ([int]$importRow.rows_imported -eq 2) 'Import log rows_imported is incorrect'
  Assert-True (@($importRow.errors).Count -eq 2) 'Import log should include two stored errors'

  $audit = Invoke-AppGetJson -Uri "${baseUrl}?action=api_audit_log&q=product_import" -Session $session
  Assert-True (@($audit | Where-Object { $_.action -eq 'product_import.commit' }).Count -ge 1) 'Product import commit audit entry is missing'

  $tooManyRows = "sku,name,price,stock,category`n" + ((1..501 | ForEach-Object { "SKU$_,Item $_,1.00,1,General" }) -join "`n")
  $tooManyError = Invoke-AppJsonExpectError -BaseUrl $baseUrl -Session $session -Csrf $csrf -Action 'api_product_import_preview' -Body @{
    filename = 'too-many.csv'
    csv = $tooManyRows
  }
  Assert-True ($tooManyError -match '500') 'Preview should reject more than 500 rows'

  Assert-True ($source -match 'api_product_import_preview') 'Product import preview API is missing'
  Assert-True ($source -match 'api_product_import_commit') 'Product import commit API is missing'
  Assert-True ($source -match 'product_import_template') 'Product import template download is missing'
  Assert-True ($source -match 'Import CSV') 'Inventory Import CSV UI is missing'
  Assert-True ($source -match 'PRODUCT_IMPORT_MAX_ROWS') 'Product import row cap is missing'

  Write-Host 'product_import_test passed.'
} finally {
  if ($server -and -not $server.HasExited) {
    Stop-Process -Id $server.Id -Force
  }
  if (Test-Path -LiteralPath $tempRoot) {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force
  }
}
