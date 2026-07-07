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
  $response = Invoke-WebRequest `
    -Uri "${BaseUrl}?action=$Action" `
    -Method Post `
    -WebSession $Session `
    -Headers @{ 'Accept' = 'application/json'; 'X-CSRF-Token' = $Csrf } `
    -ContentType 'application/json' `
    -Body $json `
    -UseBasicParsing
  $payload = $response.Content | ConvertFrom-Json
  Assert-True $payload.ok "API action $Action did not return ok=true"
  return $payload.data
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
$appSource = Join-Path $repoRoot 'neighbourpos.php'
$setupSource = Join-Path $repoRoot 'SETUP.md'
$source = Get-Content -Raw -LiteralPath $appSource
$setup = Get-Content -Raw -LiteralPath $setupSource

Assert-True ($source -match 'VACUUM INTO') 'Database backup should use VACUUM INTO instead of raw readfile on the live DB'
Assert-True ($setup -match 'Restore') 'SETUP should document database restore'
Assert-True ($setup -match 'integrity_check') 'SETUP should mention PRAGMA integrity_check for restored backups'

$phpCommand = if ($env:NEIGHBOURPOS_PHP) { $env:NEIGHBOURPOS_PHP } else { 'php' }
$phpArgs = @()
if ($env:NEIGHBOURPOS_PHP_EXT_DIR) {
  $phpArgs = @('-d', "extension_dir=$env:NEIGHBOURPOS_PHP_EXT_DIR", '-d', 'extension=pdo_sqlite', '-d', 'extension=sqlite3')
}

$phpModules = & $phpCommand @phpArgs -m
if (-not ($phpModules -contains 'pdo_sqlite')) {
  Write-Host 'backup_roundtrip source checks passed; skipping HTTP integration because PHP pdo_sqlite is not loaded.'
  return
}

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("neighbourpos-backup-test-" + [guid]::NewGuid().ToString('N'))
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

  Invoke-AppJson -BaseUrl $baseUrl -Session $session -Csrf $csrf -Action 'api_product_save' -Body @{
    sku = 'BAK-ROUND'
    name = 'Backup Roundtrip Item'
    price_cents = 1234
    stock_qty = 7
    category = 'Test'
    active = 1
  } | Out-Null

  $backupPath = Join-Path $tempRoot 'downloaded-backup.db'
  Invoke-WebRequest `
    -Uri "${baseUrl}?action=database_backup" `
    -WebSession $session `
    -OutFile $backupPath `
    -UseBasicParsing

  Assert-True (Test-Path $backupPath) 'Backup download file was not created'
  Assert-True ((Get-Item $backupPath).Length -gt 0) 'Backup download was empty'

  $backupForPhp = $backupPath.Replace('\', '/').Replace("'", "\\'")
  $phpCode = "`$pdo=new PDO('sqlite:$backupForPhp'); `$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION); echo `$pdo->query('PRAGMA integrity_check')->fetchColumn();"
  $integrity = ((& $phpCommand @phpArgs -r $phpCode) -join '').Trim()
  Assert-True ($integrity -eq 'ok') "Downloaded backup integrity_check should be ok, got $integrity"

  $countCode = "`$pdo=new PDO('sqlite:$backupForPhp'); echo (int)`$pdo->query('SELECT COUNT(*) FROM products')->fetchColumn();"
  $count = ((& $phpCommand @phpArgs -r $countCode) -join '').Trim()
  Assert-True ([int]$count -eq 1) 'Downloaded backup should include writes completed before backup'

  Write-Host 'backup_roundtrip_test passed.'
} finally {
  if ($server -and -not $server.HasExited) {
    Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
  }
  if (Test-Path $tempRoot) {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
  }
}
