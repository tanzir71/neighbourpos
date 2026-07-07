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
$phpCommand = if ($env:NEIGHBOURPOS_PHP) { $env:NEIGHBOURPOS_PHP } else { 'php' }
$phpArgs = @()
if ($env:NEIGHBOURPOS_PHP_EXT_DIR) {
  $phpArgs = @('-d', "extension_dir=$env:NEIGHBOURPOS_PHP_EXT_DIR", '-d', 'extension=pdo_sqlite', '-d', 'extension=sqlite3')
}

$phpModules = & $phpCommand @phpArgs -m
if (-not ($phpModules -contains 'pdo_sqlite')) {
  Write-Host 'dev_selftest source checks passed; skipping HTTP integration because PHP pdo_sqlite is not loaded.'
  return
}

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("neighbourpos-dev-selftest-" + [guid]::NewGuid().ToString('N'))
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

  $selftest = Invoke-AppGetJson -Uri "${baseUrl}?action=api_dev_selftest" -Session $session
  Assert-True ([int]$selftest.failures -eq 0) "Self-test failures should be 0, got $($selftest.failures)"

  $names = @($selftest.tests | ForEach-Object { $_.name })
  foreach ($required in @(
    'normalize_e164:bd_local',
    'normalize_e164:us_local',
    'segment_filter:marketing_opt_in_only',
    'segment_filter:tag',
    'segment_filter:has_balance',
    'export_headers:mailchimp',
    'export_headers:brevo',
    'export_headers:sms',
    'export_headers:whatsapp'
  )) {
    Assert-True ($names -contains $required) "Self-test result missing $required"
  }

  $failed = @($selftest.tests | Where-Object { -not $_.passed })
  Assert-True ($failed.Count -eq 0) "Every self-test row should pass"

  Write-Host 'dev_selftest_test passed.'
} finally {
  if ($server -and -not $server.HasExited) {
    Stop-Process -Id $server.Id -Force -ErrorAction SilentlyContinue
  }
  if (Test-Path $tempRoot) {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
  }
}
