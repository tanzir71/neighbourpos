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

Assert-True ($source -match 'reward_top_spenders') 'Reward top spenders preset key is missing'
Assert-True ($source -match 'win_back_lapsed') 'Win back lapsed preset key is missing'
Assert-True ($source -match 'Reward top spenders') 'Reward top spenders UI copy is missing'
Assert-True ($source -match 'Win back lapsed') 'Win back lapsed UI copy is missing'
Assert-True ($source -match 'focus_campaign_id') 'Preset response should identify the campaign export panel to focus'

$phpModules = & $phpCommand @phpArgs -m
if (-not ($phpModules -contains 'pdo_sqlite')) {
  Write-Host 'loyalty_presets source checks passed; skipping HTTP integration because PHP pdo_sqlite is not loaded.'
  return
}

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("neighbourpos-loyalty-presets-test-" + [guid]::NewGuid().ToString('N'))
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

  Invoke-AppJson -BaseUrl $baseUrl -Session $session -Csrf $csrf -Action 'api_load_sample_data' -Body @{} | Out-Null

  $defaultTop = Invoke-AppJson -BaseUrl $baseUrl -Session $session -Csrf $csrf -Action 'api_campaign_preset_create' -Body @{
    preset = 'reward_top_spenders'
  }
  Assert-True ([int]$defaultTop.queued -gt 0) 'Default reward top spenders preset should queue recipients on sample data'
  Assert-True ($defaultTop.export_format -eq 'sms') 'Default reward preset should land on SMS export format'

  $top = Invoke-AppJson -BaseUrl $baseUrl -Session $session -Csrf $csrf -Action 'api_campaign_preset_create' -Body @{
    preset = 'reward_top_spenders'
    spend_min_cents = 1000
  }
  Assert-True ([int]$top.segment_id -gt 0) 'Reward top spenders should create a segment'
  Assert-True ([int]$top.campaign_id -gt 0) 'Reward top spenders should create a campaign'
  Assert-True ([int]$top.focus_campaign_id -eq [int]$top.campaign_id) 'Reward preset should focus its campaign export panel'
  Assert-True ([int]$top.queued -gt 0) 'Reward top spenders should queue recipients on sample data'
  Assert-True ($top.export_format -eq 'sms') 'Reward preset should land on SMS export format'

  $topPreview = Invoke-AppJson -BaseUrl $baseUrl -Session $session -Csrf $csrf -Action 'api_campaign_export_preview' -Body @{
    id = [int]$top.campaign_id
    format = 'sms'
  }
  Assert-True ([int]$topPreview.total_queued -eq [int]$top.queued) 'Reward export preview queued count should match preset result'

  $topSms = Invoke-WebRequest -Uri "${baseUrl}?action=campaign_export&id=$([int]$top.campaign_id)&format=sms" -WebSession $session -UseBasicParsing
  Assert-True ((Get-CsvHeader $topSms.Content) -eq 'phone,name,coupon_code,message') 'Reward SMS export header is incorrect'
  $topRows = @($topSms.Content | ConvertFrom-Csv)
  Assert-True ($topRows.Count -eq [int]$top.queued) 'Reward SMS export row count should match queued recipients'
  Assert-True (($topRows | Where-Object { -not $_.coupon_code }).Count -eq 0) 'Reward SMS export should include coupon codes for every row'
  Assert-True (($topRows | Where-Object { $_.message -notmatch '\{coupon_code\}' }).Count -eq $topRows.Count) 'Reward SMS messages should render coupon codes'

  $lapsed = Invoke-AppJson -BaseUrl $baseUrl -Session $session -Csrf $csrf -Action 'api_campaign_preset_create' -Body @{
    preset = 'win_back_lapsed'
    inactive_days = 30
  }
  Assert-True ([int]$lapsed.segment_id -gt 0) 'Win back lapsed should create a segment'
  Assert-True ([int]$lapsed.campaign_id -gt 0) 'Win back lapsed should create a campaign'
  Assert-True ([int]$lapsed.queued -gt 0) 'Win back lapsed should queue recipients on sample data'

  $campaigns = Invoke-AppGetJson -Uri "${baseUrl}?action=api_campaigns_list" -Session $session
  $topCampaign = @($campaigns | Where-Object { [int]$_.id -eq [int]$top.campaign_id })[0]
  $lapsedCampaign = @($campaigns | Where-Object { [int]$_.id -eq [int]$lapsed.campaign_id })[0]
  Assert-True ($topCampaign.name -match 'Reward top spenders') 'Reward campaign name should be clear'
  Assert-True ([int]$topCampaign.sent_count -eq [int]$top.queued) 'Reward campaign sent_count should show queued recipients'
  Assert-True ($lapsedCampaign.name -match 'Win back lapsed') 'Lapsed campaign name should be clear'
  Assert-True ([int]$lapsedCampaign.sent_count -eq [int]$lapsed.queued) 'Lapsed campaign sent_count should show queued recipients'

  $audit = Invoke-AppGetJson -Uri "${baseUrl}?action=api_audit_log&q=preset" -Session $session
  Assert-True (@($audit | Where-Object { $_.action -eq 'campaigns.preset_create' }).Count -ge 2) 'Preset create audit entries are missing'

  Write-Host 'loyalty_presets_test passed.'
} finally {
  if ($server -and -not $server.HasExited) {
    Stop-Process -Id $server.Id -Force
  }
  if (Test-Path -LiteralPath $tempRoot) {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force
  }
}
