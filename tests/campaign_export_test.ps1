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

  $json = $Body | ConvertTo-Json -Depth 8 -Compress
  $response = Invoke-WebRequest `
    -Uri "$BaseUrl?action=$Action" `
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

function Assert-HttpStatus {
  param(
    [string]$Uri,
    [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
    [int]$ExpectedStatus
  )

  try {
    $response = Invoke-WebRequest -Uri $Uri -WebSession $Session -UseBasicParsing -ErrorAction Stop
    $actualStatus = [int]$response.StatusCode
  } catch {
    if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
      $actualStatus = [int]$_.Exception.Response.StatusCode
    } else {
      throw
    }
  }

  Assert-True ($actualStatus -eq $ExpectedStatus) "Expected HTTP $ExpectedStatus from $Uri, got $actualStatus"
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
$appSource = Join-Path $repoRoot 'neighbourpos.php'
$source = Get-Content -Raw -LiteralPath $appSource

Assert-True ($source -match "function csv_safe_cell") 'CSV spreadsheet-safety helper is missing'
Assert-True ($source -match 'if \(\$action === ''campaign_export''\)') 'campaign_export route is missing'
Assert-True ($source -match 'Content-Disposition: attachment; filename="campaign-') 'CSV download filename header is missing'
Assert-True ($source -match 'campaigns\.export') 'Campaign export audit action is missing'
Assert-True ($source -match 'No queued recipients') 'No-recipient export error is missing'
Assert-True ($source -match "message' => csv_safe_cell") 'CSV message column is not protected with csv_safe_cell'
Assert-True ($source -match 'Export CSV') 'Campaign list export control is missing'
Assert-True ($source -match 'Queue first') 'Campaign list empty-state export control is missing'

$phpModules = & php -m
if (-not ($phpModules -contains 'pdo_sqlite')) {
  Write-Host 'campaign_export source checks passed; skipping HTTP integration because PHP pdo_sqlite is not loaded.'
  return
}

$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("neighbourpos-export-test-" + [guid]::NewGuid().ToString('N'))
$server = $null

try {
  New-Item -ItemType Directory -Path $tempRoot | Out-Null
  Copy-Item -LiteralPath $appSource -Destination (Join-Path $tempRoot 'neighbourpos.php')

  $port = Get-Random -Minimum 18100 -Maximum 28999
  $stdout = Join-Path $tempRoot 'server.out.log'
  $stderr = Join-Path $tempRoot 'server.err.log'
  $server = Start-Process `
    -FilePath 'php' `
    -ArgumentList @('-S', "127.0.0.1:$port", '-t', $tempRoot) `
    -WorkingDirectory $tempRoot `
    -RedirectStandardOutput $stdout `
    -RedirectStandardError $stderr `
    -WindowStyle Hidden `
    -PassThru

  $baseUrl = "http://127.0.0.1:$port/neighbourpos.php"
  $loginPage = $null
  for ($i = 0; $i -lt 40; $i++) {
    try {
      $loginPage = Invoke-WebRequest -Uri "$baseUrl?action=staff_login" -SessionVariable session -UseBasicParsing
      break
    } catch {
      Start-Sleep -Milliseconds 250
    }
  }
  Assert-True ($null -ne $loginPage) 'PHP development server did not become ready'
  Assert-True ($loginPage.Content -match "name='csrf' value='([^']+)'") 'Could not find login CSRF token'
  $csrf = $Matches[1]

  Invoke-WebRequest `
    -Uri "$baseUrl?action=staff_login" `
    -Method Post `
    -WebSession $session `
    -Body @{ csrf = $csrf; email = 'admin@example.com'; password = 'ChangeMe123!' } `
    -UseBasicParsing | Out-Null

  Invoke-AppJson -BaseUrl $baseUrl -Session $session -Csrf $csrf -Action 'api_load_sample_data' -Body @{} | Out-Null

  $segment = Invoke-AppJson `
    -BaseUrl $baseUrl `
    -Session $session `
    -Csrf $csrf `
    -Action 'api_segment_create' `
    -Body @{ name = 'CSV Export Test Segment'; filters = @{ order_count_min = 1 } }

  $campaign = Invoke-AppJson `
    -BaseUrl $baseUrl `
    -Session $session `
    -Csrf $csrf `
    -Action 'api_campaign_create' `
    -Body @{
      name = 'CSV Export Test Campaign'
      segment_id = [int]$segment.id
      channel = 'export'
      message_template = '=SUM(1,1) spreadsheet check'
      scheduled_at = $null
    }

  $emptyCampaign = Invoke-AppJson `
    -BaseUrl $baseUrl `
    -Session $session `
    -Csrf $csrf `
    -Action 'api_campaign_create' `
    -Body @{
      name = 'CSV Export Empty Campaign'
      segment_id = [int]$segment.id
      channel = 'export'
      message_template = 'Queue me first'
      scheduled_at = $null
    }

  Invoke-AppJson `
    -BaseUrl $baseUrl `
    -Session $session `
    -Csrf $csrf `
    -Action 'api_campaign_send' `
    -Body @{ id = [int]$campaign.id; override_opt_in = 0; with_coupons = 1 } | Out-Null

  Assert-HttpStatus -Uri "$baseUrl?action=campaign_export" -Session $session -ExpectedStatus 400
  Assert-HttpStatus -Uri "$baseUrl?action=campaign_export&id=999999" -Session $session -ExpectedStatus 404
  Assert-HttpStatus -Uri "$baseUrl?action=campaign_export&id=$($emptyCampaign.id)" -Session $session -ExpectedStatus 409

  $export = Invoke-WebRequest -Uri "$baseUrl?action=campaign_export&id=$($campaign.id)" -WebSession $session -UseBasicParsing
  Assert-True ([string]$export.Headers['Content-Type'] -like 'text/csv*') 'Export did not return text/csv'
  Assert-True ([string]$export.Headers['Content-Disposition'] -match "campaign-$($campaign.id)-recipients\.csv") 'Export filename header was missing or incorrect'

  $rows = $export.Content | ConvertFrom-Csv
  $rowCount = @($rows).Count
  Assert-True ($rowCount -gt 0) 'CSV did not contain queued recipients'

  $first = @($rows)[0]
  Assert-True ($first.campaign_id -eq [string]$campaign.id) 'CSV campaign_id did not match requested campaign'
  Assert-True ($first.campaign_name -eq 'CSV Export Test Campaign') 'CSV campaign_name was incorrect'
  Assert-True ($first.segment_name -eq 'CSV Export Test Segment') 'CSV segment_name was incorrect'
  Assert-True ($first.coupon_code -match '^NP-[A-Z0-9]+$') 'CSV coupon_code did not contain generated coupon'
  Assert-True ($first.message -eq "'=SUM(1,1) spreadsheet check") 'CSV message was not protected against spreadsheet formula injection'
  Assert-True ($first.opt_in_overridden -eq '0') 'CSV opt_in_overridden should be 0 for default send'

  Write-Host "campaign_export_test passed with $rowCount exported recipient(s)."
} finally {
  if ($server -and -not $server.HasExited) {
    Stop-Process -Id $server.Id -Force
  }
  if (Test-Path -LiteralPath $tempRoot) {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force
  }
}
