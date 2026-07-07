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
    if ($content -eq '' -and $_.Exception.Response) {
      $stream = $_.Exception.Response.GetResponseStream()
      if ($stream) {
        $reader = New-Object System.IO.StreamReader($stream)
        $content = $reader.ReadToEnd()
      }
    }
    throw "API action $Action request failed with body $json`: $($_.Exception.Message) $content"
  }

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

Assert-True ($source -match "function csv_safe_cell") 'CSV spreadsheet-safety helper is missing'
Assert-True ($source -match 'if \(\$action === ''campaign_export''\)') 'campaign_export route is missing'
Assert-True ($source -match 'if \(\$action === ''customer_export''\)') 'customer_export route is missing'
Assert-True ($source -match "function campaign_export_filename") 'CSV filename helper is missing'
Assert-True ($source -match "recipients\.csv") 'Legacy full CSV download filename is missing'
Assert-True ($source -match "gmdate\('Ymd'\)") 'Profile CSV download filename date stamp is missing'
Assert-True ($source -match "bom") 'Excel-friendly BOM option is missing'
Assert-True ($source -match "function campaign_export_profile") 'Campaign export profile engine is missing'
Assert-True ($source -match "Email Address") 'Mailchimp profile header is missing'
Assert-True ($source -match "https://wa\.me/") 'WhatsApp profile link builder is missing'
Assert-True ($source -match 'campaigns\.export') 'Campaign export audit action is missing'
Assert-True ($source -match 'No queued recipients') 'No-recipient export error is missing'
Assert-True ($source -match "message' => csv_safe_cell") 'CSV message column is not protected with csv_safe_cell'
Assert-True ($source -match 'api_campaign_export_preview') 'Campaign export preview API is missing'
Assert-True ($source -match 'data-export-preview') 'Campaign export preview control is missing'
Assert-True ($source -match 'Download CSV') 'Campaign list download control is missing'
Assert-True ($source -match 'Excel-friendly') 'Campaign export BOM toggle is missing'
Assert-True ($source -match 'Works with: Mailchimp / Brevo / any SMS tool / WhatsApp manual') 'Campaign export format helper copy is missing'
Assert-True ($source -match 'Download customers') 'Customer list export control is missing'
Assert-True ($source -match 'Queue first') 'Campaign list empty-state export control is missing'

$phpModules = & $phpCommand @phpArgs -m
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

  Invoke-AppJson -BaseUrl $baseUrl -Session $session -Csrf $csrf -Action 'api_load_sample_data' -Body @{} | Out-Null

  $segment = Invoke-AppJson `
    -BaseUrl $baseUrl `
    -Session $session `
    -Csrf $csrf `
    -Action 'api_segment_create' `
    -Body @{ name = 'CSV Export Test Segment'; filters = @{ order_count_min = 1 } }
  $segmentId = [int]$segment.id
  Assert-True ($segmentId -gt 0) 'Segment create did not return a positive id'

  $campaign = Invoke-AppJson `
    -BaseUrl $baseUrl `
    -Session $session `
    -Csrf $csrf `
    -Action 'api_campaign_create' `
    -Body @{
      name = 'CSV Export Test Campaign'
      segment_id = $segmentId
      channel = 'export'
      message_template = '=SUM(1,1) spreadsheet check'
      scheduled_at = $null
    }
  $campaignId = [int]$campaign.id
  Assert-True ($campaignId -gt 0) 'Campaign create did not return a positive id'
  $campaignList = Invoke-WebRequest -Uri "${baseUrl}?action=api_campaigns_list" -WebSession $session -Headers @{ 'Accept' = 'application/json' } -UseBasicParsing
  $createdCampaign = @(($campaignList.Content | ConvertFrom-Json).data | Where-Object { [int]$_.id -eq $campaignId })[0]
  Assert-True ($null -ne $createdCampaign) 'Created campaign was not returned by api_campaigns_list'
  Assert-True ([int]$createdCampaign.segment_id -eq $segmentId) "Created campaign segment_id was $($createdCampaign.segment_id), expected $segmentId"

  $emptyCampaign = Invoke-AppJson `
    -BaseUrl $baseUrl `
    -Session $session `
    -Csrf $csrf `
    -Action 'api_campaign_create' `
    -Body @{
      name = 'CSV Export Empty Campaign'
      segment_id = $segmentId
      channel = 'export'
      message_template = 'Queue me first'
      scheduled_at = $null
    }

  Invoke-AppJson `
    -BaseUrl $baseUrl `
    -Session $session `
    -Csrf $csrf `
    -Action 'api_campaign_send' `
    -Body @{ id = $campaignId; override_opt_in = 0; with_coupons = 1 } | Out-Null

  Assert-HttpStatus -Uri "${baseUrl}?action=campaign_export" -Session $session -ExpectedStatus 400
  Assert-HttpStatus -Uri "${baseUrl}?action=campaign_export&id=999999" -Session $session -ExpectedStatus 404
  Assert-HttpStatus -Uri "${baseUrl}?action=campaign_export&id=$($emptyCampaign.id)" -Session $session -ExpectedStatus 409

  $export = Invoke-WebRequest -Uri "${baseUrl}?action=campaign_export&id=$campaignId" -WebSession $session -UseBasicParsing
  Assert-True ([string]$export.Headers['Content-Type'] -like 'text/csv*') 'Export did not return text/csv'
  Assert-True ([string]$export.Headers['Content-Disposition'] -match "campaign-$($campaignId)-recipients\.csv") 'Export filename header was missing or incorrect'

  $rows = $export.Content | ConvertFrom-Csv
  $rowCount = @($rows).Count
  Assert-True ($rowCount -gt 0) 'CSV did not contain queued recipients'

  $first = @($rows)[0]
  Assert-True ($first.campaign_id -eq [string]$campaignId) 'CSV campaign_id did not match requested campaign'
  Assert-True ($first.campaign_name -eq 'CSV Export Test Campaign') 'CSV campaign_name was incorrect'
  Assert-True ($first.segment_name -eq 'CSV Export Test Segment') 'CSV segment_name was incorrect'
  Assert-True ($first.coupon_code -match '^NP-[A-Z0-9]+$') 'CSV coupon_code did not contain generated coupon'
  Assert-True ($first.message -eq "'=SUM(1,1) spreadsheet check") 'CSV message was not protected against spreadsheet formula injection'
  Assert-True ($first.opt_in_overridden -eq '0') 'CSV opt_in_overridden should be 0 for default send'

  $profileCustomers = @(
    @{ phone = '(555) 010-9876'; name = 'No Email Regular'; email = ''; marketing_opt_in = 1; tags = @('sms_only') },
    @{ phone = '123'; name = 'Bad Phone Regular'; email = ''; marketing_opt_in = 1; tags = @('badphone') },
    @{ phone = '(555) 010-7777'; name = 'Duplicate Email'; email = 'maya@example.com'; marketing_opt_in = 1; tags = @('dupe') }
  )
  foreach ($profileCustomer in $profileCustomers) {
    Invoke-AppJson `
      -BaseUrl $baseUrl `
      -Session $session `
      -Csrf $csrf `
      -Action 'api_customer_upsert' `
      -Body $profileCustomer | Out-Null
  }

  $profileSegment = Invoke-AppJson `
    -BaseUrl $baseUrl `
    -Session $session `
    -Csrf $csrf `
    -Action 'api_segment_create' `
    -Body @{ name = 'Profile Export Segment'; filters = @{ marketing_opt_in_only = $true } }
  $profileSegmentId = [int]$profileSegment.id
  Assert-True ($profileSegmentId -gt 0) 'Profile segment create did not return a positive id'

  $mergeTemplate = 'Hi {first_name}, use {coupon_code} at {store_name}. Keep {unknown}.'
  $simulate = Invoke-AppJson `
    -BaseUrl $baseUrl `
    -Session $session `
    -Csrf $csrf `
    -Action 'api_campaign_simulate' `
    -Body @{
      segment_id = $profileSegmentId
      override_opt_in = 0
      message_template = $mergeTemplate
      sample_coupon_code = 'NP-PREVIEW'
    }
  $previewMessages = @($simulate.preview_messages | Where-Object { $null -ne $_ })
  Assert-True ($previewMessages.Count -gt 0) 'Campaign simulator did not return rendered preview messages'
  foreach ($preview in $previewMessages) {
    $expectedFirstName = (($preview.name -split '\s+', 2)[0])
    Assert-True ($preview.message -eq "Hi $expectedFirstName, use NP-PREVIEW at Neighbour Store. Keep {unknown}.") "Campaign simulator merge preview was incorrect: $($preview.message)"
  }

  $profileCampaign = Invoke-AppJson `
    -BaseUrl $baseUrl `
    -Session $session `
    -Csrf $csrf `
    -Action 'api_campaign_create' `
    -Body @{
      name = 'Profile Export Test'
      segment_id = $profileSegmentId
      channel = 'export'
      message_template = $mergeTemplate
      scheduled_at = $null
    }

  Invoke-AppJson `
    -BaseUrl $baseUrl `
    -Session $session `
    -Csrf $csrf `
    -Action 'api_campaign_send' `
    -Body @{ id = [int]$profileCampaign.id; override_opt_in = 0; with_coupons = 1 } | Out-Null

  $smsPreview = Invoke-AppJson `
    -BaseUrl $baseUrl `
    -Session $session `
    -Csrf $csrf `
    -Action 'api_campaign_export_preview' `
    -Body @{ id = [int]$profileCampaign.id; format = 'sms' }
  Assert-True ($smsPreview.total_queued -eq 5) "SMS export preview total_queued should be 5, got $($smsPreview.total_queued)"
  Assert-True ($smsPreview.opted_in -eq 5) "SMS export preview opted_in should be 5, got $($smsPreview.opted_in)"
  Assert-True ($smsPreview.with_email -eq 3) "SMS export preview with_email should be 3, got $($smsPreview.with_email)"
  Assert-True ($smsPreview.with_valid_phone -eq 4) "SMS export preview with_valid_phone should be 4, got $($smsPreview.with_valid_phone)"
  Assert-True ($smsPreview.export_count -eq 4) "SMS export preview export_count should be 4, got $($smsPreview.export_count)"
  Assert-True ($smsPreview.excluded_and_why.invalid_phone -eq 1) "SMS export preview invalid_phone should be 1, got $($smsPreview.excluded_and_why.invalid_phone)"

  $mailchimpPreview = Invoke-AppJson `
    -BaseUrl $baseUrl `
    -Session $session `
    -Csrf $csrf `
    -Action 'api_campaign_export_preview' `
    -Body @{ id = [int]$profileCampaign.id; format = 'mailchimp' }
  Assert-True ($mailchimpPreview.export_count -eq 2) "Mailchimp export preview export_count should be 2, got $($mailchimpPreview.export_count)"
  Assert-True ($mailchimpPreview.excluded_and_why.missing_email -eq 2) "Mailchimp export preview missing_email should be 2, got $($mailchimpPreview.excluded_and_why.missing_email)"
  Assert-True ($mailchimpPreview.excluded_and_why.duplicate_email -eq 1) "Mailchimp export preview duplicate_email should be 1, got $($mailchimpPreview.excluded_and_why.duplicate_email)"

  $mailchimp = Invoke-WebRequest -Uri "${baseUrl}?action=campaign_export&id=$($profileCampaign.id)&format=mailchimp" -WebSession $session -UseBasicParsing
  $mailchimpHeader = Get-CsvHeader $mailchimp.Content
  Assert-True ($mailchimpHeader -eq 'Email Address,First Name,Last Name,Phone,Tags') "Mailchimp header row is incorrect: $mailchimpHeader"
  $mailchimpRows = @($mailchimp.Content | ConvertFrom-Csv)
  Assert-True ($mailchimpRows.Count -eq 2) "Mailchimp should include 2 deduped email rows, got $($mailchimpRows.Count)"
  Assert-True (($mailchimpRows | Where-Object { -not $_.'Email Address' }).Count -eq 0) 'Mailchimp export included a blank email row'
  Assert-True (($mailchimpRows | Where-Object { $_.Tags -match 'campaign:Profile Export Test' }).Count -eq $mailchimpRows.Count) 'Mailchimp rows should include campaign tag'

  $brevo = Invoke-WebRequest -Uri "${baseUrl}?action=campaign_export&id=$($profileCampaign.id)&format=brevo" -WebSession $session -UseBasicParsing
  $brevoHeader = Get-CsvHeader $brevo.Content
  Assert-True ($brevoHeader -eq 'EMAIL,SMS,FIRSTNAME,LASTNAME,COUPON_CODE') "Brevo header row is incorrect: $brevoHeader"
  $brevoRows = @($brevo.Content | ConvertFrom-Csv)
  Assert-True ($brevoRows.Count -eq 3) "Brevo should include 3 email-or-phone rows after dedupe, got $($brevoRows.Count)"
  Assert-True (($brevoRows | Where-Object { $_.SMS -and $_.SMS -notmatch '^\+[1-9][0-9]{6,14}$' }).Count -eq 0) 'Brevo export included an invalid SMS phone'

  $sms = Invoke-WebRequest -Uri "${baseUrl}?action=campaign_export&id=$($profileCampaign.id)&format=sms" -WebSession $session -UseBasicParsing
  Assert-True ([string]$sms.Headers['Content-Disposition'] -match 'profile-export-test-sms-\d{8}\.csv') 'SMS export filename should use campaign slug, format, and date'
  $smsHeader = Get-CsvHeader $sms.Content
  Assert-True ($smsHeader -eq 'phone,name,coupon_code,message') "SMS header row is incorrect: $smsHeader"
  $smsRows = @($sms.Content | ConvertFrom-Csv)
  Assert-True ($smsRows.Count -eq 4) "SMS should include 4 valid-phone rows, got $($smsRows.Count)"
  Assert-True (($smsRows | Where-Object { $_.phone -notmatch '^\+[1-9][0-9]{6,14}$' }).Count -eq 0) 'SMS export included a blank or invalid phone'
  Assert-True (($smsRows | Where-Object { $_.message -match '\{first_name\}|\{coupon_code\}|\{store_name\}' }).Count -eq 0) 'SMS export left supported merge fields unresolved'
  Assert-True (($smsRows | Where-Object { $_.message -notmatch '^Hi .+, use NP-[A-Z0-9]+ at Neighbour Store\. Keep \{unknown\}\.$' }).Count -eq 0) 'SMS export did not render merge-field messages correctly'
  Assert-True (($smsRows | Where-Object { $_.message -notlike "*$($_.coupon_code)*" }).Count -eq 0) 'SMS export message did not include each row coupon code'
  $smsBom = Invoke-WebRequest -Uri "${baseUrl}?action=campaign_export&id=$($profileCampaign.id)&format=sms&bom=1" -WebSession $session -UseBasicParsing
  Assert-True ($smsBom.Content.StartsWith([string][char]0xFEFF)) 'Excel-friendly BOM export did not start with UTF-8 BOM'

  $whatsapp = Invoke-WebRequest -Uri "${baseUrl}?action=campaign_export&id=$($profileCampaign.id)&format=whatsapp" -WebSession $session -UseBasicParsing
  $whatsappHeader = Get-CsvHeader $whatsapp.Content
  Assert-True ($whatsappHeader -eq 'phone,name,message,wa_link') "WhatsApp header row is incorrect: $whatsappHeader"
  $whatsappRows = @($whatsapp.Content | ConvertFrom-Csv)
  Assert-True ($whatsappRows.Count -eq 4) "WhatsApp should include 4 valid-phone rows, got $($whatsappRows.Count)"
  Assert-True (($whatsappRows | Where-Object { $_.wa_link -notmatch '^https://wa\.me/[0-9]+\?text=' }).Count -eq 0) 'WhatsApp export included an invalid wa.me link'
  $firstWhatsApp = $whatsappRows[0]
  $decodedWhatsAppText = [uri]::UnescapeDataString(($firstWhatsApp.wa_link -split 'text=', 2)[1])
  Assert-True ($decodedWhatsAppText -eq $firstWhatsApp.message) 'WhatsApp wa.me link text did not match the rendered message'

  $customerSegmentFilters = @{ marketing_opt_in_only = $true; total_spent_min_cents = 1 }
  $customerSegment = Invoke-AppJson `
    -BaseUrl $baseUrl `
    -Session $session `
    -Csrf $csrf `
    -Action 'api_segment_create' `
    -Body @{ name = 'Spend Export Segment'; filters = $customerSegmentFilters }
  $customerPreview = Invoke-AppJson `
    -BaseUrl $baseUrl `
    -Session $session `
    -Csrf $csrf `
    -Action 'api_segment_preview' `
    -Body @{ segment_id = [int]$customerSegment.id; filters = $customerSegmentFilters }
  Assert-True ($customerPreview.count -gt 0) 'Customer export segment preview should include spend customers'
  $customerSms = Invoke-WebRequest -Uri "${baseUrl}?action=customer_export&segment_id=$($customerSegment.id)&format=sms" -WebSession $session -UseBasicParsing
  Assert-True ([string]$customerSms.Headers['Content-Disposition'] -match 'spend-export-segment-sms-\d{8}\.csv') 'Customer export filename should use segment slug, format, and date'
  Assert-True ((Get-CsvHeader $customerSms.Content) -eq 'phone,name,coupon_code,message') 'Customer SMS export header row is incorrect'
  $customerSmsRows = @($customerSms.Content | ConvertFrom-Csv)
  Assert-True ($customerSmsRows.Count -eq [int]$customerPreview.count) "Customer SMS export should match segment preview count, got $($customerSmsRows.Count) vs $($customerPreview.count)"
  Assert-True (($customerSmsRows | Where-Object { $_.phone -notmatch '^\+[1-9][0-9]{6,14}$' }).Count -eq 0) 'Customer SMS export included an invalid phone'

  $tagFilters = @{ marketing_opt_in_only = $true; tag_any = @('vip') }
  $tagSegment = Invoke-AppJson `
    -BaseUrl $baseUrl `
    -Session $session `
    -Csrf $csrf `
    -Action 'api_segment_create' `
    -Body @{ name = 'VIP Tag Segment'; filters = $tagFilters }
  $tagPreview = Invoke-AppJson `
    -BaseUrl $baseUrl `
    -Session $session `
    -Csrf $csrf `
    -Action 'api_segment_preview' `
    -Body @{ segment_id = [int]$tagSegment.id; filters = $tagFilters }
  Assert-True ($tagPreview.count -gt 0) 'VIP tag segment should return at least one customer'
  Assert-True (@($tagPreview.sample | Where-Object { $_.tags_text -notmatch ',vip,' }).Count -eq 0) 'VIP tag segment returned a customer without the vip tag'
  $segmentsList = Invoke-WebRequest -Uri "${baseUrl}?action=api_segments_list" -WebSession $session -Headers @{ 'Accept' = 'application/json' } -UseBasicParsing
  $segmentsPayload = $segmentsList.Content | ConvertFrom-Json
  $listedTagSegment = @(($segmentsPayload.data) | Where-Object { [int]$_.id -eq [int]$tagSegment.id })[0]
  Assert-True ($null -ne $listedTagSegment) 'Tag segment was not returned by api_segments_list'
  Assert-True ([int]$listedTagSegment.count -eq [int]$tagPreview.count) "Saved segment live count should be $($tagPreview.count), got $($listedTagSegment.count)"
  $duplicateSegment = Invoke-AppJson `
    -BaseUrl $baseUrl `
    -Session $session `
    -Csrf $csrf `
    -Action 'api_segment_duplicate' `
    -Body @{ id = [int]$tagSegment.id }
  Assert-True ([int]$duplicateSegment.id -gt 0 -and [int]$duplicateSegment.id -ne [int]$tagSegment.id) 'Duplicate segment did not return a new id'
  $segmentsListAfterDuplicate = Invoke-WebRequest -Uri "${baseUrl}?action=api_segments_list" -WebSession $session -Headers @{ 'Accept' = 'application/json' } -UseBasicParsing
  $duplicateListed = @((($segmentsListAfterDuplicate.Content | ConvertFrom-Json).data) | Where-Object { [int]$_.id -eq [int]$duplicateSegment.id })[0]
  Assert-True ($duplicateListed.name -match 'copy') 'Duplicated segment name should indicate it is a copy'
  Assert-True ([int]$duplicateListed.count -eq [int]$tagPreview.count) 'Duplicated segment live count should match the original segment count'

  Write-Host "campaign_export_test passed with $rowCount full recipient(s) and profile exports verified."
} finally {
  if ($server -and -not $server.HasExited) {
    Stop-Process -Id $server.Id -Force
  }
  if (Test-Path -LiteralPath $tempRoot) {
    Remove-Item -LiteralPath $tempRoot -Recurse -Force
  }
}
