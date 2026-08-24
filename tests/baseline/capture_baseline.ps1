param(
  [int]$EvidenceWaitSeconds = 40,
  [string]$ExpectedPath = "tests/baseline/expected_baseline.json"
)

$ErrorActionPreference = "Stop"

function Get-DotEnvValue([string]$Name) {
  $line = Get-Content -LiteralPath .env |
    Where-Object { $_ -match "^$([regex]::Escape($Name))=" } |
    Select-Object -First 1
  if (-not $line) { throw "Missing $Name in .env" }
  return $line.Substring($line.IndexOf('=') + 1).Trim('"')
}

function Invoke-MySqlQuery([string]$Query) {
  $timer = [System.Diagnostics.Stopwatch]::StartNew()
  $lines = @(docker exec -e "MYSQL_PWD=$script:MySqlPassword" capstone-main-mysql-1 mysql --protocol=TCP -h mysqlproxy -u proxyuser -D testdb --batch --raw -e $Query 2>&1)
  $exitCode = $LASTEXITCODE
  $timer.Stop()
  return [ordered]@{
    passed = ($exitCode -eq 0)
    exit_code = $exitCode
    latency_ms = [math]::Round($timer.Elapsed.TotalMilliseconds, 2)
    output = ($lines -join "`n").Trim()
  }
}

function Invoke-PostgresQuery([string]$Query) {
  $timer = [System.Diagnostics.Stopwatch]::StartNew()
  $lines = @(docker exec -e "PGPASSWORD=$script:PostgresPassword" capstone-main-postgres-1 psql -h pgproxy -U postgres -d testdb -v ON_ERROR_STOP=1 -P pager=off -A -F "`t" -c $Query 2>&1)
  $exitCode = $LASTEXITCODE
  $timer.Stop()
  return [ordered]@{
    passed = ($exitCode -eq 0)
    exit_code = $exitCode
    latency_ms = [math]::Round($timer.Elapsed.TotalMilliseconds, 2)
    output = ($lines -join "`n").Trim()
  }
}

function Get-SessionForMarker([object[]]$Sessions, [string]$Marker) {
  foreach ($session in $Sessions) {
    if (@($session.queries | Where-Object { $_.query_raw -like "*$Marker*" }).Count -gt 0) { return $session }
  }
  return $null
}

function Get-EvidenceSessions([hashtable]$Markers, [int]$WaitSeconds) {
  $deadline = [DateTime]::UtcNow.AddSeconds($WaitSeconds)
  do {
    $sessions = @((Invoke-RestMethod -Uri "http://127.0.0.1:8011/evidence/sessions?limit=100" -TimeoutSec 10).sessions)
    $found = @{}
    foreach ($name in $Markers.Keys) { $found[$name] = Get-SessionForMarker $sessions $Markers[$name] }
    $ready = @($found.Values | Where-Object { $_ -and $_.trace.connection -and $_.trace.query -and $_.trace.mitre -and $_.trace.scaling }).Count -eq $Markers.Count
    if ($ready) { return $found }
    Start-Sleep -Seconds 1
  } while ([DateTime]::UtcNow -lt $deadline)
  return $found
}

function Add-Check([string]$Name, [bool]$Passed, [string]$Detail) {
  $script:Checks.Add([ordered]@{ name = $Name; passed = $Passed; detail = $Detail })
}

function Test-ContainsAll([string]$Value, [object[]]$Required) {
  foreach ($item in $Required) { if ($Value -notlike "*$item*") { return $false } }
  return $true
}

function Get-EvidenceSummary([object]$Evidence) {
  if (-not $Evidence) { return $null }
  return [ordered]@{
    session_id = $Evidence.session_id
    protocol = $Evidence.protocol
    query_count = @($Evidence.queries).Count
    risk_score = $Evidence.risk_score
    risk_level = $Evidence.risk_level
    trap_triggered = [bool]$Evidence.trap_triggered
    mitre_techniques = @($Evidence.mitre_technique)
    scaling_events = @($Evidence.scaling_events).Count
    trace = $Evidence.trace
  }
}

if (-not (Test-Path -LiteralPath $ExpectedPath)) { throw "Missing expected fixture: $ExpectedPath" }
$expected = Get-Content -LiteralPath $ExpectedPath -Raw | ConvertFrom-Json
$script:PostgresPassword = Get-DotEnvValue "POSTGRES_PASSWORD"
$script:MySqlPassword = Get-DotEnvValue "MYSQL_PASSWORD"
$script:Checks = [System.Collections.Generic.List[object]]::new()

$runId = "baseline-$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())-$([guid]::NewGuid().ToString('N').Substring(0, 6))"
$sqlRun = $runId.Replace('-', '_')
$markers = @{
  mysql_benign = "${sqlRun}_mysql_benign"
  postgres_benign = "${sqlRun}_postgres_benign"
  catalog_enumeration = "${sqlRun}_catalog"
  trap_table = "${sqlRun}_trap"
}

$executions = [ordered]@{
  mysql_benign = Invoke-MySqlQuery "SELECT 1 AS $($markers.mysql_benign);"
  postgres_benign = Invoke-PostgresQuery "SELECT current_database() AS database_name, current_user AS user_name, 1 AS $($markers.postgres_benign);"
  catalog_enumeration = Invoke-MySqlQuery "SELECT 1 AS $($markers.catalog_enumeration); SHOW DATABASES;"
  trap_table = Invoke-MySqlQuery "SELECT *, 1 AS $($markers.trap_table) FROM api_keys_backup LIMIT 1;"
}

$evidence = Get-EvidenceSessions $markers $EvidenceWaitSeconds
$scaleMetrics = Invoke-RestMethod -Uri "http://127.0.0.1:9095/metrics" -TimeoutSec 10
$aiBrief = Invoke-RestMethod -Uri "http://127.0.0.1:8010/brief/latest" -TimeoutSec 15

foreach ($name in $executions.Keys) {
  $execution = $executions[$name]
  Add-Check "$name protocol execution" $execution.passed "exit_code=$($execution.exit_code)"
  Add-Check "$name latency ceiling" ($execution.latency_ms -le $expected.latency_ceiling_ms) "latency_ms=$($execution.latency_ms) ceiling_ms=$($expected.latency_ceiling_ms)"
  Add-Check "$name response contract" (Test-ContainsAll $execution.output $expected.$name.response_contains) "required=$($expected.$name.response_contains -join ',')"
  Add-Check "$name evidence correlation" ($null -ne $evidence[$name]) "marker=$($markers[$name])"
}

$validTrapPrefix = @($expected.trap_table.token_prefixes | Where-Object { $executions.trap_table.output -like "*$_*" }).Count -gt 0
Add-Check "trap_table synthetic token prefix" $validTrapPrefix "allowed=$($expected.trap_table.token_prefixes -join ',')"

foreach ($name in @("mysql_benign", "postgres_benign", "catalog_enumeration", "trap_table")) {
  $observed = $evidence[$name]
  if ($observed) {
    Add-Check "$name risk" ($observed.risk_level -eq $expected.$name.risk_level) "observed=$($observed.risk_level) expected=$($expected.$name.risk_level)"
    Add-Check "$name trap behavior" ([bool]$observed.trap_triggered -eq [bool]$expected.$name.trap_triggered) "observed=$($observed.trap_triggered) expected=$($expected.$name.trap_triggered)"
    Add-Check "$name complete deterministic trace" ($observed.trace.connection -and $observed.trace.query -and $observed.trace.mitre -and $observed.trace.scaling) "connection/query/mitre/scaling required"
  }
}

foreach ($name in @("catalog_enumeration", "trap_table")) {
  $observed = $evidence[$name]
  if ($observed) { Add-Check "$name MITRE mapping" (@($observed.mitre_technique) -contains $expected.$name.mitre_technique) "observed=$(@($observed.mitre_technique) -join ',')" }
}

$trapEvidence = $evidence.trap_table
$trapScaleDecision = if ($trapEvidence) { @($trapEvidence.scaling_events | Sort-Object raw_score -Descending) | Select-Object -First 1 } else { $null }
Add-Check "trap scaling decision linked" ($null -ne $trapScaleDecision) "session_id=$($trapEvidence.session_id)"
Add-Check "scaling replica bounds" ($scaleMetrics.config.replica_min -eq $expected.scaling.replica_min -and $scaleMetrics.config.replica_max -eq $expected.scaling.replica_max) "observed=$($scaleMetrics.config.replica_min)-$($scaleMetrics.config.replica_max)"
Add-Check "scaling thresholds" ($scaleMetrics.config.scale_up_threshold -eq $expected.scaling.scale_up_threshold -and $scaleMetrics.config.scale_down_threshold -eq $expected.scaling.scale_down_threshold) "up=$($scaleMetrics.config.scale_up_threshold) down=$($scaleMetrics.config.scale_down_threshold)"
Add-Check "scaling control mode" ($scaleMetrics.control_mode -eq $expected.scaling.control_mode) "observed=$($scaleMetrics.control_mode)"
Add-Check "AI v1 agent identity" ($aiBrief.agent -eq $expected.ai_v1.agent) "observed=$($aiBrief.agent)"
Add-Check "AI v1 high-risk brief" ($aiBrief.risk_level -eq $expected.ai_v1.risk_level) "observed=$($aiBrief.risk_level)"
Add-Check "AI v1 trap metric consistency" ([bool]$aiBrief.scaling_interpretation.trap_metric_consistent -eq [bool]$expected.ai_v1.trap_metric_consistent) "observed=$($aiBrief.scaling_interpretation.trap_metric_consistent)"
Add-Check "AI v1 trap-session attribution" ($aiBrief.summary -like "*$($trapEvidence.session_id)*") "summary attribution required for trap=$($trapEvidence.session_id)"
Add-Check "AI v1 evidence link stored" ([bool]$aiBrief.evidence.evidence_store_link.stored -eq [bool]$expected.ai_v1.evidence_link_stored -and $aiBrief.evidence.evidence_store_link.session_id -eq $trapEvidence.session_id) "stored=$($aiBrief.evidence.evidence_store_link.stored) session=$($aiBrief.evidence.evidence_store_link.session_id)"

$ruleHashes = [ordered]@{}
foreach ($ruleFile in $expected.rule_files) {
  $nativePath = $ruleFile.Replace('/', [IO.Path]::DirectorySeparatorChar)
  if (Test-Path -LiteralPath $nativePath) {
    $ruleHashes[$ruleFile] = (Get-FileHash -Algorithm SHA256 -LiteralPath $nativePath).Hash.ToLowerInvariant()
  } else {
    $ruleHashes[$ruleFile] = "missing"
    Add-Check "rule asset exists: $ruleFile" $false "missing"
  }
}

$failed = @($script:Checks | Where-Object { -not $_.passed })
$result = [ordered]@{
  schema_version = 1
  run_id = $runId
  captured_at = [DateTimeOffset]::UtcNow.ToString('o')
  bounded_test = $true
  deployment_performed = $false
  status = if ($failed.Count -eq 0) { "PASS" } else { "FAIL" }
  assertions = [ordered]@{ total = $script:Checks.Count; passed = $script:Checks.Count - $failed.Count; failed = $failed.Count; checks = $script:Checks }
  cases = [ordered]@{
    mysql_benign = [ordered]@{ execution = $executions.mysql_benign; evidence = Get-EvidenceSummary $evidence.mysql_benign }
    postgres_benign = [ordered]@{ execution = $executions.postgres_benign; evidence = Get-EvidenceSummary $evidence.postgres_benign }
    catalog_enumeration = [ordered]@{ execution = $executions.catalog_enumeration; evidence = Get-EvidenceSummary $evidence.catalog_enumeration }
    trap_table = [ordered]@{ execution = $executions.trap_table; evidence = Get-EvidenceSummary $evidence.trap_table }
  }
  mitre_mapping = [ordered]@{ technique_id = $expected.trap_table.mitre_technique; catalog_session_id = $evidence.catalog_enumeration.session_id; trap_session_id = $evidence.trap_table.session_id }
  scaling = [ordered]@{ config = $scaleMetrics.config; control = $scaleMetrics.control; control_mode = $scaleMetrics.control_mode; decision = $trapScaleDecision }
  ai_v1 = [ordered]@{
    report_id = $aiBrief.report_id
    risk_level = $aiBrief.risk_level
    summary = $aiBrief.summary
    scaling_interpretation = $aiBrief.scaling_interpretation
    evidence_store_link = $aiBrief.evidence.evidence_store_link
  }
  rule_asset_sha256 = $ruleHashes
}

$result | ConvertTo-Json -Depth 14
if ($failed.Count -gt 0) { exit 1 }



