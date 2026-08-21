param(
  [string]$PsqlPath = "C:\Program Files\PostgreSQL\18\bin\psql.exe",
  [int]$EvidenceWaitSeconds = 20,
  [int]$BurstConcurrency = 4
)

$ErrorActionPreference = "Stop"

function Get-DotEnvValue([string]$Name) {
  $line = Get-Content -LiteralPath .env |
    Where-Object { $_ -match "^$([regex]::Escape($Name))=" } |
    Select-Object -First 1
  if (-not $line) { throw "Missing $Name in .env" }
  return $line.Substring($line.IndexOf('=') + 1).Trim('"')
}

function Invoke-PostgresCase([string]$Query) {
  $previous = $env:PGPASSWORD
  $env:PGPASSWORD = $script:PostgresPassword
  $timer = [System.Diagnostics.Stopwatch]::StartNew()
  try {
    & $script:PsqlPath -h 127.0.0.1 -p 5432 -U postgres -d testdb -qAt -v ON_ERROR_STOP=1 -c $Query 2>$null | Out-Null
    $passed = $LASTEXITCODE -eq 0
  } finally {
    $timer.Stop()
    $env:PGPASSWORD = $previous
  }
  return [ordered]@{ passed = $passed; latency_ms = [math]::Round($timer.Elapsed.TotalMilliseconds, 2) }
}

function Invoke-MySqlCase([string]$Query) {
  $timer = [System.Diagnostics.Stopwatch]::StartNew()
  docker exec -e "MYSQL_PWD=$script:MySqlPassword" capstone-main-mysql-1 `
    mysql --protocol=TCP -h mysqlproxy -u proxyuser -D testdb -N -e $Query 2>$null | Out-Null
  $timer.Stop()
  return [ordered]@{ passed = ($LASTEXITCODE -eq 0); latency_ms = [math]::Round($timer.Elapsed.TotalMilliseconds, 2) }
}

function Get-Percentile([double[]]$Values, [double]$Percentile) {
  if (-not $Values -or $Values.Count -eq 0) { return $null }
  $sorted = @($Values | Sort-Object)
  $index = [math]::Ceiling(($Percentile / 100.0) * $sorted.Count) - 1
  $index = [math]::Max(0, [math]::Min($sorted.Count - 1, $index))
  return [math]::Round([double]$sorted[$index], 2)
}

function Get-PrometheusValue([string]$Query) {
  try {
    $encoded = [uri]::EscapeDataString($Query)
    $response = Invoke-RestMethod "http://127.0.0.1:9096/api/v1/query?query=$encoded"
    if ($response.data.result.Count -gt 0) { return [double]$response.data.result[0].value[1] }
  } catch { }
  return $null
}

if (-not (Test-Path -LiteralPath $PsqlPath)) { throw "psql was not found at $PsqlPath" }
$script:PsqlPath = $PsqlPath
$script:PostgresPassword = Get-DotEnvValue "POSTGRES_PASSWORD"
$script:MySqlPassword = Get-DotEnvValue "MYSQL_PASSWORD"

$runId = "cal-$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())-$([guid]::NewGuid().ToString('N').Substring(0, 6))"
$sqlRun = $runId.Replace('-', '_')
$cases = @(
  [ordered]@{ name = "pg-benign-1"; protocol = "postgres"; expected_positive = $false; category = "benign"; query = "SELECT 1 AS ${sqlRun}_pgb1;"; marker = "${sqlRun}_pgb1" },
  [ordered]@{ name = "pg-benign-2"; protocol = "postgres"; expected_positive = $false; category = "benign"; query = "SELECT current_database() AS ${sqlRun}_pgb2;"; marker = "${sqlRun}_pgb2" },
  [ordered]@{ name = "mysql-benign"; protocol = "mysql"; expected_positive = $false; category = "benign"; query = "SELECT 1 AS ${sqlRun}_myb1;"; marker = "${sqlRun}_myb1" },
  [ordered]@{ name = "pg-recon-1"; protocol = "postgres"; expected_positive = $true; category = "recon"; query = "SELECT table_name AS ${sqlRun}_pgr1 FROM information_schema.tables LIMIT 1;"; marker = "${sqlRun}_pgr1" },
  [ordered]@{ name = "pg-recon-2"; protocol = "postgres"; expected_positive = $true; category = "recon"; query = "SELECT tablename AS ${sqlRun}_pgr2 FROM pg_catalog.pg_tables LIMIT 1;"; marker = "${sqlRun}_pgr2" },
  [ordered]@{ name = "mysql-recon"; protocol = "mysql"; expected_positive = $true; category = "recon"; query = "SELECT table_name AS ${sqlRun}_myr1 FROM information_schema.tables LIMIT 1;"; marker = "${sqlRun}_myr1" },
  [ordered]@{ name = "pg-trap-1"; protocol = "postgres"; expected_positive = $true; category = "trap"; query = "SELECT *, 1 AS ${sqlRun}_pgt1 FROM api_keys_backup LIMIT 1;"; marker = "${sqlRun}_pgt1" },
  [ordered]@{ name = "pg-trap-2"; protocol = "postgres"; expected_positive = $true; category = "trap"; query = "SELECT *, 1 AS ${sqlRun}_pgt2 FROM api_keys_backup LIMIT 1;"; marker = "${sqlRun}_pgt2" },
  [ordered]@{ name = "mysql-trap"; protocol = "mysql"; expected_positive = $true; category = "trap"; query = "SELECT *, 1 AS ${sqlRun}_myt1 FROM api_keys_backup LIMIT 1;"; marker = "${sqlRun}_myt1" }
)

$trapBefore = Get-PrometheusValue "capstone_mitre_trap_triggers_total"
$replicasBefore = Get-PrometheusValue "capstone_scaling_current_replicas"

foreach ($case in $cases) {
  $execution = if ($case.protocol -eq "postgres") {
    Invoke-PostgresCase $case.query
  } else {
    Invoke-MySqlCase $case.query
  }
  $case.execution_passed = $execution.passed
  $case.latency_ms = $execution.latency_ms
}

$burstMarker = "${sqlRun}_burst"
$burstJobs = @()
$burstTimer = [System.Diagnostics.Stopwatch]::StartNew()
for ($index = 1; $index -le $BurstConcurrency; $index++) {
  $isTrap = ($index % 2) -eq 0
  $query = if ($isTrap) {
    "SELECT *, 1 AS ${burstMarker}_$index FROM api_keys_backup LIMIT 1;"
  } else {
    "SELECT 1 AS ${burstMarker}_$index;"
  }
  $burstJobs += Start-Job -ScriptBlock {
    param($Client, $Password, $Sql)
    $env:PGPASSWORD = $Password
    & $Client -h 127.0.0.1 -p 5432 -U postgres -d testdb -qAt -v ON_ERROR_STOP=1 -c $Sql 2>$null | Out-Null
    return $LASTEXITCODE
  } -ArgumentList $PsqlPath, $script:PostgresPassword, $query
  $cases += [ordered]@{
    name = "pg-burst-$index"
    protocol = "postgres"
    expected_positive = $isTrap
    category = if ($isTrap) { "mixed-burst-trap" } else { "mixed-burst-benign" }
    query = $query
    marker = "${burstMarker}_$index"
  }
}
$burstJobs | Wait-Job | Out-Null
$burstCodes = @($burstJobs | Receive-Job)
$burstJobs | Remove-Job -Force
$burstTimer.Stop()
for ($index = 0; $index -lt $BurstConcurrency; $index++) {
  $cases[9 + $index].execution_passed = ([int]$burstCodes[$index] -eq 0)
  $cases[9 + $index].latency_ms = $null
}

Start-Sleep -Seconds $EvidenceWaitSeconds
$sessions = (Invoke-RestMethod "http://127.0.0.1:8011/evidence/sessions?limit=100").sessions

$tp = 0; $tn = 0; $fp = 0; $fn = 0; $matched = 0
foreach ($case in $cases) {
  $evidence = @($sessions | Where-Object { $_.query_raw -like "*$($case.marker)*" }) | Select-Object -First 1
  if ($evidence) {
    $matched++
    $techniques = @($evidence.mitre_technique)
    $predicted = [bool]$evidence.trap_triggered -or $techniques.Count -gt 0 -or $evidence.risk_level -in @("high", "critical")
    $case.session_id = $evidence.session_id
    $case.observed_risk = $evidence.risk_level
    $case.trap_triggered = [bool]$evidence.trap_triggered
    $case.mitre_techniques = $techniques
    $case.predicted_positive = $predicted
    $case.trace_complete = [bool]$evidence.trace.complete
    if ($case.expected_positive -and $predicted) { $tp++ }
    elseif (-not $case.expected_positive -and -not $predicted) { $tn++ }
    elseif (-not $case.expected_positive -and $predicted) { $fp++ }
    else { $fn++ }
  } else {
    $case.session_id = $null
    $case.predicted_positive = $null
    $case.observed_risk = "missing"
  }
}

$precision = if (($tp + $fp) -gt 0) { $tp / ($tp + $fp) } else { 0 }
$recall = if (($tp + $fn) -gt 0) { $tp / ($tp + $fn) } else { 0 }
$f1 = if (($precision + $recall) -gt 0) { 2 * $precision * $recall / ($precision + $recall) } else { 0 }
$latencies = @($cases | Where-Object { $_.latency_ms -ne $null } | ForEach-Object { [double]$_.latency_ms })

$trapAfter = Get-PrometheusValue "capstone_mitre_trap_triggers_total"
$replicasAfter = Get-PrometheusValue "capstone_scaling_current_replicas"
$pressureAfter = Get-PrometheusValue "capstone_scaling_scale_pressure"

[ordered]@{
  run_id = $runId
  bounded_test = $true
  deployment_performed = $false
  case_count = $cases.Count
  evidence_matched = $matched
  execution_passed = @($cases | Where-Object { $_.execution_passed }).Count
  latency_ms = [ordered]@{
    sample_count = $latencies.Count
    p50 = Get-Percentile $latencies 50
    p95 = Get-Percentile $latencies 95
    p99 = Get-Percentile $latencies 99
    mixed_burst_wall = [math]::Round($burstTimer.Elapsed.TotalMilliseconds, 2)
  }
  classification = [ordered]@{
    true_positive = $tp
    true_negative = $tn
    false_positive = $fp
    false_negative = $fn
    precision = [math]::Round($precision, 4)
    recall = [math]::Round($recall, 4)
    f1 = [math]::Round($f1, 4)
  }
  telemetry = [ordered]@{
    trap_triggers_before = $trapBefore
    trap_triggers_after = $trapAfter
    replicas_before = $replicasBefore
    replicas_after = $replicasAfter
    scale_pressure_after = $pressureAfter
  }
  cases = $cases
} | ConvertTo-Json -Depth 12
