param(
  [int]$MySqlPort = 3306,
  [int]$PostgresPort = 5432,
  [string]$MySqlUser = "proxyuser",
  [string]$MySqlPassword = "password",
  [string]$PostgresUser = "postgres",
  [string]$PostgresPassword = "password",
  [string]$Database = "testdb",
  [int]$FailedAuthCount = 3,
  [int]$SessionWaitSeconds = 45,
  [int]$ConsumeNum = 25,
  [string]$ConsumeOffset = "start",
  [int]$ConsumeTimeoutSeconds = 12,
  [int]$MilestoneConsumeNum = 200,
  [string]$MilestoneConsumeOffset = "start",
  [int]$MilestoneTimeoutSeconds = 20,
  [switch]$SkipTraffic,
  [switch]$AssertMilestones
)

$ErrorActionPreference = "Continue"

function Invoke-Health($Url) {
  Write-Host "==> $Url"
  try {
    $output = curl.exe -fsS $Url 2>&1
    if ($LASTEXITCODE -ne 0) {
      Write-Warning "Health check failed: $Url"
      $output | Out-Host
      return
    }
    if ($Url -match "/metrics$") {
      Write-Host "[OK] metrics endpoint reachable"
    } else {
      $output | Out-Host
    }
  } catch {
    Write-Warning "Health check failed: $Url"
  }
}

function Invoke-RpkConsume([string]$Topic, [int]$Num, [string]$Offset, [int]$TimeoutSeconds) {
  Write-Host "==> Consuming $Topic (--offset $Offset --num $Num, timeout ${TimeoutSeconds}s)"

  try {
    $output = docker compose exec -T redpanda rpk topic consume $Topic --num $Num --offset $Offset 2>&1
    return @($output)
  }
  catch {
    Write-Warning "Failed consuming topic $Topic"
    return @()
  }
}

function Get-TopicOutput([string]$Topic) {
  return Invoke-RpkConsume $Topic $ConsumeNum $ConsumeOffset $ConsumeTimeoutSeconds
}

function Get-MilestoneOutput([string]$Topic) {
  return Invoke-RpkConsume $Topic $MilestoneConsumeNum $MilestoneConsumeOffset $MilestoneTimeoutSeconds
}

function Show-TopicSummary([string]$Topic, [string[]]$Output) {
  Write-Host "==> Summary: $Topic"
  if (-not $Output -or $Output.Count -eq 0) {
    Write-Warning "No output captured for $Topic"
    return
  }
  $Output | python scripts/summarize_rpk_json.py
  if ($LASTEXITCODE -ne 0) {
    Write-Warning "Could not summarize $Topic. Raw output follows."
    $Output | Out-Host
  }
}

function Assert-Technique([string]$Technique, [string[]]$Output) {
  if (-not $AssertMilestones) { return }
  Write-Host "==> Asserting MITRE milestone $Technique"
  $Output | python scripts/assert_rpk_milestone.py --technique $Technique --print-matches
  if ($LASTEXITCODE -ne 0) {
    Write-Warning "Milestone $Technique was not found in captured output. Increase -MilestoneConsumeNum, use -MilestoneConsumeOffset start, or clear old volumes for a fresh demo."
  }
}

Write-Host "==> Health/readiness checks"
Invoke-Health "http://127.0.0.1:9090/ready"
Invoke-Health "http://127.0.0.1:9091/ready"
Invoke-Health "http://127.0.0.1:8000/metrics"
Invoke-Health "http://127.0.0.1:8001/readyz"
Invoke-Health "http://127.0.0.1:8002/readyz"
Invoke-Health "http://127.0.0.1:9095/metrics"

Write-Host "==> Redpanda topics"
docker compose exec -T redpanda rpk topic list

if (-not $SkipTraffic) {
  if (Get-Command mysql -ErrorAction SilentlyContinue) {
    Write-Host "==> Trigger MySQL failed-auth burst ($FailedAuthCount attempts)"
    1..$FailedAuthCount | ForEach-Object {
      mysql -h 127.0.0.1 -P $MySqlPort -u $MySqlUser -pwrongpass $Database -e "SELECT 1;" 2>$null | Out-Null
    }

    Write-Host "==> Trigger MySQL recon/enumeration queries"
    mysql -h 127.0.0.1 -P $MySqlPort -u $MySqlUser -p$MySqlPassword $Database -e "SELECT @@version_comment LIMIT 1; SHOW DATABASES; SHOW TABLES; SELECT DATABASE();" 2>$null | Out-Host
  } else {
    Write-Warning "mysql client not found; skipping MySQL traffic generation."
  }

  if (Get-Command psql -ErrorAction SilentlyContinue) {
    Write-Host "==> Trigger PostgreSQL recon/enumeration queries"
    $env:PGPASSWORD = $PostgresPassword
    psql -h 127.0.0.1 -p $PostgresPort -U $PostgresUser -d $Database -c "SELECT version();" 2>$null | Out-Host
    psql -h 127.0.0.1 -p $PostgresPort -U $PostgresUser -d $Database -c "SELECT current_user;" 2>$null | Out-Host
    psql -h 127.0.0.1 -p $PostgresPort -U $PostgresUser -d $Database -c "SELECT * FROM information_schema.tables LIMIT 5;" 2>$null | Out-Host
  } else {
    Write-Warning "psql client not found; skipping PostgreSQL traffic generation."
  }

  Write-Host "==> Waiting $SessionWaitSeconds seconds for session close/profile publication"
  Start-Sleep -Seconds $SessionWaitSeconds
} else {
  Write-Host "==> -SkipTraffic set; only consuming existing topic data"
}

Write-Host "==> Topic summaries use --offset $ConsumeOffset, --num $ConsumeNum, timeout ${ConsumeTimeoutSeconds}s"
Write-Host "    Milestone assertions use --offset $MilestoneConsumeOffset, --num $MilestoneConsumeNum, timeout ${MilestoneTimeoutSeconds}s."
Write-Host "    On a reused Redpanda volume, increase -MilestoneConsumeNum or run docker compose down -v for a clean demo."

$sessionProfiles = Get-TopicOutput "session-profiles"
Show-TopicSummary "session-profiles" $sessionProfiles

$mitreEvents = Get-TopicOutput "mitre-events"
Show-TopicSummary "mitre-events" $mitreEvents

$mitreSessions = Get-TopicOutput "mitre-sessions"
Show-TopicSummary "mitre-sessions" $mitreSessions

if ($AssertMilestones) {
  Write-Host "==> Capturing wider MITRE sample for milestone assertions"
  $milestoneEvents = Get-MilestoneOutput "mitre-events"
  $milestoneSessions = Get-MilestoneOutput "mitre-sessions"
  $combinedMitre = @($milestoneEvents + $milestoneSessions)
  Assert-Technique "T1110.001" $combinedMitre
  Assert-Technique "T1213.006" $combinedMitre
}

Write-Host "==> Logs to inspect if any topic is empty"
Write-Host "docker compose logs --tail=120 mysqlproxy pgproxy session-module mitre-agent scaling-agent"
