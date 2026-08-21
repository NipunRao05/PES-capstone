param(
  [string]$GitPath = "C:\Program Files\Git\cmd\git.exe"
)

$ErrorActionPreference = "Stop"
$checks = [System.Collections.Generic.List[object]]::new()

function Add-Check([string]$Name, [bool]$Passed, [string]$Evidence) {
  $script:checks.Add([ordered]@{ check = $Name; passed = $Passed; evidence = $Evidence })
}

function Get-DotEnvValue([string]$Name) {
  $line = Get-Content -LiteralPath .env |
    Where-Object { $_ -match "^$([regex]::Escape($Name))=" } |
    Select-Object -First 1
  if (-not $line) { return "" }
  return $line.Substring($line.IndexOf('=') + 1).Trim('"')
}

$root = (Get-Location).Path
Add-Check "repository-root" ($root -eq "F:\b\Capstone-main") $root
Add-Check "required-git-executable" (Test-Path -LiteralPath $GitPath) $GitPath

& $GitPath ls-files --error-unmatch .env 2>$null | Out-Null
$envTracked = $LASTEXITCODE -eq 0
Add-Check "dotenv-not-tracked" (-not $envTracked) ".env is outside the Git index"

$cfg = docker compose -f docker-compose.yml config --format json | ConvertFrom-Json
$published = @()
foreach ($property in $cfg.services.psobject.Properties) {
  foreach ($port in @($property.Value.ports | Where-Object { $_ })) {
    $published += [ordered]@{
      service = $property.Name
      host_ip = $port.host_ip
      published = $port.published
      target = $port.target
    }
  }
}
$nonLoopback = @($published | Where-Object { $_.host_ip -ne "127.0.0.1" })
Add-Check "no-public-listeners" ($nonLoopback.Count -eq 0) "$($published.Count) published ports are loopback-only"
Add-Check "real-database-backends-not-published" (
  @($cfg.services.postgres.ports | Where-Object { $_ }).Count -eq 0 -and
  @($cfg.services.mysql.ports | Where-Object { $_ }).Count -eq 0
) "mysql and postgres backends have no published host ports"
Add-Check "control-network-internal" ($cfg.networks.'control-internal'.internal -eq $true) "control-internal has internal=true"
Add-Check "sandbox-network-internal" ($cfg.networks.'sandbox-internal'.internal -eq $true) "sandbox-internal has internal=true"

$llmNetworks = @($cfg.services.'llm-agent'.networks.psobject.Properties.Name)
$llmText = (Get-Content -LiteralPath llm_agent\main.py -Raw) + (Get-Content -LiteralPath llm_agent\requirements.txt -Raw)
$llmForbidden = @('openai', 'anthropic', 'psycopg', 'mysql.connector', 'sqlalchemy') |
  Where-Object { $llmText -match [regex]::Escape($_) }
Add-Check "llm-engine-internal-only" ($llmNetworks.Count -eq 1 -and $llmNetworks[0] -eq "control-internal") ($llmNetworks -join ',')
Add-Check "llm-has-no-db-or-paid-api-client" ($llmForbidden.Count -eq 0) "no paid-API or database client dependency"

$hardenedContainers = @(
  'capstone-evidence-store',
  'capstone-ai-agent',
  'capstone-llm-agent',
  'capstone-sandbox-replay-engine'
)
$containerFailures = @()
foreach ($container in $hardenedContainers) {
  $inspect = docker inspect $container | ConvertFrom-Json | Select-Object -First 1
  $user = [string]$inspect.Config.User
  $nonRoot = $user -and $user -notmatch '^(0|root)(:|$)'
  $readOnly = [bool]$inspect.HostConfig.ReadonlyRootfs
  $noNewPrivileges = @($inspect.HostConfig.SecurityOpt) -contains 'no-new-privileges:true'
  $allCapsDropped = @($inspect.HostConfig.CapDrop) -contains 'ALL'
  if (-not ($nonRoot -and $readOnly -and $noNewPrivileges -and $allCapsDropped)) {
    $containerFailures += $container
  }
}
$containerEvidence = if ($containerFailures.Count) { "failed: $($containerFailures -join ',')" } else { "non-root, read-only, cap-drop ALL, no-new-privileges" }
Add-Check "analysis-services-container-hardened" ($containerFailures.Count -eq 0) $containerEvidence

$nativePostgres = Get-Service -Name postgresql-x64-18 -ErrorAction SilentlyContinue
$nativeStartup = if ($nativePostgres) { (Get-CimInstance Win32_Service -Filter "Name='postgresql-x64-18'").StartMode } else { "Absent" }
Add-Check "native-postgresql-cannot-reclaim-5432" (
  -not $nativePostgres -or ($nativePostgres.Status -eq 'Stopped' -and $nativeStartup -eq 'Disabled')
) "service=$($nativePostgres.Status); startup=$nativeStartup; installation retained"
$pgPort = docker compose -f docker-compose.yml port pgproxy 5432
Add-Check "docker-pgproxy-owns-project-port" ($pgPort -match '127\.0\.0\.1:5432') $pgPort

$readyEndpoints = [ordered]@{
  deception = 'http://127.0.0.1:8001/readyz'
  evidence = 'http://127.0.0.1:8011/readyz'
  ai_v1 = 'http://127.0.0.1:8010/readyz'
  llm_v2 = 'http://127.0.0.1:8013/readyz'
  sandbox = 'http://127.0.0.1:8012/readyz'
}
$notReady = @()
foreach ($entry in $readyEndpoints.GetEnumerator()) {
  try {
    $response = Invoke-RestMethod $entry.Value
    $ready = $response.ready -eq $true -or $response.status -eq 'ok'
    if (-not $ready) { $notReady += $entry.Key }
  } catch { $notReady += $entry.Key }
}
$readinessEvidence = if ($notReady.Count) { "not ready: $($notReady -join ',')" } else { "deception, evidence, AI v1/v2, sandbox ready" }
Add-Check "internal-analysis-services-ready" ($notReady.Count -eq 0) $readinessEvidence

$sessions = (Invoke-RestMethod 'http://127.0.0.1:8011/evidence/sessions?limit=100').sessions
$sourceHashes = @($sessions | Where-Object { $_.source_ip_hash } | Select-Object -ExpandProperty source_ip_hash -Unique)
$badHashes = @($sourceHashes | Where-Object { $_ -notmatch '^hmac-sha256:[a-f0-9]{24}$' })
Add-Check "stored-source-addresses-anonymized" ($sourceHashes.Count -gt 0 -and $badHashes.Count -eq 0) "$($sourceHashes.Count) unique stored source hashes use HMAC-SHA256"

$logText = (docker compose -f docker-compose.yml logs --no-color --tail 500 2>&1 | Out-String)
$secretNames = @('POSTGRES_PASSWORD', 'MYSQL_PASSWORD', 'MYSQL_ROOT_PASSWORD')
$exposedNames = @()
foreach ($name in $secretNames) {
  $value = Get-DotEnvValue $name
  if ($value.Length -ge 8 -and $logText.Contains($value)) { $exposedNames += $name }
}
$logEvidence = if ($exposedNames.Count) { "secret values found for: $($exposedNames -join ',')" } else { "no configured database secret values found in recent logs" }
Add-Check "recent-logs-do-not-contain-configured-db-secrets" ($exposedNames.Count -eq 0) $logEvidence

$before = Invoke-RestMethod 'http://127.0.0.1:9095/control/status'
$originalSafeMode = [bool]$before.control.safe_mode
$killSwitchPassed = $false
if ($originalSafeMode) {
  $killSwitchPassed = $true
} else {
  Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:9095/control/safe-mode' -ContentType 'application/json' `
    -Body '{"enabled":true,"actor":"predeploy-security-gate","reason":"bounded kill-switch validation"}' | Out-Null
  $enabled = Invoke-RestMethod 'http://127.0.0.1:9095/control/status'
  Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:9095/control/safe-mode' -ContentType 'application/json' `
    -Body '{"enabled":false,"actor":"predeploy-security-gate","reason":"restore automatic local baseline"}' | Out-Null
  $restored = Invoke-RestMethod 'http://127.0.0.1:9095/control/status'
  $killSwitchPassed = $enabled.control.safe_mode -eq $true -and $restored.control.safe_mode -eq $false
}
Add-Check "operator-kill-switch" $killSwitchPassed "safe mode enabled and original state restored"

$rules = Invoke-RestMethod 'http://127.0.0.1:9096/api/v1/rules?type=alert'
$ruleNames = @($rules.data.groups.rules.name)
$requiredAlerts = @('CapstoneReplicasAtMaxBudget', 'CapstoneAIAgentDown', 'CapstoneLLMAgentDown', 'CapstoneDLQIncreasing')
$missingAlerts = @($requiredAlerts | Where-Object { $_ -notin $ruleNames })
$alertEvidence = if ($missingAlerts.Count) { "missing: $($missingAlerts -join ',')" } else { $requiredAlerts -join ',' }
Add-Check "security-and-budget-alerts-loaded" ($missingAlerts.Count -eq 0) $alertEvidence

$failed = @($checks | Where-Object { -not $_.passed })
$failedNames = @($failed | ForEach-Object { $_.check })
[ordered]@{
  gate = if ($failed.Count -eq 0) { "PASS_LOCAL_PREDEPLOY" } else { "FAIL" }
  deployment_performed = $false
  public_exposure = $false
  checks_passed = $checks.Count - $failed.Count
  checks_total = $checks.Count
  failed_checks = $failedNames
  deployment_specific_pending = @(
    'cloud egress policy enforcement',
    'cloud budget alarm delivery',
    'public honeypot-only firewall validation',
    'provider kill-switch runbook validation'
  )
  checks = $checks
} | ConvertTo-Json -Depth 10
