<#
Phase 2 bounded integration validation.
Runs one PostgreSQL and one MySQL session through the local proxies.
No load generation, external network, deployment, or production database access.
#>

[CmdletBinding()]
param(
    [string]$ComposeFile = "docker-compose.yml",
    [string]$StateApi = "http://127.0.0.1:8003",
    [int]$EvidenceWaitSeconds = 12
)

$ErrorActionPreference = "Stop"

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) {
        throw "ASSERTION FAILED: $Message"
    }
}

function Get-ProjectedSession {
    param([string]$ObjectName, [string]$Protocol, [int]$MinVerified)

    $deadline = (Get-Date).AddSeconds($EvidenceWaitSeconds)
    do {
        $payload = Invoke-RestMethod "$StateApi/state/sessions?limit=250"
        $match = $payload.sessions |
            Where-Object {
                $_.protocol -eq $Protocol -and
                ($_.dropped_objects -contains $ObjectName) -and
                ($_.outcome_verified_count -ge $MinVerified) -and
                ($_.failed_query_count -ge 1)
            } |
            Select-Object -First 1
        if ($null -ne $match) {
            return $match
        }
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $deadline)

    throw "No projected $Protocol session found for $ObjectName"
}

$running = docker compose -f $ComposeFile ps --status running --services
foreach ($service in @("postgres", "mysql", "pgproxy", "mysqlproxy", "session-module", "redpanda")) {
    Assert-True ($running -contains $service) "required service is not running: $service"
}
$ready = Invoke-RestMethod "$StateApi/readyz"
Assert-True ($ready.ready -eq $true) "authoritative state API is not ready"

$suffix = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
$pgTable = "phase2_pg_$suffix"
$pgRolled = "phase2_rb_$suffix"
$pgRole = "phase2_reader_$suffix"
$myTable = "phase2_my_$suffix"

$pgShell = 'PGPASSWORD="$POSTGRES_PASSWORD" psql -h pgproxy -p 5432 -U postgres -d testdb -v ON_ERROR_STOP=0 -At ' +
    ('-c "CREATE TABLE {0} (id integer PRIMARY KEY, name text)" ' -f $pgTable) +
    ('-c "INSERT INTO {0} VALUES (1, ''before'')" ' -f $pgTable) +
    ('-c "SELECT name FROM {0} WHERE id=1" ' -f $pgTable) +
    ('-c "UPDATE {0} SET name=''after'' WHERE id=1" ' -f $pgTable) +
    ('-c "SELECT name FROM {0} WHERE id=1" ' -f $pgTable) +
    '-c "BEGIN" ' +
    ('-c "CREATE TABLE {0} (id integer)" ' -f $pgRolled) +
    '-c "ROLLBACK" ' +
    ('-c "SELECT to_regclass(''public.{0}'') IS NULL" ' -f $pgRolled) +
    ('-c "CREATE ROLE {0} NOLOGIN" ' -f $pgRole) +
    ('-c "GRANT SELECT ON {0} TO {1}" ' -f $pgTable, $pgRole) +
    ('-c "SET ROLE {0}" ' -f $pgRole) +
    ('-c "SELECT count(*) FROM {0}" ' -f $pgTable) +
    '-c "RESET ROLE" ' +
    ('-c "REVOKE SELECT ON {0} FROM {1}" ' -f $pgTable, $pgRole) +
    ('-c "DROP ROLE {0}" ' -f $pgRole) +
    ('-c "SELECT table_name FROM information_schema.tables WHERE table_name=''{0}''" ' -f $pgTable) +
    ('-c "DROP TABLE {0}" ' -f $pgTable) +
    ('-c "SELECT * FROM {0}"' -f $pgTable)

$pgOutput = (docker compose -f $ComposeFile exec -T postgres sh -lc $pgShell 2>&1) -join [Environment]::NewLine
$pgExit = $LASTEXITCODE
Assert-True ($pgExit -ne 0) "PostgreSQL SELECT after DROP should fail"
Assert-True ($pgOutput -match "(?m)^before\r?$") "PostgreSQL INSERT to SELECT failed"
Assert-True ($pgOutput -match "(?m)^after\r?$") "PostgreSQL UPDATE to SELECT failed"
Assert-True ($pgOutput -match "(?m)^t\r?$") "PostgreSQL rollback did not remove the transactional table"
Assert-True ($pgOutput -match "does not exist") "PostgreSQL DROP failure evidence missing"

$myQuery = "CREATE TABLE $myTable (id INT PRIMARY KEY, name VARCHAR(40)); " +
    "INSERT INTO $myTable VALUES (1,'before'); " +
    "SELECT name FROM $myTable WHERE id=1; " +
    "UPDATE $myTable SET name='after' WHERE id=1; " +
    "SELECT name FROM $myTable WHERE id=1; " +
    "START TRANSACTION; INSERT INTO $myTable VALUES (2,'rollback'); ROLLBACK; " +
    "SELECT COUNT(*) FROM $myTable; SHOW COLUMNS FROM $myTable; " +
    "DROP TABLE $myTable; SELECT * FROM $myTable;"
$myShell = 'mysql --force -h mysqlproxy -P 3306 -uroot -p"$MYSQL_ROOT_PASSWORD" -N testdb -e "' + $myQuery + '"'
$myOutput = (docker compose -f $ComposeFile exec -T mysql sh -lc $myShell 2>&1) -join [Environment]::NewLine
$myExit = $LASTEXITCODE
Assert-True ($myExit -ne 0) "MySQL SELECT after DROP should fail"
Assert-True ($myOutput -match "(?m)^before\r?$") "MySQL INSERT to SELECT failed"
Assert-True ($myOutput -match "(?m)^after\r?$") "MySQL UPDATE to SELECT failed"
Assert-True ($myOutput -match "(?m)^1\r?$") "MySQL rollback count is not one"
Assert-True ($myOutput -match "(?m)^id\s+int") "MySQL schema discovery evidence missing"
Assert-True ($myOutput -match "doesn't exist") "MySQL DROP failure evidence missing"

$pgState = Get-ProjectedSession -ObjectName $pgTable -Protocol "postgres" -MinVerified 18
$myState = Get-ProjectedSession -ObjectName $myTable -Protocol "mysql" -MinVerified 12

$requiredFields = @(
    "session_id", "protocol", "persona_id", "strategy_id", "schema_version",
    "database", "user", "role", "permissions", "transaction_state",
    "visible_databases", "visible_tables", "visible_columns", "created_objects",
    "modified_objects", "dropped_objects", "discovered_objects", "triggered_traps",
    "mitre_stage", "risk_score", "query_count", "session_depth", "strategy_history"
)
foreach ($field in $requiredFields) {
    Assert-True ($pgState.PSObject.Properties.Name -contains $field) "missing state field: $field"
}

Assert-True ($pgState.outcome_verified_count -ge 18) "PostgreSQL confirmed outcome count is incomplete"
Assert-True ($pgState.unverified_query_count -eq 0) "PostgreSQL simple-query session contains unverified events"
Assert-True ($pgState.failed_query_count -eq 1) "PostgreSQL failed query was not recorded exactly once"
Assert-True ($pgState.transaction_state -eq "idle") "PostgreSQL transaction did not return to idle"
Assert-True ($pgState.role -eq "postgres") "PostgreSQL role did not reset"
Assert-True ($pgState.dropped_objects -contains $pgTable) "PostgreSQL DROP was not projected"
Assert-True (-not ($pgState.visible_tables -contains $pgTable)) "Dropped PostgreSQL table remains visible"
Assert-True (-not ($pgState.visible_tables -contains $pgRolled)) "Rolled-back PostgreSQL table remains visible"
Assert-True (-not ($pgState.visible_tables -contains $pgRole)) "Role was misclassified as a table"

Assert-True ($myState.outcome_verified_count -ge 12) "MySQL confirmed outcome count is incomplete"
Assert-True ($myState.unverified_query_count -eq 0) "MySQL text-query session contains unverified events"
Assert-True ($myState.failed_query_count -eq 1) "MySQL failed query was not recorded exactly once"
Assert-True ($myState.transaction_state -eq "idle") "MySQL transaction did not return to idle"
Assert-True ($myState.dropped_objects -contains $myTable) "MySQL DROP was not projected"
Assert-True (-not ($myState.visible_tables -contains $myTable)) "Dropped MySQL table remains visible"

[pscustomobject]@{
    status = "PASS"
    postgres_session_id = $pgState.session_id
    mysql_session_id = $myState.session_id
    postgres_verified_outcomes = $pgState.outcome_verified_count
    mysql_verified_outcomes = $myState.outcome_verified_count
    postgres_failed_queries = $pgState.failed_query_count
    mysql_failed_queries = $myState.failed_query_count
    transaction_validation = "PASS"
    role_permission_validation = "PASS"
    schema_discovery_validation = "PASS"
    state_consistency_validation = "PASS"
} | ConvertTo-Json -Depth 4
exit 0
