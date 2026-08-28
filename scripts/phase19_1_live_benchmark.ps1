param(
    [Parameter(Mandatory = $true)]
    [string]$OutputPath
)

$ErrorActionPreference = "Stop"
$pythonImage = "capstone-main-deception-engine"
$network = "capstone-main_local-llm-internal"
$llmContainer = "capstone-local-llm"
$repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

function Convert-ToMiB([string]$value) {
    $number = [double]([regex]::Match($value, '[0-9.]+').Value)
    if ($value -match 'GiB') { return $number * 1024 }
    if ($value -match 'MiB') { return $number }
    if ($value -match 'KiB') { return $number / 1024 }
    return 0
}

$records = @()
for ($index = 0; $index -lt 10; $index++) {
    $job = Start-Job -ScriptBlock {
        param($image, $networkName, $repoPath, $caseIndex)
        docker run --rm --network $networkName `
            --mount "type=bind,source=$repoPath,target=/app,readonly" `
            -w /app `
            -e SEMANTIC_LLM_ENABLED=true `
            -e SEMANTIC_LLM_URL=http://local-llm:11434 `
            -e SEMANTIC_LLM_MODEL=ornith-1.5:9b `
            -e SEMANTIC_LLM_TIMEOUT_SECONDS=300 `
            -e SEMANTIC_LLM_CONTEXT=4096 `
            -e SEMANTIC_LLM_MAX_OUTPUT_TOKENS=512 `
            -e SEMANTIC_LLM_MAX_CONCURRENCY=1 `
            -e SEMANTIC_LLM_MAX_QUEUE_DEPTH=2 `
            -e SEMANTIC_LLM_KEEP_ALIVE=5m `
            $image python -m decoy_generation_agent.semantic_live_validation --case-index $caseIndex
    } -ArgumentList $pythonImage, $network, $repo, $index

    $peakCpu = 0.0
    $peakMemoryMiB = 0.0
    while ($job.State -in @("NotStarted", "Running")) {
        $sample = docker stats $llmContainer --no-stream --format "{{.CPUPerc}}|{{.MemUsage}}"
        if ($sample) {
            $parts = $sample -split '\|'
            $cpu = [double](($parts[0] -replace '%', '').Trim())
            $used = (($parts[1] -split '/')[0]).Trim()
            $peakCpu = [math]::Max($peakCpu, $cpu)
            $peakMemoryMiB = [math]::Max($peakMemoryMiB, (Convert-ToMiB $used))
        }
        Start-Sleep -Milliseconds 750
        $job = Get-Job -Id $job.Id
    }
    $raw = (Receive-Job -Job $job | Select-Object -Last 1)
    Remove-Job -Job $job
    $record = $raw | ConvertFrom-Json
    $record | Add-Member -NotePropertyName peak_container_cpu_percent -NotePropertyValue ([math]::Round($peakCpu, 2))
    $record | Add-Member -NotePropertyName peak_container_memory_mib -NotePropertyValue ([math]::Round($peakMemoryMiB, 2))
    $records += $record
}

$latencies = @($records | ForEach-Object { [double]$_.latency_ms } | Sort-Object)
$median = if ($latencies.Count % 2 -eq 0) {
    ($latencies[$latencies.Count / 2 - 1] + $latencies[$latencies.Count / 2]) / 2
} else {
    $latencies[[math]::Floor($latencies.Count / 2)]
}
$summary = [ordered]@{
    benchmark_version = "semantic-proposal-benchmark-v1"
    fixed_case_count = $records.Count
    schema_conforming_count = @($records | Where-Object schema_conforming).Count
    semantic_pass_count = @($records | Where-Object { $_.semantic_validator -eq "PASS" }).Count
    safety_pass_count = @($records | Where-Object { $_.safety_validator -eq "PASS" }).Count
    repair_count = @($records | Where-Object repair_used).Count
    median_latency_ms = [math]::Round($median, 3)
    worst_latency_ms = [math]::Round(($latencies | Measure-Object -Maximum).Maximum, 3)
    peak_container_cpu_percent = [math]::Round(($records.peak_container_cpu_percent | Measure-Object -Maximum).Maximum, 2)
    peak_container_memory_mib = [math]::Round(($records.peak_container_memory_mib | Measure-Object -Maximum).Maximum, 2)
    records = $records
}
$json = $summary | ConvertTo-Json -Depth 20
[IO.File]::WriteAllText((Join-Path $repo $OutputPath), $json + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
$json
