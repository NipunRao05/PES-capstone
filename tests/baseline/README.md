# Deterministic Baseline Regression

This bounded local harness captures the Phase 1 deterministic behavior through the real MySQL and PostgreSQL proxies. It validates protocol output, latency, evidence correlation, MITRE mapping, trap behavior, logical scaling decisions, and the AI Agent v1 brief. The trap case traverses depth-1 and depth-2 assets in one MySQL connection before accessing the depth-3 trap; a fresh-session trap guess is intentionally hidden.

Run from the repository root while the verified Compose stack is running:

```powershell
powershell -ExecutionPolicy Bypass -File tests\baseline\capture_baseline.ps1
```

The harness reads local development credentials from `.env`, prints one JSON result to stdout, does not print credentials, does not run a load test, and does not deploy or alter application code. Dynamic IDs, timestamps, synthetic values, and measured latency are observations; assertions are defined in `expected_baseline.json`.
