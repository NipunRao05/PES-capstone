# Controlled Local Calibration Report

Date: 2026-08-21  
Run ID: `cal-1787306550-2d1e0c`  
Scope: local Docker honeypot only; no deployment, internet exposure, or long load test.

## Result

| Measure | Result |
|---|---:|
| Workload cases executed | 13/13 |
| Evidence records correlated | 13/13 |
| Benign cases classified LOW | 5/5 |
| Recon cases classified MEDIUM with `T1213.006` | 3/3 |
| Trap cases classified CRITICAL with `T1213.006` | 5/5 |
| False positives / false negatives | 0 / 0 |
| Precision / recall / F1 | 1.000 / 1.000 / 1.000 |
| Client-observed latency p50 / p95 / p99 | 174.10 / 350.97 / 350.97 ms |
| Four-connection mixed burst wall time | 1301.60 ms |
| Evidence-store Kafka lag after run | 0 |
| Trap counter before / after | 11 / 16 |
| Logical replica target before / after | 4 / 6 |

The matrix covered PostgreSQL and MySQL benign queries, metadata reconnaissance,
trap-table access, mixed benign/trap traffic, and a bounded four-connection burst.

## AI and resource snapshot

For trap session `6b301da6-c671-4ab9-b7ad-60750212c8f7`:

- deterministic evidence risk: CRITICAL;
- AI Agent v1 response: HIGH in 37.42 ms;
- bounded AI v2 response: CRITICAL in 16.47 ms;
- AI v2 report link completed the evidence trace;
- repeated AI v2 generation produced stable report ID
  `llm-local-70cc155d5282183bf2a4f9be`.

The post-run point-in-time container snapshot stayed small: proxies used under
9 MiB each, scaling-agent about 12 MiB, MITRE agent about 47 MiB,
evidence-store about 48 MiB, and the bounded report agent about 36 MiB. This is
a functional calibration snapshot, not a capacity benchmark.

## Reliability finding fixed during calibration

The first run exposed a malformed historical Kafka value that caused the
evidence-store consumer to repeatedly rebalance. The consumer now decodes each
record defensively, skips malformed/non-object values without logging payload
contents, closes failed consumers, and continues ingestion. Unit validation is
8/8 passing; the consumer group subsequently remained `Stable` with one member
and zero lag.

## Interpretation limits

The perfect classification values apply only to this small controlled matrix.
They are evidence that the implemented paths behave correctly, not a claim of
general real-world detection accuracy. Longer-duration and internet-derived
measurements remain deliberately deferred until the deployment security gate is
approved.
