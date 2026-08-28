# Phase 19.1 Interrupted Benchmark Checkpoint

Checkpoint date: 2026-08-27

Repository: `F:\b\Capstone-main`

Branch / HEAD: `main` / `1c938e47b52ef133c6f4f26fc4449673f41ff2dc`

Status: **INCOMPLETE / INTERRUPTED**

This is a cleanup and preservation checkpoint. It is not a benchmark pass, a
benchmark fail, or an Ornith failure. Phase 19.1 overall acceptance is not yet
complete, and Phase 20 was not started.

## Verified prerequisites and implementation evidence

```text
Phase 19.0 resource preflight        VERIFIED
Ornith local provisioning            VERIFIED
Ornith runtime isolation             VERIFIED
Focused Phase 19.1 tests             VERIFIED (18/18)
Preliminary CPU/RAM feasibility      VERIFIED from observed cases
10-case quality benchmark            INCOMPLETE / INTERRUPTED
Phase 19.1 overall acceptance        NOT YET COMPLETE
```

The focused suite was:

```text
python -m unittest -v local_llm.test_semantic_client
                          decoy_generation_agent.test_semantic_proposal
18/18 PASS
```

No large/full regression suite was run during cleanup.

## Provisioned model evidence

```text
model tag             ornith-1.5:9b
runtime model ID      e5df7dcdd8a2
full manifest SHA-256 e5df7dcdd8a263994df62d610317e07be0d6af23f96fcbd8543273058fce575e
architecture          qwen35
parameters            9.0B
quantization          Q4_K_M
stored path           H:\Capstone-main-data\ollama-ornith-1.5
stored files          7
stored bytes          6,550,815,695
```

The manifest references a 5,629,109,056-byte model layer and a
921,704,448-byte projector layer. The H:-backed files remain present after the
runtime was stopped. The preserved Phase 18 Qwen named volume was not changed.

## Verified runtime boundary

Before the benchmark, live Docker inspection confirmed:

```text
network               capstone-main_local-llm-internal
published host ports  none
model mount           H: bind mounted read-only (`RW=false`)
container rootfs      read-only
memory cap            9 GiB (9,663,676,416 bytes)
CPU cap               4 logical CPUs
parallel inference    1
queue depth           2
context               4096
maximum output        512
keep-alive            5m
client timeout        300 seconds
runtime health        healthy before interruption
```

The runtime container `capstone-local-llm` was stopped, not removed. Stopping it
unloaded the model without deleting or modifying the H:-backed model store.

## Interrupted benchmark evidence

The first wrapper attempt stopped before inference because the disposable
session-module image lacked PyYAML. The wrapper was changed to use the existing
deception-engine image after PyYAML 6.0.1 was verified locally. No dependency was
downloaded and no validator, schema, sampling setting, repair rule, or model tag
was changed.

The fixed benchmark then progressed sequentially as follows:

| Case | State at interruption | Durable quality result |
|---|---|---|
| 1 | invocation completed | not captured because the wrapper writes only the final ten-case aggregate |
| 2 | invocation completed; its one allowed fresh repair was observed | not captured because the wrapper writes only the final ten-case aggregate |
| 3 | inference had started; disposable client was stopped during cleanup | no completed result |
| 4-10 | not attempted | none |

Exact count:

```text
benchmark cases attempted   3
benchmark cases completed   2
benchmark cases interrupted 1
benchmark cases not started 7
```

No `PHASE_19_1_BENCHMARK.json` aggregate existed at cleanup time, so no result
file was deleted or overwritten. The stopped `capstone-local-llm` container was
preserved with its Ollama server logs. Observed preliminary resource evidence:

```text
generation throughput      approximately 3.9 tokens/second
container CPU              approximately 368-375%
loaded/active RAM           approximately 6.7-6.95 GiB
```

These measurements establish preliminary fit inside the selected 4-CPU/9-GiB
profile only. They do not establish proposal quality or complete Phase 19.1.

## Cleanup record

```text
benchmark parent process   interrupted; cannot start another case
disposable client          nervous_kapitsa stopped; auto-removed by --rm
Ornith runtime             capstone-local-llm stopped; container preserved
unrelated honeypot stack   left running
model files                retained on H:
commit                     none
push                       none
Phase 20                   not started
```

Resume Phase 19.1 later from the fixed ten-case benchmark. Do not characterize
the interrupted run as PASS, FAIL, or an Ornith failure, and do not infer results
for cases that did not complete.
