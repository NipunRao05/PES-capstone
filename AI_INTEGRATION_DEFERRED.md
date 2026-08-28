# AI Integration Deferred Checkpoint

Date: 2026-08-28

## Operator decision

Local generative-model execution is deferred while the non-AI roadmap continues.
Downstream phases may rely on the already implemented Phase 18/19 bounded client,
schema, validator, candidate-validation, and nondeployable authority contracts.
They must not claim that the deferred model-quality benchmark passed.

## Preserved evidence

- Qwen2.5 1.5B remained safely contained: malformed output was rejected after the
  one permitted structural repair, and no candidate database asset was executed.
- The Ornith 9B fixed benchmark was interrupted before completion after severe
  host instability. It produced no aggregate acceptance result.
- Phase 19 generated assets still require deterministic Phase 17 validation and
  human approval before any future promotion.

## Rules for subsequent phases

- Do not start `local-llm`, Ornith, Qwen, or another model as part of Phases
  20-22 or other AI-independent work.
- Use deterministic fixtures only when a downstream test needs a schema-valid AI
  or proposal artifact.
- Keep all AI-originated content offline, nondeployable, and outside the live SQL
  response path.
- Preserve model/runtime/settings evidence fields so a future model can be added
  without changing downstream contracts.
- Continue to fail closed on malformed, unsafe, sensitive, or cross-session
  generated content.

## Deferred acceptance work

Before claiming the live generative integration itself is accepted, run a
resource-safe model benchmark on suitable hardware and record:

- exact model digest and runtime version;
- fixed request set and reproducible settings;
- first-pass schema-valid rate and bounded-repair rate;
- deterministic rejection and safety results;
- latency, CPU, peak memory, storage, and host-stability measurements;
- proof that generated content never bypasses Phase 17 validation or human review.

This deferral does not block evidence storage, replay, hardening, persistence,
idempotency, operator controls, observability, or other deterministic phases.
Phase 23's optional LLM narrative and the dedicated model-feasibility experiment
remain deferred until a safe model runtime is available.
