# Offline Learning and Policy-Improvement Analysis

Phase 13 is a deterministic, offline, read-only evaluator. It loads completed
strategy telemetry, reward vectors, and the approved strategy registry from the
existing internal services and emits one evidence-linked JSON analysis.

It does not train the live bandit, modify policy, activate strategies, connect
to databases, accept raw SQL, or control infrastructure. Similar-session
Phase 14 adds deterministic normalized-context nearest-neighbor retrieval and
observational estimates for alternatives that were both allowed for the target
decision and actually selected in comparable completed sessions. Every estimate
includes uncertainty, evidence confidence, and supporting session/decision IDs.
It never makes a causal claim or a composite better/worse ranking while reward
weights remain uncalibrated.

Phase 15 adds deterministic action-space gap classification. It distinguishes
`ACTION_SPACE_GAP`, `NO_GAP_DETECTED`, and `INSUFFICIENT_EVIDENCE`. A proposal
requires a recurring coherent unmodeled behavior pattern, comparable completed
history, repeated weak safe outcomes, and evidence across multiple existing
strategies. Proposals are structured, deterministic, non-deployable, and marked
`REQUIRES_REVIEW`; no Phase 16 review workflow or registry/policy write exists.

Local Compose-network validation:

~~~powershell
docker run --rm --network capstone-main_default --mount "type=bind,source=F:\b\Capstone-main\learning_agent,target=/app" -w /app capstone-main-session-module python main.py SESSION_ID
~~~

Phase 14 analysis uses only existing internal read-only endpoints:

~~~powershell
docker run --rm --network capstone-main_default --mount "type=bind,source=F:\b\Capstone-main\learning_agent,target=/app" -w /app capstone-main-session-module python counterfactual_main.py SESSION_ID
~~~

Phase 15 gap classification:

~~~powershell
docker run --rm --network capstone-main_default --mount "type=bind,source=F:\b\Capstone-main\learning_agent,target=/app" -w /app capstone-main-session-module python gap_main.py SESSION_ID
~~~
