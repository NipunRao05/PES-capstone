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
`REQUIRES_REVIEW`; the proposal producer itself has no review or registry/policy
write authority.

Phase 16 adds a bounded in-memory blue-team review store for valid Phase 15
proposals. Human reviewers may APPROVE, REJECT, MODIFY, or REQUEST_MORE_EVIDENCE.
APPROVE produces only `APPROVED_FOR_VALIDATION`; every result remains
non-deployable and registry-unapproved. Original proposals are immutable and the
store retains a proposal snapshot plus deterministic audit record. Restart
persistence remains Phase 24, and Phase 17 validation is not executed here.

Phase 17 adds `candidate-validation-v1`, a deterministic twelve-stage technical
and safety validator for intact `APPROVED_FOR_VALIDATION` review results. It
performs read-only registry collision checks and bounded metadata, SQL/schema,
synthetic-data, egress, protocol, state, trap, resource, and sandbox-applicability
checks. `VALIDATED` is never live approval: deployment, strategy activation, and
registry/policy mutation remain false. Metadata-only candidates use
`NOT_APPLICABLE` for sandbox execution; database-asset candidates fail closed as
`VALIDATION_INCOMPLETE` until a real isolated candidate-import contract exists.

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

Phase 16 reads a proposal or complete gap result as JSON on standard input:

~~~powershell
Get-Content proposal.json | docker run --rm -i --mount "type=bind,source=F:\b\Capstone-main\learning_agent,target=/app" -w /app capstone-main-session-module python review_main.py --input-kind proposal --reviewer blue-team-local --decision APPROVE --reason "Proceed to validation"
~~~

Phase 17 reads a complete proposal, Phase 16 approval, and candidate validation
envelope as JSON on standard input and reads the strategy registry through its
existing internal GET endpoint:

~~~powershell
Get-Content candidate-validation.json | docker run --rm -i --network capstone-main_default --mount "type=bind,source=F:\b\Capstone-main\learning_agent,target=/app" -w /app capstone-main-session-module python validation_main.py
~~~
