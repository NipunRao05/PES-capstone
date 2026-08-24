# Retrospective Learning Agent

Phase 13 is a deterministic, offline, read-only evaluator. It loads completed
strategy telemetry, reward vectors, and the approved strategy registry from the
existing internal services and emits one evidence-linked JSON analysis.

It does not train the live bandit, modify policy, activate strategies, connect
to databases, accept raw SQL, or control infrastructure. Similar-session
retrieval and counterfactual estimation remain Phase 14; gap detection and
proposal creation remain Phase 15.

Local Compose-network validation:

~~~powershell
docker run --rm --network capstone-main_default --mount "type=bind,source=F:\b\Capstone-main\learning_agent,target=/app" -w /app capstone-main-session-module python main.py SESSION_ID
~~~
