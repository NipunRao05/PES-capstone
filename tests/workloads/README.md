# Phase 10 controlled workloads

This offline generator creates deterministic synthetic workload plans. It does
not connect to MySQL/PostgreSQL, open a network connection, execute SQL, contact
source systems, or contain real identities/credentials.

Validate 1,000 generated sessions in memory:

python scripts\controlled_workloads.py validate --count 1000 --seed 20260824

Generate a JSONL plan at an explicitly chosen new path:

python scripts\controlled_workloads.py generate --count 1000 --seed 20260824 --output controlled-workloads.jsonl

Generation refuses to overwrite an existing file. Every statement is labeled
DECOY_ONLY or SIMULATE_ONLY; destructive intent is always SIMULATE_ONLY. A future
runner must enforce those labels and may target only the local controlled decoy.

Unit validation:

python -m unittest discover -s tests\workloads -p test_*.py
