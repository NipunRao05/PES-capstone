"""Run the bounded Phase 18 synthetic-prompt benchmark."""

from __future__ import annotations

import json
import statistics
import sys

try:
    from .client import LocalLLMClient
except ImportError:
    from client import LocalLLMClient


PROMPTS = (
    "Return JSON containing three fictional database names.",
    "Summarize this synthetic security event in one sentence: a fake backup table was listed.",
    "Generate three fictional table names for a fake logistics company.",
)


def main() -> int:
    client = LocalLLMClient()
    health = client.health()
    ready = client.ready()
    model = client.model_metadata()
    results = [client.generate(prompt, max_tokens=64, temperature=0.2) for prompt in PROMPTS]
    passed = all(item.get("status") == "OK" for item in results)
    latencies = [float(item["latency_ms"]) for item in results if item.get("status") == "OK"]
    output = {
        "benchmark_version": "local-llm-benchmark-v1",
        "synthetic_prompts_only": True,
        "health": health,
        "readiness": ready,
        "model": model,
        "results": results,
        "summary": {
            "status": "PASS" if passed else "FAIL",
            "request_count": len(results),
            "completed_count": len(latencies),
            "first_latency_ms": latencies[0] if latencies else None,
            "warm_latency_ms_median": statistics.median(latencies[1:]) if len(latencies) > 1 else None,
            "generated_tokens": sum(int(item.get("generated_tokens") or 0) for item in results),
        },
    }
    print(json.dumps(output, sort_keys=True, separators=(",", ":"), allow_nan=False))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
