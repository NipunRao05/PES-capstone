import copy
import json
import threading
import time
import unittest

from local_llm.semantic_client import SemanticLLMClient, SemanticLLMConfig
from local_llm.semantic_contract import ORNITH_MODEL, SEMANTIC_PROPOSAL_JSON_SCHEMA, SEMANTIC_SEED


def configured(**overrides):
    values = {
        "enabled": True, "base_url": "http://127.0.0.1:11434", "model": ORNITH_MODEL,
        "timeout_seconds": 1.0, "max_prompt_chars": 4096, "max_output_tokens": 512,
        "context_length": 4096, "max_concurrency": 1, "max_queue_depth": 2,
        "keep_alive": "5m", "seed": SEMANTIC_SEED,
    }
    values.update(overrides)
    return SemanticLLMConfig(**values)


class FakeClient(SemanticLLMClient):
    def __init__(self, config=None, mode="ok", gate=None):
        super().__init__(config or configured())
        self.mode = mode
        self.gate = gate
        self.calls = []

    def _request_json(self, method, path, payload, timeout):
        self.calls.append((method, path, copy.deepcopy(payload), timeout))
        if self.mode == "unavailable":
            raise RuntimeError("UNAVAILABLE")
        if self.gate is not None and path == "/api/generate":
            self.gate.wait(2)
        if path == "/api/version":
            return {"version": "0.32.5"}
        if path == "/api/tags":
            return {"models": [{"name": ORNITH_MODEL, "size": 6_600_000_000}]}
        if path == "/api/show":
            return {"details": {"format": "gguf", "family": "qwen35", "parameter_size": "8.95B", "quantization_level": "Q4_K_M"}}
        if path == "/api/ps":
            return {"models": [{"name": ORNITH_MODEL, "size": 7_100_000_000, "size_vram": 0}]}
        if path == "/api/generate":
            text = json.dumps({"proposal_name": "Safe Proposal"})
            if self.mode == "think_tag":
                text = "<think>private</think>" + text
            return {
                "model": ORNITH_MODEL, "response": text, "thinking": "discard me",
                "done": True, "total_duration": 10_000_000, "load_duration": 1_000_000,
                "eval_duration": 5_000_000, "prompt_eval_count": 100, "eval_count": 20,
            }
        raise AssertionError(path)


class SemanticConfigTests(unittest.TestCase):
    def test_exact_bounded_profile_loads(self):
        value = SemanticLLMConfig.from_env({
            "SEMANTIC_LLM_ENABLED": "true", "SEMANTIC_LLM_URL": "http://local-llm:11434",
            "SEMANTIC_LLM_MODEL": ORNITH_MODEL, "SEMANTIC_LLM_TIMEOUT_SECONDS": "300",
            "SEMANTIC_LLM_MAX_OUTPUT_TOKENS": "512", "SEMANTIC_LLM_CONTEXT": "4096",
            "SEMANTIC_LLM_MAX_CONCURRENCY": "1", "SEMANTIC_LLM_MAX_QUEUE_DEPTH": "2",
            "SEMANTIC_LLM_KEEP_ALIVE": "5m", "SEMANTIC_LLM_SEED": str(SEMANTIC_SEED),
        })
        self.assertEqual(value.model, ORNITH_MODEL)
        self.assertEqual(value.context_length, 4096)

    def test_invalid_model_url_and_unbounded_profile_fail_closed(self):
        for field, value in (
            ("SEMANTIC_LLM_MODEL", "ornith-1.5:35b"),
            ("SEMANTIC_LLM_URL", "https://external.example.com:11434"),
            ("SEMANTIC_LLM_TIMEOUT_SECONDS", "301"),
            ("SEMANTIC_LLM_CONTEXT", "256000"),
            ("SEMANTIC_LLM_MAX_OUTPUT_TOKENS", "769"),
            ("SEMANTIC_LLM_MAX_CONCURRENCY", "2"),
            ("SEMANTIC_LLM_MAX_QUEUE_DEPTH", "3"),
            ("SEMANTIC_LLM_KEEP_ALIVE", "-1"),
        ):
            with self.subTest(field=field), self.assertRaises(ValueError):
                SemanticLLMConfig.from_env({field: value})


class SemanticClientTests(unittest.TestCase):
    def test_disabled_mode_never_contacts_runtime(self):
        client = FakeClient(configured(enabled=False), mode="unavailable")
        self.assertEqual(client.ready()["status"], "DISABLED")
        self.assertEqual(client.generate_structured("safe prompt")["status"], "DISABLED")
        self.assertEqual(client.calls, [])

    def test_readiness_and_metadata_are_model_specific(self):
        client = FakeClient()
        self.assertEqual(client.ready()["status"], "READY")
        metadata = client.model_metadata()
        self.assertEqual(metadata["parameter_class"], "8.95B")
        self.assertEqual(metadata["quantization"], "Q4_K_M")
        snapshot = client.resource_snapshot()
        self.assertEqual(snapshot["loaded_size_bytes"], 7_100_000_000)
        self.assertTrue(snapshot["cpu_only_observed"])

    def test_structured_request_uses_fixed_schema_sampling_and_no_thinking(self):
        client = FakeClient()
        result = client.generate_structured("Return bounded JSON.")
        self.assertEqual(result["status"], "OK")
        self.assertTrue(result["schema_constraint_active"])
        self.assertTrue(result["reasoning_discarded"])
        self.assertNotIn("thinking", result)
        body = next(call[2] for call in client.calls if call[1] == "/api/generate")
        self.assertEqual(body["format"], SEMANTIC_PROPOSAL_JSON_SCHEMA)
        self.assertIs(body["think"], False)
        self.assertEqual(body["keep_alive"], "5m")
        self.assertEqual(body["options"], {
            "num_predict": 512, "num_ctx": 4096, "num_gpu": 0,
            "temperature": 0.6, "top_p": 0.95, "top_k": 20, "min_p": 0.0,
            "presence_penalty": 0.0, "repeat_penalty": 1.0, "seed": SEMANTIC_SEED,
        })

    def test_reasoning_tags_in_final_content_fail_closed(self):
        self.assertEqual(FakeClient(mode="think_tag").generate_structured("safe")["status"], "INVALID_OUTPUT")

    def test_unavailable_and_oversized_prompt_are_bounded(self):
        self.assertEqual(FakeClient(mode="unavailable").generate_structured("safe")["status"], "UNAVAILABLE")
        client = FakeClient(configured(max_prompt_chars=10))
        self.assertEqual(client.generate_structured("x" * 11)["status"], "INVALID_REQUEST")
        self.assertEqual(client.calls, [])

    def test_queue_admission_rejects_only_excess(self):
        gate = threading.Event()
        client = FakeClient(configured(max_concurrency=1, max_queue_depth=2), gate=gate)
        results = []
        threads = [threading.Thread(target=lambda: results.append(client.generate_structured("safe"))) for _ in range(3)]
        for thread in threads:
            thread.start()
        while len(client.calls) < 1:
            time.sleep(0.005)
        time.sleep(0.02)
        self.assertEqual(client.generate_structured("excess")["status"], "QUEUE_FULL")
        gate.set()
        for thread in threads:
            thread.join(1)
        self.assertEqual(len(results), 3)


if __name__ == "__main__":
    unittest.main()
