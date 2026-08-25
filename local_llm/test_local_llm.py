import copy
import hashlib
import threading
import time
import unittest
from pathlib import Path

from client import LocalLLMClient
from config import LocalLLMConfig, MODEL_NAME


ROOT = Path(__file__).resolve().parents[1]


def configured(**overrides):
    values = {
        "enabled": True,
        "base_url": "http://127.0.0.1:11434",
        "model": MODEL_NAME,
        "timeout_seconds": 1.0,
        "max_prompt_chars": 256,
        "max_output_tokens": 128,
        "max_concurrency": 1,
        "max_queue_depth": 1,
    }
    values.update(overrides)
    return LocalLLMConfig(**values)


class FakeClient(LocalLLMClient):
    def __init__(self, config=None, *, mode="ok", gate=None):
        super().__init__(config or configured())
        self.mode = mode
        self.gate = gate
        self.calls = []

    def _request_json(self, method, path, payload, timeout):
        self.calls.append((method, path, copy.deepcopy(payload), timeout))
        if self.mode == "timeout" and path == "/api/generate":
            raise RuntimeError("TIMEOUT")
        if self.mode == "unavailable":
            raise RuntimeError("UNAVAILABLE")
        if self.gate is not None and path == "/api/generate":
            self.gate.wait(2)
        if path == "/api/version":
            return {"version": "0.32.5"}
        if path == "/api/tags":
            return {"models": [{"name": MODEL_NAME, "size": 986_000_000}]}
        if path == "/api/show":
            return {"details": {
                "format": "gguf", "family": "qwen2", "parameter_size": "1.5B",
                "quantization_level": "Q4_K_M",
            }}
        if path == "/api/generate":
            if self.mode == "invalid":
                return {"model": MODEL_NAME, "response": "", "done": False}
            count = min(payload["options"]["num_predict"], 8)
            return {
                "model": MODEL_NAME,
                "response": "Synthetic bounded response.",
                "done": True,
                "total_duration": 10_000_000,
                "load_duration": 1_000_000,
                "eval_count": count,
            }
        raise AssertionError(path)


class LocalLLMConfigTests(unittest.TestCase):
    def test_valid_configuration_loads(self):
        value = LocalLLMConfig.from_env({
            "LOCAL_LLM_ENABLED": "true",
            "LOCAL_LLM_URL": "http://local-llm:11434",
            "LOCAL_LLM_MODEL": MODEL_NAME,
            "LOCAL_LLM_TIMEOUT_SECONDS": "30",
            "LOCAL_LLM_MAX_PROMPT_CHARS": "4096",
            "LOCAL_LLM_MAX_OUTPUT_TOKENS": "128",
            "LOCAL_LLM_MAX_CONCURRENCY": "1",
            "LOCAL_LLM_MAX_QUEUE_DEPTH": "2",
        })
        self.assertTrue(value.enabled)
        self.assertEqual(value.model, MODEL_NAME)

    def test_invalid_bounds_urls_and_models_fail_closed(self):
        mutations = (
            ("LOCAL_LLM_ENABLED", "maybe"),
            ("LOCAL_LLM_URL", "https://external.example.com:11434"),
            ("LOCAL_LLM_MODEL", "cloud-model"),
            ("LOCAL_LLM_TIMEOUT_SECONDS", "nan"),
            ("LOCAL_LLM_MAX_PROMPT_CHARS", "0"),
            ("LOCAL_LLM_MAX_OUTPUT_TOKENS", "513"),
            ("LOCAL_LLM_MAX_CONCURRENCY", "3"),
            ("LOCAL_LLM_MAX_QUEUE_DEPTH", "9"),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    LocalLLMConfig.from_env({field: value})


class LocalLLMClientTests(unittest.TestCase):
    def test_disabled_mode_never_contacts_runtime(self):
        client = FakeClient(configured(enabled=False), mode="unavailable")
        self.assertEqual(client.health()["status"], "DISABLED")
        self.assertEqual(client.ready()["status"], "DISABLED")
        self.assertEqual(client.generate("synthetic prompt")["status"], "DISABLED")
        self.assertEqual(client.calls, [])

    def test_health_readiness_and_model_metadata(self):
        client = FakeClient()
        self.assertEqual(client.health()["status"], "OK")
        self.assertEqual(client.ready()["status"], "READY")
        metadata = client.model_metadata()
        self.assertEqual(metadata["status"], "OK")
        self.assertEqual(metadata["parameter_class"], "1.5B")
        self.assertEqual(metadata["quantization"], "Q4_K_M")
        self.assertTrue(metadata["cpu_only_required"])

    def test_bounded_generation_succeeds_and_is_untrusted(self):
        result = FakeClient().generate("Return three fictional database names.", 16, 0.2)
        self.assertEqual(result["status"], "OK")
        self.assertLessEqual(result["generated_tokens"], 16)
        self.assertFalse(result["trusted"])
        self.assertTrue(result["request_id"].startswith("LLMREQ-"))

    def test_invalid_requests_are_rejected_before_inference(self):
        client = FakeClient()
        values = (
            ("", 1, 0.2),
            ("x" * 257, 1, 0.2),
            ("safe", 129, 0.2),
            ("safe", 1, float("nan")),
        )
        for prompt, tokens, temperature in values:
            with self.subTest():
                self.assertEqual(
                    client.generate(prompt, tokens, temperature)["status"], "INVALID_REQUEST"
                )
        self.assertEqual(client.calls, [])

    def test_timeout_unavailable_and_invalid_output_are_bounded(self):
        self.assertEqual(FakeClient(mode="timeout").generate("safe")["status"], "TIMEOUT")
        self.assertEqual(
            FakeClient(mode="unavailable").generate("safe")["status"], "UNAVAILABLE"
        )
        self.assertEqual(
            FakeClient(mode="invalid").generate("safe")["status"], "INVALID_OUTPUT"
        )

    def test_concurrency_and_queue_capacity_reject_excess(self):
        gate = threading.Event()
        client = FakeClient(configured(max_concurrency=1, max_queue_depth=1), gate=gate)
        results = []
        first = threading.Thread(target=lambda: results.append(client.generate("first")))
        second = threading.Thread(target=lambda: results.append(client.generate("second")))
        first.start()
        while len(client.calls) < 1:
            time.sleep(0.005)
        second.start()
        time.sleep(0.02)
        excess = client.generate("third")
        self.assertEqual(excess["status"], "QUEUE_FULL")
        gate.set()
        first.join(1)
        second.join(1)
        self.assertEqual(len(results), 2)
        self.assertTrue(all(item["status"] == "OK" for item in results))

    def test_authority_boundary_preserves_live_files(self):
        paths = [
            ROOT / "deception_engine" / "strategies" / "registry.yaml",
            ROOT / "deception_engine" / "policy_guard.py",
            ROOT / "session_module" / "authoritative_state.py",
        ]
        before = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}
        result = FakeClient().generate("Harmless synthetic benchmark prompt.")
        after = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}
        self.assertEqual(result["status"], "OK")
        self.assertEqual(before, after)
        self.assertFalse(result["trusted"])


if __name__ == "__main__":
    unittest.main()
