# Local CPU LLM Runtime

Phase 18 uses one optional Ollama 0.32.5 service and one model only:
`qwen2.5:1.5b-instruct-q4_K_M` (1.54B, Q4_K_M, approximately 986 MB,
Apache-2.0). The service is CPU-only because no GPU devices or GPU runtime are
attached. It is exposed only on an internal Docker network; it has no host or
public listener.

Source metadata:

- Runtime: https://github.com/ollama/ollama/releases/tag/v0.32.5
- Model: https://ollama.com/library/qwen2.5:1.5b-instruct-q4_K_M
- Model family/license: https://github.com/QwenLM/Qwen2.5

No attacker-facing service depends on this profile. `LOCAL_LLM_ENABLED=false`
is the default client mode. The reusable client validates the fixed internal URL
and model, prompt/output bounds, one/two inference workers, bounded queue depth,
overall timeout, response size/schema, and runtime failures. It never retries.
Generated text is always returned as untrusted.

The model volume is deliberately outside Git. Provision the single model once
through a disposable network-enabled container, then run the persistent service
on its egress-isolated network:

~~~powershell
docker volume create capstone-main_local_llm_models
docker run --rm -v capstone-main_local_llm_models:/root/.ollama ollama/ollama:0.32.5 pull qwen2.5:1.5b-instruct-q4_K_M
docker compose --profile local-ai up -d local-llm
~~~

Run the three-request synthetic benchmark from the repository root through a
disposable client on the private network:

~~~powershell
docker run --rm --network capstone-main_local-llm-internal --mount "type=bind,source=F:\b\Capstone-main\local_llm,target=/app" -w /app -e LOCAL_LLM_ENABLED=true -e LOCAL_LLM_URL=http://local-llm:11434 capstone-main-session-module python benchmark.py
~~~

Do not send raw attacker SQL, source addresses, credentials, fingerprints,
database usernames, or production-like secrets. Phase 19 generation and Phase 23
reporting integrations are intentionally not present.
