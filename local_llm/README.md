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

## Phase 19.1 Ornith prototype

The Phase 18 Qwen client, volume, and validation record above remain unchanged.
Phase 19.1 adds a separate `local-llm-semantic-client-v1` contract for
`ornith-1.5:9b` and a Compose override. The model is an offline Prototype v1
candidate, not a final model selection.

The current Docker data disk is backed by C:, so the Ornith package must not be
pulled into `capstone-main_local_llm_models`. Provision the model into the
preflight-approved H:-backed directory, then run it read-only and internal-only:

~~~powershell
$env:ORNITH_MODELS_DIR = "H:\Capstone-main-data\ollama-ornith-1.5"

docker run --rm -d --name capstone-ornith-provision --cpus 4 --memory 9g `
  --mount "type=bind,source=$env:ORNITH_MODELS_DIR,target=/root/.ollama" `
  ollama/ollama:0.32.5 serve
docker exec capstone-ornith-provision ollama pull ornith-1.5:9b
docker stop capstone-ornith-provision

docker compose -f docker-compose.yml -f docker-compose.ornith.yml `
  --profile local-ai up -d local-llm
~~~

The override enforces 4 logical CPUs, 9 GiB memory, one parallel inference,
queue depth 2, 4096 context, five-minute keep-alive, no host port, internal-only
networking, and a read-only model mount. The semantic client fixes output at 512
tokens initially, uses a 300-second hard timeout, sends an exact JSON Schema,
requests no reasoning, and persists neither prompts nor reasoning text.
