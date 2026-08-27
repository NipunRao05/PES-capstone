"""Bounded offline Phase 19 decoy candidate generation.

The generator creates untrusted candidate evidence only. It cannot execute SQL,
mutate the strategy registry or policy, activate a strategy, or deploy assets.
"""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any

from learning_agent.candidate_validation import CandidateValidationPipeline

from .prompt_builder import build_prompt, build_repair_prompt
from .schemas import (
    AUTHORITY,
    GENERATION_SETTINGS,
    GENERATOR_VERSION,
    OUTPUT_SCHEMA_VERSION,
    PROMPT_TEMPLATE_VERSION,
)
from .validators import (
    enforce_requested_assets,
    parse_candidate_json,
    render_phase17_assets,
    validate_generation_request,
)


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


class DecoyGenerationAgent:
    """Generate and validate one bounded candidate with at most one repair."""

    def __init__(self, llm_client: Any, registry_snapshot: dict):
        self._llm = llm_client
        self._registry = copy.deepcopy(registry_snapshot)
        self._pipeline = CandidateValidationPipeline()

    @staticmethod
    def _candidate_metadata(request: dict, description: str, asset_ids: list[str]) -> dict:
        requirements = request["strategy_requirements"]
        return {
            "candidate_schema_version": "candidate-strategy-v1",
            "strategy_id": requirements["strategy_id"],
            "name": requirements["name"],
            "description": description,
            "supported_protocols": [request["supported_protocol"]],
            "required_state": requirements["required_state"],
            "forbidden_state": requirements["forbidden_state"],
            "activation_conditions": requirements["activation_conditions"],
            "compatible_personas": requirements["compatible_personas"],
            "schema_assets": asset_ids,
            "trap_assets": [],
            "risk_level": requirements["risk_level"],
            "resource_cost": requirements["resource_cost"],
            "validation_version": "phase19-generated-v1",
        }

    @staticmethod
    def _state_contract(request: dict, assets: list[dict]) -> dict:
        observed = {
            table["table"]: {
                column["name"]: column["type"] for column in table["columns"]
            }
            for table in request["existing_synthetic_schema_summary"]
        }
        expected = {
            asset["asset_id"]: {
                column["name"]: column["type"]
                for column in asset["schema"]["columns"]
            }
            for asset in assets
        }
        return {
            "observed_objects": observed,
            "candidate_expectations": expected,
            "retroactive_mutations": [],
        }

    def _validation_input(
        self, request: dict, description: str, assets: list[dict]
    ) -> dict:
        row_count = sum(len(asset["rows"]) for asset in assets)
        return {
            "proposal": request["proposal"],
            "review": request["review"],
            "candidate_strategy": self._candidate_metadata(
                request, description, [asset["asset_id"] for asset in assets]
            ),
            "database_assets": assets,
            "state_contract": self._state_contract(request, assets),
            "trap_definitions": [],
            "resource_limits": {
                "cost_class": request["strategy_requirements"]["resource_cost"],
                "max_rows": max(100, row_count),
                "max_schema_objects": 5,
                "background_workers": 0,
                "container_per_query": False,
            },
        }

    @staticmethod
    def _attempt_record(number: int, result: dict, validation_error: str = "") -> dict:
        text = result.get("text") if isinstance(result, dict) else ""
        status = str(result.get("status") or "INVALID_OUTPUT") if isinstance(result, dict) else "INVALID_OUTPUT"
        return {
            "attempt": number,
            "client_status": status[:32],
            "request_id": str(result.get("request_id") or "")[:64]
            if isinstance(result, dict) else "",
            "latency_ms": result.get("latency_ms")
            if isinstance(result, dict) and isinstance(result.get("latency_ms"), (int, float))
            else None,
            "output_sha256": hashlib.sha256(str(text).encode("utf-8")).hexdigest()
            if text else "",
            "structural_validation": "PASS" if status == "OK" and not validation_error else "FAIL",
            "failure": validation_error[:160] if validation_error else (
                str((result.get("error") or {}).get("code") or status)[:160]
                if status != "OK" and isinstance(result, dict) else ""
            ),
        }

    @staticmethod
    def _model_metadata(result: dict | None = None) -> dict:
        value = result if isinstance(result, dict) else {}
        return {
            "model_version": str(value.get("model_version") or "")[:128],
            "runtime_version": str(value.get("runtime_version") or "")[:64],
            "client_contract_version": str(value.get("contract_version") or "")[:64],
            "trusted": False,
        }

    @staticmethod
    def _failure(
        *, status: str, request_digest: str, reason: str, attempts: list[dict],
        preflight: dict | None = None, source_request_id: str = "",
        model_metadata: dict | None = None,
    ) -> dict:
        return {
            "generation_id": "GEN-" + hashlib.sha256(
                (request_digest + status + reason).encode("utf-8")
            ).hexdigest()[:24],
            "status": status,
            "generator_version": GENERATOR_VERSION,
            "request_sha256": request_digest,
            "source_request_id": source_request_id[:64],
            "model_runtime_metadata": copy.deepcopy(
                model_metadata or DecoyGenerationAgent._model_metadata()
            ),
            "candidate_output_schema_version": OUTPUT_SCHEMA_VERSION,
            "prompt_template_version": PROMPT_TEMPLATE_VERSION,
            "generation_settings": copy.deepcopy(GENERATION_SETTINGS),
            "attempt_count": len(attempts),
            "repair_count": max(0, len(attempts) - 1),
            "attempts": attempts,
            "candidate": None,
            "phase17_handoff": {
                "eligible": False,
                "status": (preflight or {}).get("status", "NOT_STARTED"),
                "validation": copy.deepcopy(preflight),
            },
            "rejection_reason": reason[:240],
            "trusted": False,
            "authority": copy.deepcopy(AUTHORITY),
            "meaning": "Untrusted Phase 19 candidate generation only; never approval or deployment.",
        }

    def generate(self, generation_request: dict) -> dict:
        try:
            request = validate_generation_request(generation_request)
            request_digest = _sha256(request)
        except (ValueError, TypeError, KeyError) as exc:
            request_digest = _sha256(generation_request) if isinstance(generation_request, dict) else hashlib.sha256(b"invalid").hexdigest()
            return self._failure(
                status="REJECTED", request_digest=request_digest,
                reason=f"input validation failed: {exc}", attempts=[],
            )

        source_request_id = request["proposal"]["proposal_id"]

        preflight_input = self._validation_input(
            request,
            request["proposal"]["proposed_capability"]["objective"],
            [],
        )
        preflight = self._pipeline.validate(preflight_input, self._registry)
        if preflight.get("status") != "VALIDATED":
            return self._failure(
                status="REJECTED", request_digest=request_digest,
                reason="Phase 17 approval/registry preflight rejected the request",
                attempts=[], preflight=preflight, source_request_id=source_request_id,
            )

        attempts: list[dict] = []
        candidate_output: dict | None = None
        model_metadata = self._model_metadata()
        last_error = "model output was not accepted"
        for attempt_number in (1, 2):
            prompt = build_prompt(request) if attempt_number == 1 else build_repair_prompt(request)
            result = self._llm.generate(prompt, **GENERATION_SETTINGS)
            model_metadata = self._model_metadata(result if isinstance(result, dict) else None)
            if not isinstance(result, dict) or result.get("status") != "OK":
                attempts.append(self._attempt_record(attempt_number, result if isinstance(result, dict) else {}))
                return self._failure(
                    status="GENERATION_FAILED", request_digest=request_digest,
                    reason="local model was unavailable or failed safely",
                    attempts=attempts, preflight=preflight,
                    source_request_id=source_request_id, model_metadata=model_metadata,
                )
            try:
                parsed = parse_candidate_json(result.get("text"))
                enforce_requested_assets(parsed, request["requested_asset_types"])
                candidate_output = parsed
                attempts.append(self._attempt_record(attempt_number, result))
                break
            except (ValueError, TypeError, KeyError) as exc:
                last_error = str(exc)
                attempts.append(self._attempt_record(attempt_number, result, last_error))

        if candidate_output is None:
            return self._failure(
                status="REJECTED", request_digest=request_digest,
                reason=f"model output rejected after bounded repair: {last_error}",
                attempts=attempts, preflight=preflight,
                source_request_id=source_request_id, model_metadata=model_metadata,
            )

        assets = render_phase17_assets(candidate_output, request["supported_protocol"])
        validation_input = self._validation_input(
            request, candidate_output["description"], assets
        )
        phase17 = self._pipeline.validate(validation_input, self._registry)
        status = {
            "VALIDATED": "CANDIDATE_READY",
            "VALIDATION_INCOMPLETE": "CANDIDATE_REQUIRES_SANDBOX",
        }.get(phase17.get("status"), "REJECTED")
        if status == "REJECTED":
            return self._failure(
                status=status, request_digest=request_digest,
                reason="Phase 17 rejected the generated candidate",
                attempts=attempts, preflight=phase17,
                source_request_id=source_request_id, model_metadata=model_metadata,
            )

        candidate_digest = _sha256(candidate_output)
        return {
            "generation_id": "GEN-" + hashlib.sha256(
                (request_digest + candidate_digest + GENERATOR_VERSION).encode("utf-8")
            ).hexdigest()[:24],
            "status": status,
            "generator_version": GENERATOR_VERSION,
            "request_sha256": request_digest,
            "source_request_id": source_request_id,
            "model_runtime_metadata": model_metadata,
            "candidate_output_schema_version": OUTPUT_SCHEMA_VERSION,
            "candidate_output_sha256": candidate_digest,
            "prompt_template_version": PROMPT_TEMPLATE_VERSION,
            "generation_settings": copy.deepcopy(GENERATION_SETTINGS),
            "attempt_count": len(attempts),
            "repair_count": max(0, len(attempts) - 1),
            "attempts": attempts,
            "candidate": {
                "strategy": validation_input["candidate_strategy"],
                "generated_artifacts": candidate_output,
                "database_assets": assets,
                "database_assets_executed": False,
            },
            "phase17_handoff": {
                "eligible": phase17.get("status") == "VALIDATED",
                "status": phase17.get("status"),
                "validation_id": phase17.get("validation_id"),
                "validation": phase17,
                "database_asset_count": len(assets),
                "database_execution": False,
            },
            "rejection_reason": "",
            "trusted": False,
            "authority": copy.deepcopy(AUTHORITY),
            "meaning": "Untrusted Phase 19 candidate generation only; never approval or deployment.",
        }
