"""Pre-production decision context and bounded observational transport."""
from contextvars import ContextVar
from dataclasses import dataclass
from functools import wraps
from types import SimpleNamespace
import inspect
import logging
import os
import redis
from trace_outbox import Outbox
import threading
import httpx
from decision_trace import begin, applied

log = logging.getLogger(__name__)
current = ContextVar("final_strategy_decision", default=None)
principal_context = ContextVar("trace_principal_context", default=None)
sink = None


class Emitter:
    def __init__(self, outbox=None):
        self.client = None
        if outbox is None:
            self.client = redis.Redis(host=os.getenv("REDIS_HOST", "localhost"),
                port=int(os.getenv("REDIS_PORT", "6379")), decode_responses=True,
                socket_timeout=0.4, socket_connect_timeout=0.4, retry_on_timeout=False)
            outbox = Outbox(self.client)
        self.outbox = outbox
        self.stopped = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def submit(self, pair):
        if self.stopped.is_set():
            return "STOPPED"
        try:
            status = self.outbox.enqueue(pair)
            if status != "DURABLE_PENDING":
                log.warning("strategy trace enqueue status=%s", status)
            return status
        except Exception:
            log.warning("strategy trace durable enqueue failed")
            return "FAILED"

    def close(self):
        self.stopped.set()
        self.thread.join(timeout=1.5)
        if self.client is not None and not self.thread.is_alive():
            self.client.close()

    def run(self):
        url = os.getenv("EVIDENCE_STORE_URL", "http://evidence-store:8011").rstrip("/")
        with httpx.Client(timeout=0.5, trust_env=False) as client:
            while not self.stopped.is_set():
                try:
                    result = self.outbox.step(lambda pair: client.post(url + "/evidence/strategy-trace", json=pair))
                except Exception:
                    log.warning("strategy trace outbox unavailable")
                    result = "IDLE"
                if result in {"IDLE", "STALE"}:
                    self.stopped.wait(1)


@dataclass(frozen=True)
class Finalized:
    strategy: object
    record: dict


def finalize(api, candidate, req):
    api._sync_strategy_runtime()
    selected = api._strategy_agent.select_registered_rule(candidate).strategy_id
    eligible, _reason = api._strategy_registry.eligibility(selected,
        api._strategy_registry.get(selected).strategy_version, req.protocol, principal_context.get() or {})
    if not eligible:
        selected = api._strategy_registry.default_strategy_id
    record = begin(api._strategy_registry, selected, session_id=req.session_id,
        protocol=req.protocol, transaction_state=getattr(req, "transaction_state", "idle"),
        exposure_depth=api._exposure.get_depth(req.session_id), principal_record=principal_context.get())
    record["reason_code"] = "RULE_" + selected if selected == candidate else "REGISTERED_FALLBACK"
    from query_correlation import metadata
    record.update(metadata(vars(req)))
    from research_metadata import metadata as research_metadata
    record.update(research_metadata(vars(req), producer_default=True))
    return Finalized(api._strategy_registry.get(selected), record)


def producer(candidate):
    def decorate(fn):
        def start(args, kwargs):
            import api
            try:
                bound = inspect.signature(fn).bind_partial(*args, **kwargs)
                values = tuple(bound.arguments.get(name, param.default)
                    for name, param in inspect.signature(fn).parameters.items())
                req = values[0]
                if fn.__name__ == "decide":
                    req = SimpleNamespace(**values[1])
                choice = candidate(api, values) if callable(candidate) else candidate
                final = finalize(api, choice, req)
            except Exception:
                # Observational context failures cannot introduce SQL failures.
                log.warning("strategy trace finalization unavailable")
                final = None
            return current.set(final), final

        def finish(response, final):
            global sink
            if response is None or final is None or hasattr(response, "strategy_trace"):
                return response
            import json
            try:
                application = applied(final.record, getattr(response, "action_provenance", None),
                                      result_mode=json.loads(response.body)["mode"])
                pair = {"decision": final.record, "application": application}
                response.strategy_trace = pair
                if final.record.get("query_execution_id"):
                    payload = json.loads(response.body)
                    payload["_correlation"] = {"query_execution_id": final.record["query_execution_id"],
                        "request_started_at": final.record["request_started_at"],
                        "decision_id": final.record["decision_id"], "application_id": application["application_id"]}
                    response.body = json.dumps(payload, separators=(",", ":")).encode()
                    response.headers["content-length"] = str(len(response.body))
                if sink is None:
                    sink = Emitter()
                response.trace_emission_status = sink.submit(pair)
                response.strategy_trace = pair
            except Exception:
                log.warning("strategy trace emission failed")
                response.trace_emission_status = "FAILED"
            return response

        if inspect.iscoroutinefunction(fn):
            @wraps(fn)
            async def wrapped(*args, **kwargs):
                token, final = start(args, kwargs)
                try:
                    return finish(await fn(*args, **kwargs), final)
                finally:
                    current.reset(token)
        else:
            @wraps(fn)
            def wrapped(*args, **kwargs):
                token, final = start(args, kwargs)
                try:
                    return finish(fn(*args, **kwargs), final)
                finally:
                    current.reset(token)
        return wrapped
    return decorate
