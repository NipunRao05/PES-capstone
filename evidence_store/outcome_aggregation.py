"""Read-only, manifest-scoped descriptive statistics; no policy consumer."""
from collections import Counter
from datetime import datetime, timezone
import math
import re
from statistics import mean, median
from uuid import UUID
from strategy_outcomes import OUTCOME_FIELDS, instant

GROUP_FIELDS = ("strategy_id", "strategy_version", "strategy_definition_digest",
    "experiment_id", "experiment_version", "scoring_profile_id", "scoring_profile_version")
RAW_FIELDS = ("followup_queries", "verified_followup_queries", "successful_followup_queries",
    "verified_errors", "verified_trap_interactions", "window_duration_seconds", "disconnect_observed",
    "new_relations", "new_query_families", "new_commitments", "exposure_depth_delta")
COMPONENTS = ("engagement", "error_component", "trap_interaction", "disconnect_signal")
CAPABILITIES = {
    "new_relations": "Requires retained pre-decision relation inventory",
    "new_query_families": "Requires retained pre-decision query-family inventory",
    "new_commitments": "Requires reconstructible pre/post commitment sets",
    "exposure_depth_delta": "Requires attributable end-depth excluding producing-query effects",
    "cross_session_outcomes": "Deferred delayed-outcome attribution",
}


def distribution(values, total, *, boolean=False):
    observed = [x for x in values if x is not None]
    result = {"observed_count": len(observed), "missing_count": total-len(observed),
        "observed_rate": len(observed)/total if total else None,
        "coverage": "NO_DATA" if not observed else "OBSERVED" if len(observed)==total else "PARTIAL_COVERAGE"}
    if boolean:
        if any(type(x) is not bool for x in observed):
            raise ValueError("Nonboolean outcome feature")
        result.update(observed_true=sum(x is True for x in observed), observed_false=sum(x is False for x in observed))
    else:
        if any(type(x) not in (int,float) or not math.isfinite(x) or x < 0 for x in observed):
            raise ValueError("Invalid numeric outcome feature")
        result.update(n=len(observed), minimum=min(observed) if observed else None,
            maximum=max(observed) if observed else None, mean=mean(sorted(observed)) if observed else None,
            median=median(observed) if observed else None)
    return result


def counts(records):
    n=len(records)
    completeness=Counter(r["completeness"] for r in records)
    app=Counter(r["application_status"] for r in records)
    provenance=Counter(r["provenance_status"] for r in records)
    eligible=sum(r["effectiveness_eligible"] is True for r in records)
    return {"outcome_count":n, "eligible_count":eligible, "ineligible_count":n-eligible,
        "applied_match_count":sum(r["application_status"]=="APPLIED" and r["provenance_status"]=="MATCH" for r in records),
        "application_status_counts":{k:app[k] for k in ("APPLIED","BLOCKED","ERROR","NOT_VERIFIED")},
        "provenance_status_counts":{k:provenance[k] for k in ("MATCH","MISMATCH","NOT_VERIFIED","INVALID_ACTION")},
        "completeness_counts":{k:completeness[k] for k in ("COMPLETE","PARTIAL","INSUFFICIENT_EVIDENCE")},
        "completeness_proportions":{k:completeness[k]/n if n else None for k in ("COMPLETE","PARTIAL","INSUFFICIENT_EVIDENCE")},
        "termination_counts":dict(sorted(Counter(r["termination_reason"] for r in records).items()))}


def summarize(records):
    return {**counts(records),
        "raw_features":{k:distribution([r["raw_features"].get(k) for r in records],len(records),boolean=k=="disconnect_observed") for k in RAW_FIELDS},
        "component_scores":{k:distribution([r["component_scores"].get(k) for r in records],len(records)) for k in COMPONENTS}}


def validate(record):
    if not isinstance(record,dict) or set(record)-{"traffic_origin","deployment_manifest_id"}!=OUTCOME_FIELDS or type(record["schema_version"]) is not int or record["schema_version"]!=1:
        raise ValueError("Invalid outcome schema")
    for field in ("outcome_id","decision_id","application_id"):
        if str(UUID(record[field])) != record[field]:
            raise ValueError("Noncanonical outcome identity")
    for field in ("strategy_version","experiment_version","scoring_profile_version"):
        if type(record[field]) is not int or not 1<=record[field]<=2147483647:
            raise ValueError("Invalid version")
    for field in ("strategy_id","strategy_definition_digest","experiment_id","scoring_profile_id"):
        if not isinstance(record[field],str) or not 1<=len(record[field])<=128:
            raise ValueError("Invalid grouping identity")
    if not re.fullmatch(r"D[0-9]{1,4}",record["strategy_id"]) or not re.fullmatch(r"[0-9a-f]{64}",record["strategy_definition_digest"]) or any(not re.fullmatch(r"[A-Za-z0-9_-]{1,128}",record[k]) for k in ("experiment_id","scoring_profile_id")):
        raise ValueError("Invalid bounded grouping identity")
    if record["completeness"] not in {"COMPLETE","PARTIAL","INSUFFICIENT_EVIDENCE"} or record["application_status"] not in {"APPLIED","BLOCKED","ERROR","NOT_VERIFIED"} or record["provenance_status"] not in {"MATCH","MISMATCH","NOT_VERIFIED","INVALID_ACTION"}:
        raise ValueError("Invalid outcome population")
    if type(record["effectiveness_eligible"]) is not bool or record["effectiveness_eligible"] != (record["application_status"]=="APPLIED" and record["provenance_status"]=="MATCH"):
        raise ValueError("Inconsistent outcome eligibility")
    if record["termination_reason"] not in {"NEXT_STRATEGY","SESSION_CLOSED","MAX_DURATION","MAX_EVENTS","INCOMPLETE_EVIDENCE"}:
        raise ValueError("Invalid termination reason")
    if instant(record["window_start"])>instant(record["window_end"]):
        raise ValueError("Invalid outcome window")
    if not isinstance(record["raw_features"],dict) or set(record["raw_features"])-set(RAW_FIELDS) or not isinstance(record["component_scores"],dict) or set(record["component_scores"])-set(COMPONENTS):
        raise ValueError("Unknown outcome dimension")
    if any(v is not None and (type(v) not in (int,float) or not math.isfinite(v) or not 0<=v<=1) for v in record["component_scores"].values()):
        raise ValueError("Invalid component score")


def aggregate(records, *, filters=None, generated_at=None):
    if not isinstance(records,list) or len(records)>1000:
        raise ValueError("Outcome manifest exceeds bound")
    filters={} if filters is None else filters
    if not isinstance(filters,dict) or set(filters)-set(GROUP_FIELDS)-{"traffic_origin","deployment_manifest_id"}:
        raise ValueError("Unknown aggregate filter")
    for key,value in filters.items():
        if key.endswith("_version"):
            if type(value) is not int or not 1<=value<=2147483647: raise ValueError("Invalid version filter")
        elif not isinstance(value,str) or not 1<=len(value)<=128:
            raise ValueError("Invalid identity filter")
        elif not re.fullmatch(r"[A-Za-z0-9_-]{1,128}",value):
            raise ValueError("Invalid bounded filter")
    unique={}
    for record in records:
        validate(record)
        identity=record["outcome_id"]
        if identity in unique and unique[identity]!=record:
            raise ValueError("Conflicting outcome identity")
        unique[identity]=record
    selected=sorted((r for r in unique.values() if all(r.get(k,"unknown" if k=="traffic_origin" else None)==v for k,v in filters.items())),key=lambda r:r["outcome_id"])
    groups={}
    for record in selected:
        groups.setdefault(tuple(record[k] for k in GROUP_FIELDS),[]).append(record)
    summaries=[]
    for key,values in sorted(groups.items()):
        # Keep operational records visible; do not mix them into eligible score summaries.
        summaries.append({"identity":dict(zip(GROUP_FIELDS,key)), "all_outcomes":summarize(values),
            "eligible_outcomes":summarize([r for r in values if r["effectiveness_eligible"]])})
    digests={}
    for record in selected:
        digests.setdefault((record["strategy_id"],record["strategy_version"]),set()).add(record["strategy_definition_digest"])
    diagnostics=[{"strategy_id":key[0],"strategy_version":key[1],"issue":"MULTIPLE_DEFINITION_DIGESTS","digest_count":len(value)}
        for key,value in sorted(digests.items()) if len(value)>1]
    n=len(selected)
    return {"schema_version":1,"generated_at":generated_at or datetime.now(timezone.utc).isoformat(),
        "population":"EXPLICIT_RETAINED_OUTCOME_MANIFEST", "filters":dict(sorted(filters.items())),
        "manifest_records":len(records), "unique_manifest_records":len(unique),
        "overall":counts(selected), "per_strategy":summaries,
        "coverage_denominator_status":"DENOMINATOR_NOT_VERIFIED",
        "retained_decisions":None,"retained_applications":None,"retained_outcomes_total":None,
        "applications_with_selected_outcomes":len({r["application_id"] for r in selected}),
        "applications_without_outcomes":None,"retained_store_outcome_coverage":None,
        "feature_observability":{k:{field:value for field,value in distribution([r["raw_features"].get(k) for r in selected],n,boolean=k=="disconnect_observed").items()
            if field in {"observed_count","missing_count","observed_rate","coverage","observed_true","observed_false"}} for k in RAW_FIELDS},
        "component_observability":{k:{field:value for field,value in distribution([r["component_scores"].get(k) for r in selected],n).items()
            if field in {"observed_count","missing_count","observed_rate","coverage"}} for k in COMPONENTS},
        "retained_outcome_window_range":{"earliest_start":min((instant(r["window_start"]) for r in selected),default=None).isoformat() if selected else None,
            "latest_end":max((instant(r["window_end"]) for r in selected),default=None).isoformat() if selected else None},
        "integrity_diagnostics":diagnostics,
        "capability_limits":{k:{"status":"NOT_OBSERVED_OR_DEFERRED","requirement":v} for k,v in CAPABILITIES.items()},
        "calibration_status":"CALIBRATION_REQUIRED",
        "quality_warnings":["RETAINED_MANIFEST_NOT_LIFETIME_POPULATION","TRACE_AND_OUTCOME_RETENTION_BOUNDED",
            "PRODUCING_QUERY_ATTRIBUTION_UNRESOLVED","NO_CAUSAL_OR_RANKING_INTERPRETATION"]}
