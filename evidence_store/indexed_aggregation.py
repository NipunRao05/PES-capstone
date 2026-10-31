"""Read-only reporting over one atomic, bounded indexed retained snapshot."""
import re
from collections import Counter
from outcome_aggregation import aggregate, validate, summarize, GROUP_FIELDS
from trace_index import GROUP_CONTEXT, IndexIntegrityError

REQUIRED_SCOPE = {"experiment_id", "experiment_version", "scoring_profile_id", "scoring_profile_version"}


def validate_context(context):
    if set(context)-{"traffic_origin","deployment_manifest_id"} != set(GROUP_CONTEXT):
        raise IndexIntegrityError("INDEX_INTEGRITY_ERROR")
    for field in ("strategy_version", "experiment_version"):
        if type(context[field]) is not int or not 1 <= context[field] <= 2147483647:
            raise IndexIntegrityError("INDEX_INTEGRITY_ERROR")
    patterns = {"strategy_id": r"D[0-9]{1,4}", "strategy_definition_digest": r"[0-9a-f]{64}",
                "experiment_id": r"[A-Za-z0-9_-]{1,128}"}
    if any(not isinstance(context[k], str) or not re.fullmatch(pattern, context[k]) for k, pattern in patterns.items()):
        raise IndexIntegrityError("INDEX_INTEGRITY_ERROR")


def indexed_aggregate(store, *, filters, snapshot_max_sequence=None, index_epoch=None, generated_at=None):
    # Reuse the exact bounded filter contract; require explicit experiment/profile.
    aggregate([], filters=filters, generated_at=generated_at)
    if not REQUIRED_SCOPE <= set(filters):
        raise ValueError("Indexed coverage requires exact experiment and scoring-profile scope")
    snapshot = store.indexed_snapshot(snapshot_max_sequence=snapshot_max_sequence, index_epoch=index_epoch)
    if any(not group["done"] for group in snapshot["kinds"].values()):
        raise IndexIntegrityError("INDEX_INTEGRITY_ERROR")
    selected_context = {k: v for k, v in filters.items() if k in (*GROUP_CONTEXT,"traffic_origin","deployment_manifest_id")}
    applications = {}
    all_applications = {e["record_id"]: e for e in snapshot["kinds"]["application"]["entries"]}
    decisions = {e["record_id"]: e for e in snapshot["kinds"]["decision"]["entries"]}
    diagnostics = Counter(index_member_without_record=snapshot["stale_members_removed"])
    for entry in snapshot["kinds"]["application"]["entries"]:
        a, context = entry["record"], entry["context"]
        validate_context(context)
        decision = decisions.get(a["decision_id"])
        if decision and any(context[k] != decision["record"][k] for k in GROUP_CONTEXT):
            raise IndexIntegrityError("INDEX_INTEGRITY_ERROR")
        if not all(context.get(k,"unknown" if k=="traffic_origin" else None) == v for k, v in selected_context.items()):
            continue
        if a.get("application_status") not in {"APPLIED", "BLOCKED", "ERROR", "NOT_VERIFIED"} or a.get("provenance_status") not in {"MATCH", "MISMATCH", "NOT_VERIFIED", "INVALID_ACTION"}:
            raise IndexIntegrityError("INDEX_INTEGRITY_ERROR")
        if entry["reference_status"] != "RETAINED_INDEXED":
            diagnostics["application_without_indexed_retained_decision"] += 1
        if entry["reference_status"] == "MISSING":
            diagnostics["application_without_retained_decision"] += 1
        if entry["reference_status"] == "LEGACY_UNINDEXED":
            diagnostics["record_without_index_detected"] += 1
        applications[a["application_id"]] = entry
    candidates = {}
    selected_outcomes = []
    for entry in snapshot["kinds"]["outcome"]["entries"]:
        r = entry["record"]
        validate(r)
        if any(entry["context"].get(k) != r[k] for k in GROUP_CONTEXT):
            raise IndexIntegrityError("INDEX_INTEGRITY_ERROR")
        if not all(r.get(k,"unknown" if k=="traffic_origin" else None) == v for k, v in filters.items()):
            continue
        selected_outcomes.append(r)
        app = applications.get(r["application_id"])
        if app is None:
            if r["application_id"] in all_applications:
                diagnostics["outcome_application_linkage_conflict"] += 1
                continue
            diagnostics["outcome_without_indexed_retained_application"] += 1
            if entry["reference_status"] == "MISSING":
                diagnostics["outcome_without_retained_application"] += 1
            if entry["reference_status"] == "LEGACY_UNINDEXED":
                diagnostics["record_without_index_detected"] += 1
            continue
        a, context = app["record"], app["context"]
        if (r["decision_id"] != a["decision_id"] or any(r[k] != context[k] for k in GROUP_CONTEXT)
                or any(r[k] != a[k] for k in ("application_status", "provenance_status"))):
            diagnostics["outcome_application_linkage_conflict"] += 1
            continue
        candidates.setdefault(r["application_id"], []).append(r)
    matched = {}
    for identity, records in candidates.items():
        if len(records) == 1:
            matched[identity] = records[0]
        else:
            diagnostics["multiple_outcomes_for_application_profile"] += 1
    report = aggregate(list(matched.values()), filters=filters, generated_at=generated_at)

    def coverage(entries):
        ids = {e["record_id"] for e in entries}
        eligible = {e["record_id"] for e in entries if e["record"]["application_status"] == "APPLIED" and e["record"]["provenance_status"] == "MATCH"}
        covered = ids & matched.keys()
        return dict(retained_applications=len(ids), applications_with_outcomes=len(covered),
            applications_without_outcomes=len(ids-covered), outcome_coverage=len(covered)/len(ids) if ids else None,
            eligible_retained_applications=len(eligible), eligible_applications_with_outcomes=len(eligible & covered),
            eligible_applications_without_outcomes=len(eligible-covered),
            eligible_outcome_coverage=len(eligible & covered)/len(eligible) if eligible else None)

    groups = {}
    profile = {k: filters[k] for k in ("scoring_profile_id", "scoring_profile_version")}
    for entry in applications.values():
        key = tuple(({**entry["context"], **profile})[k] for k in GROUP_FIELDS)
        groups.setdefault(key, []).append(entry)
    per_strategy = []
    for key, entries in sorted(groups.items()):
        records = [matched[e["record_id"]] for e in entries if e["record_id"] in matched]
        per_strategy.append(dict(identity=dict(zip(GROUP_FIELDS, key)), coverage=coverage(entries),
            all_outcomes=summarize(records), eligible_outcomes=summarize([r for r in records if r["effectiveness_eligible"]])))
    digests = {}
    for entry in applications.values():
        c = entry["context"]
        digests.setdefault((c["strategy_id"], c["strategy_version"]), set()).add(c["strategy_definition_digest"])
    report["integrity_diagnostics"] = [dict(strategy_id=k[0], strategy_version=k[1], issue="MULTIPLE_DEFINITION_DIGESTS", digest_count=len(v))
        for k, v in sorted(digests.items()) if len(v) > 1]
    totals = coverage(list(applications.values()))
    report.update(population="INDEXED_RETAINED_POPULATION", coverage_denominator_status="AUTHORITATIVE_INDEXED_SCOPE",
        index_snapshot={k: v for k, v in snapshot.items() if k != "kinds"},
        indexed_retained_counts={kind: group["retained_count"] for kind, group in snapshot["kinds"].items()},
        coverage=totals, retained_applications=totals["retained_applications"],
        applications_with_selected_outcomes=totals["applications_with_outcomes"],
        applications_without_outcomes=totals["applications_without_outcomes"],
        retained_store_outcome_coverage=totals["outcome_coverage"],
        retained_outcomes_total=len(selected_outcomes), per_strategy=per_strategy,
        retained_decisions=sum(all(e["record"].get(k) == v for k, v in selected_context.items()) for e in decisions.values()),
        orphan_diagnostics=dict(sorted(diagnostics.items())),
        historical_pre_index_coverage="NOT_VERIFIED",
        quality_warnings=["INDEXED_RETAINED_SCOPE_NOT_LIFETIME_POPULATION", "PRE_INDEX_HISTORY_NOT_VERIFIED",
            "TRACE_AND_OUTCOME_RETENTION_BOUNDED", "NO_CAUSAL_OR_RANKING_INTERPRETATION"])
    report.pop("manifest_records")
    report.pop("unique_manifest_records")
    report["selected_matching_outcome_count"] = len(matched)
    if any(value for name, value in diagnostics.items() if name in {
            "outcome_application_linkage_conflict", "multiple_outcomes_for_application_profile"}):
        report["coverage_denominator_status"] = "INDEX_INTEGRITY_WARNING"
    from research_journal import HEALTH
    report["collection_completeness"]="NOT_VERIFIED"
    report["collection_integrity_diagnostics"]=store.client.hgetall(HEALTH)
    return report
