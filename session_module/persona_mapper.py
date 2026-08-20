def _rule_based_persona(features):
    entropy     = features[0]
    failed_auth = features[1]
    depth       = features[2]
    query_count = features[3]

    if failed_auth >= 2:
        return "brute_bot"

    if query_count > 30 and entropy > 1.2:
        return "automated_tool"

    if depth > 2 and entropy > 1.0:
        return "human_attacker"

    if entropy > 0.5 or query_count > 15:   # catches more scripted patterns
        return "script"

    return "low_activity"


def map_cluster_to_persona(cluster_id, features):
    # Preserve DBSCAN semantics: -1 is noise/unclustered when DBSCAN actually ran.
    if cluster_id == -1:
        return "unknown"

    return _rule_based_persona(features)


def map_sparse_session_to_persona(features):
    """Rule-based fallback for batches too small for DBSCAN.

    This is intentionally separate from map_cluster_to_persona(): DBSCAN noise
    should remain "unknown", but one-session demos still need a useful persona
    so downstream MITRE/scaling dashboards receive a profile.
    """
    return _rule_based_persona(features)
