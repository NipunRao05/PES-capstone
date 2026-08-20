import math
import statistics


# ==========================================
# Shannon Entropy Calculation
# ==========================================
def shannon_entropy(counter):
    total = sum(counter.values())
    if total == 0:
        return 0.0

    entropy = 0.0
    for count in counter.values():
        p = count / total
        entropy -= p * math.log2(p)

    return entropy


# ==========================================
# Depth Score
# ==========================================
def compute_depth_score(fingerprint_keys):
    return len(list(fingerprint_keys))


# ==========================================
# Timing Variance  (Gap 1)
# Returns stdev of inter-query gaps in ms.
# 0 or 1 queries → 0.0 (no gaps to measure).
# ==========================================
def compute_timing_variance_ms(query_timestamps: list) -> float:
    """
    Given a list of per-query timestamps (float epoch seconds),
    compute the standard deviation of the gaps between consecutive
    queries, in milliseconds.

    Returns 0.0 when fewer than 2 timestamps are provided.
    """
    if len(query_timestamps) < 2:
        return 0.0

    ordered = sorted(float(ts) for ts in query_timestamps)
    gaps_ms = [
        max(0.0, (ordered[i] - ordered[i - 1]) * 1000.0)
        for i in range(1, len(ordered))
    ]

    if len(gaps_ms) == 1:
        return 0.0   # stdev undefined for a single value — treat as zero

    return statistics.stdev(gaps_ms)


# ==========================================
# Queries Per Second  (Gap 1)
# ==========================================
def compute_queries_per_second(query_count: int, duration: float) -> float:
    """
    Returns query_count / duration.
    Returns 0.0 when duration is zero (instantaneous or single-event session).
    """
    if duration <= 0.0:
        return 0.0
    return query_count / duration


# ==========================================
# Optional: Full Feature Extraction
# ==========================================
def extract_features(session):
    # Replay/out-of-order timestamps can make last_seen older than start_time in
    # older Session objects. Keep feature extraction non-negative so downstream
    # QPS and duration charts do not receive impossible values.
    duration = max(0.0, session.last_seen - session.start_time)
    entropy = shannon_entropy(session.fingerprint_counter)
    unique_fp_count = len(session.fingerprint_counter)

    read_write_ratio = (
        session.read_query_count / session.query_count
        if session.query_count > 0 else 0.0
    )

    return {
        "session_id":             session.session_id,
        "source_ip":              session.source_ip,
        "db_user":                session.db_user,
        "duration":               duration,
        "query_count":            session.query_count,
        "failed_auth_count":      session.failed_auth_count,
        "unique_fingerprint_count": unique_fp_count,
        "entropy":                entropy,
        "depth_score":            compute_depth_score(session.fingerprint_counter.keys()),
        "read_query_count":       session.read_query_count,
        "write_query_count":      session.write_query_count,
        "read_write_ratio":       read_write_ratio,
        "fingerprints":           list(session.fingerprint_counter.keys()),
        "query_sequence":         session.fingerprint_sequence,
    }