"""JSON-stdin CLI for the bounded Phase 16 blue-team review workflow."""

from __future__ import annotations

import argparse
import json
import sys

try:
    from .review import BlueTeamReviewStore, ReviewNotApplicable, extract_reviewable_proposal
except ImportError:  # Direct script execution in the documented local container.
    from review import BlueTeamReviewStore, ReviewNotApplicable, extract_reviewable_proposal


def main() -> int:
    parser = argparse.ArgumentParser(description="Review one Phase 15 proposal from JSON stdin")
    parser.add_argument("--input-kind", choices=("proposal", "gap-result"), required=True)
    parser.add_argument("--reviewer")
    parser.add_argument("--decision", choices=(
        "APPROVE", "REJECT", "MODIFY", "REQUEST_MORE_EVIDENCE"
    ))
    parser.add_argument("--reason")
    parser.add_argument("--timestamp")
    parser.add_argument("--modifications-json", default="[]")
    parser.add_argument("--requested-evidence-json", default="[]")
    args = parser.parse_args()
    try:
        payload = json.load(sys.stdin)
        if args.input_kind == "gap-result":
            proposal = extract_reviewable_proposal(payload)
        else:
            proposal = payload
        if not args.reviewer or not args.decision or not args.reason:
            raise ValueError("reviewer, decision, and reason are required for review")
        modifications = json.loads(args.modifications_json)
        requested_evidence = json.loads(args.requested_evidence_json)
        review = BlueTeamReviewStore().review(
            proposal,
            reviewer=args.reviewer,
            decision=args.decision,
            reason=args.reason,
            modifications=modifications,
            requested_evidence=requested_evidence,
            timestamp=args.timestamp,
        )
    except ReviewNotApplicable as exc:
        print(json.dumps({
            "status": "NOT_REVIEWABLE",
            "classification": exc.classification,
            "review_created": False,
        }, sort_keys=True))
        return 0
    except (ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "REJECTED", "error": str(exc)[:256]}, sort_keys=True))
        return 1
    print(json.dumps(review, sort_keys=True, separators=(",", ":"), allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
