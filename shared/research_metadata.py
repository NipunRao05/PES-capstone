"""Validated provenance/origin, independent of attacker SQL/application names."""
import os
import re

ORIGINS={"research_external","operator_validation","unknown"}
FIELDS={"deployment_manifest_id","traffic_origin"}


def metadata(payload=None, *, producer_default=False):
    payload=payload or {}
    if not producer_default and not FIELDS.intersection(payload):
        return {}
    origin=payload.get("traffic_origin","unknown")
    if origin not in ORIGINS:
        raise ValueError("Invalid traffic origin")
    identity=payload.get("deployment_manifest_id")
    if not identity and producer_default:
        identity=os.getenv("RESEARCH_MANIFEST_ID","")
    if identity and (not isinstance(identity,str) or not re.fullmatch(r"[0-9a-f]{64}",identity)):
        raise ValueError("Invalid deployment manifest reference")
    return {"traffic_origin":origin,**({"deployment_manifest_id":identity} if identity else {})}


def origin(record):
    return record.get("traffic_origin","unknown")
