"""Register generated nonsecret launch manifests from an operator-owned RO bind."""
import hashlib
import json
import os
from pathlib import Path

KEY="evidence:deployment-manifests:v1"


def validate(manifest):
    if manifest.get("image_inventory_digest"):
        images=json.dumps(manifest["images"],sort_keys=True,separators=(",",":"),ensure_ascii=True)
        if hashlib.sha256(images.encode()).hexdigest()!=manifest["image_inventory_digest"]:
            raise ValueError("Invalid image inventory digest")
    base=dict(manifest)
    identity=base.pop("manifest_id")
    base.pop("image_inventory_digest",None)
    base["images"]={}
    base["image_inventory_status"]="NOT_CAPTURED"
    raw=json.dumps(base,sort_keys=True,separators=(",",":"),ensure_ascii=True,allow_nan=False)
    if hashlib.sha256(raw.encode()).hexdigest()!=identity:
        raise ValueError("Invalid launch manifest digest")
    return identity


def refresh(client):
    directory=Path(os.getenv("RESEARCH_MANIFEST_DIR","/research-manifests"))
    if not directory.exists():return
    paths=sorted(directory.glob("*.json"))
    if len(paths)>256:raise ValueError("Deployment manifest registry exceeds bound")
    for path in paths:
        manifest=json.loads(path.read_text(encoding="utf-8"))
        identity=validate(manifest)
        old=client.hget(KEY,identity)
        if old:
            previous=json.loads(old)
            # The immutable identity fields cannot be overwritten. Image
            # observation is the only permitted post-startup supplement.
            validate(previous)
            for key in set(manifest)-{"images","image_inventory_status","image_inventory_digest"}:
                if previous.get(key)!=manifest[key]:raise ValueError("Manifest conflict")
        client.hset(KEY,identity,json.dumps(manifest,sort_keys=True,separators=(",",":")))


def manifests(client):
    refresh(client)
    data=client.hgetall(KEY)
    if len(data)>256:raise ValueError("Deployment manifest registry exceeds bound")
    return {k.decode() if isinstance(k,bytes) else k:json.loads(v) for k,v in data.items()}
