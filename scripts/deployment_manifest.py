"""Nonsecret launch provenance. Identity files are generated, never Git inputs."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from datetime import datetime, timezone
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / ".runtime"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def atomic_write(path, text):
    path=Path(path)
    temporary=path.with_suffix(path.suffix+".tmp")
    temporary.write_text(text,encoding="utf-8")
    temporary.replace(path)


def current_id():
    try:
        identity = json.loads((RUNTIME / "deployment-manifest.json").read_text(encoding="utf-8"))["manifest_id"]
        return identity if re.fullmatch(r"[0-9a-f]{64}", identity) else ""
    except (OSError, ValueError, KeyError, TypeError):
        return ""


def source_identity(root):
    """Support reviewed source archives without shipping Git history."""
    root=Path(root)
    if not (root/'.git').exists():
        release=json.loads((root/'release/source-manifest.json').read_text(encoding='utf-8'))
        commit=release['git_commit'];files=release['files']
        if not re.fullmatch(r'[0-9a-f]{40,64}',commit) or not files:
            raise ValueError('Invalid archive source identity')
        for name,expected in files.items():
            path=root/name
            if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()) or not path.is_file():
                raise ValueError('Invalid archive source path')
            if hashlib.sha256(path.read_bytes()).hexdigest()!=expected:
                raise ValueError('Archive source checksum mismatch')
        if digest(files)!=release['archive_source_digest']:
            raise ValueError('Archive source inventory checksum mismatch')
        return commit,files
    commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()
    names=subprocess.check_output(['git','ls-files','-z'],cwd=root).decode().split('\0')
    names+=subprocess.check_output(['git','ls-files','--others','--exclude-standard','-z'],cwd=root).decode().split('\0')
    source={}
    for name in sorted(set(names)):
        p=root/name
        if name and p.is_file() and (p.suffix in {'.py','.go','.mod','.sum','.yaml','.yml','.sh','.lock','.conf','.example','.service','.json','.txt'} or p.name in {'Dockerfile','.dockerignore','requirements.txt'}) and not name.startswith(('.runtime/','.env')):
            source[name]=hashlib.sha256(p.read_bytes()).hexdigest()
    return commit,source


def resolved_nonsecret(value, env):
    if isinstance(value, dict):
        return {k:("<secret>" if re.search(r"PASSWORD|SECRET|(?:^|_)TOKEN$|HMAC|API_KEY|AUTHORIZATION|RESEARCH_OPERATOR_KEY|SALT",k) else resolved_nonsecret(v,env)) for k,v in value.items()
                if k not in {"RESEARCH_MANIFEST_ID", "honeypot.config-hash"}}
    if isinstance(value, list):
        return [resolved_nonsecret(v,env) for v in value]
    if not isinstance(value,str):
        return value
    def replace(match):
        name, suffix = match.group(1), match.group(2)
        if re.search(r"PASSWORD|SECRET|(?:^|_)TOKEN$|(?:^|_)KEY$|SALT",name):
            return "<secret>"
        default = suffix[2:] if suffix.startswith(":-") else ""
        return str(env.get(name,default))
    return re.sub(r"\$\{([A-Z0-9_]+)([^}]*)\}",replace,value)


def create(flags, policy, obs, env, artifacts):
    from configuration import read_yaml
    RUNTIME.mkdir(exist_ok=True)
    identity_path=RUNTIME / "research-identity.json"
    if identity_path.exists():
        identity=json.loads(identity_path.read_text(encoding="utf-8"))
    else:
        identity={"deployment_id":str(uuid4()),"run_id":str(uuid4())}
        identity_path.write_text(json.dumps(identity,indent=2),encoding="utf-8")
    for key,variable in (("deployment_id","HONEYPOT_DEPLOYMENT_ID"),("run_id","HONEYPOT_RUN_ID")):
        identity[key]=env.get(variable) or identity[key]
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}",identity[key]):
            raise ValueError("Invalid research deployment identity")
    world=read_yaml("deception_engine/schemas/hr.yaml")
    registry=read_yaml("deception_engine/strategies/registry.yaml")
    commit,source=source_identity(ROOT)
    config={"features":flags,"policy":policy,"observability":obs,
            "rendered_runtime":resolved_nonsecret({k:v for k,v in artifacts.items() if k!='compose.yaml'},env),
            "compose":resolved_nonsecret(artifacts["compose.yaml"],env)}
    manifest={"manifest_schema_version":1,"created_at":datetime.now(timezone.utc).isoformat(),
        "launch_id":str(uuid4()),**identity,"experiment_id":"deterministic_baseline","experiment_version":1,
        "git_commit":commit,"source_digest":digest(source),"source_files":source,
        "configuration_digest":digest(config),"resolved_nonsecret_configuration":config,
        "world_id":world["world_id"],"world_version":world["world_version"],
        "strategy_registry_version":registry["registry_version"],"strategy_registry_digest":digest(registry),
        "scoring_profile_id":"deterministic_components","scoring_profile_version":1,
        "image_inventory_status":"NOT_CAPTURED","images":{}}
    manifest["manifest_id"]=digest(manifest)
    folder=RUNTIME/"manifests";folder.mkdir(exist_ok=True)
    atomic_write(folder/(manifest["manifest_id"]+".json"),canonical(manifest)+"\n")
    atomic_write(RUNTIME/"deployment-manifest.json",canonical(manifest)+"\n")
    return manifest


def capture_images():
    path=RUNTIME/"deployment-manifest.json"
    manifest=json.loads(path.read_text(encoding="utf-8"))
    # Image observation supplements the immutable launch identity; its own digest
    # authenticates the inventory. Never include inspect environment/config data.
    result=subprocess.run(["docker","ps","-a","--filter","label=com.docker.compose.project=capstone-main","-q"],capture_output=True,text=True)
    if result.returncode or not result.stdout.strip():
        return
    data=json.loads(subprocess.check_output(["docker","inspect",*result.stdout.split()],text=True))
    manifest["images"]={c["Config"]["Labels"].get("com.docker.compose.service",c["Name"]):c["Image"] for c in data}
    manifest["image_inventory_status"]="OBSERVED_AFTER_STARTUP"
    manifest["image_inventory_digest"]=digest(manifest["images"])
    atomic_write(path,canonical(manifest)+"\n")
    atomic_write(RUNTIME/"manifests"/(manifest["manifest_id"]+".json"),canonical(manifest)+"\n")
