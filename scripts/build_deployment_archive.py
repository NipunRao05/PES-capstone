"""Reviewed source archive. Actual releases require a clean tree; development is explicit."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
from datetime import datetime,timezone

SCRIPT_FILES={'configuration.py','honeypot.py','runtime_hardening.py','deployment_guard.py',
    'deployment_manifest.py','dashboard.py','build_deployment_archive.py','verify_runtime.py',
    'verify_recovery.py','validate_runtime_isolation.py','validate_resource_smoke.py','validate_release_runtime.py',
    'validate_query_trace_runtime.py','validate_backend_containment.py','backend_containment.py',
    'audit_base_world.py','export_research_evidence.py','config-requirements.txt'}
SUFFIXES={'.py','.go','.mod','.sum','.yaml','.yml','.json','.sh','.conf','.service','.example','.lock','.txt'}


def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True)


def collect(root,model):
    root=Path(root);selected=set()
    directories={'shared','config','deployment','observability/loki','observability/grafana/provisioning','observability/grafana/dashboards'}
    directories.update(s['build']['context'].removeprefix('./') for s in model['services'].values() if 'build' in s)
    for directory in directories:
        if not (root/directory).resolve().is_relative_to(root.resolve()):
            raise ValueError('Build context escapes reviewed source root')
        for path in (root/directory).rglob('*'):
            relative=path.relative_to(root)
            if any(part in {'.git','.runtime','__pycache__','.pytest_cache','tests','releases'} or part.startswith('.') and part!='.dockerignore' for part in relative.parts):continue
            if path.is_symlink():raise ValueError('Release source symlinks require explicit review')
            if not path.is_file():continue
            if path.name.startswith('test_') or path.name.endswith('_test.go') or path.name=='journal_model.py':continue
            if '.env' in path.name and path.name not in {'secrets.env.example','empty.env'}:continue
            if path.name in {'.dockerignore','Dockerfile','empty.env'} or path.suffix in SUFFIXES:selected.add(relative.as_posix())
    for name in SCRIPT_FILES:
        if (root/'scripts'/name).is_file():selected.add('scripts/'+name)
    for name in ['docker-compose.yml','.env.example','observability/promtail.yaml','observability/prometheus.yml',
        'observability/capstone_alert_rules.yml','observability/json_exporter.yml']:
        if (root/name).is_file():selected.add(name)
    # Exclude all actual secrets even if a caller accidentally changes a directory allowlist.
    if any(n.endswith('/secrets.env') or '/.runtime/' in n or n=='.env' for n in selected):raise ValueError('Unsafe release inclusion')
    return {name:(root/name).read_bytes() for name in sorted(selected)}


def build(output,development=False):
    from configuration import ROOT,load,render
    from deployment_manifest import RUNTIME
    status=subprocess.check_output(['git','status','--porcelain=v1','--untracked-files=all'],cwd=ROOT)
    dirty=bool(status.strip())
    if dirty and not development:raise ValueError('Release requires clean source; --development produces a NON-RELEASE archive')
    flags,policy,obs,env,compose=load();model=render(flags,policy,obs,compose)['compose.yaml']
    contents=collect(ROOT,model)
    hashes={name:hashlib.sha256(data).hexdigest() for name,data in contents.items()}
    source_digest=hashlib.sha256(canonical(hashes).encode()).hexdigest()
    diff=subprocess.check_output(['git','diff','--binary','HEAD'],cwd=ROOT)
    identity={'git_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
        'dirty':dirty,'release_mode':'DEVELOPMENT_NOT_RELEASE' if development else 'RELEASE',
        'archive_source_digest':source_digest,'source_diff_digest':hashlib.sha256(diff+canonical(hashes).encode()).hexdigest(),
        'files':hashes}
    contents['release/source-manifest.json']=(canonical(identity)+'\n').encode()
    output=Path(output);output.parent.mkdir(parents=True,exist_ok=True)
    with output.open('xb') as target:
        with gzip.GzipFile(filename='',fileobj=target,mode='wb',mtime=0) as compressed:
            with tarfile.open(fileobj=compressed,mode='w') as archive:
                for name,data in sorted(contents.items()):
                    info=tarfile.TarInfo(name);info.size=len(data);info.mtime=0
                    info.mode=0o755 if name.endswith('.sh') else 0o644
                    archive.addfile(info,io.BytesIO(data))
    checksum=hashlib.sha256(output.read_bytes()).hexdigest()
    manifest=json.loads((RUNTIME/'deployment-manifest.json').read_text(encoding='utf-8'))
    release={**{k:v for k,v in identity.items() if k!='files'},'created_at':datetime.now(timezone.utc).isoformat(),
        'archive_sha256':checksum,'archive_bytes':output.stat().st_size,'file_count':len(contents),
        'deployment_manifest_id':manifest['manifest_id'],
        'deployment_source_digest':manifest['source_digest'],
        **{k:manifest.get(k) for k in ('configuration_digest','world_id','world_version','strategy_registry_digest',
            'strategy_registry_version','images','image_inventory_digest')}}
    output.with_suffix(output.suffix+'.release.json').write_text(json.dumps(release,indent=2)+'\n',encoding='utf-8')
    output.with_suffix(output.suffix+'.sha256').write_text(checksum+'\n',encoding='ascii')
    return release


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--development',action='store_true');args=p.parse_args()
    try:print(canonical(build(args.output,args.development)));return 0
    except (ValueError,OSError) as exc:print(str(exc) if isinstance(exc,ValueError) else 'Archive file operation failed');return 1


if __name__=='__main__':raise SystemExit(main())
