"""Stopped-stack Redis continuity archive. No live import, key generation or restore."""
import argparse
from datetime import datetime,timezone
import hashlib
import io
import json
from pathlib import Path,PurePosixPath
import subprocess
import tarfile


def sha(path):
    with path.open('rb') as source:return hashlib.file_digest(source,'sha256').hexdigest()


def safe_name(name):
    p=PurePosixPath(name)
    if p.is_absolute() or '..' in p.parts or not p.parts or '\\' in name:raise ValueError('Unsafe archive member')
    return p


def validate(path):
    with tarfile.open(path,'r:') as archive:
        manifest=None;observed={};total=0
        for member in archive:
            safe_name(member.name)
            total+=member.size
            if len(observed)>=131072 or total>64*1024**3 or len(member.name)>1024:raise ValueError('Backup validation bound exceeded')
            if not member.isfile() or member.size>16*1024**3 or member.name in observed:raise ValueError('Unsafe/duplicate archive member')
            data=archive.extractfile(member)
            if member.name=='backup-manifest.json':
                if manifest is not None or member.size>8*1024**2:raise ValueError('Invalid backup manifest')
                manifest=json.load(data)
            else:observed[member.name]={'sha256':hashlib.file_digest(data,'sha256').hexdigest(),'bytes':member.size}
        if manifest is None or observed!=manifest['files']:raise ValueError('Backup checksum/count mismatch')
        if not any(n.startswith('evidence-redis/') for n in observed) or not any(n.startswith('principal-redis/') for n in observed):raise ValueError('Both Redis populations required')
        required={'runtime/research-identity.json','runtime/deployment-manifest.json','runtime/retained-state-baseline.json','runtime/data-volume-marker.json'}
        if not required.issubset(observed):raise ValueError('Runtime identity/baseline/marker missing')
    return {'status':'PASS','scope':'ARCHIVE_INTEGRITY_ONLY_NOT_RESTORE','archive_sha256':sha(path),'files':len(observed)}


def backup(output):
    from configuration import ROOT,load
    env=load()[3]
    from deployment_guard import preflight
    preflight(env)
    running=subprocess.check_output(['docker','ps','-q','--filter','label=com.docker.compose.project=capstone-main'],text=True)
    if running.strip():raise ValueError('Stop the complete Compose stack safely before continuity capture')
    entries={}
    for volume,prefix in [('capstone-main_redismitre','evidence-redis'),('capstone-main_redisdeception','principal-redis')]:
        row=json.loads(subprocess.check_output(['docker','volume','inspect',volume],text=True))[0]
        source=Path(row['Mountpoint'])
        if not source.resolve().is_relative_to(Path('/opt/honeypot-data/docker/volumes')):raise ValueError('Unexpected volume location')
        for path in source.rglob('*'):
            if path.is_symlink():raise ValueError('Backup does not follow symlinks')
            if path.is_file():entries[prefix+'/'+path.relative_to(source).as_posix()]=path
    for name in ('research-identity.json','deployment-manifest.json'):
        path=ROOT/'.runtime'/name
        entries['runtime/'+name]=path
    baseline=ROOT/'.runtime/azure-backup-baseline.json'
    if not baseline.is_file():raise ValueError('Capture .runtime/azure-backup-baseline.json before stopping the stack')
    entries['runtime/retained-state-baseline.json']=baseline
    entries['runtime/data-volume-marker.json']=Path('/opt/honeypot-data/.honeypot-data-volume.json')
    manifest={'schema_version':1,'created_at':datetime.now(timezone.utc).isoformat(),
        'deployment_id':env['HONEYPOT_DEPLOYMENT_ID'],'files':{name:{'sha256':sha(path),'bytes':path.stat().st_size} for name,path in entries.items()},
        'scope':'Sensitive stopped Redis volumes, runtime identity and hash baseline; secrets.env/HMAC transferred separately; no full-VM or Kafka backup'}
    output.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    with output.open('xb') as target,tarfile.open(fileobj=target,mode='w|') as archive:
        for name,path in sorted(entries.items()):archive.add(path,arcname=name,recursive=False)
        data=json.dumps(manifest,sort_keys=True).encode();info=tarfile.TarInfo('backup-manifest.json');info.size=len(data);info.mode=0o600
        archive.addfile(info,io.BytesIO(data))
    output.chmod(0o600)
    return validate(output)


def main():
    p=argparse.ArgumentParser(description=__doc__);group=p.add_mutually_exclusive_group(required=True)
    group.add_argument('--output',type=Path);group.add_argument('--validate',type=Path);a=p.parse_args()
    try:result=validate(a.validate) if a.validate else backup(a.output)
    except Exception as exc:result={'status':'FAIL','error_category':type(exc).__name__}
    print(json.dumps(result));return int(result['status']!='PASS')


if __name__=='__main__':raise SystemExit(main())
