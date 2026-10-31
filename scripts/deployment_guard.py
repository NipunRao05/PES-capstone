"""Fail-closed Ubuntu deployment guard. Never provisions/mounts a cloud disk."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

OPERATOR=('POSTGRES_PASSWORD','MYSQL_ROOT_PASSWORD','MYSQL_PASSWORD','GRAFANA_ADMIN_PASSWORD',
    'PG_RUNTIME_PASSWORD','MYSQL_RUNTIME_PASSWORD')
DECOY=('PG_DECOY_PASSWORD','MYSQL_DECOY_PASSWORD','MYSQL_DECOY_ROOT_PASSWORD')
STABLE=('DECEPTIVE_PRINCIPAL_HMAC_SECRET','EVIDENCE_IP_HASH_SALT')


def private_file(path):
    from configuration import ConfigError
    path=Path(path)
    if path.is_symlink() or not path.is_file():raise ConfigError('Required owner-only deployment file is absent or a symlink')
    info=path.stat()
    if os.name!='posix':raise ConfigError('Deployment mode requires Linux ownership/mount validation')
    if stat.S_IMODE(info.st_mode)!=0o600 or info.st_uid not in {0,os.getuid()}:
        raise ConfigError('Deployment file must be owner/root-owned with mode 600')
    return path


def validate_secrets(env):
    from configuration import ConfigError
    for name in OPERATOR+STABLE:
        value=env.get(name,'')
        lower=value.lower()
        if len(value)<32 or len(set(value))<12 or any(word in lower for word in ('change_me','changeme','password','example','default','generate_','supply_','replace_','test-only')):
            raise ConfigError(name+': deployment requires a strong explicit secret')
    try:decoded=base64.b64decode(env['DECEPTIVE_PRINCIPAL_HMAC_SECRET'],validate=True)
    except (ValueError,KeyError):raise ConfigError('Invalid deployment principal key') from None
    if len(decoded)<32 or len(set(decoded))<12:raise ConfigError('Deployment principal key lacks adequate random material')
    for name in DECOY:
        if not env.get(name):raise ConfigError(name+': explicit decoy login value is required for deployment')
    operators=[env[n] for n in OPERATOR];stable=[env[n] for n in STABLE]
    if len(set(operators))!=len(operators) or len(set(stable))!=len(stable) or set(operators)&set(stable):
        raise ConfigError('Operator credentials and stable research keys must be independent')
    if set(env[n] for n in DECOY)&set(operators+stable):
        raise ConfigError('Decoy credentials must be separate from operator/research secrets')


def fingerprints(env):
    return {name:hashlib.sha256(env[name].encode()).hexdigest() for name in STABLE}


def validate_data(root,env,*,runtime_dir=None,min_free_gib=20):
    from configuration import ConfigError
    root=Path(root)
    if not root.is_absolute() or root.is_symlink() or not root.is_dir() or not os.path.ismount(root):
        raise ConfigError('Expected data disk is not mounted; refusing fresh OS-disk state')
    marker=private_file(root/'.honeypot-data-volume.json')
    try:data=json.loads(marker.read_text(encoding='utf-8'))
    except (OSError,ValueError):raise ConfigError('Invalid data-disk marker') from None
    if data.get('schema_version')!=1 or data.get('project')!='capstone-main' or data.get('volume_id')!=env.get('HONEYPOT_DATA_VOLUME_ID'):
        raise ConfigError('Data-disk identity does not match the reviewed deployment')
    if data.get('stable_key_fingerprints')!=fingerprints(env):
        raise ConfigError('Stable research key continuity mismatch; explicit migration required')
    if shutil.disk_usage(root).free<min_free_gib*1024**3:
        raise ConfigError('Insufficient free data-disk space')
    if runtime_dir is not None:
        runtime_dir=Path(runtime_dir)
        if not runtime_dir.is_dir() or not runtime_dir.resolve().is_relative_to(root.resolve()):
            raise ConfigError('Deployment .runtime must already reside on the mounted data disk')
    return data


def preflight(env):
    from configuration import ROOT,RUNTIME,ConfigError
    from runtime_hardening import policy
    if sys.platform!='linux':raise ConfigError('Deployment startup is supported only on the reviewed Linux host')
    private_file(env.get('HONEYPOT_SECRET_FILE',''))
    validate_secrets(env);p=policy();root=Path(p['deployment_data_root'])
    validate_data(root,env,runtime_dir=RUNTIME,min_free_gib=p['deployment_min_free_gib'])
    try:
        info=json.loads(subprocess.check_output(['docker','info','--format','{{json .}}'],text=True,timeout=10))
        version=subprocess.check_output(['docker','version','--format','{{.Server.Version}}'],text=True,timeout=10).strip()
    except (OSError,subprocess.SubprocessError,ValueError):raise ConfigError('Docker is unavailable') from None
    if Path(info['DockerRootDir']).resolve()!=root/'docker':
        raise ConfigError('Docker data-root must be on the reviewed data disk')
    required_mb=sum(row['memory_mb'] for row in p['resources'].values())+2048
    if info.get('MemTotal',0)<required_mb*1024**2:
        raise ConfigError('Deployment memory does not cover reviewed container limits plus 2GiB host reserve')
    if int(version.split('.')[0])<28:raise ConfigError('Deployment requires Docker Engine 28 or newer')
    # Docker itself must not auto-start on an absent disk before this guard runs.
    installed=Path('/etc/systemd/system/docker.service.d/honeypot-data-guard.conf')
    expected=(ROOT/'deployment/docker-data-guard.conf').read_bytes()
    if not installed.is_file() or installed.read_bytes()!=expected:
        raise ConfigError('Required Docker mount-guard systemd drop-in is not installed verbatim')
    print('DEPLOYMENT GUARD PASS: mount, marker, key continuity, permissions, space and Docker root')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--initialize-marker',action='store_true',help='Explicit one-time operation on a mounted NEW data disk')
    args=parser.parse_args()
    from configuration import load,ROOT,ConfigError
    try:
        _,_,_,env,_=load()
        if args.initialize_marker:
            from runtime_hardening import policy
            root=Path(policy()['deployment_data_root'])
            private_file(env.get('HONEYPOT_SECRET_FILE',''));validate_secrets(env)
            if not os.path.ismount(root):raise ConfigError('Refusing initialization without the mounted data disk')
            if not env.get('HONEYPOT_DATA_VOLUME_ID'):raise ConfigError('Explicit volume identity required')
            target=root/'.honeypot-data-volume.json'
            # Never overwrite an existing marker or bless an existing Docker root.
            if (root/'docker').exists():raise ConfigError('Existing Docker data requires explicit migration review')
            fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,'w') as stream:
                json.dump({'schema_version':1,'project':'capstone-main','volume_id':env['HONEYPOT_DATA_VOLUME_ID'],
                    'stable_key_fingerprints':fingerprints(env)},stream,sort_keys=True)
            print('Initialized explicit data-disk marker; no Docker state created')
        else:preflight(env)
        return 0
    except (ConfigError,OSError) as exc:
        print(str(exc) if isinstance(exc,ConfigError) else 'Deployment guard file operation failed',file=sys.stderr);return 1


if __name__=='__main__':raise SystemExit(main())
