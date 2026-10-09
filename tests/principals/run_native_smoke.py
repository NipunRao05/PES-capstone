"""Local Docker smoke driver. No credentials are printed or written to artifacts.
Usage: python tests/principals/run_native_smoke.py create|return|reconnect|disable
Uses the existing replay image only for its native database client libraries.
"""
import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

parser=argparse.ArgumentParser()
parser.add_argument('stage',choices=['create','return','reconnect','disable','outage'])
parser.add_argument('--name',default='fake_compro1')
parser.add_argument('--protocol',choices=['postgres','mysql'])
args=parser.parse_args()
root=Path(__file__).resolve().parents[2]
env={}
for line in (root/'.env').read_text(encoding='utf-8').splitlines():
    if '=' in line and not line.lstrip().startswith('#'):
        key,value=line.split('=',1);env[key.strip()]=value.strip().strip('"').strip("'")
docker=shutil.which('docker') or str(Path(os.environ['LOCALAPPDATA'])/'Programs/DockerDesktop/resources/bin/docker.exe')
image=subprocess.check_output([docker,'inspect','--format','{{.Config.Image}}','capstone-sandbox-replay-engine'],text=True).strip()
networks=json.loads(subprocess.check_output([docker,'inspect','--format','{{json .NetworkSettings.Networks}}','capstone-main-pgproxy-1'],text=True))
network=next(iter(networks))
address=networks[network]['IPAddress'].rsplit('.',1)[0]+('.240' if args.stage in {'create','disable'} else '.241' if args.stage=='return' else '.242')
info=json.loads(subprocess.check_output([docker,'network','inspect',network],text=True))[0]
if any(c.get('IPv4Address','').split('/')[0]==address for c in info.get('Containers',{}).values()):
    raise SystemExit('Validation source address already in use')
password=hmac.new(env['DECEPTIVE_PRINCIPAL_HMAC_SECRET'].encode(),('native-demo:'+args.name).encode(),hashlib.sha256).hexdigest()
cfg=dict(stage=args.stage,name=args.name,synthetic_password=password,postgres_password=env['POSTGRES_PASSWORD'],mysql_root_password=env['MYSQL_ROOT_PASSWORD'])
if args.protocol:cfg['protocols']=[args.protocol]
code=(root/'tests/principals/native_smoke.py').read_text(encoding='utf-8')
result=subprocess.run([docker,'run','--rm','-i','--network',network,'--ip',address,'--entrypoint','python',image,'-c',code],input=json.dumps(cfg),text=True,capture_output=True)
print(result.stdout.strip())
if result.stderr:
    message=result.stderr
    for key,value in cfg.items():
        if 'password' in key:message=message.replace(value,'[REDACTED]')
    print(message,file=sys.stderr)
sys.exit(result.returncode)
