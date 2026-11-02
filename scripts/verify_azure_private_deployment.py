"""Private Ubuntu validation. --exercise explicitly creates operator fixtures/export."""
import argparse
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--exercise',action='store_true')
    parser.add_argument('--baseline',type=Path,help='Existing pre-reboot recovery snapshot to compare, never causes a reboot')
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if not __debug__:parser.error('Optimized Python disables validator assertions; use ordinary python -B')
    from configuration import ROOT,load
    flags,_,_,env,_=load();checks={};artifacts={}
    if env.get('HONEYPOT_DEPLOYMENT_MODE')!='true' or sys.platform!='linux':
        parser.error('Run on the intended Linux host with strict deployment environment loaded')
    args.output.mkdir(mode=0o700,parents=True,exist_ok=False)
    def check(name,operation):
        try:operation();checks[name]='PASS'
        except Exception as exc:checks[name]='FAIL';artifacts[name]={'error_category':type(exc).__name__}
    def command(name,script,*options):
        result=subprocess.run([sys.executable,'-B',str(ROOT/'scripts'/script),*map(str,options)],cwd=ROOT,env=env,capture_output=True,timeout=180)
        # Persist only successful, reviewed validator output. No exception body/argv secrets.
        if result.returncode:raise RuntimeError('Validator failed')
        target=args.output/(name+'.txt');target.write_bytes(result.stdout)
        artifacts[name]={'path':target.name,'sha256':hashlib.sha256(result.stdout).hexdigest()}
    from deployment_guard import preflight
    check('disk_secrets_resources',lambda:preflight(env))
    def image_store():
        import tomllib
        config=tomllib.loads(subprocess.check_output(['containerd','config','dump'],text=True))
        assert config['root']=='/opt/honeypot-data/containerd'
    check('containerd_data_root',image_store)
    manifest=json.loads((ROOT/'.runtime/deployment-manifest.json').read_text())
    infra=json.loads(Path('/etc/honeypot-infrastructure.json').read_text())
    def containers():
        from configuration import render
        from runtime_hardening import policy
        f,p,o,_,c=load();model=render(f,p,o,c)['compose.yaml'];limits=policy()['resources']
        ids=subprocess.check_output(['docker','ps','-aq','--filter','label=com.docker.compose.project=capstone-main'],text=True).split()
        rows=json.loads(subprocess.check_output(['docker','inspect',*ids],text=True))
        by_name={r['Config']['Labels']['com.docker.compose.service']:r for r in rows}
        assert set(by_name)==set(model['services'])
        for name,row in by_name.items():
            h=row['HostConfig'];r=limits[name];state=row['State'];init=name.endswith('-init')
            assert row['Image']==manifest['images'][name] and not state['OOMKilled']
            assert h['Memory']==r['memory_mb']*1024**2 and h['NanoCpus']==int(r['cpus']*1e9) and h['PidsLimit']==r['pids']
            assert h['RestartPolicy']['Name']==('no' if init else 'unless-stopped')
            if init:assert not state['Running'] and state['ExitCode']==0
            else:assert state['Running'] and state.get('Health',{}).get('Status','healthy')=='healthy'
    check('container_health',containers)
    def identity():
        assert manifest['deployment_id']==infra['deployment_id']==env['HONEYPOT_DEPLOYMENT_ID']
        assert manifest['run_id']==infra['run_id']==env['HONEYPOT_RUN_ID']
        assert manifest['experiment_id']==infra['experiment_id']=='deterministic_baseline'
        assert manifest['world_id']=='hr_base_v1' and manifest['world_version']==1
        assert not infra['enable_public_honeypot']
        assert all(not enabled for name,enabled in flags.items() if name.startswith('optional_future.'))
        from deployment_manifest import digest,source_identity
        _,source=source_identity(ROOT)
        assert manifest['source_digest']==digest(source)
        base=dict(manifest);identity=base.pop('manifest_id');base.pop('image_inventory_digest',None)
        base.update(images={},image_inventory_status='NOT_CAPTURED')
        assert digest(base)==identity
        assert digest(manifest['images'])==manifest['image_inventory_digest']
    check('deployment_provenance',identity)
    check('runtime_observability',lambda:command('runtime','verify_runtime.py'))
    check('egress_resources',lambda:command('isolation','validate_runtime_isolation.py'))
    def persistence():
        for name,fsync in [('redis-mitre','everysec'),('redis-deception','always')]:
            code="import redis,sys; r=redis.Redis(host=sys.argv[1],decode_responses=True); c=r.config_get(); p=r.info('persistence'); assert c['appendonly']=='yes' and c['appendfsync']==sys.argv[2] and c['maxmemory-policy']=='noeviction'; assert p['aof_last_write_status']=='ok' and p['aof_last_bgrewrite_status']=='ok'"
            container='capstone-evidence-store' if name=='redis-mitre' else 'capstone-main-deception-engine-1'
            subprocess.run(['docker','exec',container,'python','-B','-c',code,name,fsync],check=True,capture_output=True,timeout=15)
        subprocess.run(['docker','exec','capstone-main-redpanda-1','rpk','cluster','info','--brokers','127.0.0.1:9092'],check=True,capture_output=True,timeout=15)
    check('redis_redpanda',persistence)
    if args.exercise:
        check('backend_hr',lambda:command('containment','validate_backend_containment.py'))
        check('postgres_origin',lambda:command('postgres','validate_query_trace_runtime.py','--protocol','postgres'))
        check('mysql_origin',lambda:command('mysql','validate_query_trace_runtime.py','--protocol','mysql'))
        check('evidence_export',lambda:command('export','export_research_evidence.py','--traffic-origin','operator_validation','--output',args.output/'operator-export'))
    else:
        checks.update({k:'NOT_VERIFIED' for k in ('backend_hr','postgres_origin','mysql_origin','evidence_export')})
    if args.baseline:check('reboot_retained_state',lambda:command('recovery','verify_recovery.py','--check',args.baseline))
    else:checks['reboot_retained_state']='NOT_VERIFIED'
    def host_firewall():
        for chain in ('HONEYPOT-INPUT','HONEYPOT-FORWARD'):
            output=subprocess.check_output(['iptables','-S',chain],text=True)
            assert '-j DROP' in output and '-i docker0 -j RETURN' not in output
        assert subprocess.check_output(['systemctl','is-active','honeypot-firewall.service'],text=True).strip()=='active'
        assert subprocess.check_output(['systemctl','is-active','honeypot.service'],text=True).strip()=='active'
    check('steady_host_firewall',host_firewall)
    report={'schema_version':1,'deployment_id':manifest['deployment_id'],'run_id':manifest['run_id'],
        'manifest_id':manifest['manifest_id'],'checked_at':datetime.now(timezone.utc).isoformat(),'checks':checks,'artifacts':artifacts,
        'status':'PASS' if all(v=='PASS' for v in checks.values()) else 'NOT_READY'}
    (args.output/'private-report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report));return int(report['status']!='PASS')


if __name__=='__main__':raise SystemExit(main())
