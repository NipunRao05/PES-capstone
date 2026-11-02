"""Fail-closed artifact gate; never enables ingress or treats missing proof as PASS."""
import argparse
from datetime import datetime,timezone,timedelta
import hashlib
import json
import math
from pathlib import Path

REQUIRED_PRIVATE={'disk_secrets_resources','containerd_data_root','container_health','deployment_provenance','runtime_observability','egress_resources',
    'redis_redpanda','backend_hr','postgres_origin','mysql_origin','evidence_export','reboot_retained_state','steady_host_firewall'}


def load_report(path,deployment_id):
    data=json.loads(path.read_text())
    if data.get('deployment_id')!=deployment_id or data.get('status')!='PASS':raise ValueError('Report scope/status mismatch')
    checked=datetime.fromisoformat(data['checked_at'].replace('Z','+00:00'))
    age=datetime.now(timezone.utc)-checked
    if age<timedelta(minutes=-5) or age>timedelta(hours=24):raise ValueError('Proof is future-dated or older than24h')
    return data


def validate(paths,deployment_id):
    reports={name:load_report(path,deployment_id) for name,path in paths.items()}
    private=reports['private']
    if not REQUIRED_PRIVATE.issubset(private['checks']) or any(private['checks'][k]!='PASS' for k in REQUIRED_PRIVATE):
        raise ValueError('Private checks incomplete')
    if not {'runtime','isolation','containment','postgres','mysql','export','recovery'}.issubset(private['artifacts']):
        raise ValueError('Validator evidence files incomplete')
    for artifact in private['artifacts'].values():
        if 'path' not in artifact:raise ValueError('Missing validator artifact')
        target=paths['private'].parent/artifact['path']
        if target.is_symlink() or not target.resolve().is_relative_to(paths['private'].parent.resolve()):raise ValueError('Artifact escapes scope')
        if hashlib.sha256(target.read_bytes()).hexdigest()!=artifact['sha256']:raise ValueError('Artifact checksum mismatch')
    for name,vantage in [('admin','admin'),('other','other')]:
        report=reports[name]
        if report['vantage']!=vantage or report['expected_public'] or any(not c['passed'] for c in report['checks']):
            raise ValueError('External private-ingress evidence invalid')
        expected_ports={22,5432,3306,3000,8000,8001,8003,8011,8012,9090,9091,9092,9095,9096,9100,9644,3100,6379,15432,13306}
        if len(report['checks'])!=len(expected_ports) or {c['port'] for c in report['checks']}!=expected_ports:raise ValueError('External port manifest incomplete')
        for row in report['checks']:
            if row['reachable']!=(row['port']==22 and vantage=='admin'):raise ValueError('Unexpected reachable port')
    if reports['admin']['public_ip']!=reports['other']['public_ip']:raise ValueError('Different external targets')
    if not all(reports['infrastructure'].get(k) is expected for k,expected in
        [('ssh_restricted',True),('public_db_enabled',False),('management_private',True),('managed_identity_absent',True)]):
        raise ValueError('Effective cloud policy review incomplete')
    budget=reports['budget']
    for key in ('estimated_seven_day_usd','approved_usd'):
        value=budget.get(key)
        if type(value) not in (int,float) or not math.isfinite(value) or value<=0:raise ValueError('Budget amount must be finite and positive')
    if not budget.get('reviewer') or not budget.get('alerts_reviewed') or budget['estimated_seven_day_usd']>budget['approved_usd']:
        raise ValueError('Budget not approved for current estimate')
    backup=reports['backup']
    if not all(backup.get(k) is True for k in ('off_vm','export_validated','evidence_redis_loaded','principal_redis_loaded','stable_keys_preserved')):
        raise ValueError('Independent restore/key evidence incomplete')
    if reports['reboot'].get('manifest_id')!=private['manifest_id'] or not reports['reboot'].get('actual_vm_reboot'):
        raise ValueError('Actual reboot not demonstrated for current launch')
    return {'status':'PASS','deployment_id':deployment_id,'manifest_id':private['manifest_id'],
        'checked_at':datetime.now(timezone.utc).isoformat(),
        'artifacts':{name:hashlib.sha256(path.read_bytes()).hexdigest() for name,path in paths.items()},
        'scope':'Artifact completeness/integrity and operator attestations; not independent authentication or permission to publish'}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--deployment-id',required=True)
    for name in ('private','admin','other','infrastructure','budget','backup','reboot'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    try:report=validate({name:getattr(a,name) for name in ('private','admin','other','infrastructure','budget','backup','reboot')},a.deployment_id)
    except Exception as exc:report={'status':'NOT_READY','error_category':type(exc).__name__}
    with a.output.open('x') as out:json.dump(report,out,indent=2)
    print(json.dumps(report));return int(report['status']!='PASS')


if __name__=='__main__':raise SystemExit(main())
