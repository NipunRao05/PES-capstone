"""Bounded local image/log review and stateless replay backend recreation check."""
import json
from pathlib import Path
import subprocess
import time
import urllib.parse
import urllib.request


def command(*args):
    return subprocess.check_output(list(args),text=True,timeout=90)


def main():
    report={}
    images={name:'capstone-main-'+name+':runtime-v1' for name in
        ('deception-engine','session-module','evidence-store','sandbox-replay-engine','metrics-bridge')}
    review={}
    for name,image in images.items():
        code="import json,pathlib,importlib.util; print(json.dumps({'tests': [p.name for p in pathlib.Path('/app').glob('test*.py')], 'pytest_present': importlib.util.find_spec('pytest') is not None}))"
        data=json.loads(command('docker','run','--rm','--label','com.docker.compose.project=capstone-validation',
            '--network','none','--read-only','--entrypoint','python',image,'-B','-c',code))
        data['pip_check']=command('docker','run','--rm','--label','com.docker.compose.project=capstone-validation',
            '--network','none','--read-only','--entrypoint','python',image,'-B','-m','pip','check').strip()
        assert not data['tests'] and not data['pytest_present']
        data['image']=json.loads(command('docker','image','inspect',image,'--format','{{json .}}'))['Id']
        review[name]=data
    report['image_review']=review
    replay='capstone-sandbox-replay-engine'
    before=json.loads(command('docker','inspect',replay))[0]
    gateway_started=command('docker','inspect','capstone-main-operator-gateway-1','--format','{{.State.StartedAt}}').strip()
    old_ip=before['NetworkSettings']['Networks']['capstone-main_control']['IPAddress']
    # Docker may immediately reuse the old IP. Move this stateless backend to a
    # verified unused address first, so recreation exercises a real DNS change.
    network=json.loads(command('docker','network','inspect','capstone-main_control'))[0]
    occupied={row['IPv4Address'].split('/')[0] for row in network['Containers'].values()}
    temporary_ip='172.28.35.240'
    assert temporary_ip not in occupied
    command('docker','network','disconnect','capstone-main_control',replay)
    try:
        command('docker','network','connect','--ip',temporary_ip,'--alias','sandbox-replay-engine','capstone-main_control',replay)
    except Exception:
        command('docker','network','connect','--alias','sandbox-replay-engine','capstone-main_control',replay)
        raise
    old_ip=temporary_ip
    time.sleep(3)
    with urllib.request.urlopen('http://127.0.0.1:8012/readyz',timeout=5) as response:
        assert response.status==200
    # Recreate only a stateless application. Its database volumes are untouched.
    from configuration import load,ROOT,PROJECT
    _,_,_,env,_=load()
    env.update(HONEYPOT_CONFIGURED=PROJECT,COMPOSE_PROFILES='',COMPOSE_FILE='',COMPOSE_PROJECT_NAME=PROJECT)
    subprocess.run(['docker','compose','--project-directory',str(ROOT),'--env-file',str(ROOT/'config/empty.env'),
        '-p',PROJECT,'-f',str(ROOT/'.runtime/compose.yaml'),'up','-d','--force-recreate','--no-deps','sandbox-replay-engine'],
        env=env,check=True,timeout=90,stdout=subprocess.DEVNULL)
    after=json.loads(command('docker','inspect',replay))[0]
    deadline=time.monotonic()+60
    while True:
        try:
            with urllib.request.urlopen('http://127.0.0.1:8012/readyz',timeout=3) as response:
                assert response.status==200
            break
        except Exception:
            if time.monotonic()>deadline:raise
            time.sleep(1)
    assert gateway_started==command('docker','inspect','capstone-main-operator-gateway-1','--format','{{.State.StartedAt}}').strip()
    new_ip=after['NetworkSettings']['Networks']['capstone-main_control']['IPAddress']
    assert before['Id']!=after['Id']
    assert old_ip!=new_ip
    report['replay_recreation']={'new_container':True,'old_ip':old_ip,'new_ip':new_ip,
        'ip_changed':old_ip!=new_ip,'gateway_not_restarted':True,'readiness_http':200}
    services=['pgproxy','mysqlproxy','deception-engine','session-module','evidence-store',
        'redis-deception','redis-mitre','redpanda','postgres','mysql']
    coverage={}
    for service in services:
        params=urllib.parse.urlencode({'query':'{service="'+service+'"}','limit':'5','since':'24h'})
        data=json.load(urllib.request.urlopen('http://127.0.0.1:3100/loki/api/v1/query_range?'+params,timeout=10))
        rows=data['data']['result'];count=sum(len(row['values']) for row in rows)
        levels=sorted({row['stream'].get('level','') for row in rows})
        assert count and levels and '' not in levels,(service,count,levels)
        coverage[service]={'lines':count,'levels':levels}
    report['log_coverage']=coverage
    Path('.runtime/pass3-release-runtime.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))


if __name__=='__main__':main()
