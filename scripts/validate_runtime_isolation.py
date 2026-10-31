"""Bounded connectivity/route/capability checks; no HTTP metadata requests or payloads."""
import json
from pathlib import Path
import subprocess
import sys
from datetime import datetime,timezone


def call(command,timeout=8):
    return subprocess.run(command,capture_output=True,text=True,timeout=timeout)


def main():
    from configuration import load,render
    f,p,o,e,c=load();model=render(f,p,o,c)['compose.yaml'];rows={};checks=[]
    for name,s in model['services'].items():
        container=s.get('container_name','capstone-main-'+name+'-1')
        data=json.loads(subprocess.check_output(['docker','inspect',container],text=True))[0]
        h=data['HostConfig'];ports={k:v for k,v in data['NetworkSettings']['Ports'].items() if v}
        assert h['Memory']>0 and h['NanoCpus']>0 and h['PidsLimit']>0
        assert h['LogConfig']['Type']=='json-file'
        assert not any(m['Destination']=='/var/run/docker.sock' for m in data['Mounts'])
        assert all(n!='bridge' and not n.endswith('_default') for n in data['NetworkSettings']['Networks'])
        if ports:assert name in {'pgproxy','mysqlproxy','operator-gateway'}
        assert all(v['HostIp']=='127.0.0.1' for values in ports.values() for v in values)
        rows[name]={'container':container,'networks':data['NetworkSettings']['Networks'],'ports':ports,
            'memory_limit_bytes':h['Memory'],'cpu_limit':h['NanoCpus']/1e9,'pids_limit':h['PidsLimit'],
            'restart':h['RestartPolicy']['Name'],'logging':h['LogConfig'],'image':data['Image'],
            'health':data['State'].get('Health',{}).get('Status','ONE_SHOT'),
            'mounts':[{'destination':m['Destination'],'type':m['Type'],'rw':m['RW']} for m in data['Mounts']]}
    probes={
        'pgproxy':[('deception-engine',8001),('redpanda',9092),('postgres',5432)],
        'mysqlproxy':[('deception-engine',8001),('redpanda',9092),('mysql',3306)],
        'deception-engine':[('redis-deception',6379),('evidence-store',8011)],
        'evidence-store':[('redis-mitre',6379),('redpanda',9092)],
        'grafana':[('prometheus',9090),('loki',3100)],
        'sandbox-replay-engine':[('redis-mitre',6379),('evidence-store',8011),('sandbox-postgres',5432),('sandbox-mysql',3306)]}
    for name,targets in probes.items():
        if name not in rows:continue
        for host,port in targets:
            if host not in rows:continue
            if name in {'pgproxy','mysqlproxy','grafana'}:
                command=['/bin/sh','-c',f'nc -z -w 2 {host} {port}']
            else:
                command=['python','-B','-c',f'import socket;socket.create_connection(({host!r},{port}),2).close()']
            result=call(['docker','exec',rows[name]['container'],*command])
            checks.append({'check':name+' -> '+host+':'+str(port),'passed':result.returncode==0})
    for name in ('pgproxy','mysqlproxy','operator-gateway'):
        container=rows[name]['container']
        status=call(['docker','exec','-u','65532',container,'cat','/proc/1/status']).stdout
        assert all(line.endswith('0000000000000000') for line in status.splitlines() if line.startswith(('CapEff:','CapPrm:','CapBnd:','CapAmb:')))
        assert 'NoNewPrivs:\t1' in status
        for address,port in [('169.254.169.254',80),('1.1.1.1',443),('172.28.10.1',2375),('172.28.10.1',22)]:
            result=call(['docker','exec','-u','65532',container,'nc','-z','-w','1',address,str(port)])
            checks.append({'check':name+' blocked '+address+':'+str(port),'passed':result.returncode!=0})
        result=call(['docker','exec','-u','65532',container,'/bin/sh','-c','iptables -P OUTPUT ACCEPT >/dev/null 2>&1'])
        checks.append({'check':name+' cannot alter firewall','passed':result.returncode!=0})
        result=call(['docker','exec','-u','65532',container,'timeout','3','nslookup','example.com'],timeout=6)
        checks.append({'check':name+' external DNS blocked','passed':result.returncode!=0})
    for name in ('deception-engine','evidence-store','sandbox-replay-engine'):
        if name not in rows:continue
        for address,port in [('169.254.169.254',80),('1.1.1.1',443),('172.28.10.1',2375)]:
            code=f'import socket; socket.create_connection(({address!r},{port}),1).close()'
            result=call(['docker','exec',rows[name]['container'],'python','-B','-c',code])
            checks.append({'check':name+' blocked '+address,'passed':result.returncode!=0})
    if 'sandbox-replay-engine' in rows:
        ip=next(v['IPAddress'] for k,v in rows['postgres']['networks'].items() if k.endswith('_state'))
        result=call(['docker','exec',rows['sandbox-replay-engine']['container'],'python','-B','-c',
            f'import socket;socket.create_connection(({ip!r},5432),1).close()'])
        checks.append({'check':'sandbox cannot reach main PostgreSQL by actual IP','passed':result.returncode!=0})
    report={'timestamp':datetime.now(timezone.utc).isoformat(),'ok':all(c['passed'] for c in checks),'checks':checks,'services':rows}
    Path('.runtime/pass3-isolation.json').write_text(json.dumps(report,indent=2)+'\n')
    for check in checks:print(('PASS ' if check['passed'] else 'FAIL ')+check['check'])
    return 0 if report['ok'] else 1


if __name__=='__main__':raise SystemExit(main())
