"""Read-only post-smoke audit. Reports counts/IDs only; no secret values or records."""
import hashlib
import hmac
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

root=Path(__file__).resolve().parents[2]
env={}
for line in (root/'.env').read_text(encoding='utf-8').splitlines():
    if '=' in line and not line.lstrip().startswith('#'):
        key,value=line.split('=',1);env[key.strip()]=value.strip().strip('"').strip("'")
passwords=[hmac.new(env['DECEPTIVE_PRINCIPAL_HMAC_SECRET'].encode(),('native-demo:'+name).encode(),hashlib.sha256).hexdigest() for name in ('fake_compro1','fake_unused')]
docker=shutil.which('docker') or str(Path(os.environ['LOCALAPPDATA'])/'Programs/DockerDesktop/resources/bin/docker.exe')
code=r"""
import json,sys,time,redis,requests
from kafka import KafkaConsumer,TopicPartition
passwords=json.load(sys.stdin)
checks={}
registries=[]
for host in ('redis-deception','redis-mitre'):
    client=redis.Redis(host=host,decode_responses=True,socket_timeout=3)
    count=0
    for key in client.scan_iter(count=200):
        count+=1
        if count>50000:raise AssertionError('Redis audit bound exceeded')
        kind=client.type(key)
        if kind=='string':value=client.get(key)
        elif kind=='hash':value=client.hgetall(key)
        elif kind=='list':value=client.lrange(key,0,-1)
        elif kind=='set':value=list(client.smembers(key))
        elif kind=='zset':value=client.zrange(key,0,-1,withscores=True)
        else:raise AssertionError('unsupported Redis value type')
        raw=json.dumps(value)
        if any(secret in key or secret in raw for secret in passwords):raise AssertionError('credential found in Redis')
        if host=='redis-deception' and kind=='string' and key.startswith('deceptive-principal:'):
            try:record=json.loads(value)
            except Exception:continue
            if isinstance(record,dict) and record.get('username')=='fake_compro1':
                registries.append({k:record[k] for k in ('principal_id','protocol','created_by_session_id','linked_session_ids','enabled','world_revision')})
    checks[host]={'keys_scanned':count,'plaintext_matches':0}
consumer=KafkaConsumer(bootstrap_servers=['redpanda:9092'],group_id=None,enable_auto_commit=False,consumer_timeout_ms=1000)
topics=['pg-query-events','mysql-query-events','pg-session-events','mysql-session-events','pg-query-dedup','mysql-query-dedup']
parts=[TopicPartition(topic,p) for topic in topics for p in (consumer.partitions_for_topic(topic) or [])]
assert parts,'No Kafka partitions'
consumer.assign(parts);ends=consumer.end_offsets(parts);consumer.seek_to_beginning(*parts)
events=[];count=0;deadline=time.monotonic()+40
while time.monotonic()<deadline:
    for batch in consumer.poll(timeout_ms=500,max_records=1000).values():
        for message in batch:
            count+=1
            raw=message.value.decode()
            assert not any(secret in raw for secret in passwords),'credential found in Kafka'
            value=json.loads(raw)
            if isinstance(value,dict):events.append(value)
    if all(consumer.position(part)>=ends[part] for part in parts):break
else:raise AssertionError('Kafka audit did not reach captured end offsets')
consumer.close()
checks['redpanda']={'messages_scanned':count,'plaintext_matches':0}
for record in registries:
    pid=record['principal_id'];creator=record['created_by_session_id']
    relevant=[event for event in events if event.get('principal_id')==pid or event.get('deceptive_principal_id')==pid]
    kinds={e.get('event_type') for e in relevant}
    assert {'deceptive_principal_created','deceptive_principal_authenticated','session_link','query'}<=kinds, 'missing principal event kind'
    assert any(e.get('is_trap') and e.get('post_return_exploration_depth')==3 for e in relevant),'missing return trap measurement'
    links=[e for e in relevant if e.get('event_type')=='session_link']
    assert all(e.get('parent_session_id')==creator and e.get('confidence')==1 for e in links),'incorrect link'
    ips=sorted({e.get('client_ip') for e in relevant if e.get('client_ip')})
    assert len(ips)>=2,'return sessions did not use distinct IP addresses'
    evidence=requests.get('http://evidence-store:8011/evidence/session/'+creator,timeout=5)
    if evidence.status_code==404:
        evidence=requests.get('http://evidence-store:8011/evidence/sessions/'+creator,timeout=5)
    evidence.raise_for_status()
    assert not any(secret in evidence.text for secret in passwords),'credential in evidence'
    parent=evidence.json()
    assert any(e.get('event_type')=='deceptive_principal_created' and e.get('principal_id')==pid for e in parent['connection_events']),'missing creation evidence'
    child=record['linked_session_ids'][-1]
    response=requests.get('http://evidence-store:8011/evidence/session/'+child,timeout=5)
    if response.status_code==404:response=requests.get('http://evidence-store:8011/evidence/sessions/'+child,timeout=5)
    response.raise_for_status();detail=response.json()
    assert detail['deceptive_principal_id']==pid and detail['is_return_session'],'missing child evidence identity'
    assert any(e.get('event_type')=='session_link' and e.get('parent_session_id')==creator for e in detail['connection_events']),'missing stored link'
    assert not any(secret in response.text for secret in passwords),'credential in evidence'
    checks[record['protocol']]={'principal_id':pid,'creator_session_id':creator,'latest_return_session_id':child,
       'links_in_redpanda':len(links),'return_source_ips':ips,'creation_and_link_evidence':True,'world_revision':record['world_revision']}
assert len(registries)==2,'expected both native protocol identities'
print(json.dumps(checks))
"""
result=subprocess.run([docker,'exec','-i','capstone-evidence-store','python','-c',code],input=json.dumps(passwords),text=True,capture_output=True)
# Audit code never prints records; redact defensively even on unexpected failures.
output=result.stdout+result.stderr
for secret in passwords:output=output.replace(secret,'[REDACTED]')
print(output.strip())
if result.returncode:sys.exit(result.returncode)
containers=['capstone-main-pgproxy-1','capstone-main-mysqlproxy-1','capstone-main-deception-engine-1','capstone-main-session-module-1','capstone-evidence-store','capstone-main-postgres-1','capstone-main-mysql-1','capstone-main-redpanda-1','capstone-main-metrics-bridge-1']
for name in containers:
    result=subprocess.run([docker,'logs','--since','48h',name],text=True,capture_output=True)
    if result.returncode:raise SystemExit('Log audit failed: '+name)
    if any(secret in result.stdout or secret in result.stderr for secret in passwords):raise SystemExit('Credential found in logs: '+name)
print(json.dumps({'logs':{'containers_scanned':len(containers),'plaintext_matches':0}}))
