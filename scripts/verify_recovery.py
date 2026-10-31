"""Read-only before/after retained-state verification. Never restarts or deletes data."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from datetime import datetime,timezone

CHILD=r'''
import sys,json,hashlib,os
import redis
role=sys.argv[-1]
r=redis.Redis(host=os.environ['REDIS_HOST'],decode_responses=True,socket_timeout=5)
records={};world_records=0
if role=='deception':
 for key in r.scan_iter('deceptive-principal:*'):
  if r.type(key)!='string':continue
  raw=r.get(key)
  try:record=json.loads(raw)
  except (ValueError,TypeError):continue
  if not isinstance(record,dict) or not record.get('principal_id'):continue
  records[key]=hashlib.sha256(raw.encode()).hexdigest()
  world_records+=int(bool(record.get('persistent_mutations') or record.get('world_commitments') or record.get('persistent_objects')))
else:
 for kind in ('decision','application','outcome'):
  for key in r.scan_iter('evidence:strategy_trace:'+kind+':*'):
   raw=r.get(key)
   if raw and (r.pttl(key)>600000 or r.pttl(key)==-1):records[key]=hashlib.sha256(raw.encode()).hexdigest()
 from main import IP_SALT_KEY
 raw=r.get(IP_SALT_KEY)
 if raw:records[IP_SALT_KEY]=hashlib.sha256(raw.encode()).hexdigest()
journal={k:hashlib.sha256(v.encode()).hexdigest() for k,v in r.hgetall('evidence:research-journal:v1:records').items()} if role=='evidence' else {}
metadata=r.hgetall('evidence:strategy_trace:index:v1:meta') if role=='evidence' else {}
p=r.info('persistence')
print(json.dumps({'records':records,'journal':journal,'index_metadata':metadata,'world_records':world_records,
 'aof_enabled':p.get('aof_enabled'),'aof_last_write_status':p.get('aof_last_write_status'),
 'aof_last_bgrewrite_status':p.get('aof_last_bgrewrite_status'),'redis_used_memory':r.info('memory')['used_memory']}))
'''


def capture():
    values={}
    for role,container in [('deception','capstone-main-deception-engine-1'),('evidence','capstone-evidence-store')]:
        p=subprocess.run(['docker','exec','-i',container,'python','-B','-',role],input=CHILD,capture_output=True,text=True,timeout=45)
        if p.returncode:raise RuntimeError('Recovery snapshot failed for '+role)
        values[role]=json.loads(p.stdout)
    values['captured_at']=datetime.now(timezone.utc).isoformat()
    return values


def compare(before,after):
    report={}
    for role in ('deception','evidence'):
        for field in ('records','journal'):
            old=before[role][field];new=after[role][field]
            if any(new.get(k)!=v for k,v in old.items()):raise ValueError('Retained recovery integrity failure: '+role+'/'+field)
        if after[role]['aof_enabled']!=1 or after[role]['aof_last_write_status']!='ok' or after[role]['aof_last_bgrewrite_status']!='ok':
            raise ValueError('Redis persistence unhealthy after recovery')
        report[role]={'retained_records_unchanged':len(before[role]['records']),
            'retained_journal_entries_unchanged':len(before[role]['journal']),
            'world_records':before[role]['world_records'],'aof_healthy':True}
    old=before['evidence']['index_metadata'];new=after['evidence']['index_metadata']
    if old.get('epoch')!=new.get('epoch') or int(new.get('sequence',0))<int(old.get('sequence',0)):
        raise ValueError('Retained index epoch/sequence was reset')
    return {'status':'PASS','state':report,'index_epoch_preserved':True,'index_sequence_monotonic':True}


def main():
    p=argparse.ArgumentParser(description=__doc__);choice=p.add_mutually_exclusive_group(required=True)
    choice.add_argument('--capture',type=Path);choice.add_argument('--check',type=Path);args=p.parse_args()
    try:
        state=capture()
        if args.capture:
            with args.capture.open('x',encoding='utf-8') as f:json.dump(state,f,indent=2)
            print(json.dumps({'snapshot_written':str(args.capture),'principal_records':len(state['deception']['records']),
                'evidence_records':len(state['evidence']['records']),'journal_entries':len(state['evidence']['journal']),
                'world_records':state['deception']['world_records']}))
        else:
            report=compare(json.loads(args.check.read_text(encoding='utf-8')),state)
            args.check.with_suffix('.result.json').write_text(json.dumps(report,indent=2)+'\n')
            print(json.dumps(report))
        return 0
    except Exception as exc:print(json.dumps({'status':'FAIL','error_category':type(exc).__name__}));return 1


if __name__=='__main__':raise SystemExit(main())
