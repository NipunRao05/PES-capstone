"""Explicit local fixture/restart check. Never deletes non-fixture keys."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import time


def inside(stage):
    import hashlib
    import os
    import statistics
    from uuid import uuid4
    sys.path.insert(0,'/app')
    import redis
    import trace_index
    from strategy_traces import TraceStore
    from strategy_outcomes import evaluate
    from research_journal import Journal, JournalCapacityError
    r=redis.Redis(host='redis-mitre',decode_responses=True,socket_timeout=15)
    statefile=Path('/tmp/hardening2-durability.json')
    if stage=='before':
        state={'prefix':'hardening2_'+uuid4().hex,'existing':{}}
        for key in r.scan_iter('evidence:strategy_trace:*'):
            if r.type(key)=='string':state['existing'][key]=hashlib.sha256(r.get(key).encode()).hexdigest()
        state['decisions']=[];state['applications']=[]
        state['baseline_memory']=r.info('memory')['used_memory']
    else:state=json.loads(statefile.read_text())
    prefix=state['prefix'];original_key=TraceStore.key
    class PrivateStore(TraceStore):
        @staticmethod
        def key(kind,identity):return original_key(kind,identity).replace('evidence:strategy_trace:',prefix+':trace:',1)
    trace_index.PREFIX=prefix+':index'
    for name in ('WRITE','READ','ACTIVATE'):
        setattr(trace_index,name,getattr(trace_index,name).replace('evidence:strategy_trace:',prefix+':trace:'))
    store=PrivateStore(r,3600)
    journal=Journal(r,3600,capacity=132,prefix=prefix+':journal')
    if stage=='before':
        # Actual retained engine fixture encodings, never attacker data printed.
        decisions=[json.loads(r.get(k)) for k in state['existing'] if ':decision:' in k]
        applications=[json.loads(r.get(k)) for k in state['existing'] if ':application:' in k]
        original=next(d for d in decisions if d.get('traffic_origin')=='operator_validation')
        app=next(a for a in applications if a['decision_id']==original['decision_id'])
        start=time.perf_counter()
        for n in range(132):
            decision={**original,'decision_id':str(uuid4()),'session_id':prefix,'reason_code':'HARDENING2_ENGINEERING_FIXTURE'}
            application={**app,'decision_id':decision['decision_id'],'application_id':str(uuid4())}
            state['decisions'].append(decision);state['applications'].append(application)
            store.store('decision',decision);store.store('application',application)
            journal.append(prefix,'queries',str(n),{'traffic_origin':'operator_validation','deployment_manifest_id':os.environ['RESEARCH_MANIFEST_ID'],'optional':None})
        pairs=[{'decision':state['decisions'][0],'application':state['applications'][0]}]
        from datetime import datetime,timedelta
        close=(datetime.fromisoformat(original['timestamp'])+timedelta(seconds=1)).isoformat()
        state['outcome']=evaluate(prefix,pairs,[],closed_at=close,as_of=close)[0]
        store.store('outcome',state['outcome'])
        state['fixture_admission_seconds']=time.perf_counter()-start
        try:journal.append(prefix,'queries','overflow',{})
        except JournalCapacityError:pass
        else:raise AssertionError('Capacity did not reject')
        state['snapshot']=store.indexed_snapshot()
        state['journal_page']=journal.page()
        state['memory_after']=r.info('memory')['used_memory']
        statefile.write_text(json.dumps(state))
        print(json.dumps({'stage':stage,'existing_records':len(state['existing']),'fixture_records':265,'journal_records':132,
            'admission_seconds':state['fixture_admission_seconds'],'memory_delta_bytes':state['memory_after']-state['baseline_memory']}))
        return
    assert store.indexed_snapshot()==state['snapshot']
    assert journal.page()==state['journal_page']
    assert journal.status()['metadata']['capacity_rejections']=='1'
    for key,digest in state['existing'].items():
        assert hashlib.sha256((r.get(key) or '').encode()).hexdigest()==digest,'Unrelated record changed'
    for kind,records in [('decision',state['decisions']),('application',state['applications']),('outcome',[state['outcome']])]:
        for record in records:assert store.store(kind,record)=='unchanged'
    first=journal.page();second=journal.page(after=first['after_sequence'],maximum=first['snapshot_max_sequence'],epoch=first['epoch'])
    assert len(first['entries'])==128 and len(second['entries'])==4 and second['done']
    added={**state['decisions'][0],'decision_id':str(uuid4())}
    store.store('decision',added)
    sizes={}
    for kind,records in [('decision',state['decisions']),('application',state['applications']),('outcome',[state['outcome']])]:
        lengths=[len(r.get(store.key(kind,record[kind+'_id'])).encode()) for record in records]
        sizes[kind]={'n':len(lengths),'median_bytes':statistics.median(lengths),'maximum_bytes':max(lengths)}
    p=r.info('persistence')
    assert p['aof_enabled']==1 and p['aof_last_write_status']=='ok' and p['aof_last_bgrewrite_status']=='ok'
    tracked=list(r.scan_iter(prefix+':*'))
    assert tracked and all(k.startswith(prefix+':') for k in tracked)
    r.delete(*tracked)
    print(json.dumps({'stage':stage,'status':'PASS','existing_records_unchanged':len(state['existing']),
        'fixture_trace_records_survived':265,'journal_records_survived':132,'pages':[128,4],
        'index_unchanged':True,'replay_unchanged':True,'new_write_after_restart':True,'private_keys_cleaned':len(tracked),
        'record_sizes':sizes,'aof_enabled':p['aof_enabled'],'aof_last_write_status':p['aof_last_write_status']}))


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--inside',choices=['before','after'])
    args=parser.parse_args()
    if args.inside:inside(args.inside);return
    source=Path(__file__).read_text(encoding='utf-8')
    def call(stage):
        result=subprocess.run(['docker','exec','-i','capstone-evidence-store','python','-B','-','--inside',stage],input=source,text=True,capture_output=True,timeout=40)
        if result.returncode:raise RuntimeError(result.stderr)
        return json.loads(result.stdout)
    before=call('before')
    start=time.perf_counter()
    subprocess.run(['docker','restart','capstone-main-redis-mitre-1'],check=True,capture_output=True,timeout=30)
    for _ in range(20):
        ready=subprocess.run(['docker','exec','capstone-main-redis-mitre-1','redis-cli','PING'],capture_output=True,text=True,timeout=5)
        if ready.returncode==0 and ready.stdout.strip()=='PONG':break
        time.sleep(.25)
    after=call('after')
    report={'before':before,'after':after,'restart_and_validation_seconds':time.perf_counter()-start}
    output=Path('.runtime/research-durability-validation.json');output.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))


if __name__=='__main__':main()
