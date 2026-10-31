"""Run on stdin inside Evidence Store; isolated representative 1,000-query sizing."""
import sys
sys.path.insert(0,'/app')
import hashlib
import json
import os
import time
from uuid import uuid4
from datetime import datetime,timedelta,timezone
import redis
import main
import trace_index
from strategy_traces import TraceStore
from strategy_outcomes import evaluate

r=redis.Redis(host='redis-mitre',decode_responses=True,socket_timeout=15)
prefix='hardening2_size_'+uuid4().hex
before=r.info('memory')['used_memory'];started=time.perf_counter()
original_key=TraceStore.key
class PrivateStore(TraceStore):
    @staticmethod
    def key(kind,identity):return original_key(kind,identity).replace('evidence:strategy_trace:',prefix+':trace:',1)
trace_index.PREFIX=prefix+':index'
for name in ('WRITE','READ','ACTIVATE'):
    setattr(trace_index,name,getattr(trace_index,name).replace('evidence:strategy_trace:',prefix+':trace:'))
from research_journal import Journal
main.SESSION_PREFIX=prefix+':session:';main.SESSION_INDEX=prefix+':sessions';main.HEALTH=prefix+':health'
repository=main.EvidenceRepository(r);repository.journal=Journal(r,3600,prefix=prefix+':journal')
store=PrivateStore(r,3600)
sample=next(json.loads(r.get(k)) for k in r.scan_iter('evidence:strategy_trace:decision:*') if json.loads(r.get(k)).get('traffic_origin')=='operator_validation')
sample_app=next(json.loads(r.get(k)) for k in r.scan_iter('evidence:strategy_trace:application:*') if json.loads(r.get(k))['decision_id']==sample['decision_id'])
metadata={'traffic_origin':'operator_validation','deployment_manifest_id':os.environ['RESEARCH_MANIFEST_ID']}
stamp=datetime.now(timezone.utc);closed=(stamp+timedelta(seconds=10)).isoformat()
for n in range(1000):
    sid=prefix+'_'+str(n//10)
    if n%10==0:
        for index,event_type in enumerate(['session_start','principal_created','session_profile']):
            repository.ingest_kafka('pg-session-events',{'session_id':sid,'event_type':event_type,'timestamp':stamp.isoformat(),
                'protocol':'postgres','username':'fixture','database':'testdb',**metadata},0,n*10+index)
    decision={**sample,'decision_id':str(uuid4()),'session_id':sid,'timestamp':stamp.isoformat(),'query_execution_id':str(uuid4()),'request_started_at':stamp.isoformat()}
    application={**sample_app,'decision_id':decision['decision_id'],'application_id':str(uuid4()),'timestamp':stamp.isoformat()}
    store.store('decision',decision);store.store('application',application)
    outcome=evaluate(sid,[{'decision':decision,'application':application}],[],closed_at=closed,as_of=closed)[0]
    store.store('outcome',outcome)
    repository.ingest_kafka('pg-query-events',{'session_id':sid,'timestamp':stamp.isoformat(),'protocol':'postgres','database':'testdb','username':'fixture',
        'query_raw':'select first_name,last_name,email,salary from employees limit 10','query_normalized':'select first_name,last_name,email,salary from employees limit ?',
        'fingerprint':'select first_name,last_name,email,salary from employees limit ?',
        'query_execution_id':decision['query_execution_id'],'request_started_at':stamp.isoformat(),'decision_id':decision['decision_id'],
        'application_id':application['application_id'],'outcome_verified':True,'success':True,'authority':'deception_engine',**metadata},0,n)
    if n%10==9:
        repository.ingest_kafka('pg-session-events',{'session_id':sid,'event_type':'session_end','timestamp':closed,'query_count':10,
            'protocol':'postgres','username':'fixture','database':'testdb',**metadata},0,n*10+9)
after=r.info('memory')['used_memory'];elapsed=time.perf_counter()-started
extra_decision={**decision,'decision_id':str(uuid4())}
extra_application={**application,'decision_id':extra_decision['decision_id'],'application_id':str(uuid4())}
store.store('decision',extra_decision);store.store('application',extra_application)
extra_outcome=evaluate(sid,[{'decision':extra_decision,'application':extra_application}],[],closed_at=closed,as_of=closed)[0]
store.store('outcome',extra_outcome)
assert all(store.list_records(kind)['kinds'][kind]['entries'] for kind in ('decision','application','outcome'))
keys=list(r.scan_iter(prefix+':*'))
assert keys and all(k.startswith(prefix+':') for k in keys)
serialized=sum(len(r.get(k).encode()) for k in keys if r.type(k)=='string')
print(json.dumps({'fixture_queries':1000,'sessions':100,'outcomes':1000,'principal_events':100,'journal_events':repository.journal.status()['entries'],
    'redis_used_memory_delta_bytes':after-before,'bytes_per_query_with_all_modeled_duplicates':(after-before)/1000,
    'elapsed_seconds':elapsed,'private_key_count':len(keys),'string_trace_payload_bytes':serialized,'admitted_beyond_1000_per_kind':True}))
r.delete(*keys)
