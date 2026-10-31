import pytest
import json
import threading
from types import SimpleNamespace, ModuleType
from unittest.mock import patch
from research_journal import Journal, JournalCapacityError
from test_evidence_store import MemoryRedis, EvidenceRepository
from strategy_traces import TraceStore, validate_ingestion, TraceConflict
from test_strategy_traces import RedisDouble
from test_strategy_trace_endpoint import pair
from strategy_outcomes import evaluate
from indexed_aggregation import indexed_aggregate
from test_trace_index import SCOPE


def test_journal_replay_conflict_capacity_and_snapshot():
    redis=MemoryRedis(); redis.now=1000
    journal=Journal(redis,ttl=100,capacity=3)
    assert journal.append('s','queries','1',{'value':None})=='inserted'
    first=journal.page(limit=1)
    assert journal.append('s','queries','1',{'value':None})=='unchanged'
    with pytest.raises(ValueError):journal.append('s','queries','1',{'value':0})
    for identity in ['2','3']:journal.append('s','queries',identity,{'value':None})
    assert len(journal.page(maximum=first['snapshot_max_sequence'],epoch=first['epoch'])['entries'])==1
    with pytest.raises(JournalCapacityError):journal.append('s','queries','4',{})
    assert journal.status()['metadata']['capacity_rejections']=='1'
    redis.now+=101
    assert journal.page()['missing_records']==3
    journal.append('s','queries','4',{})
    assert journal.page()['entries'][0]['sequence']==4


def test_journal_preserves_events_after_projection_rollover():
    repo=EvidenceRepository(MemoryRedis())
    for i in range(5):repo._append_once('s','queries',str(i),{'value':None},2)
    assert len(repo.client.lrange(repo._child_key('s','queries'),0,-1))==2
    assert len(repo.journal.page()['entries'])==5


def test_configured_pseudonymization_key_must_match_retained_identity(monkeypatch):
    redis=MemoryRedis()
    monkeypatch.setenv('EVIDENCE_IP_HASH_SALT','fixture-stable-pseudonym-key')
    first=EvidenceRepository(redis)
    assert EvidenceRepository(redis).ip_hash_salt==first.ip_hash_salt
    monkeypatch.setenv('EVIDENCE_IP_HASH_SALT','changed-unapproved-pseudonym-key')
    with pytest.raises(RuntimeError,match='continuity'):EvidenceRepository(redis)


def test_large_online_report_fails_explicitly_instead_of_reporting_prefix():
    import main
    def oversized(**kwargs):raise ValueError('REPORT_LIMIT_EXCEEDED_USE_PAGINATED_EXPORT')
    runtime=SimpleNamespace(repository=SimpleNamespace(strategy_traces=lambda:SimpleNamespace(indexed_snapshot=oversized)))
    with patch.object(main,'require_runtime',return_value=runtime):
        with pytest.raises(main.HTTPException) as failure:
            main.aggregate_strategy_outcomes({'population_mode':'INDEXED_RETAINED','filters':SCOPE})
        assert failure.value.status_code==413


def test_origin_manifest_outcome_filters_and_legacy():
    store=TraceStore(RedisDouble(),3600)
    p=pair()
    for record in p.values():record.update(traffic_origin='operator_validation',deployment_manifest_id='a'*64)
    validate_ingestion(p)
    for kind,record in p.items():store.store(kind,record)
    outcome=evaluate('s1',[p],[],closed_at='2026-10-30T00:00:10+00:00',as_of='2026-10-30T00:00:10+00:00')[0]
    assert outcome['traffic_origin']=='operator_validation' and outcome['deployment_manifest_id']=='a'*64
    store.store('outcome',outcome)
    with pytest.raises(TraceConflict):store.store('outcome',{**outcome,'traffic_origin':'research_external'})
    for origin,count in [('research_external',0),('operator_validation',1),('unknown',0)]:
        report=indexed_aggregate(store,filters={**SCOPE,'traffic_origin':origin})
        assert report['retained_applications']==count
        assert report['collection_completeness']=='NOT_VERIFIED'
    p['application']['traffic_origin']='research_external'
    with pytest.raises(ValueError):validate_ingestion(p)


@pytest.mark.parametrize('failure',[False,True])
def test_consumer_commits_only_after_successful_journal_admission(failure):
    import main
    from collections import namedtuple
    stop=threading.Event();commits=[]
    class Consumer:
        def __init__(self,*args,**kwargs):assert kwargs['enable_auto_commit'] is False
        def __iter__(self):
            yield SimpleNamespace(value=json.dumps({'session_id':'s'}).encode(),topic='pg-query-events',partition=0,offset=4)
        def commit(self,offsets):commits.append(offsets);stop.set()
        def close(self):pass
    def ingest(*args):
        if failure:
            stop.set()
            raise JournalCapacityError('full')
        return True
    structs=ModuleType('kafka.structs')
    structs.TopicPartition=namedtuple('TopicPartition','topic partition')
    structs.OffsetAndMetadata=namedtuple('OffsetAndMetadata','offset metadata leader_epoch')
    repository=SimpleNamespace(ingest_kafka=ingest)
    with patch.object(main,'KafkaConsumer',Consumer),patch.dict('sys.modules',{'kafka.structs':structs}):
        main.EvidenceConsumer(repository,stop).run()
    assert len(commits)==(0 if failure else 1)
    if commits:assert next(iter(commits[0].values())).offset==5
