import json
from copy import deepcopy
import pytest
import export_research_evidence as e
from deployment_manifest import resolved_nonsecret, digest


def test_configuration_digest_excludes_secret_rotation_but_tracks_policy():
    source={'environment':{'PASSWORD':'${PASSWORD}','RESEARCH_OPERATOR_KEY':'${RESEARCH_OPERATOR_KEY}','EVIDENCE_IP_HASH_SALT':'${EVIDENCE_IP_HASH_SALT}',
        'PORT':'${PORT:-8000}','LOCAL_LLM_MAX_OUTPUT_TOKENS':'64'}}
    first=resolved_nonsecret(source,{'PASSWORD':'one','RESEARCH_OPERATOR_KEY':'one','EVIDENCE_IP_HASH_SALT':'salt-one'})
    second=resolved_nonsecret(source,{'PASSWORD':'two','RESEARCH_OPERATOR_KEY':'two','EVIDENCE_IP_HASH_SALT':'salt-two'})
    assert digest(first)==digest(second)
    assert 'one' not in json.dumps(first)
    assert first['environment']['LOCAL_LLM_MAX_OUTPUT_TOKENS']=='64'
    assert digest(first)!=digest(resolved_nonsecret(source,{'PORT':'9000'}))


def test_export_origin_nulls_checksums_and_missing_relationships(tmp_path,monkeypatch):
    manifest={'created_at':'2026-10-31T00:00:00Z','images':{},'image_inventory_status':'NOT_CAPTURED'}
    manifest['manifest_id']=digest(manifest)
    decision={'decision_id':'d','traffic_origin':'operator_validation','nullable':None}
    application={'application_id':'a','decision_id':'missing','traffic_origin':'operator_validation'}
    def request(base,path,body=None,headers=None):
        if path.endswith('deployment-manifests'):return {'manifests':{manifest['manifest_id']:manifest}}
        if path.endswith('/status'):return {'collection_completeness':'NOT_VERIFIED'}
        if path.endswith('/session-projections/list'):
            return {'sessions':[],'maximum':0,'consistency':'MUTABLE_RANK_PAGES','truncated':False,'missing_sessions':0,'done':True}
        if path.endswith('research-journal/list'):
            return {'snapshot_max_sequence':0,'epoch':'','after_sequence':0,'done':True,'missing_records':0,'entries':[]}
        kind=body['kind']
        records={'decision':[decision],'application':[application],'outcome':[]}[kind]
        return {'snapshot_max_sequence':2,'index_epoch':'epoch','stale_members_removed':0,
            'kinds':{kind:{'entries':[{'record_id':r[kind+'_id'],'record':deepcopy(r),'sequence':i+1} for i,r in enumerate(records)],'done':True,'after_sequence':2}}}
    monkeypatch.setattr(e,'request',request)
    external=e.export('test',tmp_path/'external')
    assert external['record_counts']['decision']==0
    assert external['export_context_manifest_id']==manifest['manifest_id']
    assert json.loads((tmp_path/'external/deployments.json').read_text())
    assert e.validate(tmp_path/'external')['valid']
    info=e.export('test',tmp_path/'operator','operator_validation')
    assert info['record_counts']['decision']==1
    assert e.validate(tmp_path/'operator')['unresolved_relationships']==1
    assert '"nullable":null' in (tmp_path/'operator/traces.jsonl').read_text()
    with pytest.raises(FileExistsError):e.export('test',tmp_path/'operator')
    with (tmp_path/'operator/traces.jsonl').open('a') as stream:stream.write('{}\n')
    with pytest.raises(ValueError,match='checksum'):e.validate(tmp_path/'operator')
