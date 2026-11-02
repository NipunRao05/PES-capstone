import importlib.util
import io
import json
from pathlib import Path
import socket
import tarfile
import pytest
from build_deployment_archive import collect
from verify_external_ports import verify,MANAGEMENT
from validate_azure_gate import load_report
from validate_azure_gate import validate as gate,REQUIRED_PRIVATE
from backup_azure_evidence import validate,safe_name

ROOT=Path(__file__).resolve().parents[1]


def module(name):
    spec=importlib.util.spec_from_file_location(name,ROOT/'deployment/azure'/(name+'.py'))
    obj=importlib.util.module_from_spec(spec);spec.loader.exec_module(obj);return obj


@pytest.mark.parametrize('changed',[
    {'fstype':'xfs'}, {'children':[{'name':'partition'}]}, {'mountpoints':['/']}, {'type':'part'}])
def test_disk_refuses_unknown_or_occupied(changed):
    info={'type':'disk','fstype':None,'mountpoints':[None],**changed}
    with pytest.raises(ValueError):module('prepare_disk').action(info,[],True,True)


def test_disk_never_reformats_existing_or_unapproved():
    disk=module('prepare_disk');info={'type':'disk','fstype':None,'mountpoints':[None]}
    assert disk.action({**info,'fstype':'ext4'},[{'type':'ext4'}],True,False)=='mount_existing'
    for signatures,permission,zero in [([],False,True),([{'type':'gpt'}],True,True),([],True,False)]:
        with pytest.raises(ValueError):disk.action(info,signatures,permission,zero)
    assert disk.action(info,[],True,True)=='format_blank'
    assert disk.all_zero(io.BytesIO(b'\0'*100))
    assert not disk.all_zero(io.BytesIO(b'\0'*100+b'old-data'+b'\0'*100))


def test_host_rules_keep_ssh_restricted_and_runtime_egress_blocked():
    rules=module('host_firewall').rules('203.0.113.10/32')
    assert any('169.254.0.0/16' in row for _,row in rules)
    assert not any('docker0' in row for _,row in rules)
    assert [row for chain,row in rules if chain=='HONEYPOT-INPUT' and '--dport' in row and 'tcp' in row]==[
        ['-p','tcp','-s','203.0.113.10/32','--dport','22','-j','ACCEPT']]
    with pytest.raises(ValueError):module('host_firewall').rules('0.0.0.0/0')


def test_external_observation_does_not_enable_ports():
    class Connection:
        def __enter__(self):return self
        def __exit__(self,*args):pass
    def connector(address,timeout):
        if address[1]==22:return Connection()
        raise socket.timeout()
    assert all(row['passed'] for row in verify('203.0.113.1','admin',connect=connector))
    assert not all(row['passed'] for row in verify('203.0.113.1','other',connect=connector))
    assert not any(row['expected_reachable'] for row in verify('203.0.113.1','other',connect=connector) if row['port'] in MANAGEMENT)


def test_archive_excludes_terraform_secret_state_variants(tmp_path):
    directory=tmp_path/'deployment';directory.mkdir()
    for name in ('terraform.tfstate','terraform.tfstate.backup','private.tfvars.json','plan.tfplan','secrets.env'):
        (directory/name).write_text('private')
    assert collect(tmp_path,{'services':{}})=={}


def test_gate_does_not_accept_missing_or_unsuccessful_proof(tmp_path):
    path=tmp_path/'report.json';path.write_text(json.dumps({'deployment_id':'a','status':'NOT_VERIFIED'}))
    with pytest.raises(ValueError):load_report(path,'a')


@pytest.mark.parametrize('name',['../secret','/absolute','prefix/../../bad','prefix\\bad'])
def test_backup_path_rejection(name):
    with pytest.raises(ValueError):safe_name(name)


def test_backup_validation_refuses_links_and_missing_manifest(tmp_path):
    target=tmp_path/'bad.tar'
    with tarfile.open(target,'w') as archive:
        info=tarfile.TarInfo('bad-link');info.type=tarfile.SYMTYPE;info.linkname='/etc/shadow';archive.addfile(info)
    with pytest.raises(ValueError):validate(target)


def test_gate_complete_fixture_and_missing_proof_tampering(tmp_path):
    from datetime import datetime,timezone
    import hashlib
    common={'status':'PASS','deployment_id':'fixture-only','checked_at':datetime.now(timezone.utc).isoformat()}
    manifest='f'*64
    artifacts={}
    for name in ('runtime','isolation','containment','postgres','mysql','export','recovery'):
        path=tmp_path/(name+'.txt');path.write_text('engineering-test-fixture')
        artifacts[name]={'path':path.name,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
    private={**common,'manifest_id':manifest,'checks':dict.fromkeys(REQUIRED_PRIVATE,'PASS'),'artifacts':artifacts}
    rows={
        'private':private,
        'infrastructure':{**common,'ssh_restricted':True,'public_db_enabled':False,'management_private':True,'managed_identity_absent':True},
        'budget':{**common,'reviewer':'unit-fixture','alerts_reviewed':True,'estimated_seven_day_usd':45,'approved_usd':50},
        'backup':{**common,**dict.fromkeys(('off_vm','export_validated','evidence_redis_loaded','principal_redis_loaded','stable_keys_preserved'),True)},
        'reboot':{**common,'actual_vm_reboot':True,'manifest_id':manifest}}
    for name in ('admin','other'):
        ports=[22,5432,3306,*MANAGEMENT]
        rows[name]={**common,'public_ip':'203.0.113.1','vantage':name,'expected_public':False,
            'checks':[{'port':p,'reachable':p==22 and name=='admin','passed':True} for p in ports]}
    paths={name:tmp_path/(name+'.json') for name in rows}
    for name,row in rows.items():paths[name].write_text(json.dumps(row))
    assert gate(paths,'fixture-only')['status']=='PASS'
    broken={**rows['budget'],'estimated_seven_day_usd':float('nan')}
    paths['budget'].write_text(json.dumps(broken))
    with pytest.raises(ValueError,match='finite'):gate(paths,'fixture-only')
    paths['budget'].write_text(json.dumps(rows['budget']))
    (tmp_path/'runtime.txt').write_text('tampered')
    with pytest.raises(ValueError,match='checksum'):gate(paths,'fixture-only')


def test_kill_switch_not_part_of_vm_immutable_bootstrap():
    text=(ROOT/'deployment/azure/main.tf').read_text()
    assert 'enable_public_honeypot = false' in text
    assert 'var.enable_public_honeypot' not in (ROOT/'deployment/azure/compute.tf').read_text()


def test_offline_guard_never_needs_docker(monkeypatch):
    import deployment_guard as guard
    monkeypatch.setattr(guard.sys,'platform','linux')
    monkeypatch.setattr(guard,'private_file',lambda path:None)
    monkeypatch.setattr(guard,'validate_secrets',lambda env:None)
    monkeypatch.setattr(guard,'validate_data',lambda *args,**kwargs:None)
    def forbidden(*args,**kwargs):raise AssertionError('Offline guard contacted Docker')
    monkeypatch.setattr(guard.subprocess,'check_output',forbidden)
    policy,root=guard.offline_preflight({'HONEYPOT_SECRET_FILE':'fixture'})
    assert policy['deployment_data_root']=='/opt/honeypot-data'


def test_manifest_rejects_new_experiment_before_writing():
    from deployment_manifest import create
    with pytest.raises(ValueError,match='deterministic_baseline'):
        create({}, {}, {}, {'HONEYPOT_EXPERIMENT_ID':'unknown'}, {})


def test_cloud_init_json_content_and_guard_order():
    import yaml
    azure=ROOT/'deployment/azure'
    values={'infrastructure':json.dumps({'deployment_id':'fixture','enable_public_honeypot':False}),
        'bootstrap':(azure/'bootstrap.sh').read_text(),'disk_prepare':(azure/'prepare_disk.py').read_text(),
        'firewall':(azure/'host_firewall.py').read_text()}
    template=(azure/'cloud-init.yaml').read_text()
    for name,value in values.items():template=template.replace('${jsonencode('+name+')}',json.dumps(value))
    document=yaml.safe_load(template)
    assert json.loads(document['write_files'][0]['content'])['enable_public_honeypot'] is False
    assert document['runcmd'][0][0]=='systemd-run'
    bootstrap=values['bootstrap']
    assert bootstrap.index('systemctl mask') < bootstrap.index('apt-get install')
    assert 'containerd.service.d/honeypot-data-guard.conf' in bootstrap
    assert 'ExecStartPre=/usr/bin/python3 /opt/honeypot/scripts/deployment_guard.py --offline' in bootstrap
    assert 'systemctl start docker' not in bootstrap


def test_backup_valid_bytes_and_corruption_detection(tmp_path):
    import hashlib
    names=['evidence-redis/dump.rdb','principal-redis/dump.rdb',
        'runtime/research-identity.json','runtime/deployment-manifest.json',
        'runtime/retained-state-baseline.json','runtime/data-volume-marker.json']
    data=b'engineering-fixture-not-redis'
    files={name:{'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data)} for name in names}
    def write(path,corrupt=False):
        with tarfile.open(path,'w') as archive:
            for index,name in enumerate(names):
                payload=b'tampered' if corrupt and index==0 else data
                info=tarfile.TarInfo(name);info.size=len(payload);archive.addfile(info,io.BytesIO(payload))
            payload=json.dumps({'files':files}).encode();info=tarfile.TarInfo('backup-manifest.json');info.size=len(payload)
            archive.addfile(info,io.BytesIO(payload))
    good=tmp_path/'good.tar';write(good)
    assert validate(good)['scope']=='ARCHIVE_INTEGRITY_ONLY_NOT_RESTORE'
    bad=tmp_path/'bad.tar';write(bad,True)
    with pytest.raises(ValueError,match='checksum'):validate(bad)
