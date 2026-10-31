import base64
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import pytest
import configuration as c
import deployment_guard as g
from runtime_hardening import policy,gateway_configuration
from build_deployment_archive import collect


def test_archive_identity_without_git_and_tampering(tmp_path):
    from deployment_manifest import source_identity,digest
    (tmp_path/'release').mkdir();(tmp_path/'main.py').write_bytes(b'fixture')
    files={'main.py':hashlib.sha256(b'fixture').hexdigest()}
    (tmp_path/'release/source-manifest.json').write_text(json.dumps({
        'git_commit':'a'*40,'files':files,'archive_source_digest':digest(files)}))
    assert source_identity(tmp_path)==('a'*40,files)
    (tmp_path/'main.py').write_bytes(b'changed')
    with pytest.raises(ValueError,match='checksum'):source_identity(tmp_path)


def secrets():
    env={name:hashlib.sha256(name.encode()).hexdigest() for name in g.OPERATOR+g.STABLE}
    env['DECEPTIVE_PRINCIPAL_HMAC_SECRET']=base64.b64encode(bytes(range(32))).decode()
    env.update({name:'documented-decoy' for name in g.DECOY})
    env['HONEYPOT_DATA_VOLUME_ID']='fixture-volume'
    return env


def model():
    with patch.object(c,'read_environment',return_value=secrets()):
        f,p,o,e,s=c.load();return c.render(f,p,o,s)['compose.yaml']


def test_every_enabled_service_bounded_socket_free_and_reviewed_networks():
    value=model()
    for name,row in value['services'].items():
        assert row['mem_limit'] and row['cpus']>0 and row['pids_limit']>0
        assert row['logging']['driver']=='json-file'
        assert row['logging']['options']['max-file']=='3'
        assert 'default' not in row['networks']
        assert not any('docker.sock' in str(v) for v in row.get('volumes',[]))
        assert row['restart']==('no' if name.endswith('-init') else 'unless-stopped')
        if 'build' not in row:assert '@sha256:' in row['image']
        if row.get('ports'):assert name in {'pgproxy','mysqlproxy','operator-gateway'}
        assert all(str(p).startswith('127.0.0.1:') for p in row.get('ports',[]))
    for name,net in value['networks'].items():
        if name!='edge':
            assert net['internal'] and net['driver_opts']['com.docker.network.bridge.gateway_mode_ipv4']=='isolated'
    for name in ('pgproxy','mysqlproxy','operator-gateway'):
        assert 'runtime_guard.sh' in str(value['services'][name]['entrypoint'])
        assert value['services'][name]['cap_drop']==['ALL']
    assert not any(str(p).endswith(':9090') for p in value['services']['pgproxy']['ports'])
    assert not any(str(p).endswith(':9091') for p in value['services']['mysqlproxy']['ports'])
    assert 'state' not in value['services']['sandbox-replay-engine']['networks']
    assert 'application' not in value['services']['sandbox-replay-engine']['networks']


def test_gateway_keeps_operator_workflows_and_dynamic_dns():
    text=gateway_configuration(model())
    assert 'resolver 127.0.0.11 valid=2s' in text
    assert 'proxy_pass $upstream$request_uri' in text
    for port in (3000,8001,8003,8011,8012,9096):assert f'listen {port};' in text
    assert '169.254' not in text and 'docker.sock' not in text


def test_deployment_rejects_weak_reused_operator_keys_but_allows_decoys():
    env=secrets();g.validate_secrets(env)
    for name in g.OPERATOR:
        changed={**env,name:'password'}
        with pytest.raises(c.ConfigError):g.validate_secrets(changed)
    with pytest.raises(c.ConfigError):g.validate_secrets({**env,'PG_RUNTIME_PASSWORD':env['POSTGRES_PASSWORD']})
    with pytest.raises(c.ConfigError):g.validate_secrets({**env,'PG_DECOY_PASSWORD':env['POSTGRES_PASSWORD']})


def test_existing_directory_and_marker_cannot_replace_mounted_disk(tmp_path):
    (tmp_path/'.honeypot-data-volume.json').write_text('{}')
    with patch.object(os.path,'ismount',return_value=False):
        with pytest.raises(c.ConfigError,match='not mounted'):g.validate_data(tmp_path,secrets())


def test_disk_identity_and_stable_key_continuity(tmp_path):
    env=secrets();marker=tmp_path/'.honeypot-data-volume.json'
    metadata={'schema_version':1,'project':'capstone-main','volume_id':'fixture-volume','stable_key_fingerprints':g.fingerprints(env)}
    marker.write_text(json.dumps(metadata))
    with patch.object(os.path,'ismount',return_value=True),patch.object(g,'private_file',return_value=marker),patch.object(g.shutil,'disk_usage',return_value=SimpleNamespace(free=100*1024**3)):
        assert g.validate_data(tmp_path,env)['volume_id']=='fixture-volume'
        with pytest.raises(c.ConfigError,match='continuity'):
            g.validate_data(tmp_path,{**env,'EVIDENCE_IP_HASH_SALT':'new-unapproved-key'})
        with pytest.raises(c.ConfigError,match='identity'):
            g.validate_data(tmp_path,{**env,'HONEYPOT_DATA_VOLUME_ID':'wrong-disk'})


@pytest.mark.parametrize('mode,owner,valid',[(0o100600,1000,True),(0o100644,1000,False),(0o100600,2000,False)])
def test_private_secret_file_ownership_and_mode(tmp_path,mode,owner,valid):
    target=tmp_path/'secrets.env';target.write_text('fixture')
    info=SimpleNamespace(st_mode=mode,st_uid=owner)
    with patch.object(g,'os',SimpleNamespace(name='posix',getuid=lambda:1000)),patch.object(Path,'stat',return_value=info):
        if valid:assert g.private_file(target)==target
        else:
            with pytest.raises(c.ConfigError):g.private_file(target)


def test_archive_allowlist_excludes_secrets_state_tests_and_symlinks(tmp_path):
    for directory in ('app','scripts','config','shared','deployment'):(tmp_path/directory).mkdir()
    for name in ('app/main.py','app/test_secret.py','app/Dockerfile','app/.dockerignore',
        'app/.env','deployment/secrets.env','deployment/secrets.env.example','config/empty.env'):
        (tmp_path/name).write_text('fixture')
    selected=collect(tmp_path,{'services':{'app':{'build':{'context':'./app'}}}})
    assert 'app/main.py' in selected and 'app/Dockerfile' in selected
    assert 'deployment/secrets.env.example' in selected and 'config/empty.env' in selected
    assert not any(n in selected for n in ('app/.env','deployment/secrets.env','app/test_secret.py'))
    with pytest.raises(ValueError,match='escapes'):
        collect(tmp_path,{'services':{'bad':{'build':{'context':'../outside'}}}})


