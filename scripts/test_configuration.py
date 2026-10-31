"""Offline regression checks for canonical gating and deployment generation."""
import base64
import copy
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch
import configuration as c


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.features=c.read_yaml('config/features.yaml')
        self.read_yaml=c.read_yaml
        self.env={'POSTGRES_PASSWORD':'unit-test-only', 'MYSQL_PASSWORD':'unit-test-only',
                  'MYSQL_ROOT_PASSWORD':'unit-test-only', 'GRAFANA_ADMIN_PASSWORD':'unit-test-only',
                  'DECEPTIVE_PRINCIPAL_HMAC_SECRET':base64.b64encode(b'x'*32).decode()}

    def load(self):
        def read(name):
            return copy.deepcopy(self.features) if name=='config/features.yaml' else self.read_yaml(name)
        with patch.object(c,'read_environment',return_value=self.env), patch.object(c,'read_yaml',side_effect=read):
            return c.load()

    def model(self):
        flags,policy,obs,_,compose=self.load()
        return c.render(flags,policy,obs,compose)

    def test_default_has_no_future_services_or_external_model_volume(self):
        model=self.model()['compose.yaml']
        self.assertFalse({'ai-agent','llm-agent','mitre-agent','local-llm'} & model['services'].keys())
        self.assertNotIn('local_llm_models',model['volumes'])
        for service in model['services'].values():
            self.assertTrue(set(service.get('depends_on',{})) <= model['services'].keys())

    def test_prometheus_has_no_nested_read_only_mounts(self):
        service=self.model()['compose.yaml']['services']['prometheus']
        destinations=[mount.split(':')[1] for mount in service['volumes']]
        for first in destinations:
            for second in destinations:
                if first!=second: self.assertFalse(first.startswith(second+'/'))
        self.assertIn('--config.file=/etc/prometheus/prometheus.yml',service['command'])

    def test_observability_off_keeps_core(self):
        self.features['observability']['enabled']=False
        model=self.model()['compose.yaml']
        self.assertTrue({'pgproxy','mysqlproxy','deception-engine'} <= model['services'].keys())
        self.assertFalse({'grafana','prometheus','loki','metrics-bridge'} & model['services'].keys())
        self.assertEqual(model['services']['scaling-agent']['environment']['METRIC_SCALING_ENABLED'],'false')

    def test_dependency_is_rejected(self):
        self.features['analysis']['session_behavior']=False
        with self.assertRaisesRegex(c.ConfigError,'requires'): self.load()

    def test_future_feature_is_rejected(self):
        self.features['optional_future']['live_learning']=True
        with self.assertRaisesRegex(c.ConfigError,'not supported'): self.load()

    def test_legacy_flag_cannot_enable_disabled_feature(self):
        self.env['MITRE_ENABLED']='true'
        with self.assertRaisesRegex(c.ConfigError,'conflicts'): self.load()

    def test_disabled_optional_secrets_are_not_required(self):
        self.features['deception']['deceptive_principals']=False
        self.features['observability']['enabled']=False
        del self.env['DECEPTIVE_PRINCIPAL_HMAC_SECRET']
        del self.env['GRAFANA_ADMIN_PASSWORD']
        self.env['PG_RUNTIME_PASSWORD']='private-pg-runtime-fixture-secret'
        self.env['MYSQL_RUNTIME_PASSWORD']='private-mysql-runtime-fixture-secret'
        model=self.model()['compose.yaml']
        self.assertEqual(model['services']['pgproxy']['environment']['DECEPTIVE_PRINCIPAL_HMAC_SECRET'],'')

    def test_runtime_identity_secrets_are_separate_and_stable(self):
        first=self.load()[3]
        second=self.load()[3]
        self.assertEqual(first['PG_RUNTIME_PASSWORD'],second['PG_RUNTIME_PASSWORD'])
        self.assertNotEqual(first['PG_RUNTIME_PASSWORD'],first['MYSQL_RUNTIME_PASSWORD'])
        self.assertNotEqual(first['PG_RUNTIME_PASSWORD'],first['PG_DECOY_PASSWORD'])
        model=self.model()['compose.yaml']
        for name in ('pgproxy','mysqlproxy'):
            self.assertEqual(model['services'][name]['depends_on']['backend-containment-init']['condition'],'service_completed_successfully')

    def test_short_hmac_is_rejected(self):
        self.env['DECEPTIVE_PRINCIPAL_HMAC_SECRET']=base64.b64encode(b'x'*31).decode()
        with self.assertRaisesRegex(c.ConfigError,'at least 32 bytes'): self.load()

    def test_research_retention_capacity_and_init_command(self):
        model=self.model()['compose.yaml']['services']
        self.assertEqual(model['evidence-store']['environment']['TRACE_INDEX_CAPACITY'],'131072')
        self.assertEqual(model['evidence-store']['environment']['EVENT_JOURNAL_CAPACITY'],'524288')
        self.assertIn('--appendonly',model['redis-mitre']['command'])
        self.assertIn('noeviction',model['redis-mitre']['command'])
        command=model['redpanda-init']['command']
        self.assertEqual(len(command),1)
        self.assertIn('log_retention_ms 1209600000',command[0])
        for name,port in [('pgproxy','15432'),('mysqlproxy','13306')]:
            self.assertIn('127.0.0.1:'+port+':'+port,model[name]['ports'])

    def test_undersized_research_capacity_rejected(self):
        original=self.read_yaml
        def read(name):
            value=original(name)
            if name=='config/deception.yaml':value['research']['trace_index_capacity']=1000
            return value
        with patch.object(c,'read_environment',return_value=self.env),patch.object(c,'read_yaml',side_effect=read):
            with self.assertRaisesRegex(c.ConfigError,'headroom'):c.load()

    def test_string_boolean_is_rejected(self):
        self.features['analysis']['evidence_store']='false'
        with self.assertRaisesRegex(c.ConfigError,'YAML true or false'): self.load()

    def test_unknown_feature_key_is_rejected(self):
        self.features['core']['unknown']=True
        with self.assertRaisesRegex(c.ConfigError,'exactly these keys'): self.load()


    def test_monitoring_content_changes_container_config_hash(self):
        flags,policy,obs,_,compose=self.load()
        first=c.render(flags,policy,obs,compose)
        obs['scrape_interval_seconds']+=1
        second=c.render(flags,policy,obs,compose)
        self.assertNotEqual(first['compose.yaml']['services']['prometheus']['labels'],
                            second['compose.yaml']['services']['prometheus']['labels'])

    def test_unchanged_artifact_keeps_existing_bind_mount_inode(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(c,'RUNTIME',Path(directory)):
            c.write_artifacts({'compose.yaml': {'name': 'unit-test'}})
            with patch.object(Path,'replace',side_effect=AssertionError('Unchanged file replaced')):
                c.write_artifacts({'compose.yaml': {'name': 'unit-test'}})


if __name__=='__main__':
    unittest.main()
