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
        model=self.model()['compose.yaml']
        self.assertEqual(model['services']['pgproxy']['environment']['DECEPTIVE_PRINCIPAL_HMAC_SECRET'],'')

    def test_short_hmac_is_rejected(self):
        self.env['DECEPTIVE_PRINCIPAL_HMAC_SECRET']=base64.b64encode(b'x'*31).decode()
        with self.assertRaisesRegex(c.ConfigError,'at least 32 bytes'): self.load()

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
