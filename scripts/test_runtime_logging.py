import importlib.util
import logging
from pathlib import Path
import sys
import json
from unittest.mock import patch

def test_secret_values_and_sql_do_not_enter_operational_json():
    path=Path(__file__).resolve().parents[1]/'shared/safe_logging.py'
    with patch.dict('os.environ',{'RESEARCH_OPERATOR_KEY':'fixture-operator-secret-value','EVIDENCE_IP_HASH_SALT':'fixture-stable-hash-value'}):
        spec=importlib.util.spec_from_file_location('isolated_safe_logging',path)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    formatter=module.Formatter()
    for secret in ('fixture-operator-secret-value','fixture-stable-hash-value'):
        record=logging.LogRecord('fixture',logging.WARNING,'fixture',1,'failure '+secret,(),None)
        text=formatter.format(record)
        assert secret not in text and json.loads(text)['level']=='warning'
    record=logging.LogRecord('fixture',logging.ERROR,'fixture',1,"SELECT 'private literal'",(),None)
    assert 'private literal' not in formatter.format(record)
