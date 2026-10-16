#!/usr/bin/env python3
"""Read-only checks for the selected local runtime. No container or data mutations."""
import base64
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from configuration import ConfigError, ROOT, load


def main():
    try:
        flags, _, _, env, _ = load()
    except ConfigError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    checks, warnings = [], []

    def fetch(url, headers=None):
        request = urllib.request.Request(url, headers=headers or {})
        with urllib.request.urlopen(request, timeout=8) as response:
            return response.read().decode()

    def check(name, operation):
        try:
            detail = operation()
            checks.append({'check': name, 'ok': True, 'detail': detail})
            return detail
        except Exception as exc:
            # Exception bodies/URLs can contain sensitive material. Report type only.
            checks.append({'check': name, 'ok': False, 'error': type(exc).__name__})
            return None

    def ready(port):
        data = json.loads(fetch(f'http://127.0.0.1:{port}/readyz'))
        if data.get('ready') is not True:
            raise ValueError('not ready')
        return 'ready'

    for name, port, feature in (
        ('deception',8001,'core.deception_engine'), ('session',8003,'analysis.session_behavior'),
        ('evidence',8011,'analysis.evidence_store'), ('replay',8012,'infrastructure.sandbox_replay')):
        if flags[feature]:
            check(name+' readiness', lambda port=port: ready(port))

    def proxy(port):
        data = json.loads(fetch(f'http://127.0.0.1:{port}/metrics'))
        if data.get('backend_healthy') is not True:
            raise ValueError('backend unavailable')
        return 'backend reachable (TCP health, not password verification)'
    check('PostgreSQL backend', lambda: proxy(9090))
    check('MySQL backend', lambda: proxy(9091))

    if flags['observability.prometheus']:
        def targets():
            items = json.loads(fetch('http://127.0.0.1:9096/api/v1/targets'))['data']['activeTargets']
            if not items or any(item['health'] != 'up' for item in items):
                raise ValueError('scrape target unavailable')
            return sorted(item['labels']['job'] for item in items)
        check('Prometheus scrape targets', targets)
        def queries():
            dashboard = json.loads((ROOT/'.runtime/grafana/dashboards/operations_overview.json').read_text(encoding='utf-8'))
            count = 0
            for panel in dashboard['panels']:
                if panel.get('datasource',{}).get('type') != 'prometheus':
                    continue
                for target in panel.get('targets',[]):
                    expr = target['expr'].replace('$__rate_interval','1m').replace('$__interval','1m')
                    response = json.loads(fetch('http://127.0.0.1:9096/api/v1/query?'+urllib.parse.urlencode({'query':expr})))
                    if response.get('status') != 'success':
                        raise ValueError('invalid panel query')
                    if not response['data']['result']:
                        warnings.append('No samples: '+panel['title'])
                    count += 1
            return count
        if flags['observability.grafana']:
            check('Primary dashboard PromQL expressions', queries)

    if flags['observability.grafana']:
        headers = {'Authorization':'Basic '+base64.b64encode(('admin:'+env['GRAFANA_ADMIN_PASSWORD']).encode()).decode()}
        def dashboard():
            data = json.loads(fetch('http://127.0.0.1:3000/api/dashboards/uid/honeypot-operations',headers))
            return data['dashboard']['title']
        check('Grafana login and provisioned dashboard', dashboard)
        for source in ('prometheus','loki'):
            if not flags['observability.'+source]:
                continue
            def datasource(source=source):
                data=json.loads(fetch('http://127.0.0.1:3000/api/datasources/uid/'+source+'/health',headers))
                if data.get('status') != 'OK': raise ValueError('datasource unavailable')
                return data['status']
            check('Grafana '+source+' datasource', datasource)

    if flags['observability.loki']:
        check('Loki readiness', lambda: fetch('http://127.0.0.1:3100/ready').strip())
        def logs():
            query=urllib.parse.urlencode({'query':'{compose_project="capstone-main"}', 'limit':20})
            data=json.loads(fetch('http://127.0.0.1:3100/loki/api/v1/query_range?'+query))
            streams=data['data']['result']
            if not streams: raise ValueError('no project logs received')
            return sorted({stream['stream'].get('service','unknown') for stream in streams})
        check('Loki received project logs', logs)

    report={'timestamp':datetime.now(timezone.utc).isoformat(), 'ok':all(item['ok'] for item in checks),
            'checks':checks,'warnings':sorted(set(warnings))}
    output=ROOT/'.runtime/runtime-verification.json'
    output.parent.mkdir(exist_ok=True)
    output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    for item in checks:
        print(('PASS' if item['ok'] else 'FAIL')+' '+item['check']+': '+str(item.get('detail',item.get('error'))))
    for warning in report['warnings']:
        print('NOTE '+warning+' (may require traffic or a completed session)')
    print('Report: .runtime/runtime-verification.json')
    return 0 if report['ok'] else 1


if __name__=='__main__':
    sys.exit(main())
