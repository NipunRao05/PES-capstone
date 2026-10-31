"""Canonical Docker-only containment. No cloud calls or secret material."""
import hashlib
import ipaddress
import math
import os
from pathlib import Path

GATEWAY_TARGETS={8000:('session-module',8000),8003:('session-module',8003),
    8001:('deception-engine',8001),8011:('evidence-store',8011),9090:('pgproxy',9090),
    9091:('mysqlproxy',9091),9095:('scaling-agent',8080),9100:('metrics-bridge',9100),
    9096:('prometheus',9090),3000:('grafana',3000),3100:('loki',3100),
    8012:('sandbox-replay-engine',8012)}


def policy():
    from configuration import read_yaml,keys,integer,ConfigError
    value=read_yaml('config/runtime.yaml')
    keys(value,('version','networks','proxy_max_connections','redis_deception_maxmemory_mb',
        'docker_log_max_size_mb','docker_log_max_files','deployment_data_root','deployment_min_free_gib','resources'),'runtime')
    if value['version']!=1:raise ConfigError('Unsupported runtime policy version')
    keys(value['networks'],('edge','application','state','control','observability','sandbox'),'runtime.networks')
    subnets=[ipaddress.ip_network(cidr) for cidr in value['networks'].values()]
    if any(n.version!=4 or not n.is_private or n.prefixlen!=24 for n in subnets) or any(
        a.overlaps(b) for i,a in enumerate(subnets) for b in subnets[i+1:]):
        raise ConfigError('Runtime networks must be distinct private IPv4 /24 networks')
    for name,bounds in {'proxy_max_connections':(16,512),'redis_deception_maxmemory_mb':(128,1024),
        'docker_log_max_size_mb':(1,50),'docker_log_max_files':(2,5),'deployment_min_free_gib':(10,1000)}.items():
        integer(value[name],*bounds,'runtime.'+name)
    if value['deployment_data_root']!='/opt/honeypot-data':raise ConfigError('Unexpected deployment data-root contract')
    for name,row in value['resources'].items():
        keys(row,('memory_mb','cpus','pids'),'resources.'+name)
        integer(row['memory_mb'],64,8192,'memory_mb');integer(row['pids'],32,512,'pids')
        if type(row['cpus']) not in (int,float) or not math.isfinite(row['cpus']) or not .1<=row['cpus']<=4:
            raise ConfigError('Invalid runtime CPU limit')
    return value


def health(test):
    return {'test':test,'interval':'10s','timeout':'3s','retries':12,'start_period':'30s'}


def python_health(port,path='/readyz'):
    return health(['CMD','python','-B','-c',
        f'import urllib.request;urllib.request.urlopen("http://127.0.0.1:{port}{path}",timeout=2).read(1024)'])


def apply(model,flags,research):
    from configuration import ConfigError,read_yaml
    p=policy();services=model['services'];nets=p['networks']
    # Replace the old replay-only nginx with one loopback management gateway.
    services.pop('sandbox-replay-api',None)
    targets={port:target for port,target in GATEWAY_TARGETS.items() if target[0] in services}
    services['operator-gateway']={
        'build':{'context':'./operator_gateway'},'ports':[f'127.0.0.1:{port}:{port}' for port in targets],
        'volumes':['./.runtime/operator-nginx.conf:/etc/nginx/nginx.conf:ro','./shared:/opt/honeypot:ro'],
        'command':['nginx','-e','stderr','-g','daemon off;'],'entrypoint':['/bin/sh','/opt/honeypot/runtime_guard.sh'],
        'depends_on':{name:{'condition':'service_started'} for name,_ in targets.values()}}
    groups={
        'pgproxy':['edge','application','state'],'mysqlproxy':['edge','application','state'],
        'deception-engine':['application','state'],'session-module':['application'],
        'evidence-store':['application','control'],'scaling-agent':['application','control'],
        'redis-deception':['state'],'redis-mitre':['control'],
        'postgres':['state'],'mysql':['state'],'backend-containment-init':['state'],
        'redpanda':['application'],'redpanda-init':['application'],
        'sandbox-replay-engine':['control','sandbox'],'sandbox-postgres':['sandbox'],'sandbox-mysql':['sandbox'],
        'metrics-bridge':['application'],'prometheus':['application','observability'],
        'json-exporter':['control','observability'],'grafana':['observability'],'loki':['observability'],
        'promtail':['observability'],'operator-gateway':['edge','application','control','observability']}
    model['networks']={name:{'driver':'bridge','internal':name!='edge',
        'ipam':{'config':[{'subnet':cidr}]},'driver_opts':{
            'com.docker.network.bridge.host_binding_ipv4':'127.0.0.1',
            **({'com.docker.network.bridge.gateway_mode_ipv4':'isolated'} if name!='edge' else {})}}
        for name,cidr in nets.items()}
    python_services={'deception-engine','session-module','evidence-store','metrics-bridge','sandbox-replay-engine','backend-containment-init'}
    for name,s in services.items():
        if name not in groups or name not in p['resources']:raise ConfigError('Unreviewed enabled runtime service: '+name)
        r=p['resources'][name];s.update(mem_limit=f'{r["memory_mb"]}m',cpus=r['cpus'],pids_limit=r['pids'],
            restart='no' if name.endswith('-init') else 'unless-stopped',dns=['127.0.0.1'])
        s['networks']={network:{} for network in groups[name]}
        s.setdefault('security_opt',[])
        if 'no-new-privileges:true' not in s['security_opt']:s['security_opt'].append('no-new-privileges:true')
        s.setdefault('labels',{}).update({'honeypot.environment':'controlled-baseline'})
        s['logging']={'driver':'json-file','options':{'max-size':str(p['docker_log_max_size_mb'])+'m',
            'max-file':str(p['docker_log_max_files']),'labels':'com.docker.compose.service,com.docker.compose.project,honeypot.environment'}}
        if name not in {'pgproxy','mysqlproxy','operator-gateway'}:s.pop('ports',None)
        elif name in {'pgproxy','mysqlproxy'}:
            allowed={'5432','15432'} if name=='pgproxy' else {'3306','13306'}
            s['ports']=[binding for binding in s.get('ports',[]) if str(binding).split(':')[-1] in allowed]
        if name in python_services or name in {'scaling-agent','json-exporter','operator-gateway','pgproxy','mysqlproxy'}:
            s.update(read_only=True,cap_drop=['ALL'])
            s['tmpfs']=['/tmp:rw,noexec,nosuid,size=64m']
            if name not in {'operator-gateway','pgproxy','mysqlproxy'}:s['user']='65532:65532'
        if name in python_services:
            s.setdefault('environment',{}).update(PYTHONDONTWRITEBYTECODE='1',HOME='/tmp',
                OPENBLAS_NUM_THREADS='1',OMP_NUM_THREADS='2')
        if 'build' in s:
            # Explicit local build tag; immutable observed IDs are captured after up.
            s['image']='capstone-main-'+name+':runtime-v1'
        else:
            lock=read_yaml('config/image-lock.yaml')
            if s.get('image') not in lock:raise ConfigError('Enabled image lacks immutable lock: '+name)
            s['image']=s['image']+'@'+lock[s['image']]
        deps=s.get('depends_on',{})
        if isinstance(deps,list):deps={n:{'condition':'service_started'} for n in deps}
        for dep,rule in deps.items():
            if dep in {'postgres','mysql','redis-deception','redis-mitre','redpanda','deception-engine','evidence-store','session-module'}:
                rule['condition']='service_healthy'
        s['depends_on']=deps
    for name in ('pgproxy','mysqlproxy','operator-gateway'):
        s=services[name];env=s.setdefault('environment',{})
        zones=['application','state'] if name!='operator-gateway' else ['edge','application','control','observability']
        env['RUNTIME_ALLOWED_NETWORKS']=' '.join(nets[z] for z in zones)
        env['RUNTIME_ALLOWED_PORTS']='5432,3306,8001,8003,9092' if name!='operator-gateway' else '3000,3100,8000,8001,8003,8011,8012,8080,9090,9091,9100'
        s.update(user='0:0',cap_add=['NET_ADMIN','SETUID','SETGID','SETPCAP'])
        s['entrypoint']=['/bin/sh','/opt/honeypot/runtime_guard.sh']
        if name!='operator-gateway':
            s.setdefault('volumes',[]).append('./shared:/opt/honeypot:ro')
            s['command']=['/app/pgproxy'] if name=='pgproxy' else ['/mysqlproxy']
            env['MAX_CONNECTIONS']=str(p['proxy_max_connections'])
            env['CLIENT_IDLE_TIMEOUT']='5m'
            s['healthcheck']=health(['CMD','wget','-q','-O','/dev/null',f'http://127.0.0.1:{9090 if name=="pgproxy" else 9091}/healthz'])
    gateway=services['operator-gateway']
    gateway['healthcheck']=health(['CMD','wget','-q','-O','/dev/null','http://127.0.0.1:9980/healthz'])
    if 'sandbox-replay-engine' in services:gateway['networks']['control']['aliases']=['sandbox-replay-api']
    for name in ('postgres','sandbox-postgres'):
        if name not in services:continue
        services[name]['command']=['postgres','-c','max_connections=64','-c','shared_buffers=128MB',
            '-c','work_mem=2MB','-c','maintenance_work_mem=64MB','-c','statement_timeout=5000',
            '-c','lock_timeout=1000','-c','idle_in_transaction_session_timeout=30000']
        services[name]['healthcheck']=health(['CMD-SHELL','pg_isready -U postgres -d '+('testdb' if name=='postgres' else 'sandboxdb')])
    for name in ('mysql','sandbox-mysql'):
        if name not in services:continue
        services[name]['command']=['--default-authentication-plugin=mysql_native_password','--character-set-server=utf8mb4',
            '--collation-server=utf8mb4_unicode_ci','--max-connections=48','--innodb-buffer-pool-size=134217728',
            '--tmp-table-size=8388608','--max-heap-table-size=8388608','--max-allowed-packet=1048576',
            '--connect-timeout=5','--net-read-timeout=10','--net-write-timeout=10','--wait-timeout=300',
            '--interactive-timeout=300','--max-execution-time=2000','--thread-cache-size=8']
        services[name]['healthcheck']=health(['CMD','mysqladmin','ping','-h','127.0.0.1','--silent'])
    services['redis-deception']['command']=['redis-server','--appendonly','yes','--appendfsync','always',
        '--maxmemory',str(p['redis_deception_maxmemory_mb'])+'mb','--maxmemory-policy','noeviction']
    for name in ('redis-deception','redis-mitre'):
        if name in services:services[name]['healthcheck']=health(['CMD','redis-cli','PING'])
    if p['resources']['redis-mitre']['memory_mb']<2*research['evidence_redis_maxmemory_mb']+256:
        raise ConfigError('Evidence Redis container limit lacks reviewed AOF/COW headroom')
    services['redpanda']['healthcheck']=health(['CMD','rpk','cluster','info','--brokers','127.0.0.1:9092'])
    services['redpanda-init']['depends_on']['redpanda']={'condition':'service_healthy'}
    for name,port in [('deception-engine',8001),('evidence-store',8011),('session-module',8003),('sandbox-replay-engine',8012)]:
        if name in services:services[name]['healthcheck']=python_health(port)
    if 'metrics-bridge' in services:services['metrics-bridge']['healthcheck']=python_health(9100,'/healthz')
    if 'evidence-store' in services:
        services['evidence-store']['environment']['EVIDENCE_IP_HASH_SALT']='${EVIDENCE_IP_HASH_SALT:-}'
    if 'prometheus' in services:
        services['prometheus']['command'].append('--storage.tsdb.retention.size=2GB')
    if 'grafana' in services:
        services['grafana']['environment'].update(GF_AUTH_ANONYMOUS_ENABLED='false',GF_SECURITY_COOKIE_SAMESITE='lax',
            GF_SECURITY_CSRF_ALWAYS_CHECK='true',GF_ANALYTICS_REPORTING_ENABLED='false',GF_ANALYTICS_CHECK_FOR_UPDATES='false',GF_PLUGINS_CHECK_FOR_UPDATES='false')
    if 'promtail' in services:
        services['promtail']['volumes']=[os.getenv('HONEYPOT_DOCKER_LOG_ROOT','/var/lib/docker/containers')+':/var/lib/docker/containers:ro',
            './observability/promtail.yaml:/etc/promtail/config.yml:ro','collectorpositions:/positions']
        services['promtail'].update(cap_drop=['ALL'],read_only=True,tmpfs=['/tmp:rw,noexec,nosuid,size=32m'])
        model['volumes']['collectorpositions']={}
    return model


def gateway_configuration(model):
    services=model['services'];blocks=[]
    for port,(name,target) in GATEWAY_TARGETS.items():
        if name not in services:continue
        blocks.append(f'''server {{ listen {port}; server_name _;
 location / {{ set $upstream http://{name}:{target}; proxy_pass $upstream$request_uri;
 proxy_http_version 1.1; proxy_set_header Host $http_host;
 proxy_set_header X-Forwarded-For $remote_addr;
 proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection $connection_upgrade;
 proxy_connect_timeout 2s; proxy_read_timeout 60s; }} }}''')
    return '''worker_processes 1;
pid /tmp/nginx.pid;
error_log stderr warn;
events { worker_connections 256; }
http { access_log off; resolver 127.0.0.11 valid=2s ipv6=off; resolver_timeout 2s;
 map $http_upgrade $connection_upgrade { default upgrade; '' close; }
 client_max_body_size 2m; client_body_temp_path /tmp/client;
 proxy_temp_path /tmp/proxy; fastcgi_temp_path /tmp/fastcgi;
 uwsgi_temp_path /tmp/uwsgi; scgi_temp_path /tmp/scgi;
 server { listen 9980; location = /healthz { return 200 'ready'; } }
'''+ '\n'.join(blocks)+'\n}\n'
