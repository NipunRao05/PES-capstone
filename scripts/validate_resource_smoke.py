"""24 bounded private-listener queries; not a load-capacity or soak test."""
import json
from pathlib import Path
import subprocess
import time
import urllib.request

DRIVER=r'''
import json,sys,time
from concurrent.futures import ThreadPoolExecutor
import psycopg,pymysql
values=json.load(sys.stdin)
def worker(index):
 protocol='postgres' if index%2==0 else 'mysql'
 if protocol=='postgres':
  connection=psycopg.connect(host='pgproxy',port=15432,user='postgres',dbname='testdb',password=values['PG_DECOY_PASSWORD'],autocommit=True,connect_timeout=5)
 else:
  connection=pymysql.connect(host='mysqlproxy',port=13306,user='root',database='testdb',password=values['MYSQL_DECOY_ROOT_PASSWORD'],autocommit=True,connect_timeout=5,read_timeout=5)
 count=0
 try:
  with connection.cursor() as cursor:
   for query in ['select 1','select version()','select id,salary from employees limit 3']*2:
    cursor.execute(query);rows=cursor.fetchall();assert rows;count+=1
 finally:connection.close()
 return {'protocol':protocol,'successful_queries':count}
started=time.monotonic()
with ThreadPoolExecutor(max_workers=4) as executor:results=list(executor.map(worker,range(4)))
print(json.dumps({'results':results,'successful_queries':sum(r['successful_queries'] for r in results),'elapsed_seconds':time.monotonic()-started,'traffic_origin':'operator_validation'}))
'''


def json_http(url):
    with urllib.request.urlopen(url,timeout=5) as f:return json.load(f)


def main():
    from configuration import load
    env=load()[3]
    before=json_http('http://127.0.0.1:8011/evidence/research/status')
    command=['docker','run','--rm','-i','--network','capstone-main_application','--label','com.docker.compose.project=capstone-validation',
        '--read-only','--cap-drop','ALL','--security-opt','no-new-privileges:true','--memory','256m','--cpus','1','--pids-limit','64',
        '--entrypoint','python','capstone-main-sandbox-replay-engine:runtime-v1','-B','-c',DRIVER]
    result=subprocess.run(command,input=json.dumps({k:env[k] for k in ('PG_DECOY_PASSWORD','MYSQL_DECOY_ROOT_PASSWORD')}),text=True,capture_output=True,timeout=45)
    if result.returncode:raise RuntimeError('Bounded query driver failed; inspect controlled test environment')
    queries=json.loads(result.stdout)
    # SELECT 1 is native/constant passthrough and has no strategy application.
    # Four workers each issue four managed reads and two native constants.
    expected_applications=16
    deadline=time.monotonic()+20
    while True:
        after=json_http('http://127.0.0.1:8011/evidence/research/status')
        delivery=json_http('http://127.0.0.1:8001/research/delivery-status')
        admitted=int(after['trace_index_metadata']['application_count'])-int(before['trace_index_metadata']['application_count'])
        if admitted>=expected_applications and delivery['pending']==0:break
        if time.monotonic()>deadline:raise RuntimeError('Bounded evidence delivery did not settle')
        time.sleep(.5)
    stats=[json.loads(line) for line in subprocess.check_output(['docker','stats','--no-stream','--format','{{json .}}'],text=True).splitlines()]
    ids=subprocess.check_output(['docker','ps','-q','--filter','label=com.docker.compose.project=capstone-main'],text=True).split()
    containers=json.loads(subprocess.check_output(['docker','inspect',*ids],text=True))
    assert all(not c['State']['OOMKilled'] for c in containers)
    assert all(c['State'].get('Health',{}).get('Status','healthy')=='healthy' for c in containers)
    report={'status':'PASS','queries':queries,'expected_managed_applications':expected_applications,
        'native_constant_queries':8,'indexed_application_increase':admitted,'outbox':delivery,
        'no_oom':True,'health_stable':True,'stats':stats,'source_consistency':'bounded before/after counters; not an exclusive population proof'}
    Path('.runtime/pass3-pressure.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k!='stats'}))
    return 0


if __name__=='__main__':raise SystemExit(main())
