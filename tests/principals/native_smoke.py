"""Run in the existing replay dependency image. Configuration/secrets arrive on stdin.
Only sanitized measurements are printed. Uses libpq simple queries and PyMySQL.
"""
import json
import sys
import psycopg
import pymysql

cfg = json.load(sys.stdin)
results = []

def connect(protocol, username, password, backend=False):
    if protocol == 'postgres':
        return psycopg.connect(host='postgres' if backend else 'pgproxy', dbname='testdb',
                              user=username, password=password, sslmode='disable', connect_timeout=5, autocommit=True)
    return pymysql.connect(host='mysql' if backend else 'mysqlproxy', database='testdb',
                           user=username, password=password, connect_timeout=5, read_timeout=5, autocommit=True)

def execute(conn, protocol, sql, success=True):
    if protocol=='postgres':
        result=conn.pgconn.exec_(sql.encode())
        ok=result.status in (psycopg.pq.ExecStatus.COMMAND_OK,psycopg.pq.ExecStatus.TUPLES_OK)
        rows=[[result.get_value(i,j).decode() if result.get_value(i,j) else None
               for j in range(result.nfields)] for i in range(result.ntuples)]
        if ok != success: raise AssertionError('unexpected PostgreSQL query outcome: '+result.error_message.decode())
        return rows
    try:
        with conn.cursor() as cursor:
            cursor.execute(sql)
            rows=cursor.fetchall()
        if not success:raise AssertionError('unexpected MySQL success')
        return rows
    except pymysql.MySQLError:
        if success:raise
        return []

def login_rejected(protocol,name,password):
    try:
        conn=connect(protocol,name,password)
    except (psycopg.Error,pymysql.MySQLError):return True
    conn.close();raise AssertionError('unexpected authentication success')

try:
    for protocol in cfg.get('protocols',['postgres','mysql']):
        admin='postgres' if protocol=='postgres' else 'root'
        secret=cfg['postgres_password' if protocol=='postgres' else 'mysql_root_password']
        name=cfg.get('name','fake_compro1')
        password=cfg['synthetic_password']
        if cfg['stage']=='create':
            with connect(protocol,admin,secret) as conn:
                create=f"CREATE USER {name} "+('PASSWORD' if protocol=='postgres' else 'IDENTIFIED BY')+f" '{password}'"
                execute(conn,protocol,create)
                grant=f"GRANT SELECT, INSERT, UPDATE, DELETE ON "+('ALL TABLES IN SCHEMA public' if protocol=='postgres' else 'testdb.*')+f" TO {name}"
                execute(conn,protocol,grant)
                execute(conn,protocol,create,success=False)
                execute(conn,protocol,'select id from employees where id = 1')
            with connect(protocol,admin,secret,backend=True) as conn:
                sql=f"SELECT count(*) FROM "+('pg_roles WHERE rolname' if protocol=='postgres' else 'mysql.user WHERE user')+f" = '{name}'"
                assert int(execute(conn,protocol,sql)[0][0])==0
            results.append(dict(protocol=protocol,stage='create',backend_user_count=0,duplicate_rejected=True,seeded_auth=True))
        elif cfg['stage']=='return':
            login_rejected(protocol,name,'incorrect-password')
            with connect(protocol,name,password) as conn:
                baseline=execute(conn,protocol,'select salary from employees where id = 1')
                execute(conn,protocol,'BEGIN')
                execute(conn,protocol,'update employees set salary = 12345 where id = 1')
                execute(conn,protocol,'ROLLBACK')
                assert execute(conn,protocol,'select salary from employees where id = 1')==baseline, 'rollback did not restore baseline'
                execute(conn,protocol,'BEGIN')
                execute(conn,protocol,'update employees set salary = 54321 where id = 1')
                execute(conn,protocol,'COMMIT')
                execute(conn,protocol,'select id from api_keys')
                execute(conn,protocol,'select id from api_keys_backup')
                execute(conn,protocol,'create table unsupported (id int)',success=False)
            with connect(protocol,name,password) as conn:
                assert int(float(execute(conn,protocol,'select salary from employees where id = 1')[0][0]))==54321, 'committed salary not restored'
                execute(conn,protocol,'BEGIN')
                execute(conn,protocol,'update employees set salary = 99999 where id = 1')
                if protocol == "postgres":
                    conn.close()  # psycopg context exit would otherwise COMMIT.
            with connect(protocol,name,password) as conn:
                assert int(float(execute(conn,protocol,'select salary from employees where id = 1')[0][0]))==54321, 'committed salary not restored'
            results.append(dict(protocol=protocol,stage='return',wrong_password_rejected=True,rollback=True,
                                committed_state_restored=True,disconnect_discards_uncommitted=True,trap_query=True))
        elif cfg['stage']=='reconnect':
            with connect(protocol,name,password) as conn:
                assert int(float(execute(conn,protocol,'select salary from employees where id = 1')[0][0]))==54321, 'committed salary not restored'
            results.append(dict(protocol=protocol,stage='reconnect',persistent_state=True))
        elif cfg['stage']=='outage':
            login_rejected(protocol,name,password)
            with connect(protocol,admin,secret) as conn:
                assert int(execute(conn,protocol,'select 1')[0][0])==1
                sql="CREATE USER fake_outage "+('PASSWORD' if protocol=='postgres' else 'IDENTIFIED BY')+f" '{password}'"
                execute(conn,protocol,sql,success=False)
            with connect(protocol,admin,secret,backend=True) as conn:
                sql="SELECT count(*) FROM "+('pg_roles WHERE rolname' if protocol=='postgres' else 'mysql.user WHERE user')+" = 'fake_outage'"
                assert int(execute(conn,protocol,sql)[0][0])==0
            results.append(dict(protocol=protocol,stage='outage',synthetic_auth_rejected=True,
                                seeded_auth_preserved=True,creation_rejected=True,backend_user_count=0))
        elif cfg['stage']=='disable':
            with connect(protocol,admin,secret) as conn:
                execute(conn,protocol,('ALTER ROLE '+name+' NOLOGIN') if protocol=='postgres' else ('ALTER USER '+name+' ACCOUNT LOCK'))
            login_rejected(protocol,name,password)
            results.append(dict(protocol=protocol,stage='disable',disabled_login_rejected=True))
    print(json.dumps({'ok':True,'results':results}))
except Exception as exc:
    message=str(exc)
    for name,value in cfg.items():
        if 'password' in name and value:message=message.replace(value,'[REDACTED]')
    import traceback
    print(json.dumps({'ok':False,'results':results,'error':message,'type':type(exc).__name__,'line':traceback.extract_tb(exc.__traceback__)[-1].lineno}))
    sys.exit(1)
