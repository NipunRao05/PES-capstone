"""Bounded local hardening check. No filesystem/process/plugin payload executes.

Host mode supplies credentials privately on stdin to a disposable driver container.
All query results containing lure values remain inside that process. Output is
checks/counts/privilege metadata only. Query sessions are engineering fixtures.
"""
import json
import os
from pathlib import Path
import subprocess
import sys


def inside():
    from datetime import datetime, timezone
    started_at=datetime.now(timezone.utc).isoformat()
    import psycopg
    import pymysql
    secrets = json.load(sys.stdin)
    results = []
    phase = ["initial"]
    fixture_principals = []

    def record(name, fn):
        try:
            fn()
            results.append({"check": name, "passed": True})
        except Exception as exc:
            results.append({"check": name, "passed": False, "category": type(exc).__name__, "phase":phase[0],
                            "sqlstate":getattr(exc,"sqlstate",None),
                            "errno":exc.args[0] if exc.args and isinstance(exc.args[0],int) else None,
                            "diagnostic_categories":[x for x in ("authentication failed", "connection refused", "permission denied", "Command denied", "Unknown database", "could not translate", "SCRAM") if x.lower() in str(exc).lower()]})

    def pg_grants():
        with psycopg.connect(host="postgres", user="honeypot_pg_runtime", dbname="testdb",
                              password=secrets["PG_RUNTIME_PASSWORD"], autocommit=True) as conn:
            row = conn.execute("SELECT current_user,rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls FROM pg_roles WHERE rolname=current_user").fetchone()
            assert row[0] == "honeypot_pg_runtime" and not any(row[1:])
            assert conn.execute("SELECT has_database_privilege(current_user,'testdb','CREATE'),has_database_privilege(current_user,'testdb','TEMP'),has_schema_privilege(current_user,'public','CREATE')").fetchone() == (False, False, False)
            assert conn.execute("SHOW default_transaction_read_only").fetchone()[0] == "on"

    def mysql_grants():
        conn = pymysql.connect(host="mysql", user="honeypot_mysql_runtime", database="testdb",
                               password=secrets["MYSQL_RUNTIME_PASSWORD"], autocommit=True)
        try:
            with conn.cursor() as cur:
                cur.execute("SHOW GRANTS")
                grants = [r[0] for r in cur.fetchall()]
                assert len(grants) == 2
                assert any("GRANT SELECT ON `testdb`.*" in r for r in grants)
                assert all(not any(x in r for x in ("FILE", "SUPER", "PROCESS", "GRANT OPTION", "SYSTEM_USER")) for r in grants)
        finally:
            conn.close()

    def pg_world():
        phase[0]="postgres_login"
        with psycopg.connect(host="pgproxy",port=15432, user="postgres", dbname="testdb", password=secrets["PG_DECOY_PASSWORD"],
                              application_name="operator_hardening_pass1", autocommit=True) as conn:
            phase[0]="postgres_select1"
            assert conn.execute("SELECT 1").fetchone() == (1,)
            phase[0]="postgres_identity"
            assert conn.execute("SELECT current_user").fetchone() == ("postgres",)
            assert conn.execute("SELECT current_database()").fetchone() == ("testdb",)
            phase[0]="postgres_database_enumeration"
            assert [r[0] for r in conn.execute("SELECT datname FROM pg_database").fetchall()] == ["testdb"]
            phase[0]="postgres_table_enumeration"
            visible = {r[0] for r in conn.execute("SELECT table_name FROM information_schema.tables WHERE table_schema='public'").fetchall()}
            assert visible == {"employees", "departments", "sessions"}
            phase[0]="postgres_hr_read"
            first = conn.execute("SELECT id,email FROM employees LIMIT 3").fetchall()
            assert first and all(r[1].endswith("@company.internal") for r in first)
            assert conn.execute("SELECT id,email FROM employees LIMIT 3").fetchall() == first
            phase[0]="postgres_exposure"
            conn.execute("SELECT * FROM payroll LIMIT 1").fetchall()
            traps = conn.execute("SELECT token FROM api_keys_backup LIMIT 1").fetchall()
            assert traps and traps[0][0].startswith("hrv1_")
            phase[0]="postgres_mutation"
            conn.execute("UPDATE employees SET salary=123456 WHERE id=1")
            assert conn.execute("SELECT salary FROM employees WHERE id=1").fetchone() == (123456,)
            for query in ("CREATE ROLE unapproved_probe", "ALTER ROLE postgres SUPERUSER", "CREATE DATABASE unapproved_probe",
                          "SELECT pg_read_file('never-read')", "CREATE EXTENSION unapproved_probe",
                          "SELECT 1; SELECT pg_read_file('never-read')"):
                try:
                    conn.execute(query, prepare=False)
                except psycopg.Error:
                    continue
                raise AssertionError("unsafe statement was accepted")

    def mysql_world():
        conn = pymysql.connect(host="mysqlproxy",port=13306, user="root", database="testdb", password=secrets["MYSQL_DECOY_ROOT_PASSWORD"], autocommit=True)
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT 1"); assert cur.fetchone() == (1,)
                cur.execute("SHOW DATABASES"); assert cur.fetchall() == (("testdb",),)
                cur.execute("SHOW TABLES"); assert {r[0] for r in cur.fetchall()} == {"employees","departments","sessions"}
                conn.select_db("testdb")
                try:
                    conn.select_db("finance_production")
                except pymysql.Error:
                    pass
                else:
                    raise AssertionError("unapproved database switch")
                cur.execute("SELECT id,email FROM employees LIMIT 3"); first=cur.fetchall()
                assert first and all(r[1].endswith("@company.internal") for r in first)
                cur.execute("SELECT id,email FROM employees LIMIT 3"); assert cur.fetchall()==first
                cur.execute("SELECT * FROM payroll LIMIT 1"); cur.fetchall()
                cur.execute("SELECT token FROM api_keys_backup LIMIT 1"); assert cur.fetchone()[0].startswith("hrv1_")
                cur.execute("UPDATE employees SET salary=123456 WHERE id=1")
                cur.execute("SELECT salary FROM employees WHERE id=1"); assert int(cur.fetchone()[0])==123456
                for query in ("CREATE USER unapproved_probe", "GRANT ALL ON *.* TO unapproved_probe",
                              "SELECT LOAD_FILE('never-read')", "SET GLOBAL unapproved_probe=1", "DROP DATABASE unapproved_probe"):
                    try:
                        cur.execute(query)
                    except pymysql.Error:
                        continue
                    raise AssertionError("unsafe statement was accepted")
        finally:
            conn.close()

    def principal_world(protocol):
        import secrets as random_secrets
        username = "fake_hp1_" + protocol + "_" + random_secrets.token_hex(4)
        password = random_secrets.token_urlsafe(18)
        fixture_principals.append(username)
        if protocol == "pg":
            with psycopg.connect(host="pgproxy",port=15432,user="postgres",dbname="testdb",password=secrets["PG_DECOY_PASSWORD"],autocommit=True) as seed:
                seed.execute(f"CREATE USER {username} PASSWORD '{password}'")
                seed.execute(f"GRANT SELECT,UPDATE ON ALL TABLES IN SCHEMA public TO {username}")
                try:
                    for returning in (False,True):
                        with psycopg.connect(host="pgproxy",port=15432,user=username,dbname="testdb",password=password,autocommit=True) as conn:
                            if not returning:
                                conn.execute("SELECT id FROM employees LIMIT 1").fetchall()
                                conn.execute("SELECT employee_id FROM payroll LIMIT 1").fetchall()
                                conn.execute("BEGIN")
                                conn.execute("UPDATE employees SET salary=123457 WHERE id=1")
                                conn.execute("COMMIT")
                            assert conn.execute("SELECT salary FROM employees WHERE id=1").fetchone()==(123457,)
                            tables={r[0] for r in conn.execute("SELECT table_name FROM information_schema.tables WHERE table_schema='public'").fetchall()}
                            assert {"api_keys_backup","prod_credentials","salary_executives"} <= tables
                finally:
                    seed.execute(f"ALTER ROLE {username} NOLOGIN")
        else:
            seed=pymysql.connect(host="mysqlproxy",port=13306,user="root",database="testdb",password=secrets["MYSQL_DECOY_ROOT_PASSWORD"],autocommit=True)
            try:
                with seed.cursor() as cur:
                    cur.execute(f"CREATE USER {username} IDENTIFIED BY '{password}'")
                    cur.execute(f"GRANT SELECT,UPDATE ON testdb.* TO {username}")
                try:
                    for returning in (False,True):
                        conn=pymysql.connect(host="mysqlproxy",port=13306,user=username,database="testdb",password=password,autocommit=True,charset="utf8mb4")
                        try:
                            with conn.cursor() as cur:
                                if not returning:
                                    cur.execute("SELECT id FROM employees LIMIT 1");cur.fetchall()
                                    cur.execute("SELECT employee_id FROM payroll LIMIT 1");cur.fetchall()
                                    cur.execute("BEGIN");cur.execute("UPDATE employees SET salary=123457 WHERE id=1");cur.execute("COMMIT")
                                cur.execute("SELECT salary FROM employees WHERE id=1");assert int(cur.fetchone()[0])==123457
                                cur.execute("SHOW TABLES");assert {"api_keys_backup","prod_credentials","salary_executives"}<={r[0] for r in cur.fetchall()}
                        finally:
                            conn.close()
                finally:
                    with seed.cursor() as cur:
                        cur.execute(f"ALTER USER {username} ACCOUNT LOCK")
            finally:
                seed.close()

    for name, fn in (("PostgreSQL runtime privileges", pg_grants), ("MySQL runtime privileges", mysql_grants),
                     ("PostgreSQL proxy containment and HR world", pg_world), ("MySQL proxy containment and HR world", mysql_world),
                     ("PostgreSQL principal reconnect/commit/exposure",lambda:principal_world("pg")),
                     ("MySQL principal reconnect/commit/exposure",lambda:principal_world("mysql"))):
        record(name, fn)
    print(json.dumps({"validation_started_at":started_at,"validation_completed_at":datetime.now(timezone.utc).isoformat(),"fixture_origin":"operator_hardening_pass1", "fixture_principals":fixture_principals,"checks":results}, indent=2))
    return int(any(not r["passed"] for r in results))


def main():
    if "--inside" in sys.argv:
        return inside()
    from configuration import ROOT, load
    values = load()[3]
    keys = ("PG_RUNTIME_PASSWORD", "MYSQL_RUNTIME_PASSWORD", "PG_DECOY_PASSWORD", "MYSQL_DECOY_ROOT_PASSWORD")
    command = ["docker", "run", "--rm", "-i", "--label", "com.docker.compose.project=capstone-validation", "--network", "capstone-main_application", "--network", "capstone-main_state", "--mount",
               f"type=bind,source={ROOT / 'scripts/validate_backend_containment.py'},target=/validate.py,readonly",
               "capstone-main-backend-containment-init:runtime-v1", "python", "-B", "/validate.py", "--inside"]
    return subprocess.run(command, input=json.dumps({k: values[k] for k in keys}), text=True).returncode


if __name__ == "__main__":
    raise SystemExit(main())
