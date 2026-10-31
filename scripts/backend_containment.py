"""Idempotent operator-only bootstrap; never print credentials or SQL errors.

Runs from the existing replay image, whose pinned DB drivers are reused. Runtime
passwords arrive only through the canonical launcher child environment. Existing
volumes are migrated in place; no schema, rows, admin roles or volumes are removed.
"""
import os
import time

import psycopg
import pymysql
from psycopg import sql


def postgres():
    with psycopg.connect(host="postgres", dbname="testdb", user="postgres",
                          password=os.environ["POSTGRES_PASSWORD"], connect_timeout=3,
                          autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM pg_roles WHERE rolname='honeypot_pg_runtime'")
            if not cur.fetchone():
                cur.execute("CREATE ROLE honeypot_pg_runtime LOGIN")
            cur.execute(sql.SQL("ALTER ROLE honeypot_pg_runtime WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD {}").format(sql.Literal(os.environ["PG_RUNTIME_PASSWORD"])))
            cur.execute("SELECT parent.rolname FROM pg_auth_members m JOIN pg_roles child ON child.oid=m.member JOIN pg_roles parent ON parent.oid=m.roleid WHERE child.rolname='honeypot_pg_runtime'")
            for (role,) in cur.fetchall():
                cur.execute(sql.SQL("REVOKE {} FROM honeypot_pg_runtime").format(sql.Identifier(role)))
            cur.execute("SELECT EXISTS(SELECT 1 FROM pg_database WHERE datdba=(SELECT oid FROM pg_roles WHERE rolname='honeypot_pg_runtime')) OR EXISTS(SELECT 1 FROM pg_namespace WHERE nspowner=(SELECT oid FROM pg_roles WHERE rolname='honeypot_pg_runtime')) OR EXISTS(SELECT 1 FROM pg_class WHERE relowner=(SELECT oid FROM pg_roles WHERE rolname='honeypot_pg_runtime'))")
            if cur.fetchone()[0]:
                raise RuntimeError("runtime ownership requires operator review")
            cur.execute("REVOKE ALL ON DATABASE testdb FROM honeypot_pg_runtime")
            cur.execute("REVOKE CREATE,TEMPORARY ON DATABASE testdb FROM PUBLIC")
            cur.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
            cur.execute("GRANT CONNECT ON DATABASE testdb TO honeypot_pg_runtime")
            cur.execute("GRANT USAGE ON SCHEMA public TO honeypot_pg_runtime")
            cur.execute("ALTER ROLE honeypot_pg_runtime SET default_transaction_read_only=on")
            cur.execute("ALTER ROLE honeypot_pg_runtime SET statement_timeout='2s'")
            cur.execute("SELECT rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls FROM pg_roles WHERE rolname='honeypot_pg_runtime'")
            if any(cur.fetchone()):
                raise RuntimeError("privilege verification failed")


def mysql():
    conn = pymysql.connect(host="mysql", user="root", password=os.environ["MYSQL_ROOT_PASSWORD"],
                           connect_timeout=3, autocommit=True)
    try:
        with conn.cursor() as cur:
            # Disable query logging for this operator session before password DDL.
            cur.execute("SET SESSION sql_log_off=1")
            cur.execute("CREATE USER IF NOT EXISTS 'honeypot_mysql_runtime'@'%%' IDENTIFIED WITH mysql_native_password BY %s", (os.environ["MYSQL_RUNTIME_PASSWORD"],))
            cur.execute("ALTER USER 'honeypot_mysql_runtime'@'%%' IDENTIFIED WITH mysql_native_password BY %s", (os.environ["MYSQL_RUNTIME_PASSWORD"],))
            cur.execute("SELECT FROM_USER,FROM_HOST FROM mysql.role_edges WHERE TO_USER='honeypot_mysql_runtime' AND TO_HOST='%'")
            for role, host in cur.fetchall():
                cur.execute("REVOKE %s@%s FROM 'honeypot_mysql_runtime'@'%%'", (role, host))
            cur.execute("REVOKE ALL PRIVILEGES,GRANT OPTION FROM 'honeypot_mysql_runtime'@'%'")
            cur.execute("SET DEFAULT ROLE NONE TO 'honeypot_mysql_runtime'@'%'")
            cur.execute("GRANT SELECT ON testdb.* TO 'honeypot_mysql_runtime'@'%'")
            cur.execute("SELECT PRIV FROM mysql.global_grants WHERE USER='honeypot_mysql_runtime' AND HOST='%'")
            if cur.fetchall():
                raise RuntimeError("unexpected dynamic privileges")
            cur.execute("SHOW GRANTS FOR 'honeypot_mysql_runtime'@'%'")
            grants = [row[0] for row in cur.fetchall()]
            if len(grants) != 2 or not any("GRANT SELECT ON `testdb`.*" in g for g in grants):
                raise RuntimeError("privilege verification failed")
    finally:
        conn.close()


def main():
    for attempt in range(30):
        stage = "postgres"
        try:
            postgres()
            stage = "mysql"
            mysql()
            print("BACKEND CONTAINMENT INITIALIZED: non-admin runtime identities verified")
            return
        except Exception as exc:
            if attempt == 29:
                print("Initialization stage:", stage, "error category:", type(exc).__name__, flush=True)
                raise SystemExit("Backend containment initialization failed (details suppressed)") from None
            time.sleep(2)


if __name__ == "__main__":
    main()
