import asyncio
import hashlib
import hmac
import json
import secrets
import unittest
from contextlib import nullcontext
from unittest.mock import MagicMock, patch

import api
from exposure import ExposureTracker
from generator import DataGenerator
from mutation_store import MutationStore
from schema_loader import SchemaLoader
from principal_registry import PrincipalRegistry, PrincipalError, PREFIX, b64, unb64
from principal_runtime import query


class MemoryRedis:
    def __init__(self):
        self.values, self.hashes, self.sets, self.expiry = {}, {}, {}, {}
    def get(self, key): return self.values.get(key)
    def set(self, key, value): self.values[key] = value
    def setex(self, key, ttl, value): self.set(key, value); self.expiry[key] = ttl
    def getdel(self, key): return self.values.pop(key, None)
    def exists(self, key): return key in self.values
    def delete(self, *keys):
        for key in keys:
            self.values.pop(key, None); self.hashes.pop(key, None)
    def sadd(self, key, value): self.sets.setdefault(key, set()).add(value)
    def scard(self, key): return len(self.sets.get(key, set()))
    def incr(self, key): self.values[key] = int(self.values.get(key, 0)) + 1
    def hset(self, key, mapping): self.hashes.setdefault(key, {}).update(mapping)
    def hget(self, key, field): return self.hashes.get(key, {}).get(field)
    def expire(self, key, ttl): self.expiry[key] = ttl
    def scan_iter(self, pattern, count=200): return iter([k for k in self.values if k.startswith(pattern.rstrip('*'))])
    def lock(self, *a, **kw): return nullcontext()
    def pipeline(self, **kw): return self
    def execute(self): pass
    def __enter__(self): return self
    def __exit__(self, *args): pass


class PrincipalTests(unittest.TestCase):
    def setUp(self):
        self.redis = MemoryRedis()
        self.secret = b64(secrets.token_bytes(32))
        self.reg = PrincipalRegistry(self.redis, self.secret)
        self.password = secrets.token_hex(18)

    def command(self, sql, protocol='postgres', session='creator', **extra):
        return self.reg.command(dict(protocol=protocol, username='postgres' if protocol=='postgres' else 'root',
                                     session_id=session, sql=sql, **extra))

    def create(self, protocol='postgres', name='fake_compro1'):
        sql = f"CREATE USER {name} " + ("PASSWORD" if protocol=='postgres' else "IDENTIFIED BY") + f" '{self.password}'"
        return self.command(sql, protocol)

    def native(self, sid='return-1', name='fake_compro1', password=None):
        salt = secrets.token_bytes(20)
        first = hashlib.sha1((password or self.password).encode()).digest()
        second = hashlib.sha1(first).digest()
        scramble = hashlib.sha1(salt+second).digest()
        token = bytes(a^b for a,b in zip(first,scramble))
        return self.reg.native_auth(dict(username=name, session_id=sid, salt=b64(salt), auth_token=b64(token)))

    def scram_body(self, password=None, sid='return-1'):
        nonce=secrets.token_hex(16)
        first='n=,r='+nonce
        start=self.reg.start_scram(dict(username='fake_compro1',session_id=sid,client_first='n,,'+first))
        values=dict(x.split('=',1) for x in start['server_first'].split(','))
        final='c=biws,r='+values['r']
        salted=hashlib.pbkdf2_hmac('sha256',(password or self.password).encode(),unb64(values['s']),int(values['i']))
        client=hmac.new(salted,b'Client Key',hashlib.sha256).digest()
        auth=(first+','+start['server_first']+','+final).encode()
        signature=hmac.new(hashlib.sha256(client).digest(),auth,hashlib.sha256).digest()
        proof=bytes(a^b for a,b in zip(client,signature))
        body=dict(token=start['token'],client_final=final+',p='+b64(proof))
        expected=hmac.new(hmac.new(salted,b'Server Key',hashlib.sha256).digest(),auth,hashlib.sha256).digest()
        return body,expected

    def test_secret_and_full_key(self):
        for secret in ('', 'bad', b64(b'x'*31)):
            reg=PrincipalRegistry(self.redis,secret)
            self.assertFalse(reg.enabled)
            with self.assertRaises(PrincipalError): reg.key('postgres','fake_one')
        self.create()
        record=self.reg.load(self.reg.key('postgres','fake_compro1'))
        self.assertEqual(len(record['principal_id']),67)
        self.assertNotIn(self.password,repr(self.redis.values))
        self.assertNotIn(self.reg.key('postgres','fake_compro1'),self.redis.expiry)

    def test_duplicate_and_invalid_are_not_created(self):
        self.create()
        with self.assertRaises(PrincipalError): self.create()
        for sql in ("CREATE USER real_user PASSWORD 'something'", "CREATE USER fake_x", "GRANT ALL ON *.* TO fake_compro1"):
            with self.assertRaises(PrincipalError): self.command(sql)
        self.assertEqual(self.reg.metrics()['deceptive_principals_created_total'],1)

    def test_bounded_role_and_quoted_mysql_syntax(self):
        self.command("CREATE ROLE fake_role LOGIN PASSWORD 'synthetic-value'")
        self.command("CREATE USER 'fake_quoted'@'%' IDENTIFIED BY 'synthetic-value'", 'mysql')
        with self.assertRaises(PrincipalError):
            self.command("CREATE USER 'fake_malformed IDENTIFIED BY 'synthetic-value'", 'mysql')
        self.assertEqual(self.reg.metrics()['deceptive_principals_created_total'], 2)

    def test_permission_and_transaction_rejection(self):
        with self.assertRaises(PrincipalError):
            self.reg.command(dict(protocol='postgres', username='proxyuser', session_id='s', sql='CREATE USER fake_x PASSWORD \'secret123\''))
        with self.assertRaises(PrincipalError): self.command("CREATE USER fake_x PASSWORD 'secret123'",transaction_active=True)
        self.assertEqual(self.reg.metrics()['deceptive_principals_created_total'],0)

    def test_scram_proof_signature_and_replay(self):
        self.create(); body,expected=self.scram_body()
        result=self.reg.finish_scram(body)
        self.assertEqual(result['server_final'],'v='+b64(expected))
        self.assertEqual(result['events'][1]['confidence'],1.0)
        self.assertEqual(result['events'][1]['parent_session_id'],'creator')
        with self.assertRaises(PrincipalError): self.reg.finish_scram(body)
        self.assertNotIn(self.password,repr(self.redis.values))
        self.assertNotIn('stored_key',json.dumps(result))

    def test_scram_wrong_password_and_disable_in_flight(self):
        self.create(); body,_=self.scram_body(password='wrong-password')
        with self.assertRaises(PrincipalError): self.reg.finish_scram(body)
        body,_=self.scram_body(); self.command('ALTER ROLE fake_compro1 NOLOGIN')
        with self.assertRaises(PrincipalError): self.reg.finish_scram(body)
        self.assertEqual(self.reg.metrics()['deceptive_principal_return_sessions_total'],0)

    def test_mysql_proof_wrong_password_and_disabled(self):
        self.create('mysql')
        with self.assertRaises(PrincipalError): self.native(password='wrong-password')
        result=self.native()
        self.assertTrue(result['is_return_session'])
        self.command('DROP USER fake_compro1','mysql')
        with self.assertRaises(PrincipalError): self.native('return-2')
        self.assertEqual(self.reg.metrics()['deceptive_principals_created_total'],1)

    def test_metrics_distinct_two_created_one_reused(self):
        self.assertEqual(self.reg.metrics()['deceptive_persistence_reengagement_rate'],0)
        self.create('mysql');self.create('mysql','fake_unused')
        self.native('r1');self.native('r2')
        metrics=self.reg.metrics()
        self.assertEqual(list(metrics.values()),[2,1,2,0.5])
        self.assertNotIn('fake_',json.dumps(metrics))

    def test_rotation_preserves_identity_and_rejects_old_password(self):
        self.create('mysql'); old=self.native()['deceptive_principal_id']
        self.command("ALTER USER fake_compro1 IDENTIFIED BY 'different-password'",'mysql')
        with self.assertRaises(PrincipalError):self.native('r2')
        self.assertEqual(self.native('r3',password='different-password')['deceptive_principal_id'],old)

    def test_registry_outage_never_claims_success(self):
        with patch.object(self.redis,'get',side_effect=ConnectionError):
            with self.assertRaises(ConnectionError):self.native()
        with patch.object(self.redis,'exists',side_effect=ConnectionError):
            with self.assertRaises(ConnectionError):self.create()

    def test_expired_login_and_creation_do_not_change_metrics(self):
        self.create('mysql')
        self.reg.deadline_ms = 1
        with self.assertRaises(PrincipalError): self.native()
        with self.assertRaises(PrincipalError): self.create('mysql', 'fake_late')
        self.assertEqual(self.reg.metrics()['deceptive_principals_created_total'], 1)
        self.assertEqual(self.reg.metrics()['deceptive_principal_return_sessions_total'], 0)

    def test_native_malformed_lengths(self):
        self.create('mysql')
        for salt,token in ((b'',b''),(b'x'*20,b'x'*19),(b'x'*19,b'x'*20)):
            with self.assertRaises(PrincipalError):self.reg.native_auth(dict(username='fake_compro1',session_id='r',salt=b64(salt),auth_token=b64(token)))


class PersistentStateTests(PrincipalTests):
    # Separate class runs only persistence methods; inherited verifier tests are intentionally excluded below.
    def setUp(self):
        super().setUp()
        self.old={name:getattr(api,name) for name in ('_schema_loader','_generator','_exposure','_mutations','DECIDE_RATE_LIMIT_ENABLED')}
        api._schema_loader=SchemaLoader();api._generator=DataGenerator()
        api._exposure=ExposureTracker(self.redis);api._mutations=MutationStore(self.redis)
        api.DECIDE_RATE_LIMIT_ENABLED=False
        self.create('mysql')
        self.command('GRANT SELECT, INSERT, UPDATE, DELETE ON testdb.* TO fake_compro1','mysql')
        self.native('s1')
    def tearDown(self):
        for name,value in self.old.items():setattr(api,name,value)
    def q(self,sql,sid='s1'):
        return asyncio.run(query(self.reg,api,MagicMock(),dict(session_id=sid,sql=sql)))
    def test_committed_state_survives_reconnect_and_rollback(self):
        original=self.q('select * from employees where id = 1')['rows'][0]
        self.q('begin');self.q("update employees set salary = 12345 where id = 1");self.q('rollback')
        self.assertEqual(self.q('select * from employees where id = 1')['rows'][0],original)
        self.q('begin');self.q("update employees set salary = 54321 where id = 1");self.q('commit')
        api._mutations.cleanup_session('s1');api._exposure.cleanup_session('s1')
        self.native('s2')
        self.assertEqual(self.q('select salary from employees where id = 1','s2')['rows'][0]['salary'],54321)
        self.assertEqual(self.q('select salary from employees where id = 1','s2')['tx_status'],'I')
    def test_disconnect_discards_uncommitted_state(self):
        baseline=self.q('select salary from employees where id = 1')['rows']
        self.q('begin');self.q('update employees set salary = 98765 where id = 1')
        self.native('s2')
        self.assertEqual(self.q('select salary from employees where id = 1','s2')['rows'],baseline)
    def test_concurrent_commit_conflict_and_unsupported_operation(self):
        self.q('begin');self.q('update employees set salary = 10101 where id = 1')
        self.native('s2');self.q('update employees set salary = 20202 where id = 1','s2')
        self.assertEqual(self.q('commit')['sqlstate'],'40001')
        self.q('rollback')
        self.assertEqual(self.q('create table unsafe (id int)')['mode'],'block')
        self.assertEqual(self.q('select * from unknown_table')['mode'],'block')


# Reuse fixture helpers without collecting base tests twice under unittest.
for _name in list(PrincipalTests.__dict__):
    if _name.startswith('test_'):
        setattr(PersistentStateTests,_name,None)
