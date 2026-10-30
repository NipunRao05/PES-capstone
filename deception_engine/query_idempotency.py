"""Redis-owned duplicate suppression, not transactional exactly-once execution."""
import base64
from functools import lru_cache
import hashlib
import json
import os
from uuid import UUID, uuid4
import redis
from fastapi import HTTPException
from starlette.responses import Response

RETENTION = 600
CAPACITY = 1024
STALE_AFTER = 5
MAX_REQUEST_BYTES = 192 * 1024
MAX_RESPONSE_BYTES = 2 << 20  # Existing private proxy response decoder limit.
MAX_RECORD_BYTES = 3 << 20   # Base64 response plus metadata.
TOTAL_BYTES = 32 << 20
PREFIX = "deception:query-idempotency:v1"

PRELUDE = r'''
local function kind(k) return redis.call('TYPE',k).ok end
local types = {'hash','zset','string'}
for i=1,3 do local t=kind(KEYS[i]); if t~='none' and t~=types[i] then return {'INTEGRITY'} end end
local count=redis.call('HLEN',KEYS[1])
local bytes=tonumber(redis.call('GET',KEYS[3]) or '0')
if count~=redis.call('ZCARD',KEYS[2]) or not bytes or bytes<0 or bytes~=math.floor(bytes) then return {'INTEGRITY'} end
if count>0 and redis.call('EXISTS',KEYS[3])==0 then return {'INTEGRITY'} end
local now=tonumber(redis.call('TIME')[1])
-- Expiry is the protection horizon, not an execution lease or safe takeover.
if count>tonumber(ARGV[1]) then return {'INTEGRITY'} end
local expired=redis.call('ZRANGEBYSCORE',KEYS[2],'-inf',now,'LIMIT',0,tonumber(ARGV[1]))
for _,id in ipairs(expired) do
 bytes=bytes-redis.call('HSTRLEN',KEYS[1],id)
 redis.call('HDEL',KEYS[1],id);redis.call('ZREM',KEYS[2],id)
end
if bytes<0 then return {'INTEGRITY'} end
if #expired>0 then redis.call('SET',KEYS[3],bytes) end
local function replace(id,raw)
 bytes=bytes-redis.call('HSTRLEN',KEYS[1],id)+string.len(raw)
 redis.call('HSET',KEYS[1],id,raw);redis.call('SET',KEYS[3],bytes)
end
local function load(id)
 local raw=redis.call('HGET',KEYS[1],id)
 if not raw then return nil end
 local ok,r=pcall(cjson.decode,raw)
 if not ok or type(r)~='table' or r.idempotency_schema_version~=1 or r.query_execution_id~=id or
  type(r.request_digest)~='string' or #r.request_digest~=64 or type(r.owner_token)~='string' or #r.owner_token~=36 or
  type(r.claimed_at)~='number' or type(r.expires_at)~='number' or r.expires_at<=now or
  (r.status~='CLAIMED' and r.status~='COMPLETE' and r.status~='AMBIGUOUS' and r.status~='COMPLETE_UNREPLAYABLE') then return false end
 local expiry=tonumber(redis.call('ZSCORE',KEYS[2],id))
 if not expiry or expiry~=r.expires_at then return false end
 if r.status=='COMPLETE' and type(r.payload)~='string' then return false end
 return r
end
'''

CLAIM = PRELUDE + r'''
-- capacity, id, digest, owner, retention, stale_after, total_bytes
local r=load(ARGV[2])
if r==false then return {'INTEGRITY'} end
if r then
 if r.request_digest~=ARGV[3] then return {'CONFLICT'} end
 if r.status=='CLAIMED' and now-r.claimed_at>=tonumber(ARGV[6]) then
  r.status='AMBIGUOUS'; replace(ARGV[2],cjson.encode(r))
 end
 return {r.status,redis.call('HGET',KEYS[1],ARGV[2])}
end
if redis.call('HLEN',KEYS[1])>=tonumber(ARGV[1]) then return {'FULL'} end
r={idempotency_schema_version=1,query_execution_id=ARGV[2],request_digest=ARGV[3],
 owner_token=ARGV[4],claimed_at=now,expires_at=now+tonumber(ARGV[5]),status='CLAIMED'}
local raw=cjson.encode(r)
if bytes+#raw>tonumber(ARGV[7]) then return {'FULL'} end
replace(ARGV[2],raw)
redis.call('ZADD',KEYS[2],r.expires_at,ARGV[2])
for _,key in ipairs(KEYS) do redis.call('EXPIRE',key,tonumber(ARGV[5])+1) end
return {'OWNER',raw}
'''

FINISH = PRELUDE + r'''
-- capacity, id, digest, owner, status, payload, max_record, total_bytes
local r=load(ARGV[2])
if r==false then return {'INTEGRITY'} end
if not r or r.status~='CLAIMED' or r.owner_token~=ARGV[4] or r.request_digest~=ARGV[3] then return {'STALE'} end
r.status=ARGV[5]
if r.status=='COMPLETE' then r.payload=ARGV[6] end
local raw=cjson.encode(r)
local newbytes=bytes-redis.call('HSTRLEN',KEYS[1],ARGV[2])+#raw
if #raw>tonumber(ARGV[7]) or newbytes>tonumber(ARGV[8]) then
 r.status='COMPLETE_UNREPLAYABLE';r.payload=nil;raw=cjson.encode(r)
end
replace(ARGV[2],raw)
return {r.status}
'''


class ReplayIntegrityError(ValueError):
    pass


def encode(value):
    return json.dumps(value,sort_keys=True,separators=(",", ":"),allow_nan=False)


def request_digest(scope, body, principal_reference=None):
    # Deadline changes on retry; every other supplied field participates.
    semantic={k:v for k,v in body.items() if k!="deadline_ms"}
    raw=encode(dict(scope=scope,request=semantic,principal_reference=principal_reference))
    if len(raw.encode())>MAX_REQUEST_BYTES:
        raise ValueError("Idempotency request exceeds bound")
    return hashlib.sha256(raw.encode()).hexdigest()


def pack_response(result):
    if isinstance(result,Response):
        body=result.body
        headers=[[k.decode("latin1"),v.decode("latin1")] for k,v in result.raw_headers]
        if len(headers)>16 or any(k not in {"content-type","content-length"} or len(v)>256 for k,v in headers):return None
        kind,status="response",result.status_code
    elif isinstance(result,HTTPException):
        if result.headers:return None
        body=json.dumps({"detail":result.detail},separators=(",", ":"),allow_nan=False).encode()
        kind,status,headers="exception",result.status_code,[]
    elif isinstance(result,dict):
        body=json.dumps(result,separators=(",", ":"),allow_nan=False).encode()
        kind,status,headers="dict",200,[]
    else:return None
    if len(body)>MAX_RESPONSE_BYTES:return None
    return encode(dict(kind=kind,status=status,headers=headers,body=base64.b64encode(body).decode()))


def unpack_response(payload, identity):
    try:
        p=json.loads(payload)
        if set(p)!={"kind","status","headers","body"} or type(p["status"]) is not int or not 100<=p["status"]<=599:raise ValueError()
        body=base64.b64decode(p["body"],validate=True)
        if len(body)>MAX_RESPONSE_BYTES or p["kind"] not in {"response","dict","exception"} or not isinstance(p["headers"],list) or len(p["headers"])>16:raise ValueError()
        data=json.loads(body)
        if not isinstance(data,dict):raise ValueError()
        correlation=data.get("_correlation")
        if correlation is not None:
            if correlation.get("query_execution_id")!=identity:raise ValueError()
            for field in ("decision_id","application_id"):
                if str(UUID(correlation[field]))!=correlation[field]:raise ValueError()
        headers=[]
        for key,value in p["headers"]:
            if key not in {"content-type","content-length"} or not isinstance(value,str) or len(value)>256:raise ValueError()
            headers.append((key.encode("latin1"),value.encode("latin1")))
        if p["kind"]=="dict":return data
        if p["kind"]=="exception":return HTTPException(p["status"],data["detail"])
        result=Response(content=body,status_code=p["status"])
        result.raw_headers=headers
        return result
    except (ValueError,TypeError,KeyError,AttributeError,UnicodeError):
        raise ReplayIntegrityError("IDEMPOTENCY_INTEGRITY_ERROR") from None


class ReplayStore:
    def __init__(self,client,*,prefix=PREFIX,retention=RETENTION,capacity=CAPACITY,stale_after=STALE_AFTER):
        self.client,self.retention,self.capacity,self.stale_after=client,retention,capacity,stale_after
        self.keys=[prefix+suffix for suffix in (":records",":expiry",":bytes")]

    def claim(self,identity,digest,owner):
        result=self.client.eval(CLAIM,3,*self.keys,self.capacity,identity,digest,owner,self.retention,self.stale_after,TOTAL_BYTES)
        result=[x.decode() if isinstance(x,bytes) else x for x in result]
        if result[0]=="INTEGRITY":raise ReplayIntegrityError("IDEMPOTENCY_INTEGRITY_ERROR")
        if result[0]=="COMPLETE":
            try:
                r=json.loads(result[1])
                return "COMPLETE",unpack_response(r["payload"],identity)
            except (ValueError,TypeError,KeyError):
                raise ReplayIntegrityError("IDEMPOTENCY_INTEGRITY_ERROR") from None
        return result[0],None

    def finish(self,identity,digest,owner,result=None,*,ambiguous=False):
        payload=None if ambiguous else pack_response(result)
        status="AMBIGUOUS" if ambiguous else "COMPLETE" if payload is not None else "COMPLETE_UNREPLAYABLE"
        response=self.client.eval(FINISH,3,*self.keys,self.capacity,identity,digest,owner,status,payload or "",MAX_RECORD_BYTES,TOTAL_BYTES)
        value=response[0].decode() if isinstance(response[0],bytes) else response[0]
        if value=="INTEGRITY":raise ReplayIntegrityError("IDEMPOTENCY_INTEGRITY_ERROR")
        return value


@lru_cache(maxsize=1)
def get_store():
    # Pool only; no process-local request authority or Redis-failure fallback.
    return ReplayStore(redis.Redis(host=os.getenv("REDIS_HOST","localhost"),port=int(os.getenv("REDIS_PORT","6379")),
        decode_responses=True,socket_timeout=0.2,socket_connect_timeout=0.2,retry_on_timeout=False))


def owner_token():
    return str(uuid4())
