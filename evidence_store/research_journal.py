"""Bounded immutable sanitized event journal; session lists remain projections."""
import hashlib
import json
import os
from datetime import datetime, timezone
from uuid import uuid4

PREFIX="evidence:research-journal:v1"
HEALTH="evidence:research-health:v1"
CAPACITY=int(os.getenv("EVENT_JOURNAL_CAPACITY","524288"))
MAX_RECORD_BYTES=524288


class JournalCapacityError(ValueError):
    pass


WRITE=r'''
-- research-journal-write-v1
for i=1,4 do
 local typ=redis.call('TYPE',KEYS[i]).ok
 local expected=(i==2 or i==3) and 'zset' or 'hash'
 if typ~='none' and typ~=expected then return {'INTEGRITY'} end
end
if redis.call('HLEN',KEYS[1])~=redis.call('ZCARD',KEYS[2]) or redis.call('HLEN',KEYS[1])~=redis.call('ZCARD',KEYS[3]) then return {'INTEGRITY'} end
local old=redis.call('HGET',KEYS[1],ARGV[1])
if old then return {old==ARGV[2] and 'UNCHANGED' or 'CONFLICT'} end
local clock=redis.call('TIME');local now=tonumber(clock[1])
local expired=redis.call('ZRANGEBYSCORE',KEYS[3],'-inf',now,'LIMIT',0,128)
for _,id in ipairs(expired) do
 redis.call('HDEL',KEYS[1],id);redis.call('ZREM',KEYS[2],id);redis.call('ZREM',KEYS[3],id)
end
if #expired>0 then redis.call('HINCRBY',KEYS[4],'expired_records',#expired) end
if redis.call('HLEN',KEYS[1])>=tonumber(ARGV[3]) then
 redis.call('HINCRBY',KEYS[4],'capacity_rejections',1);return {'CAPACITY'}
end
local sequence=redis.call('HINCRBY',KEYS[4],'sequence',1)
if sequence>=9007199254740991 then return {'INTEGRITY'} end
redis.call('HSETNX',KEYS[4],'epoch',ARGV[5]);redis.call('HSETNX',KEYS[4],'enabled_at',ARGV[6])
redis.call('HSET',KEYS[1],ARGV[1],ARGV[2]);redis.call('ZADD',KEYS[2],sequence,ARGV[1]);redis.call('ZADD',KEYS[3],now+tonumber(ARGV[4]),ARGV[1])
return {'INSERTED'}
'''

PAGE=r'''
-- research-journal-page-v1
local maximum=ARGV[2]=='-1' and tonumber(redis.call('HGET',KEYS[4],'sequence') or '0') or tonumber(ARGV[2])
local epoch=redis.call('HGET',KEYS[4],'epoch') or ''
if ARGV[4]~='' and epoch~=ARGV[4] then return {'INTEGRITY'} end
local rows=redis.call('ZRANGEBYSCORE',KEYS[2],'('..ARGV[1],maximum,'WITHSCORES','LIMIT',0,ARGV[3])
local result={};local cursor=tonumber(ARGV[1]);local missing=0
local now=tonumber(redis.call('TIME')[1])
for n=1,#rows,2 do
 cursor=tonumber(rows[n+1]);local raw=redis.call('HGET',KEYS[1],rows[n]);local expiry=redis.call('ZSCORE',KEYS[3],rows[n])
 if raw and expiry and tonumber(expiry)>now then table.insert(result,{rows[n],rows[n+1],raw}) else missing=missing+1 end
end
return {'OK',tostring(maximum),epoch,tostring(cursor),tostring(redis.call('ZCOUNT',KEYS[2],'('..cursor,maximum)),result,tostring(missing)}
'''


def decoded(value):
    if isinstance(value,bytes):return value.decode()
    if isinstance(value,list):return [decoded(x) for x in value]
    return value


class Journal:
    def __init__(self,client,ttl=2592000,capacity=CAPACITY,prefix=PREFIX):
        self.client,self.ttl,self.capacity=client,ttl,capacity
        self.keys=[prefix+x for x in (":records",":members",":expiry",":meta")]

    def append(self,session_id,collection,event_id,payload):
        record={"schema_version":1,"session_id":session_id,"collection":collection,"event_id":event_id,"payload":payload}
        raw=json.dumps(record,sort_keys=True,separators=(",",":"),allow_nan=False)
        if len(raw.encode())>MAX_RECORD_BYTES:raise ValueError("Journal record exceeds bound")
        identity=hashlib.sha256((session_id+":"+collection+":"+event_id).encode()).hexdigest()
        result=decoded(self.client.eval(WRITE,4,*self.keys,identity,raw,self.capacity,self.ttl,str(uuid4()),datetime.now(timezone.utc).isoformat()))[0]
        if result=="CAPACITY":raise JournalCapacityError("Research journal full; consumer backpressured")
        if result not in {"INSERTED","UNCHANGED"}:raise ValueError("Research journal integrity conflict")
        return result.lower()

    def page(self,after=0,maximum=None,epoch="",limit=128):
        if type(after) is not int or after<0 or type(limit) is not int or not 1<=limit<=128:
            raise ValueError("Invalid journal page")
        if maximum is not None and (type(maximum) is not int or maximum<after):raise ValueError("Invalid boundary")
        result=decoded(self.client.eval(PAGE,4,*self.keys,after,-1 if maximum is None else maximum,limit,epoch))
        if result[0]!="OK":raise ValueError("Journal epoch/integrity error")
        return {"snapshot_max_sequence":int(result[1]),"epoch":result[2],"after_sequence":int(result[3]),
            "done":int(result[4])==0,"missing_records":int(result[6]),
            "entries":[{"record_id":i,"sequence":int(s),"record":json.loads(raw)} for i,s,raw in result[5]]}

    def status(self):
        return {"entries":self.client.hlen(self.keys[0]),"capacity":self.capacity,
            "metadata":self.client.hgetall(self.keys[3]),"collection_completeness":"NOT_VERIFIED"}
