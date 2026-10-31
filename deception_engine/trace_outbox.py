"""Bounded Redis-owned trace outbox. Redis acknowledgements precede HTTP sends."""
import json
import logging
import time
import os

log = logging.getLogger(__name__)
CAPACITY = int(os.getenv("TRACE_OUTBOX_CAPACITY", "32768"))
RETENTION = int(os.getenv("TRACE_OUTBOX_RETENTION_SECONDS", "172800"))
MAX_ATTEMPTS = int(os.getenv("TRACE_OUTBOX_MAX_ATTEMPTS", "500"))

ENQUEUE = """
local expired=redis.call('ZRANGEBYSCORE',KEYS[3],'-inf',ARGV[1],'LIMIT',0,128)
for _,id in ipairs(expired) do
 redis.call('HDEL',KEYS[1],id); redis.call('ZREM',KEYS[2],id); redis.call('ZREM',KEYS[3],id);redis.call('ZREM',KEYS[4],id)
end
if #expired>0 then redis.call('HINCRBY',KEYS[5],'expired_total',#expired) end
local old=redis.call('HGET',KEYS[1],ARGV[2])
if old then return old end
if redis.call('HLEN',KEYS[1])>=tonumber(ARGV[5]) then redis.call('HINCRBY',KEYS[5],'full_total',1);return 'FULL' end
redis.call('HSET',KEYS[1],ARGV[2],ARGV[3])
redis.call('ZADD',KEYS[2],ARGV[1],ARGV[2])
redis.call('ZADD',KEYS[3],ARGV[4],ARGV[2])
redis.call('ZADD',KEYS[4],ARGV[1],ARGV[2])
local ttl=math.max(1,math.ceil(tonumber(ARGV[4])-tonumber(ARGV[1])))
for i=1,4 do redis.call('EXPIRE',KEYS[i],ttl) end
return 'INSERTED'
"""
UPDATE = """
if redis.call('HGET',KEYS[1],ARGV[1])~=ARGV[2] then return 0 end
if ARGV[3]=='DELIVERED' then
 redis.call('HDEL',KEYS[1],ARGV[1]); redis.call('ZREM',KEYS[2],ARGV[1]); redis.call('ZREM',KEYS[3],ARGV[1]);redis.call('ZREM',KEYS[4],ARGV[1])
else
 redis.call('HSET',KEYS[1],ARGV[1],ARGV[4])
 if ARGV[3]=='RETRY_PENDING' then redis.call('ZADD',KEYS[2],ARGV[5],ARGV[1])
 else redis.call('ZREM',KEYS[2],ARGV[1]);redis.call('ZREM',KEYS[4],ARGV[1]);redis.call('HINCRBY',KEYS[5],'terminal_total',1) end
end
return 1
"""
PRUNE = ENQUEUE[:ENQUEUE.index("local old=")] + "return #expired"


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def classify(response):
    if response.status_code == 409:
        return "CONFLICT"
    if response.status_code == 429 or response.status_code >= 500:
        return "RETRYABLE"
    if 400 <= response.status_code < 500:
        return "PERMANENT_FAILURE"
    if 200 <= response.status_code < 300:
        try:
            ack = response.json()
            if set(ack) == {"decision", "application"} and all(x in {"inserted", "unchanged"} for x in ack.values()):
                return "SUCCESS"
        except Exception:
            pass
    return "RETRYABLE"


class Outbox:
    def __init__(self, client, *, prefix="trace-outbox:v1", clock=time.time, capacity=CAPACITY):
        self.client, self.clock, self.capacity = client, clock, capacity
        self.keys = [prefix + ":entries", prefix + ":due", prefix + ":expiry",prefix+":pending-created",prefix+":diagnostics"]

    def enqueue(self, pair):
        now = self.clock()
        identity = pair["application"]["application_id"]
        if pair["application"]["decision_id"] != pair["decision"]["decision_id"]:
            raise ValueError("Invalid trace pair")
        entry = dict(pair=pair, delivery_id=identity, created_at=now, expires_at=now + RETENTION,
                     attempt_count=0, next_attempt_at=now, status="PENDING", last_error_category=None)
        raw = encode(entry)
        if len(raw.encode()) > 32768:
            raise ValueError("Outbox envelope exceeds bound")
        result = self.client.eval(ENQUEUE, 5, *self.keys, now, identity, raw, now + RETENTION, self.capacity)
        if result == "FULL":
            return "FULL"
        if result != "INSERTED" and json.loads(result)["pair"] != pair:
            return "CONFLICT"
        if result != "INSERTED" and json.loads(result)["status"] not in {"PENDING", "RETRY_PENDING"}:
            return json.loads(result)["status"]
        return "DURABLE_PENDING"

    def step(self, send):
        now = self.clock()
        if self.client.eval(PRUNE, 5, *self.keys, now):
            log.warning("strategy trace outbox retention expired")
        due = self.client.zrangebyscore(self.keys[1], "-inf", now, start=0, num=1)
        if not due:
            return "IDLE"
        identity = due[0]
        raw = self.client.hget(self.keys[0], identity)
        if raw is None:
            return "STALE"
        entry = json.loads(raw)
        if hasattr(self.client,"zadd"):
            self.client.zadd(self.keys[3],{identity:entry["created_at"]})
        if now >= entry["expires_at"]:
            result = "EXPIRED"
        else:
            try:
                result = classify(send(entry["pair"]))
            except Exception:
                result = "RETRYABLE"
        entry["attempt_count"] += 1
        entry["last_attempt_at"] = now
        entry["last_error_category"] = None if result == "SUCCESS" else result
        status = "DELIVERED" if result == "SUCCESS" else result
        if result == "RETRYABLE":
            status = "EXHAUSTED" if entry["attempt_count"] >= MAX_ATTEMPTS else "RETRY_PENDING"
            entry["next_attempt_at"] = now + min(2 ** entry["attempt_count"], 300)
        entry["status"] = status
        if not self.client.eval(UPDATE, 5, *self.keys, identity, raw, status, encode(entry), entry["next_attempt_at"]):
            return "STALE"
        if status != "DELIVERED":
            log.warning("strategy trace delivery status=%s", status)
        return status


    def stats(self):
        script="""
local count=redis.call('HLEN',KEYS[1]);local pending=redis.call('ZCARD',KEYS[2])
local oldest=redis.call('ZRANGE',KEYS[4],0,0,'WITHSCORES')
return {count,pending,count-pending,redis.call('ZCARD',KEYS[4]),oldest[2] or '',redis.call('HGET',KEYS[5],'full_total') or '0',redis.call('HGET',KEYS[5],'terminal_total') or '0',redis.call('HGET',KEYS[5],'expired_total') or '0'}
"""
        values=self.client.eval(script,5,*self.keys)
        count,pending,terminal,age_count=map(int,values[:4])
        oldest=float(values[4]) if values[4] else None
        return {"entries":count,"capacity":self.capacity,"pending":pending,"terminal":terminal,
            "oldest_pending_age_seconds":max(0,self.clock()-oldest) if oldest is not None and age_count==pending else (0 if pending==0 else None),
            "full_total":int(values[5]),"terminal_total":int(values[6]),"expired_total":int(values[7])}
