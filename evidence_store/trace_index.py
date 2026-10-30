"""Versioned retained-population index on the existing TraceStore Redis authority."""
import json
from datetime import datetime, timezone
from uuid import uuid4, UUID

VERSION = 1
CAPACITY = 1000  # Per kind. Full reports read at most 3,000 records atomically.
PAGE_LIMIT = 128
KINDS = ("decision", "application", "outcome")
PREFIX = "evidence:strategy_trace:index:v1"
GROUP_CONTEXT = ("strategy_id", "strategy_version", "strategy_definition_digest",
                 "experiment_id", "experiment_version")


class IndexIntegrityError(ValueError):
    pass


class IndexCapacityError(ValueError):
    pass


# Validate types BEFORE mutations: Lua does not roll back commands on script errors.
# All index keys are passed explicitly; no SCAN/KEYS discovery or dynamic query API.
PRELUDE = r'''
local function keytype(k) return redis.call('TYPE', k).ok end
if keytype(KEYS[1]) ~= 'none' and keytype(KEYS[1]) ~= 'hash' then return {'INTEGRITY'} end
for i=2,10 do
  local expected = ((i-2)%3 == 2) and 'hash' or 'zset'
  local actual = keytype(KEYS[i])
  if actual ~= 'none' and actual ~= expected then return {'INTEGRITY'} end
end
local meta = redis.call('HMGET', KEYS[1], 'index_version', 'enabled_at', 'epoch', 'sequence','decision_count','application_count','outcome_count')
local active = meta[1] ~= false
if not active then
  if redis.call('EXISTS', KEYS[1]) ~= 0 then return {'INTEGRITY'} end
  for i=2,10 do if redis.call('EXISTS', KEYS[i]) ~= 0 then return {'INTEGRITY'} end end
else
  if meta[1] ~= '1' or not meta[2] or not meta[3] or not meta[4] then return {'INTEGRITY'} end
  local seq = tonumber(meta[4])
  if not seq or seq < 0 or seq ~= math.floor(seq) or seq >= 9007199254740991 then return {'INTEGRITY'} end
  for i=2,8,3 do
    local count = tonumber(meta[5+(i-2)/3])
    if not count or count < 0 or count > tonumber(ARGV[1]) or count ~= math.floor(count) or
      redis.call('ZCARD',KEYS[i]) ~= count or redis.call('ZCARD',KEYS[i+1]) ~= count or
      redis.call('HLEN',KEYS[i+2]) ~= count then return {'INTEGRITY'} end
    local last = redis.call('ZREVRANGE',KEYS[i],0,0,'WITHSCORES')
    if #last > 0 and tonumber(last[2]) > seq then return {'INTEGRITY'} end
  end
end
local function activate()
  if not active then
    redis.call('HSET',KEYS[1],'index_version','1','enabled_at',ARGV[2],'epoch',ARGV[3],'sequence','0',
      'decision_count','0','application_count','0','outcome_count','0')
    meta = {'1',ARGV[2],ARGV[3],'0','0','0','0'}
    active = true
  end
end
local function prune(base, kind, count)
  local now = redis.call('TIME')
  local millis = tonumber(now[1])*1000 + math.floor(tonumber(now[2])/1000)
  local ids = redis.call('ZRANGEBYSCORE',KEYS[base+1],'-inf',millis,'LIMIT',0,count)
  local removed = 0
  for _,id in ipairs(ids) do
    if redis.call('EXISTS','evidence:strategy_trace:'..kind..':'..id) == 0 then
      local removed_member = redis.call('ZREM',KEYS[base],id)
      redis.call('ZREM',KEYS[base+1],id)
      redis.call('HDEL',KEYS[base+2],id)
      if removed_member == 1 then redis.call('HINCRBY',KEYS[1],kind..'_count',-1) end
      removed = removed + 1
    end
  end
  return removed
end
'''

WRITE = PRELUDE + r'''
-- ARGV: capacity, enabled_at, epoch, kind, id, encoded, ttl, context
local base = ({decision=2,application=5,outcome=8})[ARGV[4]]
local actual = keytype(KEYS[11])
if actual ~= 'none' and actual ~= 'string' then return {'INTEGRITY'} end
local existing = redis.call('GET',KEYS[11])
if existing and existing ~= ARGV[6] then return {'CONFLICT'} end
local position = redis.call('ZSCORE',KEYS[base],ARGV[5])
if existing and position then
  if not redis.call('ZSCORE',KEYS[base+1],ARGV[5]) or not redis.call('HGET',KEYS[base+2],ARGV[5]) then return {'INTEGRITY'} end
  return {'UNCHANGED'}
end
local ttl = existing and redis.call('PTTL',KEYS[11]) or tonumber(ARGV[7])*1000
if ttl <= 0 then return {'INTEGRITY'} end
if ARGV[8] == 'null' then return {'INTEGRITY'} end
local removed = prune(base,ARGV[4],128)
if not position and redis.call('ZCARD',KEYS[base]) >= tonumber(ARGV[1]) then return {'CAPACITY'} end
activate()
local seq = redis.call('HINCRBY',KEYS[1],'sequence',1)
if not existing then redis.call('SET',KEYS[11],ARGV[6],'PX',ttl) end
local now = redis.call('TIME')
local expires = tonumber(now[1])*1000 + math.floor(tonumber(now[2])/1000) + ttl
local added = redis.call('ZADD',KEYS[base],seq,ARGV[5])
if added == 1 then redis.call('HINCRBY',KEYS[1],ARGV[4]..'_count',1) end
redis.call('ZADD',KEYS[base+1],expires,ARGV[5])
redis.call('HSET',KEYS[base+2],ARGV[5],ARGV[8])
return {existing and 'UNCHANGED' or 'INSERTED'}
'''

ACTIVATE = PRELUDE + "\nactivate()\nreturn {'OK',meta}\n"

READ = PRELUDE + r'''
-- ARGV: capacity, unused, unused, kind/all, after, limit, max/-1, epoch/empty
if not active then return {'NOT_ACTIVE'} end
if ARGV[8] ~= '' and meta[3] ~= ARGV[8] then return {'INTEGRITY'} end
local maximum = tonumber(ARGV[7])
if maximum == -1 then maximum = tonumber(meta[4]) end
if maximum > tonumber(meta[4]) then return {'INTEGRITY'} end
local groups = {}
local stale = 0
local kinds = {'decision','application','outcome'}
for n,kind in ipairs(kinds) do
  if ARGV[4] == 'all' or ARGV[4] == kind then
    local base = 2+(n-1)*3
    local rows = redis.call('ZRANGEBYSCORE',KEYS[base],'('..ARGV[5],maximum,'WITHSCORES','LIMIT',0,tonumber(ARGV[6]))
    local entries = {}
    local cursor = tonumber(ARGV[5])
    for j=1,#rows,2 do
      local id,seq = rows[j],tonumber(rows[j+1])
      if seq <= cursor then return {'INTEGRITY'} end
      cursor = seq
      local rawkey = 'evidence:strategy_trace:'..kind..':'..id
      local actual = keytype(rawkey)
      if actual ~= 'none' and actual ~= 'string' then return {'INTEGRITY'} end
      local raw = redis.call('GET',rawkey)
      if not raw then
        local removed_member = redis.call('ZREM',KEYS[base],id)
        redis.call('ZREM',KEYS[base+1],id)
        redis.call('HDEL',KEYS[base+2],id)
        if removed_member == 1 then redis.call('HINCRBY',KEYS[1],kind..'_count',-1) end
        stale = stale+1
      else
        local context = redis.call('HGET',KEYS[base+2],id)
        local expiry = redis.call('ZSCORE',KEYS[base+1],id)
        if not context or not expiry or seq < 1 or seq ~= math.floor(seq) then return {'INTEGRITY'} end
        local ok,record = pcall(cjson.decode,raw)
        if not ok or type(record) ~= 'table' then return {'INTEGRITY'} end
        local reference = 'NOT_APPLICABLE'
        local refkind = kind == 'application' and 'decision' or (kind == 'outcome' and 'application' or nil)
        if refkind then
          local refid = record[refkind..'_id']
          if type(refid) ~= 'string' then return {'INTEGRITY'} end
          local refbase = refkind == 'decision' and 2 or 5
          local refseq = redis.call('ZSCORE',KEYS[refbase],refid)
          local retained = redis.call('EXISTS','evidence:strategy_trace:'..refkind..':'..refid) == 1
          reference = not retained and 'MISSING' or (not refseq and 'LEGACY_UNINDEXED' or
            (tonumber(refseq) > maximum and 'AFTER_SNAPSHOT' or 'RETAINED_INDEXED'))
        end
        table.insert(entries,{id,tostring(seq),raw,context,reference})
      end
    end
    local more = redis.call('ZCOUNT',KEYS[base],'('..cursor,maximum)
    table.insert(groups,{kind,entries,tostring(cursor),tostring(more)})
  end
end
return {'OK',meta,tostring(maximum),groups,tostring(stale)}
'''


def index_keys():
    return [PREFIX+":meta"] + [PREFIX+":"+kind+suffix
        for kind in KINDS for suffix in (":members", ":expiry", ":context")]


def decode(value):
    if isinstance(value, bytes):
        return value.decode()
    if isinstance(value, list):
        return [decode(x) for x in value]
    return value


class TraceIndex:
    def __init__(self, client):
        self.client = client

    def call(self, script, args, record_key=None):
        keys = index_keys() + ([record_key] if record_key else [])
        result = decode(self.client.eval(script, len(keys), *keys, *args))
        status = result[0]
        if status in {"INTEGRITY", "NOT_ACTIVE"}:
            raise IndexIntegrityError("INDEX_" + ("NOT_ACTIVE" if status == "NOT_ACTIVE" else "INTEGRITY_ERROR"))
        if status == "CAPACITY":
            raise IndexCapacityError("Indexed trace capacity reached; retry after retention cleanup")
        return result

    @staticmethod
    def metadata(meta, maximum):
        version, enabled, epoch, sequence = meta[:4]
        try:
            if version != "1" or str(UUID(epoch)) != epoch or datetime.fromisoformat(enabled).tzinfo is None:
                raise ValueError()
            if not 0 <= maximum <= int(sequence):
                raise ValueError()
        except (TypeError, ValueError, AttributeError):
            raise IndexIntegrityError("INDEX_INTEGRITY_ERROR")
        return dict(index_version=VERSION, index_enabled_at=enabled, index_epoch=epoch,
                    snapshot_max_sequence=maximum, historical_pre_index_coverage="NOT_VERIFIED")

    def activate(self):
        result = self.call(ACTIVATE, [CAPACITY, datetime.now(timezone.utc).isoformat(), str(uuid4())])
        return self.metadata(result[1], int(result[1][3]))

    def write(self, kind, identity, encoded, ttl, context, key):
        return self.call(WRITE, [CAPACITY, datetime.now(timezone.utc).isoformat(), str(uuid4()),
            kind, identity, encoded, ttl, json.dumps(context, sort_keys=True, separators=(",", ":"))], key)[0]

    def read(self, kind="all", *, after_sequence=0, limit=PAGE_LIMIT,
             snapshot_max_sequence=None, index_epoch=None):
        if kind not in (*KINDS, "all") or type(after_sequence) is not int or after_sequence < 0:
            raise ValueError("Invalid index cursor")
        max_limit = CAPACITY if kind == "all" else PAGE_LIMIT
        if type(limit) is not int or not 1 <= limit <= max_limit:
            raise ValueError("Invalid index page size")
        if snapshot_max_sequence is not None and (type(snapshot_max_sequence) is not int or not after_sequence <= snapshot_max_sequence < 2**53):
            raise ValueError("Invalid index snapshot")
        if (snapshot_max_sequence is None) != (index_epoch is None):
            raise ValueError("Snapshot requires its index epoch")
        if after_sequence and snapshot_max_sequence is None:
            raise ValueError("Continuation requires its original snapshot")
        if index_epoch is not None and str(UUID(index_epoch)) != index_epoch:
            raise ValueError("Invalid index epoch")
        result = self.call(READ, [CAPACITY, "", "", kind, after_sequence, limit,
            -1 if snapshot_max_sequence is None else snapshot_max_sequence, index_epoch or ""])
        metadata = self.metadata(result[1], int(result[2]))
        groups = {}
        for record_kind, rows, cursor, more in result[3]:
            entries = []
            try:
                for identity, sequence, raw, context, reference in rows:
                    record, context = json.loads(raw), json.loads(context)
                    if str(UUID(identity)) != identity or record[record_kind+"_id"] != identity or not isinstance(context, dict):
                        raise ValueError()
                    entries.append(dict(record_id=identity, sequence=int(sequence), record=record,
                                        context=context, reference_status=reference))
            except (ValueError, TypeError, KeyError):
                raise IndexIntegrityError("INDEX_INTEGRITY_ERROR")
            groups[record_kind] = dict(record_kind=record_kind, entries=entries,
                retained_count=len(entries), after_sequence=int(cursor), done=int(more)==0)
        return {**metadata, "kinds": groups, "stale_members_removed": int(result[4]),
                "population_status": "AUTHORITATIVE_INDEXED_SCOPE"}
