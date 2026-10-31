from copy import deepcopy
from uuid import uuid4
import pytest
from strategy_traces import TraceStore, TraceConflict, FIELDS
import json
import threading
from trace_index import WRITE, READ, ACTIVATE, KINDS


class RedisDouble:
    def __init__(self):
        self.values = {}
        self.failure = None
        self.hashes = {}
        self.zsets = {}
        self.expires = {}
        self.now = 1000000
        self.lock = threading.Lock()

    def hgetall(self, key):
        return dict(self.hashes.get(key, {}))

    def get(self, key):
        if key in self.expires and self.expires[key] <= self.now:
            self.values.pop(key, None)
            self.expires.pop(key, None)
        return self.values.get(key)

    def set(self, key, value, *, nx, ex):
        if self.failure == "before":
            raise ConnectionError()
        if key in self.values:
            return False
        self.values[key] = value
        if self.failure == "after":
            raise ConnectionError()
        return True

    def eval(self, script, number, *arguments):
        """Contract model, not Lua execution. Serialize concurrent callers."""
        with self.lock:
            if self.failure == "before":
                raise ConnectionError()
            keys, args = list(arguments[:number]), list(arguments[number:])
            capacity = int(args[0])
            meta = self.hashes.get(keys[0])
            for i, key in enumerate(keys[:10]):
                if i == 0 or (i-1)%3 == 2:
                    if key in self.values or key in self.zsets: return ["INTEGRITY"]
                elif key in self.values or key in self.hashes: return ["INTEGRITY"]
            if meta is None:
                if any(k in self.hashes or k in self.zsets for k in keys[1:10]): return ["INTEGRITY"]
            elif (set(meta) != {"index_version", "enabled_at", "epoch", "sequence", "decision_count", "application_count", "outcome_count"}
                    or meta["index_version"] != "1" or not str(meta["sequence"]).isdigit()):
                return ["INTEGRITY"]
            if meta:
                for base in (1,4,7):
                    members = self.zsets.get(keys[base], {})
                    count = int(meta[KINDS[(base-1)//3]+"_count"])
                    if count!=len(members) or len(self.zsets.get(keys[base+1],{}))!=count or len(self.hashes.get(keys[base+2],{}))!=count or count>capacity or max(members.values(), default=0)>int(meta["sequence"]): return ["INTEGRITY"]

            def activate():
                nonlocal meta
                if meta is None:
                    meta = dict(index_version="1", enabled_at=args[1], epoch=args[2], sequence="0",
                        decision_count="0",application_count="0",outcome_count="0")
                    self.hashes[keys[0]] = meta

            def metadata():
                return [meta[k] for k in ("index_version", "enabled_at", "epoch", "sequence")]

            def remove(base, identity):
                existed = self.zsets.get(keys[base], {}).pop(identity, None)
                self.zsets.get(keys[base+1], {}).pop(identity, None)
                self.hashes.get(keys[base+2], {}).pop(identity, None)
                if existed is not None:
                    name=KINDS[(base-1)//3]+"_count"
                    meta[name]=str(int(meta[name])-1)

            if script == ACTIVATE:
                activate()
                result = ["OK", metadata()]
            elif script == WRITE:
                kind, identity, encoded, ttl, context = args[3:8]
                base = 1 + KINDS.index(kind)*3
                existing = self.get(keys[10])
                if existing is not None and existing != encoded: return ["CONFLICT"]
                members = self.zsets.get(keys[base], {})
                if existing is not None and identity in members:
                    if identity not in self.zsets.get(keys[base+1], {}) or identity not in self.hashes.get(keys[base+2], {}): return ["INTEGRITY"]
                    result = ["UNCHANGED"]
                else:
                    remaining = self.expires.get(keys[10], self.now)-self.now if existing is not None else int(ttl)*1000
                    if remaining <= 0 or context == "null": return ["INTEGRITY"]
                    expiry = self.zsets.get(keys[base+1], {})
                    for stale in [i for i,e in sorted(expiry.items(),key=lambda p:p[1]) if e <= self.now][:128]:
                        if self.get(TraceStore.key(kind, stale)) is None: remove(base, stale)
                    if identity not in members and len(members)>=capacity: return ["CAPACITY"]
                    activate()
                    meta["sequence"] = str(int(meta["sequence"])+1)
                    if existing is None:
                        self.values[keys[10]] = encoded
                        self.expires[keys[10]] = self.now+remaining
                    if identity not in self.zsets.get(keys[base], {}):
                        meta[kind+"_count"]=str(int(meta[kind+"_count"])+1)
                    self.zsets.setdefault(keys[base], {})[identity] = int(meta["sequence"])
                    self.zsets.setdefault(keys[base+1], {})[identity] = self.now+remaining
                    self.hashes.setdefault(keys[base+2], {})[identity] = context
                    result = ["UNCHANGED" if existing is not None else "INSERTED"]
            elif script == READ:
                if meta is None: return ["NOT_ACTIVE"]
                kind, after, limit, maximum, epoch = args[3:8]
                maximum = int(meta["sequence"]) if int(maximum) == -1 else int(maximum)
                if maximum>int(meta["sequence"]) or (epoch and epoch!=meta["epoch"]): return ["INTEGRITY"]
                groups, stale = [], 0
                for n, current in enumerate(KINDS):
                    if kind not in ("all", current): continue
                    base, rows, cursor = 1+n*3, [], int(after)
                    members = self.zsets.get(keys[base], {})
                    page = sorted(((i,s) for i,s in members.items() if int(after)<s<=maximum),key=lambda p:p[1])[:int(limit)]
                    for identity,seq in page:
                        cursor = seq
                        raw = self.get(TraceStore.key(current, identity))
                        if raw is None:
                            remove(base,identity);stale+=1;continue
                        context = self.hashes.get(keys[base+2], {}).get(identity)
                        if context is None or identity not in self.zsets.get(keys[base+1], {}): return ["INTEGRITY"]
                        reference = "NOT_APPLICABLE"
                        refkind = {"application":"decision", "outcome":"application"}.get(current)
                        if refkind:
                            refid = json.loads(raw)[refkind+"_id"]
                            refseq = self.zsets.get(keys[1+KINDS.index(refkind)*3], {}).get(refid)
                            reference = ("MISSING" if self.get(TraceStore.key(refkind,refid)) is None else
                                "LEGACY_UNINDEXED" if refseq is None else "AFTER_SNAPSHOT" if refseq>maximum else "RETAINED_INDEXED")
                        rows.append([identity,str(seq),raw,context,reference])
                    more = sum(cursor<s<=maximum for s in members.values())
                    groups.append([current,rows,str(cursor),str(more)])
                result = ["OK",metadata(),str(maximum),groups,str(stale)]
            else:
                raise AssertionError("Unexpected script")
            if self.failure == "after": raise ConnectionError()
            return result


def record(kind):
    item = dict.fromkeys(FIELDS[kind], None)
    item.update(schema_version=1, timestamp="2026-10-30T00:00:00+00:00",
                expected_action_binding="baseline_response")
    item[kind + "_id"] = str(uuid4())
    return item


def test_identity_dedupe_conflict_and_distinct_events():
    store = TraceStore(RedisDouble(), 3600)
    d = record("decision")
    assert store.store("decision", d) == "inserted"
    assert store.store("decision", deepcopy(d)) == "unchanged"
    other = {**d, "decision_id": str(uuid4())}
    assert store.store("decision", other) == "inserted"
    assert store.get("decision", other["decision_id"]) == other
    with pytest.raises(TraceConflict):
        store.store("decision", {**d, "reason_code": "changed"})
    assert store.get("decision", d["decision_id"]) == d


@pytest.mark.parametrize("failure", ["before", "after"])
def test_write_failure_does_not_suppress_retry(failure):
    redis = RedisDouble()
    store = TraceStore(redis, 3600)
    d = record("decision")
    redis.failure = failure
    with pytest.raises(ConnectionError):
        store.store("decision", d)
    redis.failure = None
    assert store.store("decision", d) == ("inserted" if failure == "before" else "unchanged")
    assert TraceStore(redis, 3600).get("decision", d["decision_id"]) == d


def test_application_linkage_order_duplicates_and_conflict():
    store = TraceStore(RedisDouble(), 3600)
    d, a = record("decision"), record("application")
    a["decision_id"] = d["decision_id"]
    with pytest.raises(ValueError, match="Decision missing"):
        store.store("application", a)
    store.store("decision", d)
    assert store.store("application", a) == "inserted"
    assert store.store("application", a) == "unchanged"
    with pytest.raises(TraceConflict):
        store.store("application", {**a, "actual_action_binding": "changed"})
