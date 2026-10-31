"""Test-only contract model; real Redis tests execute the actual Lua separately."""
import time
from research_journal import WRITE, PAGE


def evaluate(client, script, keys, args):
    records = client.hashes.setdefault(keys[0], {})
    members = client.sorted_sets.setdefault(keys[1], {})
    expiry = client.sorted_sets.setdefault(keys[2], {})
    meta = client.hashes.setdefault(keys[3], {})
    now = getattr(client, 'now', time.time())
    if script == WRITE:
        identity, raw, capacity, ttl, epoch, enabled = args
        if identity in records:
            return ['UNCHANGED' if records[identity] == raw else 'CONFLICT']
        for identity_old in [i for i, deadline in expiry.items() if deadline <= now][:128]:
            for target in (records, members, expiry):
                target.pop(identity_old, None)
            meta['expired_records'] = str(int(meta.get('expired_records', 0))+1)
        if len(records) >= capacity:
            meta['capacity_rejections'] = str(int(meta.get('capacity_rejections', 0))+1)
            return ['CAPACITY']
        sequence = int(meta.get('sequence', 0))+1
        meta.update(sequence=str(sequence))
        meta.setdefault('epoch', epoch); meta.setdefault('enabled_at', enabled)
        records[identity], members[identity], expiry[identity] = raw, sequence, now+ttl
        return ['INSERTED']
    assert script == PAGE
    after, maximum, limit, epoch = args
    maximum = int(meta.get('sequence', 0)) if maximum == -1 else maximum
    if epoch and epoch != meta.get('epoch', ''):
        return ['INTEGRITY']
    rows = sorted(((i, s) for i, s in members.items() if after < s <= maximum), key=lambda x:x[1])[:limit]
    cursor = rows[-1][1] if rows else after
    live = [[i, str(s), records[i]] for i,s in rows if i in records and expiry.get(i, 0)>now]
    remaining = sum(cursor < s <= maximum for s in members.values())
    return ['OK',str(maximum),meta.get('epoch',''),str(cursor),str(remaining),live,str(len(rows)-len(live))]
