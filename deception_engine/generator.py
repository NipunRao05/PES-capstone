"""
generator.py — Seeded Faker data generator for the deception engine.

Every row generated for a given (seed, session_id, table_name) is deterministic:
  seed = stable_hash(DECEPTION_FAKE_DATA_SEED + ":" + session_id + ":" + table_name)

This guarantees:
  - SELECT COUNT(*) and SELECT * return consistent results per session
  - Different sessions see different data (attacker can't compare notes)
  - Different tables in the same session produce different data
  - Referential integrity: FK columns draw from PK values of the referenced
    table using the same seeding strategy

Supported column types (from schema YAML):
  pk_int, uuid, name, first_name, last_name, email, phone, company,
  job_title, address, ipv4, url, country, sentence, json_blob,
  past_date, past_datetime, future_date, credit_card_number,
  credit_card_expire, iban, routing, ssn, bcrypt, password, api_key,
  aws_access_key, user_agent, bank, bool, int_range, float_range, choice, fk
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import random
import string
from datetime import datetime, timedelta
from typing import Any

from faker import Faker

log = logging.getLogger(__name__)

# Optional deployment-wide fake-data seed.
#
# Leave this unset to preserve the original capstone demo seed algorithm and
# therefore keep existing demo output stable. Set it to a fixed value when you
# want an explicit reproducibility contract across environments, rebuilds, and
# scaled deception-engine replicas.
FAKE_DATA_SEED = os.environ.get("DECEPTION_FAKE_DATA_SEED", "").strip()

# Fixed anchor keeps generated date/time values deterministic across days.
# Using datetime.now() would make the same session/table drift over time and
# break consistency probes that revisit fake rows after a restart.
FAKE_TIME_ANCHOR_DEFAULT = "2024-01-01T12:00:00"
FAKE_TIME_ANCHOR_RAW = os.environ.get("DECEPTION_FAKE_TIME_ANCHOR", FAKE_TIME_ANCHOR_DEFAULT)


def _parse_fake_time_anchor(raw: str) -> datetime:
    try:
        return datetime.fromisoformat((raw or FAKE_TIME_ANCHOR_DEFAULT).replace("Z", "+00:00")).replace(tzinfo=None)
    except Exception:
        log.warning(
            "Invalid DECEPTION_FAKE_TIME_ANCHOR=%r; falling back to %s",
            raw,
            FAKE_TIME_ANCHOR_DEFAULT,
        )
        return datetime.fromisoformat(FAKE_TIME_ANCHOR_DEFAULT)


FAKE_TIME_ANCHOR = _parse_fake_time_anchor(FAKE_TIME_ANCHOR_RAW)

# Faker is used through per-row seeded local instances. Pin the locale so output
# does not depend on host/container locale defaults.
FAKER_LOCALE = os.environ.get("DECEPTION_FAKER_LOCALE", "en_US")
_fake = Faker(FAKER_LOCALE)  # fallback only


# ─── Seed computation ─────────────────────────────────────────────────────────

def _normalise_session_id(value: str) -> str:
    return str(value or "").strip()


def _normalise_table_name(value: str) -> str:
    return str(value or "").strip().lower()


def session_seed(session_id: str, table_name: str) -> int:
    """
    Deterministic seed for a (session, table) pair.

    Default behavior preserves the original MD5(session_id:table_name) seed so
    existing demos do not suddenly change their fake data. If
    DECEPTION_FAKE_DATA_SEED is set, SHA-256 is used with that deployment seed
    to make reproducibility explicit across replicas and rebuilds.
    """
    session = _normalise_session_id(session_id)
    table = _normalise_table_name(table_name)
    if FAKE_DATA_SEED:
        combined = f"{FAKE_DATA_SEED}:{session}:{table}"
        digest = hashlib.sha256(combined.encode("utf-8")).digest()
        return int.from_bytes(digest[:8], "big") % (2 ** 32)

    combined = f"{session}:{table}"
    return int(hashlib.md5(combined.encode("utf-8")).hexdigest(), 16) % (2 ** 32)


# ─── Main generator ───────────────────────────────────────────────────────────

class DataGenerator:
    """
    Generates fake rows for a table definition using seeded Faker.
    """

    def generate_rows(
        self,
        columns: list[dict],
        row_count: int,
        session_id: str,
        table_name: str,
        limit: int = 100,
        offset: int = 0,
        pk_pool: dict[str, list] | None = None,
    ) -> list[dict]:
        """
        Generate `limit` rows starting at `offset` for the given table.

        pk_pool: maps "schema.table" → list of PK values already generated,
                 used to satisfy FK columns with real references.
        """
        try:
            row_count = max(0, int(row_count))
            limit = max(0, int(limit))
            offset = max(0, int(offset))
        except Exception:
            log.warning(
                "Invalid row generation bounds: row_count=%r limit=%r offset=%r",
                row_count,
                limit,
                offset,
            )
            return []

        if not columns or limit == 0 or row_count == 0:
            return []

        table_name = _normalise_table_name(table_name)
        seed = session_seed(session_id, table_name)
        rng = random.Random(seed)

        # Pre-compute PK sequence for this table so row[offset] is stable
        pk_col = self._pk_column(columns)
        pk_start = 1

        rows = []
        for row_idx in range(offset, offset + limit):
            if row_idx >= row_count:
                break
            # Advance Faker/rng state consistently to the right row
            row_rng = random.Random(seed ^ row_idx)
            row_fake = Faker(FAKER_LOCALE)
            row_fake.seed_instance(seed ^ row_idx)

            row = {}
            pk_value = pk_start + row_idx if pk_col else None

            for col in columns:
                name = col["name"]
                col_type = col.get("type", "sentence")

                if col_type == "pk_int":
                    row[name] = pk_start + row_idx
                elif col_type == "fk":
                    row[name] = self._fk_value(col, row_idx, pk_pool, row_rng)
                else:
                    row[name] = self._generate_value(col, row_rng, row_fake)

            rows.append(row)

        return rows

    def generate_count(self, row_count: int, session_id: str, table_name: str) -> int:
        """
        Return the deterministic row count for this session + table.
        Adds a small deterministic jitter to make it look like a live system.
        """
        try:
            row_count = max(0, int(row_count))
        except Exception:
            log.warning("Invalid configured row_count=%r for table=%s", row_count, table_name)
            return 0

        if row_count == 0:
            return 0

        seed = session_seed(session_id, table_name)
        rng = random.Random(seed)
        jitter_radius = int(row_count * 0.02)
        jitter = rng.randint(-jitter_radius, jitter_radius) if jitter_radius else 0
        return max(1, row_count + jitter)

    # ─── Value generators ──────────────────────────────────────────────────

    def _generate_value(self, col: dict, rng: random.Random, fake: Faker | None = None) -> Any:
        fake = fake or _fake
        col_type = col.get("type", "sentence")
        nullable = col.get("nullable", False)

        if nullable and rng.random() < 0.08:
            return None

        if col_type == "name":
            return fake.name()
        elif col_type == "first_name":
            return fake.first_name()
        elif col_type == "last_name":
            return fake.last_name()
        elif col_type == "email":
            domain = col.get("domain", "")
            base = fake.user_name()
            if domain:
                return f"{base}{domain}"
            return fake.email()
        elif col_type == "phone":
            return fake.phone_number()
        elif col_type == "company":
            return fake.company()
        elif col_type == "job_title":
            return fake.job()
        elif col_type == "address":
            return fake.address().replace("\n", ", ")
        elif col_type == "ipv4":
            return fake.ipv4_private()
        elif col_type == "url":
            return fake.url()
        elif col_type == "country":
            return fake.country()
        elif col_type == "sentence":
            return fake.sentence()
        elif col_type == "json_blob":
            return json.dumps({
                "key": fake.word(),
                "value": fake.word(),
                "enabled": rng.choice([True, False]),
            })
        elif col_type == "user_agent":
            return fake.user_agent()
        elif col_type == "bank":
            return fake.company() + " Bank"
        elif col_type == "uuid":
            return str(fake.uuid4())

        # Date/time types
        elif col_type == "past_date":
            years_back = col.get("years_back", 5)
            delta = timedelta(days=rng.randint(1, years_back * 365))
            return (FAKE_TIME_ANCHOR - delta).strftime("%Y-%m-%d")
        elif col_type == "past_datetime":
            days_back = col.get("days_back", 365)
            delta = timedelta(
                days=rng.randint(0, days_back),
                hours=rng.randint(0, 23),
                minutes=rng.randint(0, 59),
            )
            return (FAKE_TIME_ANCHOR - delta).strftime("%Y-%m-%d %H:%M:%S")
        elif col_type == "future_date":
            days_ahead = col.get("days_ahead", 365)
            delta = timedelta(days=rng.randint(1, days_ahead))
            return (FAKE_TIME_ANCHOR + delta).strftime("%Y-%m-%d")

        # Numeric types
        elif col_type == "int_range":
            return rng.randint(col.get("min", 0), col.get("max", 100))
        elif col_type == "float_range":
            val = rng.uniform(col.get("min", 0.0), col.get("max", 1.0))
            decimals = col.get("decimals", 2)
            return round(val, decimals)
        elif col_type == "bool":
            true_ratio = col.get("true_ratio", 0.5)
            return rng.random() < true_ratio

        # Choice type
        elif col_type == "choice":
            choices = col.get("choices", ["unknown"])
            return rng.choice(choices)

        # Sensitive / honeytoken types
        elif col_type == "bcrypt":
            # Realistic bcrypt hash — fake but correct format
            salt = "".join(rng.choices(string.ascii_letters + string.digits, k=22))
            return f"$2a$12${salt}AAAAAAAAAAAAAAAAAAAAAA"
        elif col_type == "password":
            words = [fake.word(), fake.word()]
            return "DECOY_" + "".join(words).capitalize() + str(rng.randint(10, 99)) + "!"
        elif col_type == "api_key":
            prefix = rng.choice(["HONEYPOT_SK_LIVE_FAKE_", "HONEYPOT_PK_LIVE_FAKE_", "DECOY_API_KEY_", "DECOY_TOKEN_"])
            body = "".join(rng.choices(string.ascii_letters + string.digits, k=32))
            return prefix + body
        elif col_type == "aws_access_key":
            body = "".join(rng.choices(string.ascii_uppercase + string.digits, k=16))
            return "HONEYPOT_AKIA_FAKE_" + body
        elif col_type == "iban":
            body = "".join(rng.choices(string.ascii_uppercase + string.digits, k=18))
            return "DECOY_IBAN_" + body
        elif col_type == "routing":
            return "DECOY_ROUTING_" + str(rng.randint(100000000, 999999999))
        elif col_type == "ssn":
            return "DECOY_SSN_000-00-" + str(rng.randint(1000, 9999))
        elif col_type == "credit_card_number":
            return "DECOY_CC_411111111111" + str(rng.randint(1000, 9999))
        elif col_type == "credit_card_expire":
            return "DECOY_EXP_" + fake.credit_card_expire()

        # Fallback
        return fake.word()

    def _pk_column(self, columns: list[dict]) -> str | None:
        for col in columns:
            if col.get("type") == "pk_int":
                return col["name"]
        return None

    def _fk_value(
        self,
        col: dict,
        row_idx: int,
        pk_pool: dict[str, list] | None,
        rng: random.Random,
    ) -> int:
        """
        Return a FK value that references an existing PK in the target table.
        Uses the pk_pool if available, otherwise generates a plausible int.
        """
        ref = col.get("ref", "")
        if pk_pool and ref in pk_pool:
            pool = pk_pool[ref]
            if pool:
                return rng.choice(pool)
        # Fallback: pick a small int that's likely to exist in the target
        return rng.randint(1, 200)
