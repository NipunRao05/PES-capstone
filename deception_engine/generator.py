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
  past_date, past_datetime, future_date, money, credit_card_number,
  credit_card_expire, iban, routing, ssn, bcrypt, password, api_key,
  aws_access_key, user_agent, bank, bool, int_range, float_range, choice, fk
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import random
import re
import string
import threading
import unicodedata
from collections import OrderedDict
from datetime import datetime, timedelta
from decimal import Decimal, ROUND_HALF_UP
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

    # Bounded, fictional HR roles.  The tuple shape is
    # (title, seniority, minimum_salary, maximum_salary).  Keeping this next to
    # the generator makes the dependency chain explicit instead of allowing
    # unrelated Faker fields to accidentally contradict each other.
    HR_ROLE_BANDS = {
        "Engineering": (
            ("Junior Software Engineer", 1, 65000, 85000),
            ("Software Engineer", 2, 82000, 115000),
            ("Senior Software Engineer", 3, 110000, 145000),
            ("Engineering Manager", 4, 135000, 170000),
            ("Director of Engineering", 5, 165000, 205000),
        ),
        "Finance": (
            ("Accountant", 1, 52000, 70000),
            ("Financial Analyst", 2, 68000, 90000),
            ("Senior Financial Analyst", 3, 88000, 115000),
            ("Finance Manager", 4, 108000, 140000),
            ("Controller", 5, 138000, 180000),
        ),
        "HR": (
            ("HR Coordinator", 1, 48000, 62000),
            ("Recruiter", 2, 60000, 82000),
            ("HR Business Partner", 3, 80000, 108000),
            ("HR Manager", 4, 102000, 132000),
            ("HR Director", 5, 130000, 170000),
        ),
        "Sales": (
            ("Sales Representative", 1, 50000, 70000),
            ("Account Executive", 2, 68000, 95000),
            ("Senior Account Executive", 3, 90000, 125000),
            ("Sales Manager", 4, 115000, 150000),
            ("Sales Director", 5, 145000, 190000),
        ),
        "Legal": (
            ("Paralegal", 1, 52000, 72000),
            ("Compliance Analyst", 2, 70000, 95000),
            ("Legal Counsel", 3, 105000, 145000),
            ("Senior Legal Counsel", 4, 140000, 185000),
            ("Legal Director", 5, 180000, 225000),
        ),
        "Operations": (
            ("Logistics Coordinator", 1, 47000, 62000),
            ("Operations Analyst", 2, 60000, 82000),
            ("Procurement Specialist", 3, 78000, 105000),
            ("Operations Manager", 4, 100000, 132000),
            ("Director of Operations", 5, 130000, 170000),
        ),
        "IT": (
            ("IT Support Specialist", 1, 50000, 68000),
            ("Systems Administrator", 2, 70000, 95000),
            ("Senior Systems Engineer", 3, 95000, 128000),
            ("IT Manager", 4, 118000, 150000),
            ("Director of IT", 5, 148000, 188000),
        ),
        "Executive": (
            ("Executive Assistant", 1, 55000, 75000),
            ("Business Operations Analyst", 2, 75000, 100000),
            ("Chief of Staff", 4, 145000, 195000),
            ("Chief Executive Officer", 6, 220000, 300000),
        ),
    }

    _DEPARTMENT_WEIGHTS = {
        "Engineering": 0.27,
        "Finance": 0.11,
        "HR": 0.07,
        "Sales": 0.18,
        "Legal": 0.05,
        "Operations": 0.14,
        "IT": 0.12,
        "Executive": 0.06,
    }

    # (fixed departmental cost, approximate annual cost per employee).
    _DEPARTMENT_BUDGET_MODEL = {
        "Engineering": (Decimal("950000.00"), Decimal("142000.00")),
        "Finance": (Decimal("520000.00"), Decimal("118000.00")),
        "HR": (Decimal("380000.00"), Decimal("98000.00")),
        "Sales": (Decimal("780000.00"), Decimal("132000.00")),
        "Legal": (Decimal("610000.00"), Decimal("155000.00")),
        "Operations": (Decimal("690000.00"), Decimal("108000.00")),
        "IT": (Decimal("820000.00"), Decimal("128000.00")),
        "Executive": (Decimal("1250000.00"), Decimal("210000.00")),
    }

    _ORG_CACHE_LIMIT = 256

    _FIRST_NAMES = (
        "Aaron", "Aisha", "Alex", "Amelia", "Andre", "Anika", "Benjamin", "Bianca",
        "Caleb", "Camila", "Caroline", "Charlotte", "Chloe", "Daniel", "David", "Diego",
        "Elena", "Elias", "Emily", "Ethan", "Eva", "Gabriel", "Grace", "Hannah",
        "Henry", "Isaac", "Isabel", "Jack", "Jasmine", "Jonah", "Jordan", "Julia",
        "Kai", "Katherine", "Layla", "Leo", "Liam", "Lily", "Lucas", "Maya",
        "Mia", "Nathan", "Nina", "Noah", "Nora", "Oliver", "Olivia", "Owen",
        "Priya", "Rafael", "Riley", "Ruby", "Samuel", "Sara", "Sofia", "Theo",
        "Thomas", "Valerie", "Victor", "William", "Xavier", "Yasmin", "Zoe", "Zachary",
    )
    _LAST_NAMES = (
        "Adams", "Allen", "Baker", "Bell", "Bennett", "Brooks", "Campbell", "Carter",
        "Chen", "Clark", "Collins", "Cooper", "Cruz", "Davis", "Diaz", "Edwards",
        "Evans", "Fisher", "Flores", "Foster", "Garcia", "Gomez", "Gray", "Green",
        "Hall", "Harris", "Hayes", "Hill", "Hughes", "Jackson", "James", "Jenkins",
        "Johnson", "Kelly", "Kim", "King", "Lee", "Lewis", "Long", "Martin",
        "Martinez", "Miller", "Mitchell", "Moore", "Morgan", "Morris", "Nelson", "Nguyen",
        "Parker", "Patel", "Perez", "Perry", "Phillips", "Price", "Ramirez", "Reed",
        "Rivera", "Roberts", "Ross", "Sanchez", "Scott", "Stewart", "Taylor", "Turner",
    )

    def __init__(self) -> None:
        self._organization_cache: OrderedDict[tuple, tuple[list[dict], list[dict]]] = OrderedDict()
        self._organization_cache_lock = threading.RLock()

    def generate_organization_rows(
        self,
        schema_name: str,
        table_name: str,
        schema_tables: dict[str, dict],
        employee_count: int,
        session_id: str,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[dict]:
        """Return coherent HR employee/department rows from one deterministic world.

        This is deliberately limited to the two related HR base tables.  Other
        schemas and lure/trap tables continue through the existing generic
        generator unchanged.
        """
        if schema_name != "hr" or table_name not in {"employees", "departments"}:
            return []

        employee_count = max(0, int(employee_count))
        offset = max(0, int(offset))
        key = (
            _normalise_session_id(session_id),
            employee_count,
            tuple(self._department_names(schema_tables)),
            self._employee_email_domain(schema_tables),
        )
        with self._organization_cache_lock:
            world = self._organization_cache.get(key)
            if world is None:
                world = self._build_hr_organization(
                    session_id=session_id,
                    employee_count=employee_count,
                    schema_tables=schema_tables,
                )
                self._organization_cache[key] = world
                self._organization_cache.move_to_end(key)
                while len(self._organization_cache) > self._ORG_CACHE_LIMIT:
                    self._organization_cache.popitem(last=False)
            else:
                self._organization_cache.move_to_end(key)

            source = world[0] if table_name == "employees" else world[1]
            end = len(source) if limit is None else offset + max(0, int(limit))
            return [dict(row) for row in source[offset:end]]

    def cleanup_session(self, session_id: str) -> None:
        """Drop cached base-world rows for a completed session."""
        session = _normalise_session_id(session_id)
        with self._organization_cache_lock:
            for key in [item for item in self._organization_cache if item[0] == session]:
                self._organization_cache.pop(key, None)

    def _build_hr_organization(
        self,
        session_id: str,
        employee_count: int,
        schema_tables: dict[str, dict],
    ) -> tuple[list[dict], list[dict]]:
        departments = self._department_names(schema_tables)
        if not departments or employee_count < len(departments):
            return [], []
        unsupported = [name for name in departments if name not in self.HR_ROLE_BANDS]
        if unsupported:
            raise ValueError(f"HR departments lack role bands: {unsupported}")

        world_seed = session_seed(session_id, "hr_organization")
        rng = random.Random(world_seed)
        counts = self._allocate_department_counts(employee_count, departments)
        email_domain = self._employee_email_domain(schema_tables)
        employee_columns = schema_tables["employees"].get("columns", [])
        employee_column_names = [column["name"] for column in employee_columns]

        employees: list[dict] = []
        heads: dict[str, int] = {}
        identities = self._identity_pool(world_seed, employee_count, email_domain)

        # Heads receive the first stable IDs so every later row can safely refer
        # to an already-existing same-department authority.
        for department in departments:
            role = self.HR_ROLE_BANDS[department][-1]
            row = self._employee_row(
                employee_id=len(employees) + 1,
                department=department,
                role=role,
                world_seed=world_seed,
                identity=identities[len(employees)],
                employee_columns=employee_columns,
            )
            employees.append(row)
            heads[department] = row["id"]

        # Generate bounded department-appropriate roles.  Lower levels are more
        # common; titles may repeat, identities may not.
        for department in departments:
            roles = self.HR_ROLE_BANDS[department][:-1]
            weights = [max(1, 7 - role[1]) for role in roles]
            for _ in range(counts[department] - 1):
                role = rng.choices(roles, weights=weights, k=1)[0]
                employees.append(self._employee_row(
                    employee_id=len(employees) + 1,
                    department=department,
                    role=role,
                    world_seed=world_seed,
                    identity=identities[len(employees)],
                    employee_columns=employee_columns,
                ))

        by_department: dict[str, list[dict]] = {name: [] for name in departments}
        for employee in employees:
            by_department[employee["department"]].append(employee)

        executive_id = heads["Executive"]
        for employee in employees:
            level = employee["seniority_level"]
            department = employee["department"]
            if employee["id"] == executive_id:
                employee["manager_id"] = None
                continue
            if employee["id"] == heads[department]:
                employee["manager_id"] = executive_id
                manager = next(row for row in employees if row["id"] == executive_id)
            else:
                candidates = [
                    candidate for candidate in by_department[department]
                    if candidate["seniority_level"] > level
                ]
                manager_rng = random.Random(world_seed ^ (employee["id"] * 2654435761))
                manager = manager_rng.choice(candidates)
                employee["manager_id"] = manager["id"]
            manager_rng = random.Random(world_seed ^ (employee["id"] * 2654435761))
            if employee["hire_date"] <= manager["hire_date"]:
                manager_hired = datetime.strptime(manager["hire_date"], "%Y-%m-%d")
                employee["hire_date"] = min(
                    FAKE_TIME_ANCHOR - timedelta(days=30),
                    manager_hired + timedelta(days=manager_rng.randint(90, 540)),
                ).strftime("%Y-%m-%d")

        # Render only canonical schema columns.  Internal seniority is exposed by
        # the HR schema so clients and validation use the same fact.
        employees = [
            {name: employee.get(name) for name in employee_column_names}
            for employee in employees
        ]

        department_columns = [
            column["name"] for column in schema_tables["departments"].get("columns", [])
        ]
        department_rows: list[dict] = []
        for department_id, department in enumerate(departments, start=1):
            budget_rng = random.Random(world_seed ^ (department_id * 2246822519))
            fixed_cost, per_person = self._DEPARTMENT_BUDGET_MODEL[department]
            variation = Decimal(str(budget_rng.uniform(-0.04, 0.04)))
            modeled = fixed_cost + (per_person * counts[department])
            budget = (modeled * (Decimal("1.00") + variation)).quantize(
                Decimal("0.01"), rounding=ROUND_HALF_UP
            )
            row = {
                "id": department_id,
                "name": department,
                "head_count": counts[department],
                "budget_usd": format(budget, ".2f"),
                "manager_id": heads[department],
            }
            department_rows.append({name: row.get(name) for name in department_columns})

        self._validate_hr_organization(employees, department_rows)
        return employees, department_rows

    def _employee_row(
        self,
        employee_id: int,
        department: str,
        role: tuple[str, int, int, int],
        world_seed: int,
        identity: tuple[str, str],
        employee_columns: list[dict],
    ) -> dict:
        title, seniority, salary_minimum, salary_maximum = role
        row_rng = random.Random(world_seed ^ (employee_id * 3266489917))
        full_name, email = identity
        raw_salary = row_rng.randint(salary_minimum, salary_maximum)
        salary = max(salary_minimum, min(salary_maximum, (raw_salary // 250) * 250))
        hire_bounds = {
            1: (120, 3 * 365),
            2: (2 * 365, 6 * 365),
            3: (4 * 365, 9 * 365),
            4: (7 * 365, 12 * 365),
            5: (10 * 365, 15 * 365),
            6: (14 * 365, 18 * 365),
        }
        minimum_days, maximum_days = hire_bounds[seniority]
        hire_date = (FAKE_TIME_ANCHOR - timedelta(
            days=row_rng.randint(minimum_days, maximum_days)
        )).strftime("%Y-%m-%d")
        bcrypt_column = next(
            (column for column in employee_columns if column.get("name") == "password_hash"),
            {"type": "bcrypt"},
        )
        return {
            "id": employee_id,
            "full_name": full_name,
            "email": email,
            "department": department,
            "job_title": title,
            "seniority_level": seniority,
            "hire_date": hire_date,
            "salary": salary,
            "manager_id": None,
            # Managers and department heads remain active members of the
            # hierarchy; ordinary employees retain a realistic inactive tail.
            "is_active": True if seniority >= 4 else row_rng.random() < 0.92,
            "password_hash": self._generate_value(bcrypt_column, row_rng),
        }

    @classmethod
    def _identity_pool(
        cls, world_seed: int, employee_count: int, email_domain: str
    ) -> list[tuple[str, str]]:
        """Build a fast deterministic pool of unique fictional identities."""
        candidates = [
            f"{first} {last}"
            for first in cls._FIRST_NAMES
            for last in cls._LAST_NAMES
        ]
        if employee_count > len(candidates):
            raise ValueError("configured HR employee count exceeds synthetic identity pool")
        identity_rng = random.Random(world_seed ^ 0x9E3779B9)
        identity_rng.shuffle(candidates)
        return [
            (name, f"{cls._email_local_part(name)}{email_domain}")
            for name in candidates[:employee_count]
        ]

    @staticmethod
    def _email_local_part(full_name: str) -> str:
        normalized = unicodedata.normalize("NFKD", full_name).encode("ascii", "ignore").decode("ascii")
        return re.sub(r"[^a-z0-9.]", "", normalized.lower().replace(" ", "."))

    @staticmethod
    def _department_names(schema_tables: dict[str, dict]) -> list[str]:
        columns = schema_tables.get("departments", {}).get("columns", [])
        name_column = next((column for column in columns if column.get("name") == "name"), {})
        return list(dict.fromkeys(name_column.get("choices", [])))

    @staticmethod
    def _employee_email_domain(schema_tables: dict[str, dict]) -> str:
        columns = schema_tables.get("employees", {}).get("columns", [])
        email_column = next((column for column in columns if column.get("name") == "email"), {})
        domain = str(email_column.get("domain", "@company.internal"))
        return domain if domain.startswith("@") else "@" + domain

    def _allocate_department_counts(
        self, employee_count: int, departments: list[str]
    ) -> dict[str, int]:
        remaining = employee_count - len(departments)
        weights = [self._DEPARTMENT_WEIGHTS[name] for name in departments]
        total_weight = sum(weights)
        exact = [remaining * weight / total_weight for weight in weights]
        counts = {name: 1 + int(value) for name, value in zip(departments, exact)}
        assigned = sum(counts.values())
        remainder_order = sorted(
            range(len(departments)),
            key=lambda index: (exact[index] - int(exact[index]), -index),
            reverse=True,
        )
        for index in remainder_order[:employee_count - assigned]:
            counts[departments[index]] += 1
        return counts

    @staticmethod
    def _validate_hr_organization(employees: list[dict], departments: list[dict]) -> None:
        by_id = {row["id"]: row for row in employees}
        if len(by_id) != len(employees):
            raise ValueError("duplicate synthetic employee IDs")
        if len({row["full_name"] for row in employees}) != len(employees):
            raise ValueError("duplicate synthetic employee names")
        if len({row["email"] for row in employees}) != len(employees):
            raise ValueError("duplicate synthetic employee emails")
        for employee in employees:
            manager_id = employee["manager_id"]
            if manager_id is None:
                continue
            manager = by_id.get(manager_id)
            if manager is None or manager_id == employee["id"]:
                raise ValueError("invalid synthetic manager reference")
            if manager["seniority_level"] <= employee["seniority_level"]:
                raise ValueError("synthetic manager is not more senior")
            visited = {employee["id"]}
            current = employee
            while current["manager_id"] is not None:
                if current["manager_id"] in visited:
                    raise ValueError("synthetic manager cycle")
                visited.add(current["manager_id"])
                current = by_id[current["manager_id"]]
        for department in departments:
            manager = by_id.get(department["manager_id"])
            if not manager or manager["department"] != department["name"]:
                raise ValueError("invalid synthetic department manager")
            actual = sum(1 for row in employees if row["department"] == department["name"])
            if actual != department["head_count"]:
                raise ValueError("synthetic department head_count mismatch")

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

            self._enforce_temporal_integrity(table_name, row, row_rng)

            rows.append(row)

        return rows

    @staticmethod
    def _enforce_temporal_integrity(
        table_name: str, row: dict, rng: random.Random
    ) -> None:
        """Enforce the two declared cross-column time relationships."""
        pairs = {
            "sessions": ("login_at", "logout_at"),
            "api_keys": ("created_at", "last_used"),
        }
        pair = pairs.get(table_name)
        if not pair:
            return
        earlier_name, later_name = pair
        earlier_raw, later_raw = row.get(earlier_name), row.get(later_name)
        if earlier_raw is None or later_raw is None:
            return
        earlier = datetime.strptime(earlier_raw, "%Y-%m-%d %H:%M:%S")
        later = datetime.strptime(later_raw, "%Y-%m-%d %H:%M:%S")
        if later < earlier:
            later = min(
                FAKE_TIME_ANCHOR,
                earlier + timedelta(minutes=rng.randint(5, 12 * 60)),
            )
            row[later_name] = later.strftime("%Y-%m-%d %H:%M:%S")

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
        elif col_type == "money":
            minimum = Decimal(str(col.get("min", "0.00")))
            maximum = Decimal(str(col.get("max", "100.00")))
            cents_min = int(minimum * 100)
            cents_max = int(maximum * 100)
            return format(Decimal(rng.randint(cents_min, cents_max)) / 100, ".2f")
        elif col_type == "bool":
            true_ratio = col.get("true_ratio", 0.5)
            return rng.random() < true_ratio

        # Choice type
        elif col_type == "choice":
            choices = col.get("choices", ["unknown"])
            return rng.choice(choices)

        # Sensitive / honeytoken types
        elif col_type == "bcrypt":
            # Syntactically valid bcrypt encoding (22-char salt + 31-char
            # digest).  It is random synthetic text, not a hash of a password.
            alphabet = "./" + string.ascii_letters + string.digits
            encoded = "".join(rng.choices(alphabet, k=53))
            return f"$2b$12${encoded}"
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
