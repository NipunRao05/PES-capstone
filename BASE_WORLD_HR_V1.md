# HR v1 frozen base-world contract

2026-10-31. World `hr_base_v1`, version `1`. This is the first approved deployment
world, not an Azure deployment or a new strategy. Executable table/identity authority
is `deception_engine/schemas/hr.yaml`; `base_world.py` reads that file. No duplicate
world table manifest exists. `scripts/audit_base_world.py` prints nonsecret inventory.

## Identity and time

The fictional **Company Internal Research Cooperative** uses `company.internal`
for company-controlled email. No public corporate website exists. Host persona is
`db-prod-02`; environment is a production replica; internal lure systems are
`hr-db-01`, `hr-app-prod`, `payroll-sync`, `hr-backup`. These names advertise no real
corporate infrastructure. `testdb` is deliberately retained for compatibility.
PostgreSQL schema is `public`; MySQL schema/database is `testdb`.

This is an explicitly historical, immutable snapshot with reference time
**2024-01-01T12:00:00**. Dates do not advance with the VM clock. Keeping the existing
reference preserves deterministic date semantics rather than silently changing
existing worlds. Employee hire dates precede this reference; sessions enforce
logout >= login, and API usage timestamps enforce last_used >= created_at.

Native/backend and default SQL personas align at PostgreSQL **16.15** and MySQL
**8.0.46**, as inspected locally. Tags are not immutable image locks: later image
updates require rechecking persona compatibility. No learning/adaptation is enabled.

## Exact tables

Counts below are frozen base populations, without session-count jitter. Synthetic
D6 overlays can change a session/principal's effective count.

| Table | Depth | Rows | Trap | Read strategy | Columns |
|---|---:|---:|---|---|---|
| employees | 1 | 847 | No | D4 | id, full_name, email, department, job_title, seniority_level, hire_date, salary, manager_id, is_active, password_hash |
| departments | 1 | 8 | No | D0 | id, name, head_count, budget_usd, manager_id |
| sessions | 1 | 2341 | No | D0 | id, employee_id, ip_address, login_at, logout_at, user_agent |
| payroll | 2 | 847 | No | D4 | employee_id, bank_name, account_number, routing_number, last_pay_date, annual_bonus |
| api_keys | 2 | 23 | No | D3 | id, service, token, created_by, created_at, last_used, is_active |
| api_keys_backup | 3 | 15 | Yes | D2 | id, service, token, notes, created_at |
| salary_executives | 3 | 12 | Yes | D4 | id, full_name, title, base_salary, equity_shares, ssn, home_address |
| prod_credentials | 3 | 8 | Yes | D3 | id, system, username, password, last_rotated, notes |

Employee department, title, seniority, pay and manager relationships use the
existing department-specific organization generator. Department names are unique;
heads belong to their departments; reported head counts reconcile to employees.
Session employee IDs and token created_by values reference 1..847. Payroll has one
row per employee, including stable page offsets. Executive lure names/titles refer
to generated senior Executive employees. Payroll clearing is fictional.

## Exposure and catalog behavior

Sessions begin at depth 1. An authorized read of a table whose configured depth is
at least current depth advances exposure by one, capped at 3. Thus reading employees
opens depth 2; reading payroll opens depth 3. Re-reading depth 1 does not itself
advance depth 2 to 3. Catalog listings and direct managed-table access use the
same visibility authority. Hidden tables return protocol-native missing-table errors.

Database enumeration advertises only `testdb`, never unreachable Finance/CRM aliases.
PostgreSQL seed connections require `testdb`; current_database() reports it. MySQL
defaults to `testdb`, supports COM_INIT_DB/testdb and bounded USE testdb, and rejects
other switches without updating session identity. Synthetic table/column catalogs
come from the YAML. Physical main backends remain without application tables.
Finance and CRM files remain available for offline/future experiments but database
input cannot select them in this baseline. W1/W2/W3 are not implemented worlds.

## Lures and sensitive data

Vendor names in api_keys are fictional integration metadata only. HR tokens use
the application-owned `hrv1_` namespace, not valid AWS/GitHub/Stripe credential
syntax. Bank account strings use invalid country/check digits `ZZ00`; routing
numbers use an invalid `000` prefix; SSN-like values use invalid area/group `000-00`.
Bcrypt text is random encoding, not a hash of an imported password. Password lures
are generated text and are never provisioned as backend/vendor login credentials.
No external validation/authentication API is called. No real person/company dataset
is imported. Generated names/addresses can coincidentally resemble real ones; no
claim of global uniqueness or knowledge of every real-world password is possible.

Attacker-visible token/password fields no longer carry HONEYPOT/DECOY banners.
Their schema metadata and this contract establish synthetic provenance. No secret
or generated lure value belongs in the inventory command or operational logs.

## Strategies and principal integration

D0 supplies baseline banners, permitted native constants/transactions and default
responses; D1 produces catalog reconnaissance; D2 reads api_keys_backup; D3 reads
api_keys/prod_credentials; D4 reads employees/payroll/salary_executives; D6 simulates
supported INSERT/UPDATE/DELETE in Redis overlays. D5 remains REQUIRES_REVIEW and D7
unmapped. Registry definitions/versions/lock and scoring formulas are unchanged.

Ordinary mutations remain session-scoped; virtual fake_ principals retain committed
permissions, overlays and exposure across reconnect. Rollback/disconnect do not
promote pending work. PostgreSQL uses SCRAM; MySQL uses native challenge proof.
Virtual users are never physical DB users. Existing retained principal records and
overlays are not rewritten or deleted; older records have no authenticated historical
base-world version. Relation commitments retain their existing bounded semantics,
not a promise that all previously generated uncommitted row values are archived.

New decisions/applications and covered query evidence carry world_id/world_version.
Historical missing metadata remains LEGACY/UNKNOWN; old immutable traces are not
retrofitted. Principal-specific world state is distinct from this base-world ID.

## Protocol boundary and limitations

Supported research paths are PostgreSQL simple queries, MySQL text queries, and the
existing bounded virtual-principal subsets. Covered projections, ID predicates,
pagination, catalog filters and mutations retain their existing implementation.
This is not a complete SQL engine: arbitrary joins, expressions, DDL, savepoints and
all native client startup commands are not promised. Results remain capped at 100
rows per request. Raw extended/prepared/binary execution is rejected before native
forwarding in the contained baseline; PostgreSQL recovery discards through Sync.
Native cancellation, MySQL change-user/process-kill/admin commands are unsupported.

Native fallback is restricted independently of the engine. See
`BACKEND_PRIVILEGE_CONTAINMENT.md`. Internet exposure, disk-loss durability,
full capacity, calibrated effectiveness and complete lifetime evidence remain outside
this contract. Current local traffic is engineering validation, not research data.
