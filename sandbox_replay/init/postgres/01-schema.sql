CREATE TABLE customers (
    id integer PRIMARY KEY,
    full_name text NOT NULL,
    email text NOT NULL,
    status text NOT NULL
);

CREATE TABLE orders (
    id integer PRIMARY KEY,
    customer_id integer REFERENCES customers(id),
    amount numeric(10, 2) NOT NULL,
    created_at timestamp NOT NULL
);

CREATE TABLE api_keys_backup (
    id integer PRIMARY KEY,
    service text NOT NULL,
    token text NOT NULL,
    notes text NOT NULL
);

INSERT INTO customers VALUES
    (1, 'Synthetic Customer One', 'one@example.test', 'active'),
    (2, 'Synthetic Customer Two', 'two@example.test', 'inactive');

INSERT INTO orders VALUES
    (101, 1, 42.50, '2026-01-15 10:00:00'),
    (102, 2, 18.25, '2026-01-16 11:00:00');

INSERT INTO api_keys_backup VALUES
    (1, 'synthetic-service', 'FAKE-HONEYTOKEN-NOT-VALID', 'synthetic replay data');

\getenv replay_password SANDBOX_REPLAY_PASSWORD
CREATE ROLE replay_user LOGIN PASSWORD :'replay_password';
REVOKE ALL ON DATABASE sandboxdb FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT CONNECT ON DATABASE sandboxdb TO replay_user;
GRANT USAGE ON SCHEMA public TO replay_user;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO replay_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO replay_user;
ALTER ROLE replay_user SET default_transaction_read_only = on;
ALTER ROLE replay_user SET statement_timeout = '750ms';
