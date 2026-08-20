CREATE TABLE customers (
    id INT PRIMARY KEY,
    full_name VARCHAR(128) NOT NULL,
    email VARCHAR(255) NOT NULL,
    status VARCHAR(32) NOT NULL
);

CREATE TABLE orders (
    id INT PRIMARY KEY,
    customer_id INT NOT NULL,
    amount DECIMAL(10, 2) NOT NULL,
    created_at DATETIME NOT NULL
);

CREATE TABLE api_keys_backup (
    id INT PRIMARY KEY,
    service VARCHAR(128) NOT NULL,
    token VARCHAR(255) NOT NULL,
    notes VARCHAR(255) NOT NULL
);

INSERT INTO customers VALUES
    (1, 'Synthetic Customer One', 'one@example.test', 'active'),
    (2, 'Synthetic Customer Two', 'two@example.test', 'inactive');

INSERT INTO orders VALUES
    (101, 1, 42.50, '2026-01-15 10:00:00'),
    (102, 2, 18.25, '2026-01-16 11:00:00');

INSERT INTO api_keys_backup VALUES
    (1, 'synthetic-service', 'FAKE-HONEYTOKEN-NOT-VALID', 'synthetic replay data');

REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'replay_user'@'%';
GRANT SELECT ON sandboxdb.customers TO 'replay_user'@'%';
GRANT SELECT ON sandboxdb.orders TO 'replay_user'@'%';
GRANT SELECT ON sandboxdb.api_keys_backup TO 'replay_user'@'%';
FLUSH PRIVILEGES;
