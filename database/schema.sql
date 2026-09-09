CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS roles (
    code VARCHAR(50) PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    is_system BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS permissions (
    code VARCHAR(100) PRIMARY KEY,
    name VARCHAR(150) NOT NULL UNIQUE,
    module VARCHAR(100) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS role_permissions (
    role_code VARCHAR(50) NOT NULL REFERENCES roles(code) ON DELETE CASCADE,
    permission_code VARCHAR(100) NOT NULL REFERENCES permissions(code) ON DELETE CASCADE,
    PRIMARY KEY (role_code, permission_code)
);

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(100) NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'WORKER',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);


CREATE TABLE IF NOT EXISTS customers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL DEFAULT '',
    company_name VARCHAR(200) NOT NULL DEFAULT '',
    phone VARCHAR(40) NOT NULL DEFAULT '',
    whatsapp VARCHAR(40) NOT NULL DEFAULT '',
    address VARCHAR(250) NOT NULL DEFAULT '',
    city VARCHAR(100) NOT NULL DEFAULT 'Banja Luka',
    note TEXT NOT NULL DEFAULT '',
    latitude DOUBLE PRECISION,
    longitude DOUBLE PRECISION,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_customers_name
    ON customers (LOWER(first_name), LOWER(last_name));

CREATE INDEX IF NOT EXISTS idx_customers_phone
    ON customers (phone);

CREATE INDEX IF NOT EXISTS idx_customers_city
    ON customers (city);

ALTER TABLE customers ADD COLUMN IF NOT EXISTS latitude DOUBLE PRECISION;
ALTER TABLE customers ADD COLUMN IF NOT EXISTS longitude DOUBLE PRECISION;

CREATE INDEX IF NOT EXISTS idx_customers_coordinates
    ON customers (latitude, longitude);

INSERT INTO roles (code, name, description, is_system)
VALUES
    ('ADMIN', 'Administrator', 'Potpuni pristup aplikaciji.', TRUE),
    ('MANAGER', 'Poslovođa', 'Rad sa poslovnim podacima i izvještajima.', FALSE),
    ('WORKER', 'Radnik', 'Operativni rad sa narudžbama i kupcima.', FALSE),
    ('ACCOUNTANT', 'Knjigovođa', 'Rad sa računima i finansijskim izvještajima.', FALSE)
ON CONFLICT (code) DO NOTHING;

INSERT INTO permissions (code, name, module)
VALUES
    ('customers.view', 'Pregled kupaca', 'Kupci'),
    ('customers.create', 'Dodavanje kupaca', 'Kupci'),
    ('customers.edit', 'Izmjena kupaca', 'Kupci'),
    ('customers.delete', 'Brisanje kupaca', 'Kupci'),
    ('orders.view', 'Pregled narudžbi', 'Narudžbe'),
    ('orders.create', 'Dodavanje narudžbi', 'Narudžbe'),
    ('orders.edit', 'Izmjena narudžbi', 'Narudžbe'),
    ('orders.delete', 'Brisanje narudžbi', 'Narudžbe'),
    ('pricing.view', 'Pregled cjenovnika', 'Cjenovnik'),
    ('pricing.edit', 'Izmjena cjenovnika', 'Cjenovnik'),
    ('labels.view', 'Pregled etiketa', 'Etikete'),
    ('labels.print', 'Štampanje etiketa', 'Etikete'),
    ('qr.view', 'Pregled QR kodova', 'QR'),
    ('qr.create', 'Kreiranje QR kodova', 'QR'),
    ('invoices.view', 'Pregled računa', 'Računi'),
    ('invoices.create', 'Kreiranje računa', 'Računi'),
    ('invoices.edit', 'Izmjena računa', 'Računi'),
    ('invoices.print', 'Štampanje računa', 'Računi'),
    ('reports.view', 'Pregled izvještaja', 'Izvještaji'),
    ('reports.export', 'Izvoz izvještaja', 'Izvještaji'),
    ('excel.import', 'Uvoz Excel podataka', 'Excel'),
    ('excel.export', 'Izvoz Excel podataka', 'Excel'),
    ('admin.users', 'Upravljanje korisnicima', 'Administracija'),
    ('admin.roles', 'Upravljanje ulogama i dozvolama', 'Administracija'),
    ('admin.settings', 'Podešavanja aplikacije', 'Administracija')
ON CONFLICT (code) DO NOTHING;

INSERT INTO role_permissions (role_code, permission_code)
SELECT 'ADMIN', code FROM permissions
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_code, permission_code)
VALUES
    ('MANAGER', 'customers.view'),
    ('MANAGER', 'customers.create'),
    ('MANAGER', 'customers.edit'),
    ('MANAGER', 'orders.view'),
    ('MANAGER', 'orders.create'),
    ('MANAGER', 'orders.edit'),
    ('MANAGER', 'pricing.view'),
    ('MANAGER', 'labels.view'),
    ('MANAGER', 'labels.print'),
    ('MANAGER', 'qr.view'),
    ('MANAGER', 'qr.create'),
    ('MANAGER', 'invoices.view'),
    ('MANAGER', 'invoices.create'),
    ('MANAGER', 'invoices.print'),
    ('MANAGER', 'reports.view'),
    ('MANAGER', 'reports.export'),
    ('MANAGER', 'excel.import'),
    ('MANAGER', 'excel.export'),
    ('WORKER', 'customers.view'),
    ('WORKER', 'customers.create'),
    ('WORKER', 'orders.view'),
    ('WORKER', 'orders.create'),
    ('WORKER', 'orders.edit'),
    ('WORKER', 'labels.view'),
    ('WORKER', 'labels.print'),
    ('WORKER', 'qr.view'),
    ('WORKER', 'qr.create'),
    ('ACCOUNTANT', 'customers.view'),
    ('ACCOUNTANT', 'orders.view'),
    ('ACCOUNTANT', 'invoices.view'),
    ('ACCOUNTANT', 'invoices.create'),
    ('ACCOUNTANT', 'invoices.edit'),
    ('ACCOUNTANT', 'invoices.print'),
    ('ACCOUNTANT', 'reports.view'),
    ('ACCOUNTANT', 'reports.export'),
    ('ACCOUNTANT', 'excel.export')
ON CONFLICT DO NOTHING;


CREATE TABLE IF NOT EXISTS orders (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    order_number BIGSERIAL UNIQUE,
    customer_id UUID NOT NULL REFERENCES customers(id) ON DELETE RESTRICT,
    order_date DATE NOT NULL DEFAULT CURRENT_DATE,
    status VARCHAR(30) NOT NULL DEFAULT 'RECEIVED'
        CHECK (status IN ('RECEIVED', 'WASHING', 'DRYING', 'READY', 'DELIVERED', 'PAID', 'CANCELLED')),
    note TEXT NOT NULL DEFAULT '',
    delivery_price NUMERIC(12, 2) NOT NULL DEFAULT 0,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS order_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    order_id UUID NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
    service_name VARCHAR(200) NOT NULL,
    unit VARCHAR(20) NOT NULL CHECK (unit IN ('m2', 'piece')),
    length_m NUMERIC(10, 2),
    width_m NUMERIC(10, 2),
    quantity NUMERIC(10, 2) NOT NULL DEFAULT 1,
    unit_price NUMERIC(12, 2) NOT NULL DEFAULT 0,
    area_m2 NUMERIC(12, 2),
    total NUMERIC(12, 2) NOT NULL DEFAULT 0,
    note TEXT NOT NULL DEFAULT '',
    qr_scan_count INTEGER NOT NULL DEFAULT 0,
    last_qr_scanned_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_orders_customer_id ON orders(customer_id);
CREATE INDEX IF NOT EXISTS idx_orders_date ON orders(order_date);
CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status);

ALTER TABLE orders
    ADD COLUMN IF NOT EXISTS delivery_requested BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE orders
    ADD COLUMN IF NOT EXISTS delivery_price NUMERIC(12, 2) NOT NULL DEFAULT 0;
UPDATE orders
SET delivery_price = 0
WHERE delivery_price IS NULL;
CREATE INDEX IF NOT EXISTS idx_order_items_order_id ON order_items(order_id);
CREATE INDEX IF NOT EXISTS idx_order_items_last_qr_scan ON order_items(last_qr_scanned_at DESC);


CREATE TABLE IF NOT EXISTS invoices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    order_id UUID NOT NULL UNIQUE REFERENCES orders(id) ON DELETE RESTRICT,
    invoice_no BIGSERIAL UNIQUE,
    status VARCHAR(20) NOT NULL DEFAULT 'INVOICED'
        CHECK (status IN ('INVOICED', 'CANCELLED')),
    payment_method VARCHAR(20) NOT NULL DEFAULT 'cash'
        CHECK (payment_method IN ('cash', 'card', 'bank')),
    issued_at DATE NOT NULL DEFAULT CURRENT_DATE,
    due_date DATE,
    cancelled_at TIMESTAMPTZ,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_invoices_status ON invoices(status);
CREATE INDEX IF NOT EXISTS idx_invoices_order_id ON invoices(order_id);

CREATE TABLE IF NOT EXISTS price_list (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    service_name VARCHAR(200) NOT NULL,
    unit VARCHAR(20) NOT NULL DEFAULT 'm2',
    price NUMERIC(12,2) NOT NULL DEFAULT 0,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT price_list_unit_check CHECK (unit IN ('m2', 'piece')),
    CONSTRAINT price_list_price_check CHECK (price >= 0),
    CONSTRAINT price_list_service_unit_unique UNIQUE (service_name, unit)
);

CREATE INDEX IF NOT EXISTS idx_price_list_active
    ON price_list (is_active, sort_order, service_name);

INSERT INTO price_list (service_name, unit, price, sort_order)
VALUES
    ('Pranje tepiha', 'm2', 0, 10),
    ('Dubinsko pranje namještaja', 'piece', 0, 20),
    ('Pranje stakala', 'piece', 0, 30),
    ('Pranje fasada', 'm2', 0, 40)
ON CONFLICT DO NOTHING;


CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    username VARCHAR(100) NOT NULL DEFAULT '',
    role VARCHAR(50) NOT NULL DEFAULT '',
    action VARCHAR(250) NOT NULL,
    method VARCHAR(10) NOT NULL DEFAULT '',
    path VARCHAR(250) NOT NULL DEFAULT '',
    status_code INTEGER,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at
    ON audit_logs (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id
    ON audit_logs (user_id);

CREATE TABLE IF NOT EXISTS backup_records (
    id BIGSERIAL PRIMARY KEY,
    filename VARCHAR(300) NOT NULL UNIQUE,
    backup_type VARCHAR(20) NOT NULL CHECK (backup_type IN ('MANUAL', 'AUTOMATIC')),
    file_size_bytes BIGINT NOT NULL DEFAULT 0,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_backup_records_created_at
    ON backup_records (created_at DESC);
