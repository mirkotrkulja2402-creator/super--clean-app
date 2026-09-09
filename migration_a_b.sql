
CREATE TABLE IF NOT EXISTS payment_methods (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


CREATE TABLE IF NOT EXISTS route_vehicles (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Super Clean A+B database migration.
-- Safe to run more than once.

ALTER TABLE orders
    ADD COLUMN IF NOT EXISTS planned_pickup_date DATE,
    ADD COLUMN IF NOT EXISTS pickup_time_from TIME,
    ADD COLUMN IF NOT EXISTS pickup_time_to TIME,
    ADD COLUMN IF NOT EXISTS actual_pickup_at TIMESTAMPTZ;

UPDATE orders
SET planned_pickup_date = COALESCE(planned_pickup_date, order_date)
WHERE planned_pickup_date IS NULL;

ALTER TABLE order_items
    ADD COLUMN IF NOT EXISTS measured_at_pickup BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS vehicles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL UNIQUE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS route_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_type VARCHAR(20) NOT NULL CHECK (source_type IN ('ORDER', 'INVOICE')),
    source_id UUID NOT NULL,
    action_type VARCHAR(20) NOT NULL CHECK (action_type IN ('PICKUP', 'DELIVERY')),
    vehicle_id UUID REFERENCES vehicles(id) ON DELETE SET NULL,
    sequence_no INTEGER,
    status VARCHAR(20) NOT NULL DEFAULT 'UNROUTED'
        CHECK (status IN ('UNROUTED', 'ASSIGNED', 'COMPLETED')),
    latitude DOUBLE PRECISION,
    longitude DOUBLE PRECISION,
    assigned_at TIMESTAMPTZ,
    assigned_by UUID REFERENCES users(id) ON DELETE SET NULL,
    completed_at TIMESTAMPTZ,
    last_attempt_at TIMESTAMPTZ,
    last_attempt_by UUID REFERENCES users(id) ON DELETE SET NULL,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    note TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (source_type, source_id, action_type)
);

CREATE TABLE IF NOT EXISTS route_attempts (
    id BIGSERIAL PRIMARY KEY,
    route_job_id UUID NOT NULL REFERENCES route_jobs(id) ON DELETE CASCADE,
    vehicle_id UUID REFERENCES vehicles(id) ON DELETE SET NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    result VARCHAR(30) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS invoice_payments (
    invoice_id UUID PRIMARY KEY REFERENCES invoices(id) ON DELETE CASCADE,
    paid BOOLEAN NOT NULL DEFAULT FALSE,
    payment_method VARCHAR(50),
    paid_at TIMESTAMPTZ,
    paid_by UUID REFERENCES users(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS app_settings (
    setting_key VARCHAR(150) PRIMARY KEY,
    setting_value JSONB NOT NULL DEFAULT '{}'::jsonb,
    updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO vehicles (name, sort_order)
VALUES ('Vozilo 1', 1), ('Vozilo 2', 2)
ON CONFLICT (name) DO NOTHING;

INSERT INTO permissions (code, name, module)
VALUES
    ('routes.view', 'Pregled ruta', 'Ruta'),
    ('routes.assign', 'Dodjela i vođenje ruta', 'Ruta'),
    ('routes.manage', 'Upravljanje vozilima', 'Ruta'),
    ('cashier.view', 'Pregled blagajne', 'Blagajna'),
    ('cashier.edit', 'Evidentiranje naplate', 'Blagajna')
ON CONFLICT (code) DO NOTHING;
