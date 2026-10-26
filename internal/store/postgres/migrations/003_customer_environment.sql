CREATE TABLE customer (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    display_name text NOT NULL CHECK (octet_length(display_name) BETWEEN 1 AND 120 AND display_name = btrim(display_name) AND display_name !~ '[[:cntrl:]]'),
    short_code text NOT NULL CHECK (short_code ~ '^[A-Z][A-Z0-9_-]{1,23}$'),
    notes text NOT NULL DEFAULT '' CHECK (octet_length(notes) <= 4096),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','archived')),
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX customer_display_name_key ON customer (lower(display_name));
CREATE UNIQUE INDEX customer_short_code_key ON customer (short_code);

CREATE TABLE environment (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id uuid NOT NULL REFERENCES customer(id) ON DELETE RESTRICT,
    name text NOT NULL CHECK (octet_length(name) BETWEEN 1 AND 80 AND name = btrim(name) AND name !~ '[[:cntrl:]]'),
    kind text NOT NULL CHECK (kind IN ('lab','test','production')),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','archived')),
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (id, customer_id)
);
CREATE UNIQUE INDEX environment_customer_name_key ON environment (customer_id, lower(name));

-- Keep ownership fixed even for direct SQL, and serialize environment writes
-- against customer archival. The row lock is held through statement commit.
CREATE FUNCTION enforce_environment_owner() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE customer_status text;
BEGIN
    IF TG_OP = 'UPDATE' AND (NEW.customer_id IS DISTINCT FROM OLD.customer_id OR NEW.id IS DISTINCT FROM OLD.id) THEN
        RAISE EXCEPTION 'environment ownership is immutable' USING ERRCODE='23514', CONSTRAINT='environment_owner_immutable';
    END IF;
    SELECT status INTO customer_status FROM customer WHERE id=NEW.customer_id FOR SHARE;
    IF customer_status = 'archived' THEN
        RAISE EXCEPTION 'customer is archived' USING ERRCODE='23514', CONSTRAINT='environment_customer_active';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER environment_owner BEFORE INSERT OR UPDATE ON environment
FOR EACH ROW EXECUTE FUNCTION enforce_environment_owner();
