-- NW-005: entered topology only. No connection, trust or health is inferred.
CREATE FUNCTION topology_host_valid(h text) RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$
BEGIN
 IF h='' OR octet_length(h)>253 OR h<>lower(h) THEN RETURN false; END IF;
 IF position(':' in h)>0 OR h ~ '^[0-9.]+$' THEN
  BEGIN PERFORM h::inet; RETURN h !~ '[/%%]'; EXCEPTION WHEN invalid_text_representation THEN RETURN false; END;
 END IF;
 RETURN h ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$';
END $$;
CREATE TABLE cluster (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), environment_id uuid NOT NULL REFERENCES environment(id) ON DELETE RESTRICT,
name text NOT NULL CHECK(octet_length(name) BETWEEN 1 AND 120 AND name=btrim(name) AND name !~ '[[:cntrl:]]'),
type text NOT NULL DEFAULT '' CHECK(octet_length(type) BETWEEN 0 AND 80 AND type=btrim(type) AND type !~ '[[:cntrl:]]'),
tags text NOT NULL DEFAULT '' CHECK(octet_length(tags) BETWEEN 0 AND 512 AND tags=btrim(tags) AND tags !~ '[[:cntrl:]]'),
lifecycle text NOT NULL DEFAULT 'active' CHECK(lifecycle IN ('active','archived')),
created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP, UNIQUE(id,environment_id)
);
CREATE UNIQUE INDEX cluster_name_key ON cluster(environment_id,lower(name));
CREATE INDEX cluster_environment_idx ON cluster(environment_id);
CREATE TABLE asset (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), environment_id uuid NOT NULL REFERENCES environment(id) ON DELETE RESTRICT,
name text NOT NULL CHECK(octet_length(name) BETWEEN 1 AND 120 AND name=btrim(name) AND name !~ '[[:cntrl:]]'),
kind text NOT NULL CHECK(kind IN ('server','network','appliance')),
tags text NOT NULL DEFAULT '' CHECK(octet_length(tags) BETWEEN 0 AND 512 AND tags=btrim(tags) AND tags !~ '[[:cntrl:]]'),
lifecycle text NOT NULL DEFAULT 'active' CHECK(lifecycle IN ('active','archived')),
created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP, UNIQUE(id,environment_id)
);
CREATE UNIQUE INDEX asset_name_key ON asset(environment_id,lower(name));
CREATE INDEX asset_environment_idx ON asset(environment_id);
CREATE TABLE asset_endpoint (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), environment_id uuid NOT NULL REFERENCES environment(id) ON DELETE RESTRICT,
asset_id uuid NOT NULL,
protocol text NOT NULL CHECK(protocol IN ('ssh','http','https','tcp','udp')),
host text NOT NULL CHECK(topology_host_valid(host)),
port integer NOT NULL CHECK(port BETWEEN 1 AND 65535),
preferred boolean NOT NULL DEFAULT false,
status text NOT NULL DEFAULT 'active' CHECK(status IN ('active','archived')),
created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP, UNIQUE(id,environment_id), FOREIGN KEY(asset_id,environment_id) REFERENCES asset(id,environment_id) ON DELETE RESTRICT
);
CREATE UNIQUE INDEX asset_endpoint_address_key ON asset_endpoint(asset_id,protocol,host,port);
CREATE UNIQUE INDEX asset_endpoint_preferred_key ON asset_endpoint(asset_id) WHERE preferred AND status='active';
CREATE INDEX asset_endpoint_environment_idx ON asset_endpoint(environment_id);
CREATE TABLE cluster_membership (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), environment_id uuid NOT NULL REFERENCES environment(id) ON DELETE RESTRICT,
cluster_id uuid NOT NULL,
asset_id uuid NOT NULL,
role text NOT NULL DEFAULT '' CHECK(octet_length(role) BETWEEN 0 AND 80 AND role=btrim(role) AND role !~ '[[:cntrl:]]'),
source text NOT NULL DEFAULT 'manual' CHECK(source='manual'), verified_at timestamptz CHECK(verified_at IS NULL),
created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP, UNIQUE(id,environment_id), FOREIGN KEY(cluster_id,environment_id) REFERENCES cluster(id,environment_id) ON DELETE RESTRICT, FOREIGN KEY(asset_id,environment_id) REFERENCES asset(id,environment_id) ON DELETE RESTRICT
);
CREATE UNIQUE INDEX cluster_membership_pair_key ON cluster_membership(cluster_id,asset_id);
CREATE INDEX cluster_membership_environment_idx ON cluster_membership(environment_id);
CREATE TABLE service (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), environment_id uuid NOT NULL REFERENCES environment(id) ON DELETE RESTRICT,
cluster_id uuid ,
name text NOT NULL CHECK(octet_length(name) BETWEEN 1 AND 120 AND name=btrim(name) AND name !~ '[[:cntrl:]]'),
service_type text NOT NULL CHECK(octet_length(service_type) BETWEEN 1 AND 80 AND service_type=btrim(service_type) AND service_type !~ '[[:cntrl:]]'),
lifecycle text NOT NULL DEFAULT 'active' CHECK(lifecycle IN ('active','archived')),
created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP, UNIQUE(id,environment_id), FOREIGN KEY(cluster_id,environment_id) REFERENCES cluster(id,environment_id) ON DELETE RESTRICT
);
CREATE UNIQUE INDEX service_name_key ON service(environment_id,lower(name));
CREATE INDEX service_environment_idx ON service(environment_id);
CREATE TABLE service_instance (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), environment_id uuid NOT NULL REFERENCES environment(id) ON DELETE RESTRICT,
service_id uuid NOT NULL,
name text NOT NULL CHECK(octet_length(name) BETWEEN 1 AND 120 AND name=btrim(name) AND name !~ '[[:cntrl:]]'),
role text NOT NULL DEFAULT '' CHECK(octet_length(role) BETWEEN 0 AND 80 AND role=btrim(role) AND role !~ '[[:cntrl:]]'),
instance_key text NOT NULL DEFAULT '' CHECK(octet_length(instance_key) BETWEEN 0 AND 80 AND instance_key=btrim(instance_key) AND instance_key !~ '[[:cntrl:]]'),
lifecycle text NOT NULL DEFAULT 'active' CHECK(lifecycle IN ('active','archived')),
created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP, UNIQUE(id,environment_id), FOREIGN KEY(service_id,environment_id) REFERENCES service(id,environment_id) ON DELETE RESTRICT
);
CREATE UNIQUE INDEX service_instance_name_key ON service_instance(service_id,lower(name));
CREATE UNIQUE INDEX service_instance_key_key ON service_instance(service_id,instance_key) WHERE instance_key<>'';
CREATE INDEX service_instance_environment_idx ON service_instance(environment_id);
CREATE TABLE service_instance_host (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), environment_id uuid NOT NULL REFERENCES environment(id) ON DELETE RESTRICT,
service_instance_id uuid NOT NULL,
asset_id uuid NOT NULL,
binding_role text NOT NULL DEFAULT '' CHECK(octet_length(binding_role) BETWEEN 0 AND 80 AND binding_role=btrim(binding_role) AND binding_role !~ '[[:cntrl:]]'),
verified_at timestamptz CHECK(verified_at IS NULL),
created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP, UNIQUE(id,environment_id), FOREIGN KEY(service_instance_id,environment_id) REFERENCES service_instance(id,environment_id) ON DELETE RESTRICT, FOREIGN KEY(asset_id,environment_id) REFERENCES asset(id,environment_id) ON DELETE RESTRICT
);
CREATE UNIQUE INDEX service_instance_host_pair_key ON service_instance_host(service_instance_id,asset_id);
CREATE INDEX service_instance_host_environment_idx ON service_instance_host(environment_id);
CREATE FUNCTION topology_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE e_status text; c_status text; parent_status text; parent_table text; ref text; j jsonb; active_record boolean;
BEGIN
 j:=to_jsonb(NEW);
 IF TG_OP='UPDATE' THEN
  IF NEW.id IS DISTINCT FROM OLD.id OR NEW.environment_id IS DISTINCT FROM OLD.environment_id THEN
   RAISE EXCEPTION 'immutable topology identity' USING ERRCODE='23514',CONSTRAINT='topology_immutable';
  END IF;
  FOREACH ref IN ARRAY COALESCE(TG_ARGV,ARRAY[]::text[]) LOOP
   IF j->ref IS DISTINCT FROM to_jsonb(OLD)->ref THEN
    RAISE EXCEPTION 'immutable topology owner' USING ERRCODE='23514',CONSTRAINT='topology_immutable';
   END IF;
  END LOOP;
 END IF;
 -- Lock customer before environment, using the same order across all writes.
 SELECT c.status INTO c_status FROM customer c JOIN environment e ON e.customer_id=c.id WHERE e.id=NEW.environment_id FOR SHARE OF c;
 SELECT status INTO e_status FROM environment WHERE id=NEW.environment_id FOR SHARE;
 active_record := COALESCE(j->>'lifecycle',j->>'status','active')='active';
 IF active_record AND (c_status='archived' OR e_status='archived') THEN
  RAISE EXCEPTION 'archived topology owner' USING ERRCODE='23514',CONSTRAINT='topology_active';
 END IF;
 -- All declared references must be in the same environment (also enforced by FKs).
 FOREACH ref IN ARRAY ARRAY['cluster_id','asset_id','service_id','service_instance_id'] LOOP
  IF j->>ref IS NOT NULL THEN
   parent_table:=CASE ref WHEN 'cluster_id' THEN 'cluster' WHEN 'asset_id' THEN 'asset' WHEN 'service_id' THEN 'service' ELSE 'service_instance' END;
   EXECUTE format('SELECT lifecycle FROM %I WHERE id=$1 AND environment_id=$2 FOR SHARE',parent_table) INTO parent_status USING (j->>ref)::uuid,NEW.environment_id;
   IF active_record AND parent_status='archived' THEN
    RAISE EXCEPTION 'archived topology reference' USING ERRCODE='23514',CONSTRAINT='topology_active';
   END IF;
  END IF;
 END LOOP;
 RETURN NEW;
END $$;
CREATE TRIGGER cluster_guard BEFORE INSERT OR UPDATE ON cluster FOR EACH ROW EXECUTE FUNCTION topology_guard();
CREATE TRIGGER asset_guard BEFORE INSERT OR UPDATE ON asset FOR EACH ROW EXECUTE FUNCTION topology_guard();
CREATE TRIGGER asset_endpoint_guard BEFORE INSERT OR UPDATE ON asset_endpoint FOR EACH ROW EXECUTE FUNCTION topology_guard('asset_id');
CREATE TRIGGER cluster_membership_guard BEFORE INSERT OR UPDATE ON cluster_membership FOR EACH ROW EXECUTE FUNCTION topology_guard('cluster_id','asset_id');
CREATE TRIGGER service_guard BEFORE INSERT OR UPDATE ON service FOR EACH ROW EXECUTE FUNCTION topology_guard();
CREATE TRIGGER service_instance_guard BEFORE INSERT OR UPDATE ON service_instance FOR EACH ROW EXECUTE FUNCTION topology_guard('service_id');
CREATE TRIGGER service_instance_host_guard BEFORE INSERT OR UPDATE ON service_instance_host FOR EACH ROW EXECUTE FUNCTION topology_guard('service_instance_id','asset_id');
