-- NW-006 single-operator workspace. This principal is not a multi-user account.
CREATE TABLE workspace_principal(id uuid PRIMARY KEY, designation text NOT NULL UNIQUE CHECK(designation='local-operator'));
INSERT INTO workspace_principal VALUES('00000000-0000-4000-8000-000000000001','local-operator');
-- A reference registry supplies real FKs for every supported resource, not an
-- unchecked polymorphic ID. Canonical inventory identities remain authoritative.
CREATE TABLE workspace_target(
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 kind text NOT NULL,
 customer_id uuid NOT NULL REFERENCES customer(id) ON DELETE RESTRICT,
 environment_id uuid,
 cluster_id uuid, asset_id uuid, endpoint_id uuid, service_id uuid, instance_id uuid,
 FOREIGN KEY(environment_id,customer_id) REFERENCES environment(id,customer_id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,environment_id) REFERENCES cluster(id,environment_id) ON DELETE RESTRICT,
 FOREIGN KEY(asset_id,environment_id) REFERENCES asset(id,environment_id) ON DELETE RESTRICT,
 FOREIGN KEY(endpoint_id,environment_id) REFERENCES asset_endpoint(id,environment_id) ON DELETE RESTRICT,
 FOREIGN KEY(service_id,environment_id) REFERENCES service(id,environment_id) ON DELETE RESTRICT,
 FOREIGN KEY(instance_id,environment_id) REFERENCES service_instance(id,environment_id) ON DELETE RESTRICT,
 resource_id uuid GENERATED ALWAYS AS (coalesce(cluster_id,asset_id,endpoint_id,service_id,instance_id,environment_id,customer_id)) STORED,
 UNIQUE(kind,resource_id),
 CHECK((kind='customers' AND environment_id IS NULL AND num_nonnulls(cluster_id,asset_id,endpoint_id,service_id,instance_id)=0)
 OR (kind='environments' AND environment_id IS NOT NULL AND num_nonnulls(cluster_id,asset_id,endpoint_id,service_id,instance_id)=0)
 OR (environment_id IS NOT NULL AND num_nonnulls(cluster_id,asset_id,endpoint_id,service_id,instance_id)=1 AND
 ((kind='clusters' AND cluster_id IS NOT NULL) OR (kind='assets' AND asset_id IS NOT NULL) OR (kind='endpoints' AND endpoint_id IS NOT NULL) OR (kind='services' AND service_id IS NOT NULL) OR (kind='instances' AND instance_id IS NOT NULL))))
);
CREATE FUNCTION workspace_target_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF NEW IS DISTINCT FROM OLD THEN RAISE EXCEPTION 'workspace reference is immutable' USING ERRCODE='23514'; END IF; RETURN NEW;
END $$;
CREATE TRIGGER workspace_target_immutable BEFORE UPDATE ON workspace_target FOR EACH ROW EXECUTE FUNCTION workspace_target_immutable();
CREATE TABLE workspace_pin(principal_id uuid NOT NULL REFERENCES workspace_principal(id), target_id uuid NOT NULL REFERENCES workspace_target(id), created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(principal_id,target_id));
CREATE TABLE workspace_recent(principal_id uuid NOT NULL REFERENCES workspace_principal(id), target_id uuid NOT NULL REFERENCES workspace_target(id), visited_at timestamptz NOT NULL DEFAULT clock_timestamp(), PRIMARY KEY(principal_id,target_id));
CREATE INDEX workspace_recent_order ON workspace_recent(principal_id,visited_at DESC,target_id);
CREATE TABLE operator_note(id uuid PRIMARY KEY DEFAULT gen_random_uuid(),target_id uuid NOT NULL REFERENCES workspace_target(id),principal_id uuid NOT NULL REFERENCES workspace_principal(id),
 body text NOT NULL CHECK(octet_length(body) BETWEEN 1 AND 4096 AND body=btrim(body)),visibility text NOT NULL CHECK(visibility IN ('private','shared')),
 created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE INDEX operator_note_target ON operator_note(target_id,updated_at DESC,id);
CREATE INDEX operator_note_search ON operator_note USING gin(to_tsvector('simple',body));
CREATE TABLE external_link(id uuid PRIMARY KEY DEFAULT gen_random_uuid(),target_id uuid NOT NULL REFERENCES workspace_target(id),principal_id uuid NOT NULL REFERENCES workspace_principal(id),
 label text NOT NULL CHECK(octet_length(label) BETWEEN 1 AND 120 AND label=btrim(label) AND label !~ '[[:cntrl:]]'),
 url text NOT NULL CHECK(octet_length(url)<=2048 AND url ~ '^https?://[^/@?#[:space:]]+(/[^?#[:space:]]*)?$'),
 type text NOT NULL CHECK(type IN ('rtm','admin','dashboard','support','other')), pinned boolean NOT NULL DEFAULT false,
 created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(target_id,label));
CREATE INDEX external_link_target ON external_link(target_id,pinned DESC,label,id);
CREATE TABLE workspace_audit(id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,principal_id uuid NOT NULL REFERENCES workspace_principal(id),target_id uuid NOT NULL REFERENCES workspace_target(id),operation text NOT NULL CHECK(operation IN ('pin','unpin','note.save','note.remove','link.save','link.remove','command.copy')),at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP);
-- Notes and links cannot change authors or owning resources, even through SQL.
CREATE FUNCTION workspace_content_owner() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF NEW.id<>OLD.id OR NEW.target_id<>OLD.target_id OR NEW.principal_id<>OLD.principal_id THEN RAISE EXCEPTION 'workspace ownership is immutable' USING ERRCODE='23514'; END IF; RETURN NEW;
END $$;
CREATE TRIGGER note_owner BEFORE UPDATE ON operator_note FOR EACH ROW EXECUTE FUNCTION workspace_content_owner();
CREATE TRIGGER link_owner BEFORE UPDATE ON external_link FOR EACH ROW EXECUTE FUNCTION workspace_content_owner();
CREATE INDEX customer_workspace_search ON customer USING gin(to_tsvector('simple',display_name || ' ' || short_code || ' ' || notes));
CREATE INDEX environment_workspace_search ON environment USING gin(to_tsvector('simple',name || ' ' || kind));
CREATE INDEX cluster_workspace_search ON cluster USING gin(to_tsvector('simple',name || ' ' || type || ' ' || tags));
CREATE INDEX asset_workspace_search ON asset USING gin(to_tsvector('simple',name || ' ' || kind || ' ' || tags));
CREATE INDEX asset_endpoint_workspace_search ON asset_endpoint USING gin(to_tsvector('simple',host || ' ' || protocol || ' ' || port::text));
CREATE INDEX service_workspace_search ON service USING gin(to_tsvector('simple',name || ' ' || service_type));
CREATE INDEX service_instance_workspace_search ON service_instance USING gin(to_tsvector('simple',name || ' ' || role || ' ' || instance_key));
CREATE VIEW workspace_inventory AS
SELECT 'customers'::text kind,c.id,c.id customer_id,NULL::uuid environment_id,c.display_name label,c.display_name customer,''::text environment,c.status lifecycle,c.short_code summary,to_tsvector('simple',c.display_name || ' ' || c.short_code || ' ' || c.notes) document FROM customer c
UNION ALL
SELECT 'environments',x.id,x.customer_id,x.id,x.name,c.display_name,x.name,CASE WHEN c.status='archived' THEN 'archived' ELSE x.status END,(x.kind),to_tsvector('simple',x.name || ' ' || x.kind) FROM environment x JOIN customer c ON c.id=x.customer_id
UNION ALL
SELECT 'clusters',x.id,e.customer_id,x.environment_id,x.name,c.display_name,e.name,CASE WHEN c.status='archived' OR e.status='archived' THEN 'archived' ELSE x.lifecycle END,(x.type || ' ' || x.tags),to_tsvector('simple',x.name || ' ' || x.type || ' ' || x.tags) FROM cluster x JOIN environment e ON e.id=x.environment_id JOIN customer c ON c.id=e.customer_id
UNION ALL
SELECT 'assets',x.id,e.customer_id,x.environment_id,x.name,c.display_name,e.name,CASE WHEN c.status='archived' OR e.status='archived' THEN 'archived' ELSE x.lifecycle END,(x.kind || ' ' || x.tags),to_tsvector('simple',x.name || ' ' || x.kind || ' ' || x.tags) FROM asset x JOIN environment e ON e.id=x.environment_id JOIN customer c ON c.id=e.customer_id
UNION ALL
SELECT 'endpoints',x.id,e.customer_id,x.environment_id,x.host,c.display_name,e.name,CASE WHEN c.status='archived' OR e.status='archived' OR a.lifecycle='archived' THEN 'archived' ELSE x.status END,(x.protocol || ' ' || x.port::text),to_tsvector('simple',x.host || ' ' || x.protocol || ' ' || x.port::text) FROM asset_endpoint x JOIN environment e ON e.id=x.environment_id JOIN customer c ON c.id=e.customer_id JOIN asset a ON a.id=x.asset_id
UNION ALL
SELECT 'services',x.id,e.customer_id,x.environment_id,x.name,c.display_name,e.name,CASE WHEN c.status='archived' OR e.status='archived' THEN 'archived' ELSE x.lifecycle END,(x.service_type),to_tsvector('simple',x.name || ' ' || x.service_type) FROM service x JOIN environment e ON e.id=x.environment_id JOIN customer c ON c.id=e.customer_id
UNION ALL
SELECT 'instances',x.id,e.customer_id,x.environment_id,x.name,c.display_name,e.name,CASE WHEN c.status='archived' OR e.status='archived' OR s.lifecycle='archived' THEN 'archived' ELSE x.lifecycle END,(x.role || ' ' || x.instance_key),to_tsvector('simple',x.name || ' ' || x.role || ' ' || x.instance_key) FROM service_instance x JOIN environment e ON e.id=x.environment_id JOIN customer c ON c.id=e.customer_id JOIN service s ON s.id=x.service_id;
-- Serialize workspace assignments against inventory archival. Removal stays
-- possible; history is retained when an ancestor is archived later.
CREATE FUNCTION workspace_active_target() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE t workspace_target; state text;
BEGIN
 SELECT * INTO t FROM workspace_target WHERE id=NEW.target_id;
 PERFORM id FROM customer WHERE id=t.customer_id FOR SHARE;
 IF t.environment_id IS NOT NULL THEN PERFORM id FROM environment WHERE id=t.environment_id FOR SHARE; END IF;
 IF t.cluster_id IS NOT NULL THEN PERFORM id FROM cluster WHERE id=t.cluster_id FOR SHARE; END IF;
 IF t.asset_id IS NOT NULL THEN PERFORM id FROM asset WHERE id=t.asset_id FOR SHARE; END IF;
 IF t.endpoint_id IS NOT NULL THEN
  PERFORM a.id FROM asset a JOIN asset_endpoint e ON e.asset_id=a.id WHERE e.id=t.endpoint_id FOR SHARE OF a;
  PERFORM id FROM asset_endpoint WHERE id=t.endpoint_id FOR SHARE;
 END IF;
 IF t.service_id IS NOT NULL THEN PERFORM id FROM service WHERE id=t.service_id FOR SHARE; END IF;
 IF t.instance_id IS NOT NULL THEN
  PERFORM s.id FROM service s JOIN service_instance i ON i.service_id=s.id WHERE i.id=t.instance_id FOR SHARE OF s;
  PERFORM id FROM service_instance WHERE id=t.instance_id FOR SHARE;
 END IF;
 SELECT lifecycle INTO state FROM workspace_inventory WHERE kind=t.kind AND id=t.resource_id;
 IF state='archived' THEN RAISE EXCEPTION 'workspace target is archived' USING ERRCODE='23514',CONSTRAINT='topology_active'; END IF;
 IF TG_TABLE_NAME='workspace_pin' AND t.kind NOT IN ('customers','clusters','assets') THEN RAISE EXCEPTION 'unsupported pin target' USING ERRCODE='23514'; END IF;
 IF TG_TABLE_NAME='external_link' AND t.kind NOT IN ('customers','environments','clusters') THEN RAISE EXCEPTION 'unsupported link scope' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER pin_active BEFORE INSERT OR UPDATE ON workspace_pin FOR EACH ROW EXECUTE FUNCTION workspace_active_target();
CREATE TRIGGER note_active BEFORE INSERT OR UPDATE ON operator_note FOR EACH ROW EXECUTE FUNCTION workspace_active_target();
CREATE TRIGGER link_active BEFORE INSERT OR UPDATE ON external_link FOR EACH ROW EXECUTE FUNCTION workspace_active_target();
CREATE INDEX membership_workspace_search ON cluster_membership USING gin(to_tsvector('simple',role));
