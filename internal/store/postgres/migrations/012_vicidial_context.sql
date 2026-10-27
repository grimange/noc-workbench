ALTER TABLE external_link ADD COLUMN enabled boolean NOT NULL DEFAULT true;

-- Optional V1 installation context. Canonical topology, links and observations
-- remain authoritative. Immutable revisions preserve metadata provenance.
CREATE TABLE vicidial_integration (
 id uuid NOT NULL DEFAULT gen_random_uuid(),
 revision bigint NOT NULL DEFAULT 1 CHECK(revision BETWEEN 1 AND 4096),
 customer_id uuid NOT NULL, environment_id uuid NOT NULL, cluster_id uuid NOT NULL,
 name text NOT NULL CHECK(octet_length(name) BETWEEN 1 AND 120 AND name=btrim(name) AND name !~ '[[:cntrl:]]'),
 enabled boolean NOT NULL DEFAULT false,
 version text NOT NULL DEFAULT '' CHECK(octet_length(version)<=120 AND version=btrim(version) AND version !~ '[[:cntrl:]]'),
 revision_source text NOT NULL DEFAULT '' CHECK(octet_length(revision_source)<=256 AND revision_source=btrim(revision_source) AND revision_source !~ '[[:cntrl:]]'),
 verified_at timestamptz,
 notes text NOT NULL DEFAULT '' CHECK(octet_length(notes)<=2048 AND notes=btrim(notes) AND notes !~ '[[:cntrl:]]'),
 actor uuid NOT NULL REFERENCES workspace_principal(id),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(id,revision), UNIQUE(cluster_id,revision),
 FOREIGN KEY(environment_id,customer_id) REFERENCES environment(id,customer_id) ON DELETE RESTRICT,
 FOREIGN KEY(cluster_id,environment_id) REFERENCES cluster(id,environment_id) ON DELETE RESTRICT,
 CHECK((version='' AND revision_source='' AND verified_at IS NULL) OR (version<>'' AND revision_source<>'')),
 CHECK(verified_at IS NULL OR (verified_at>='1970-01-01 UTC' AND verified_at<=updated_at)),
 CHECK(created_at<=updated_at)
);
CREATE INDEX vicidial_integration_scope ON vicidial_integration(customer_id,environment_id,cluster_id,revision DESC);
CREATE FUNCTION vicidial_context_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE c_status text; e_status text; cl_status text; previous vicidial_integration%ROWTYPE;
BEGIN
 NEW.updated_at:=clock_timestamp();
 IF TG_OP='UPDATE' THEN RAISE EXCEPTION 'immutable integration revision' USING ERRCODE='23514',CONSTRAINT='vicidial_immutable'; END IF;
 -- Shared ownership locks serialize registration against parent archival. The
 -- cluster lock also serializes revision creation from concurrent transactions.
 SELECT status INTO c_status FROM customer WHERE id=NEW.customer_id FOR SHARE;
 SELECT status INTO e_status FROM environment WHERE id=NEW.environment_id AND customer_id=NEW.customer_id FOR SHARE;
 SELECT lifecycle INTO cl_status FROM cluster WHERE id=NEW.cluster_id AND environment_id=NEW.environment_id FOR UPDATE;
 IF c_status IS NULL OR e_status IS NULL OR cl_status IS NULL THEN RAISE EXCEPTION 'invalid integration scope' USING ERRCODE='23503',CONSTRAINT='vicidial_scope'; END IF;
 IF NEW.enabled AND (c_status<>'active' OR e_status<>'active' OR cl_status<>'active') THEN RAISE EXCEPTION 'inactive integration owner' USING ERRCODE='23514',CONSTRAINT='topology_active'; END IF;
 SELECT * INTO previous FROM vicidial_integration WHERE cluster_id=NEW.cluster_id ORDER BY revision DESC LIMIT 1;
 IF FOUND THEN
  IF NEW.id<>previous.id OR NEW.customer_id<>previous.customer_id OR NEW.environment_id<>previous.environment_id OR NEW.revision<>previous.revision+1 OR NEW.created_at<>previous.created_at OR NEW.updated_at<previous.updated_at THEN
   RAISE EXCEPTION 'invalid integration revision chain' USING ERRCODE='23514',CONSTRAINT='vicidial_revision';
  END IF;
 ELSE
  IF NEW.revision<>1 OR EXISTS(SELECT 1 FROM vicidial_integration WHERE id=NEW.id) THEN
   RAISE EXCEPTION 'invalid integration identity' USING ERRCODE='23514',CONSTRAINT='vicidial_revision';
  END IF;
  NEW.created_at:=NEW.updated_at;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER vicidial_context_guard BEFORE INSERT OR UPDATE ON vicidial_integration FOR EACH ROW EXECUTE FUNCTION vicidial_context_guard();
