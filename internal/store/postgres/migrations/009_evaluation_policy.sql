-- Immutable policy revisions; existing observations and TTL envelopes are unchanged.
CREATE TABLE evaluation_policy (
 id uuid NOT NULL DEFAULT gen_random_uuid(), revision bigint NOT NULL DEFAULT 1 CHECK(revision>0),
 customer_id uuid, environment_id uuid, asset_id uuid,
 selector text NOT NULL CHECK(selector IN ('linux.identity','linux.uptime','linux.load','linux.memory','linux.filesystems','linux.hostname','linux.os.name','linux.os.version','linux.kernel.release','linux.architecture','linux.uptime.seconds','linux.load.1m','linux.load.5m','linux.load.15m','linux.cpu.logical_count','linux.mem.total_bytes','linux.mem.available_bytes','linux.mem.free_bytes','linux.filesystem.identifier','linux.filesystem.total_bytes','linux.filesystem.used_bytes','linux.filesystem.available_bytes','linux.filesystem.utilization_percent')),
 version text NOT NULL CHECK(version='linux-evidence.v1'),
 ttl_seconds int NOT NULL CHECK(ttl_seconds BETWEEN 1 AND 604800),
 rule text NOT NULL CHECK(rule IN ('none','filesystem_used_high','memory_available_low')),
 threshold double precision NOT NULL DEFAULT 0,
 enabled boolean NOT NULL DEFAULT true,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 actor uuid NOT NULL REFERENCES workspace_principal(id),
 PRIMARY KEY(id,revision),
 FOREIGN KEY(environment_id,customer_id) REFERENCES environment(id,customer_id) ON DELETE CASCADE,
 FOREIGN KEY(asset_id,environment_id) REFERENCES asset(id,environment_id) ON DELETE CASCADE,
 CHECK((asset_id IS NULL AND customer_id IS NULL AND environment_id IS NULL AND revision=1 AND rule='none' AND selector IN ('linux.identity','linux.uptime','linux.load','linux.memory','linux.filesystems')) OR (asset_id IS NOT NULL AND customer_id IS NOT NULL AND environment_id IS NOT NULL)),
 CHECK((rule='none' AND threshold=0) OR (rule='filesystem_used_high' AND selector='linux.filesystem.utilization_percent' AND threshold BETWEEN 0 AND 100) OR (rule='memory_available_low' AND selector='linux.mem.available_bytes' AND threshold BETWEEN 0 AND 9007199254740992 AND threshold=trunc(threshold)))
);
CREATE UNIQUE INDEX evaluation_policy_scope_revision ON evaluation_policy(asset_id,selector,revision) NULLS NOT DISTINCT;
CREATE INDEX evaluation_policy_asof ON evaluation_policy(asset_id,selector,created_at DESC,revision DESC);
CREATE FUNCTION evaluation_policy_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'evaluation policy revisions are immutable'; END; $$;
CREATE TRIGGER evaluation_policy_no_update BEFORE UPDATE ON evaluation_policy FOR EACH ROW EXECUTE FUNCTION evaluation_policy_immutable();
INSERT INTO evaluation_policy(selector,version,ttl_seconds,rule,actor)
 SELECT s,'linux-evidence.v1',CASE WHEN s='linux.identity' THEN 86400 ELSE 180 END,'none',id
 FROM workspace_principal CROSS JOIN unnest(ARRAY['linux.identity','linux.uptime','linux.load','linux.memory','linux.filesystems']) s
 WHERE designation='local-operator';
-- Record when evidence becomes available to the store, independently of the
-- measurement clock. Existing rows conservatively become available at upgrade.
ALTER TABLE observation ADD COLUMN recorded_at timestamptz NOT NULL DEFAULT clock_timestamp();
ALTER TABLE collection_run ADD COLUMN evidence_recorded_at timestamptz NOT NULL DEFAULT clock_timestamp();
CREATE FUNCTION collection_evidence_recorded() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN NEW.evidence_recorded_at=clock_timestamp(); RETURN NEW; END; $$;
CREATE TRIGGER collection_evidence_recorded BEFORE UPDATE OF state ON collection_run FOR EACH ROW EXECUTE FUNCTION collection_evidence_recorded();
CREATE FUNCTION evaluation_policy_chain() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.revision>1 AND NOT EXISTS(SELECT 1 FROM evaluation_policy p WHERE p.id=NEW.id AND p.revision=NEW.revision-1 AND p.asset_id=NEW.asset_id AND p.customer_id=NEW.customer_id AND p.environment_id=NEW.environment_id AND p.selector=NEW.selector AND p.version=NEW.version AND p.created_at<=NEW.created_at) THEN RAISE EXCEPTION 'invalid policy revision chain'; END IF;
 IF NEW.revision=1 AND EXISTS(SELECT 1 FROM evaluation_policy p WHERE p.id=NEW.id) THEN RAISE EXCEPTION 'policy identity already exists'; END IF;
 RETURN NEW;
END; $$;
CREATE TRIGGER evaluation_policy_chain BEFORE INSERT ON evaluation_policy FOR EACH ROW EXECUTE FUNCTION evaluation_policy_chain();
