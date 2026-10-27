-- Optional cluster collection authorities. No endpoint secrets or automatic opt-in.
CREATE TABLE collection_source (
 id uuid NOT NULL DEFAULT gen_random_uuid(), revision bigint NOT NULL CHECK(revision BETWEEN 1 AND 4096),
 customer_id uuid NOT NULL, environment_id uuid NOT NULL, cluster_id uuid NOT NULL,
 adapter_id text NOT NULL CHECK(adapter_id ~ '^[a-z][a-z0-9_.]{1,63}$'),
 credential_reference text NOT NULL CHECK(credential_reference ~ '^[A-Za-z0-9_-]{1,64}$'),
 enabled boolean NOT NULL DEFAULT false,
 actor uuid NOT NULL REFERENCES workspace_principal(id),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(id,revision), UNIQUE(cluster_id,adapter_id,revision),
 UNIQUE(id,revision,customer_id,environment_id,cluster_id),
 FOREIGN KEY(environment_id,customer_id) REFERENCES environment(id,customer_id),
 FOREIGN KEY(cluster_id,environment_id) REFERENCES cluster(id,environment_id)
);
CREATE FUNCTION collection_source_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE previous collection_source%ROWTYPE; c text; e text; cl text;
BEGIN
 IF TG_OP='UPDATE' THEN RAISE EXCEPTION 'immutable source revision' USING ERRCODE='23514'; END IF;
 SELECT status INTO c FROM customer WHERE id=NEW.customer_id FOR SHARE;
 SELECT status INTO e FROM environment WHERE id=NEW.environment_id AND customer_id=NEW.customer_id FOR SHARE;
 SELECT lifecycle INTO cl FROM cluster WHERE id=NEW.cluster_id AND environment_id=NEW.environment_id FOR UPDATE;
 IF c IS NULL OR e IS NULL OR cl IS NULL OR (NEW.enabled AND (c<>'active' OR e<>'active' OR cl<>'active')) THEN RAISE EXCEPTION 'ineligible source owner' USING ERRCODE='23514'; END IF;
 SELECT * INTO previous FROM collection_source WHERE cluster_id=NEW.cluster_id AND adapter_id=NEW.adapter_id ORDER BY revision DESC LIMIT 1;
 IF FOUND THEN
  IF NEW.id<>previous.id OR NEW.revision<>previous.revision+1 OR NEW.customer_id<>previous.customer_id OR NEW.environment_id<>previous.environment_id THEN RAISE EXCEPTION 'source revision conflict' USING ERRCODE='23514'; END IF;
 ELSE
  IF NEW.revision<>1 OR EXISTS(SELECT 1 FROM collection_source WHERE id=NEW.id) THEN RAISE EXCEPTION 'source identity conflict' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER collection_source_guard BEFORE INSERT OR UPDATE ON collection_source FOR EACH ROW EXECUTE FUNCTION collection_source_guard();

ALTER TABLE collection_run ADD COLUMN source_id uuid, ADD COLUMN source_revision bigint, ADD COLUMN cluster_id uuid;
ALTER TABLE collection_run ALTER COLUMN asset_id DROP NOT NULL, ALTER COLUMN endpoint_id DROP NOT NULL, ALTER COLUMN profile_id DROP NOT NULL, ALTER COLUMN profile_revision DROP NOT NULL, ALTER COLUMN endpoint_revision DROP NOT NULL;
ALTER TABLE collection_run ADD FOREIGN KEY(source_id,source_revision,customer_id,environment_id,cluster_id) REFERENCES collection_source(id,revision,customer_id,environment_id,cluster_id),
 ADD UNIQUE(id,source_id,source_revision),
 ADD CONSTRAINT collection_run_subject CHECK (
 (source_id IS NULL AND source_revision IS NULL AND cluster_id IS NULL AND asset_id IS NOT NULL AND endpoint_id IS NOT NULL AND profile_id IS NOT NULL AND profile_revision IS NOT NULL AND endpoint_revision IS NOT NULL) OR
 (source_id IS NOT NULL AND source_revision IS NOT NULL AND cluster_id IS NOT NULL AND asset_id IS NULL AND endpoint_id IS NULL AND profile_id IS NULL AND profile_revision IS NULL AND endpoint_revision IS NULL));
CREATE INDEX collection_run_source_time ON collection_run(source_id,started_at DESC,id DESC) WHERE source_id IS NOT NULL;
ALTER TABLE collection_run DROP CONSTRAINT collection_run_collectors;
ALTER TABLE collection_run ADD CONSTRAINT collection_run_collectors CHECK (
 (source_id IS NULL AND cardinality(collector_ids) BETWEEN 1 AND 9 AND collector_ids <@ ARRAY['linux.identity','linux.uptime','linux.load','linux.memory','linux.filesystems','asterisk.identity','asterisk.channels','asterisk.modules','asterisk.pjsip']::text[]) OR
 (source_id IS NOT NULL AND cardinality(collector_ids) BETWEEN 1 AND 3 AND collector_ids <@ ARRAY['vicidial.api.version','vicidial.api.campaigns','vicidial.api.agents']::text[]));
ALTER TABLE collector_result DROP CONSTRAINT collector_result_collector_id_check;
ALTER TABLE collector_result ADD CHECK(collector_id IN ('linux.identity','linux.uptime','linux.load','linux.memory','linux.filesystems','asterisk.identity','asterisk.channels','asterisk.modules','asterisk.pjsip','vicidial.api.version','vicidial.api.campaigns','vicidial.api.agents'));

ALTER TABLE observation ADD COLUMN source_id uuid, ADD COLUMN source_revision bigint;
ALTER TABLE observation ALTER COLUMN asset_id DROP NOT NULL, ALTER COLUMN endpoint_id DROP NOT NULL, ALTER COLUMN profile_id DROP NOT NULL, ALTER COLUMN profile_revision DROP NOT NULL;
ALTER TABLE observation ADD FOREIGN KEY(run_id,source_id,source_revision) REFERENCES collection_run(id,source_id,source_revision) ON DELETE CASCADE;
ALTER TABLE observation DROP CONSTRAINT observation_subject_type_check, DROP CONSTRAINT observation_transport_check, DROP CONSTRAINT observation_key_check;
ALTER TABLE observation ADD CONSTRAINT observation_subject CHECK (
 (subject_type='asset' AND source_id IS NULL AND source_revision IS NULL AND asset_id IS NOT NULL AND endpoint_id IS NOT NULL AND profile_id IS NOT NULL AND profile_revision IS NOT NULL AND transport='ssh' AND key ~ '^(linux|asterisk)\.[a-z0-9_.]{1,100}$') OR
 (subject_type='cluster' AND source_id IS NOT NULL AND source_revision IS NOT NULL AND asset_id IS NULL AND endpoint_id IS NULL AND profile_id IS NULL AND profile_revision IS NULL AND transport IN ('https','http_fixture') AND key ~ '^vicidial\.[a-z0-9_.]{1,100}$'));
DO $$ DECLARE previous text; BEGIN
 SELECT pg_get_constraintdef(oid) INTO previous FROM pg_constraint WHERE conrelid='observation'::regclass AND conname='observation_collector_contract';
 ALTER TABLE observation DROP CONSTRAINT observation_collector_contract;
 EXECUTE 'ALTER TABLE observation ADD CONSTRAINT observation_collector_contract CHECK ((source_id IS NULL AND '||substr(previous,8,length(previous)-8)||') OR (source_id IS NOT NULL AND resource='''' AND ((collector_id=''vicidial.api.version'' AND key IN (''vicidial.api.version'',''vicidial.api.build'') AND kind=''text'' AND unit=''text'') OR (collector_id=''vicidial.api.campaigns'' AND key IN (''vicidial.campaigns.configured_count'',''vicidial.campaigns.active_count'') AND kind=''integer'' AND unit=''count'' AND integer_value IN (0,1)) OR (collector_id=''vicidial.api.agents'' AND key IN (''vicidial.agents.visible_logged_in_count'',''vicidial.agents.visible_in_call_count'',''vicidial.agents.visible_paused_count'') AND kind=''integer'' AND unit=''count'' AND integer_value<=1000))))';
END $$;
CREATE INDEX observation_source_latest ON observation(source_id,key,observed_at DESC,id DESC) WHERE source_id IS NOT NULL;

ALTER TABLE collection_schedule ADD COLUMN source_id uuid UNIQUE, ADD COLUMN source_revision bigint, ADD COLUMN cluster_id uuid;
ALTER TABLE collection_schedule ALTER COLUMN asset_id DROP NOT NULL, ALTER COLUMN endpoint_id DROP NOT NULL, ALTER COLUMN profile_id DROP NOT NULL, ALTER COLUMN profile_revision DROP NOT NULL, ALTER COLUMN endpoint_revision DROP NOT NULL;
ALTER TABLE collection_schedule ADD FOREIGN KEY(source_id,source_revision,customer_id,environment_id,cluster_id) REFERENCES collection_source(id,revision,customer_id,environment_id,cluster_id),
 ADD UNIQUE(id,source_id),
 ADD CONSTRAINT collection_schedule_subject CHECK(
 (source_id IS NULL AND source_revision IS NULL AND cluster_id IS NULL AND asset_id IS NOT NULL AND endpoint_id IS NOT NULL AND profile_id IS NOT NULL AND profile_revision IS NOT NULL AND endpoint_revision IS NOT NULL) OR
 (source_id IS NOT NULL AND source_revision IS NOT NULL AND cluster_id IS NOT NULL AND asset_id IS NULL AND endpoint_id IS NULL AND profile_id IS NULL AND profile_revision IS NULL AND endpoint_revision IS NULL));
ALTER TABLE collection_schedule DROP CONSTRAINT collection_schedule_collector_ids_check;
ALTER TABLE collection_schedule ADD CHECK(
 (source_id IS NULL AND cardinality(collector_ids) BETWEEN 1 AND 9 AND collector_ids <@ ARRAY['linux.identity','linux.uptime','linux.load','linux.memory','linux.filesystems','asterisk.identity','asterisk.channels','asterisk.modules','asterisk.pjsip']::text[]) OR
 (source_id IS NOT NULL AND collector_ids=ARRAY['vicidial.api.version','vicidial.api.campaigns','vicidial.api.agents']::text[]));
ALTER TABLE collection_run ADD FOREIGN KEY(schedule_id,source_id) REFERENCES collection_schedule(id,source_id);
CREATE FUNCTION source_schedule_owner_guard() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF TG_OP='UPDATE' AND (NEW.source_id,NEW.cluster_id) IS DISTINCT FROM (OLD.source_id,OLD.cluster_id) THEN RAISE EXCEPTION 'immutable source schedule owner' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER source_schedule_owner_guard BEFORE UPDATE ON collection_schedule FOR EACH ROW EXECUTE FUNCTION source_schedule_owner_guard();

-- Reuse canonical versioned evaluation policies, with no operational-health rules.
DO $$ DECLARE c record; BEGIN
 FOR c IN SELECT conname,pg_get_constraintdef(oid) AS def FROM pg_constraint WHERE conrelid='evaluation_policy'::regclass AND contype='c' LOOP
  IF c.def LIKE '%linux.identity%' THEN
   EXECUTE format('ALTER TABLE evaluation_policy DROP CONSTRAINT %I',c.conname);
   IF c.def LIKE '%asset_id IS NULL%' THEN
    EXECUTE 'ALTER TABLE evaluation_policy ADD CHECK ('||substr(c.def,8,length(c.def)-8)||' OR (asset_id IS NULL AND customer_id IS NULL AND environment_id IS NULL AND revision=1 AND rule=''none'' AND selector IN (''vicidial.api.version'',''vicidial.api.campaigns'',''vicidial.api.agents'')))';
   ELSE
    EXECUTE 'ALTER TABLE evaluation_policy ADD CHECK ('||substr(c.def,8,length(c.def)-8)||' OR selector IN (''vicidial.api.version'',''vicidial.api.campaigns'',''vicidial.api.agents'',''vicidial.api.build'',''vicidial.campaigns.configured_count'',''vicidial.campaigns.active_count'',''vicidial.agents.visible_logged_in_count'',''vicidial.agents.visible_in_call_count'',''vicidial.agents.visible_paused_count''))';
   END IF;
  END IF;
 END LOOP;
END $$;
INSERT INTO evaluation_policy(selector,version,ttl_seconds,rule,actor)
 SELECT s,'linux-evidence.v1',CASE WHEN s='vicidial.api.version' THEN 86400 ELSE 180 END,'none',id
 FROM workspace_principal CROSS JOIN unnest(ARRAY['vicidial.api.version','vicidial.api.campaigns','vicidial.api.agents']) s WHERE designation='local-operator';
