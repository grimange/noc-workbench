-- Explicit optional-adapter opt-in. No existing asset or schedule is enabled.
CREATE TABLE collection_integration (
 profile_id uuid NOT NULL, customer_id uuid NOT NULL, environment_id uuid NOT NULL,
 asset_id uuid NOT NULL, endpoint_id uuid NOT NULL,
 integration text NOT NULL CHECK(integration ~ '^[a-z][a-z0-9_]{0,31}$'),
 profile_revision bigint NOT NULL CHECK(profile_revision>0),
 enabled boolean NOT NULL DEFAULT false,
 revision bigint NOT NULL DEFAULT 1 CHECK(revision>0),
 actor uuid NOT NULL REFERENCES workspace_principal(id),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(profile_id,integration),
 FOREIGN KEY(profile_id,customer_id,environment_id,asset_id,endpoint_id) REFERENCES connection_profile(id,customer_id,environment_id,asset_id,endpoint_id)
);
ALTER TABLE collection_run DROP CONSTRAINT collection_run_success_count_check, DROP CONSTRAINT collection_run_failure_count_check, DROP CONSTRAINT collection_run_collectors;
ALTER TABLE collection_run ADD CHECK(success_count BETWEEN 0 AND 9), ADD CHECK(failure_count BETWEEN 0 AND 9),
 ADD CONSTRAINT collection_run_collectors CHECK(cardinality(collector_ids) BETWEEN 1 AND 9 AND collector_ids <@ ARRAY['linux.identity','linux.uptime','linux.load','linux.memory','linux.filesystems','asterisk.identity','asterisk.channels','asterisk.modules','asterisk.pjsip']::text[]);
ALTER TABLE collection_schedule DROP CONSTRAINT collection_schedule_collector_ids_check;
ALTER TABLE collection_schedule ADD CHECK(cardinality(collector_ids) BETWEEN 1 AND 9 AND collector_ids <@ ARRAY['linux.identity','linux.uptime','linux.load','linux.memory','linux.filesystems','asterisk.identity','asterisk.channels','asterisk.modules','asterisk.pjsip']::text[]);
ALTER TABLE collector_result DROP CONSTRAINT collector_result_collector_id_check;
ALTER TABLE collector_result ADD CHECK(collector_id IN ('linux.identity','linux.uptime','linux.load','linux.memory','linux.filesystems','asterisk.identity','asterisk.channels','asterisk.modules','asterisk.pjsip'));
ALTER TABLE observation DROP CONSTRAINT observation_key_check;
ALTER TABLE observation ADD CHECK(key ~ '^(linux|asterisk)\.[a-z0-9_.]{1,100}$');
-- Preserve all accepted Linux key/type/unit/resource restrictions.
DO $$ DECLARE c record; BEGIN
 FOR c IN SELECT conname,pg_get_constraintdef(oid) AS def FROM pg_constraint WHERE conrelid='observation'::regclass AND contype='c' LOOP
  IF c.def LIKE '%linux.identity%' THEN
   EXECUTE format('ALTER TABLE observation DROP CONSTRAINT %I',c.conname);
   EXECUTE 'ALTER TABLE observation ADD CONSTRAINT observation_collector_contract CHECK ('||substr(c.def,8,length(c.def)-8)||' OR (resource='''' AND ((collector_id=''asterisk.identity'' AND ((key=''asterisk.version'' AND kind=''text'' AND unit=''text'') OR (key=''asterisk.cli.available'' AND kind=''integer'' AND unit=''count'' AND integer_value=1))) OR (collector_id=''asterisk.channels'' AND key=''asterisk.channels.active'' AND kind=''integer'' AND unit=''count'') OR (collector_id=''asterisk.modules'' AND key IN (''asterisk.modules.pjsip.available'',''asterisk.modules.chan_pjsip.available'') AND kind=''integer'' AND unit=''count'' AND integer_value IN (0,1)) OR (collector_id=''asterisk.pjsip'' AND key=''asterisk.pjsip.registrations.count'' AND kind=''integer'' AND unit=''count'' AND integer_value<=4096))))';
  END IF;
 END LOOP;
END $$;
-- Extend the accepted policy vocabulary; health rules remain explicit Linux rules.
DO $$ DECLARE c record; BEGIN
 FOR c IN SELECT conname,pg_get_constraintdef(oid) AS def FROM pg_constraint WHERE conrelid='evaluation_policy'::regclass AND contype='c' LOOP
  IF c.def LIKE '%linux.identity%' THEN
   EXECUTE format('ALTER TABLE evaluation_policy DROP CONSTRAINT %I',c.conname);
   IF c.def LIKE '%asset_id IS NULL%' THEN
    EXECUTE 'ALTER TABLE evaluation_policy ADD CHECK ((asset_id IS NULL AND customer_id IS NULL AND environment_id IS NULL AND revision=1 AND rule=''none'' AND selector IN (''linux.identity'',''linux.uptime'',''linux.load'',''linux.memory'',''linux.filesystems'',''asterisk.identity'',''asterisk.channels'',''asterisk.modules'',''asterisk.pjsip'')) OR (asset_id IS NOT NULL AND customer_id IS NOT NULL AND environment_id IS NOT NULL))';
   ELSE
    EXECUTE 'ALTER TABLE evaluation_policy ADD CHECK ('||substr(c.def,8,length(c.def)-8)||' OR selector IN (''asterisk.identity'',''asterisk.channels'',''asterisk.modules'',''asterisk.pjsip'',''asterisk.version'',''asterisk.cli.available'',''asterisk.channels.active'',''asterisk.modules.pjsip.available'',''asterisk.modules.chan_pjsip.available'',''asterisk.pjsip.registrations.count''))';
   END IF;
  END IF;
 END LOOP;
END $$;
INSERT INTO evaluation_policy(selector,version,ttl_seconds,rule,actor)
 SELECT s,'linux-evidence.v1',CASE WHEN s IN ('asterisk.identity','asterisk.modules') THEN 86400 ELSE 180 END,'none',id
 FROM workspace_principal CROSS JOIN unnest(ARRAY['asterisk.identity','asterisk.channels','asterisk.modules','asterisk.pjsip']) s WHERE designation='local-operator';
