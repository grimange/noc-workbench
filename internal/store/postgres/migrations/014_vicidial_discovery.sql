-- On-demand server installation discovery reuses immutable observation history.
-- No schedule, inventory relationship or remote authority is created here.
ALTER TABLE collection_run DROP CONSTRAINT collection_run_collectors;
ALTER TABLE collection_run ADD CONSTRAINT collection_run_collectors CHECK (
 (source_id IS NULL AND cardinality(collector_ids) BETWEEN 1 AND 9 AND collector_ids <@ ARRAY['linux.identity','linux.uptime','linux.load','linux.memory','linux.filesystems','asterisk.identity','asterisk.channels','asterisk.modules','asterisk.pjsip','vicidial.discovery']::text[]) OR
 (source_id IS NOT NULL AND cardinality(collector_ids) BETWEEN 1 AND 3 AND collector_ids <@ ARRAY['vicidial.api.version','vicidial.api.campaigns','vicidial.api.agents']::text[]));
ALTER TABLE collector_result DROP CONSTRAINT collector_result_collector_id_check;
ALTER TABLE collector_result ADD CHECK(collector_id IN ('linux.identity','linux.uptime','linux.load','linux.memory','linux.filesystems','asterisk.identity','asterisk.channels','asterisk.modules','asterisk.pjsip','vicidial.api.version','vicidial.api.campaigns','vicidial.api.agents','vicidial.discovery'));
ALTER TABLE observation DROP CONSTRAINT observation_subject;
ALTER TABLE observation ADD CONSTRAINT observation_subject CHECK (
 (subject_type='asset' AND source_id IS NULL AND source_revision IS NULL AND asset_id IS NOT NULL AND endpoint_id IS NOT NULL AND profile_id IS NOT NULL AND profile_revision IS NOT NULL AND transport='ssh' AND (key ~ '^(linux|asterisk)\.[a-z0-9_.]{1,100}$' OR key='vicidial.discovery.snapshot')) OR
 (subject_type='cluster' AND source_id IS NOT NULL AND source_revision IS NOT NULL AND asset_id IS NULL AND endpoint_id IS NULL AND profile_id IS NULL AND profile_revision IS NULL AND transport IN ('https','http_fixture') AND key ~ '^vicidial\.[a-z0-9_.]{1,100}$'));
DO $$ DECLARE previous text; BEGIN
 SELECT pg_get_constraintdef(oid) INTO previous FROM pg_constraint WHERE conrelid='observation'::regclass AND conname='observation_collector_contract';
 ALTER TABLE observation DROP CONSTRAINT observation_collector_contract;
 EXECUTE 'ALTER TABLE observation ADD CONSTRAINT observation_collector_contract CHECK ('||substr(previous,8,length(previous)-8)||' OR (source_id IS NULL AND collector_id=''vicidial.discovery'' AND key=''vicidial.discovery.snapshot'' AND resource='''' AND kind=''text'' AND unit=''text''))';
END $$;
DO $$ DECLARE c record; BEGIN
 FOR c IN SELECT conname,pg_get_constraintdef(oid) AS def FROM pg_constraint WHERE conrelid='evaluation_policy'::regclass AND contype='c' LOOP
  IF c.def LIKE '%linux.identity%' THEN
   EXECUTE format('ALTER TABLE evaluation_policy DROP CONSTRAINT %I',c.conname);
   IF c.def LIKE '%asset_id IS NULL%' THEN
    EXECUTE 'ALTER TABLE evaluation_policy ADD CHECK ('||substr(c.def,8,length(c.def)-8)||' OR (asset_id IS NULL AND customer_id IS NULL AND environment_id IS NULL AND revision=1 AND rule=''none'' AND selector=''vicidial.discovery''))';
   ELSE
    EXECUTE 'ALTER TABLE evaluation_policy ADD CHECK ('||substr(c.def,8,length(c.def)-8)||' OR selector IN (''vicidial.discovery'',''vicidial.discovery.snapshot''))';
   END IF;
  END IF;
 END LOOP;
END $$;
INSERT INTO evaluation_policy(selector,version,ttl_seconds,rule,actor)
 SELECT 'vicidial.discovery','linux-evidence.v1',86400,'none',id FROM workspace_principal WHERE designation='local-operator';
