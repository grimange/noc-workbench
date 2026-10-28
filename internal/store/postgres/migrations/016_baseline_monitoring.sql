-- Reviewed baseline capability is opt-in per enrollment revision. This migration
-- grants no remote authority and creates no schedules for existing enrollments.
DO $$ DECLARE c record; d text; BEGIN
 FOR c IN SELECT conrelid::regclass AS tbl,conname,pg_get_constraintdef(oid) AS def FROM pg_constraint WHERE conrelid IN ('collection_run'::regclass,'collector_result'::regclass,'collection_schedule'::regclass) AND contype='c' LOOP
  d:=c.def;
  IF d LIKE '%linux.identity%' THEN d:=replace(d,'''linux.identity''::text','''linux.baseline''::text, ''linux.identity''::text'); END IF;
  IF d<>c.def THEN EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I',c.tbl,c.conname);EXECUTE format('ALTER TABLE %s ADD CONSTRAINT %I %s',c.tbl,c.conname,d); END IF;
 END LOOP;
 SELECT pg_get_constraintdef(oid) INTO d FROM pg_constraint WHERE conrelid='observation'::regclass AND conname='observation_collector_contract';
 ALTER TABLE observation DROP CONSTRAINT observation_collector_contract;
 EXECUTE 'ALTER TABLE observation ADD CONSTRAINT observation_collector_contract CHECK ('||substr(d,8,length(d)-8)||' OR (source_id IS NULL AND collector_id=''linux.baseline'' AND ((resource='''' AND ((key IN (''linux.baseline.cpu_percent'',''linux.baseline.pressure_some_percent'') AND kind=''number'' AND unit=''percent'' AND number_value BETWEEN 0 AND 100) OR (key IN (''linux.baseline.swap_total_bytes'',''linux.baseline.swap_free_bytes'') AND kind=''integer'' AND unit=''bytes'') OR (key IN (''linux.baseline.processes'',''linux.baseline.status'') AND kind=''text'' AND unit=''text''))) OR (key IN (''linux.baseline.units'',''linux.baseline.jobs'') AND resource ~ ''^[0-9]{2}$'' AND kind=''text'' AND unit=''text''))))';
 FOR c IN SELECT conname,pg_get_constraintdef(oid) AS def FROM pg_constraint WHERE conrelid='evaluation_policy'::regclass AND contype='c' LOOP
  IF c.def LIKE '%linux.identity%' THEN
   EXECUTE format('ALTER TABLE evaluation_policy DROP CONSTRAINT %I',c.conname);
   IF c.def LIKE '%asset_id IS NULL%' THEN
    EXECUTE 'ALTER TABLE evaluation_policy ADD CHECK ('||substr(c.def,8,length(c.def)-8)||' OR (asset_id IS NULL AND customer_id IS NULL AND environment_id IS NULL AND revision=1 AND rule=''none'' AND selector=''linux.baseline''))';
   ELSE
    EXECUTE 'ALTER TABLE evaluation_policy ADD CHECK ('||substr(c.def,8,length(c.def)-8)||' OR selector IN (''linux.baseline'',''linux.baseline.cpu_percent'',''linux.baseline.pressure_some_percent'',''linux.baseline.swap_total_bytes'',''linux.baseline.swap_free_bytes'',''linux.baseline.processes'',''linux.baseline.units'',''linux.baseline.jobs'',''linux.baseline.status''))';
   END IF;
  END IF;
 END LOOP;
END $$;
INSERT INTO evaluation_policy(selector,version,ttl_seconds,rule,actor) SELECT 'linux.baseline','linux-evidence.v1',180,'none',id FROM workspace_principal WHERE designation='local-operator';
ALTER TABLE connection_audit DROP CONSTRAINT connection_audit_operation_check;
ALTER TABLE connection_audit ADD CHECK(operation IN ('create','submit','authorize','inspect','approve','verify','disable','reject','review','baseline'));
