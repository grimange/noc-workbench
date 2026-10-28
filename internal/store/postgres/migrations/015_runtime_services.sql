-- Runtime evidence extends the accepted observation/scheduler framework. No
-- inventory, enrollment, schedule, or remote authorization is created here.
DO $$ DECLARE c record; d text; BEGIN
 FOR c IN SELECT conrelid::regclass AS tbl,conname,pg_get_constraintdef(oid) AS def FROM pg_constraint
 WHERE conrelid IN ('collection_run'::regclass,'collector_result'::regclass,'collection_schedule'::regclass) AND contype='c' LOOP
  d:=c.def;
  IF d LIKE '%linux.identity%' THEN d:=replace(d,'''linux.identity''::text','''linux.services''::text, ''linux.identity''::text'); END IF;
  IF c.tbl IN ('collection_run'::regclass,'collection_schedule'::regclass) THEN d:=replace(d,'<= 9','<= 10'); END IF;
  IF d<>c.def THEN EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I',c.tbl,c.conname); EXECUTE format('ALTER TABLE %s ADD CONSTRAINT %I %s',c.tbl,c.conname,d); END IF;
 END LOOP;
 SELECT pg_get_constraintdef(oid) INTO d FROM pg_constraint WHERE conrelid='observation'::regclass AND conname='observation_collector_contract';
 ALTER TABLE observation DROP CONSTRAINT observation_collector_contract;
 EXECUTE 'ALTER TABLE observation ADD CONSTRAINT observation_collector_contract CHECK ('||substr(d,8,length(d)-8)||' OR (source_id IS NULL AND collector_id=''linux.services'' AND key=''linux.service.runtime'' AND resource IN (''asterisk'',''database'',''apache'',''AST_update.pl'',''AST_VDauto_dial.pl'',''AST_VDauto_dial_FILL.pl'',''AST_manager_send.pl'',''AST_manager_listen.pl'') AND kind=''text'' AND unit=''text''))';
 FOR c IN SELECT conname,pg_get_constraintdef(oid) AS def FROM pg_constraint WHERE conrelid='evaluation_policy'::regclass AND contype='c' LOOP
  IF c.def LIKE '%linux.identity%' THEN
   EXECUTE format('ALTER TABLE evaluation_policy DROP CONSTRAINT %I',c.conname);
   IF c.def LIKE '%asset_id IS NULL%' THEN
    EXECUTE 'ALTER TABLE evaluation_policy ADD CHECK ('||substr(c.def,8,length(c.def)-8)||' OR (asset_id IS NULL AND customer_id IS NULL AND environment_id IS NULL AND revision=1 AND rule=''none'' AND selector=''linux.services''))';
   ELSE
    EXECUTE 'ALTER TABLE evaluation_policy ADD CHECK ('||substr(c.def,8,length(c.def)-8)||' OR selector IN (''linux.services'',''linux.service.runtime''))';
   END IF;
  END IF;
 END LOOP;
END $$;
INSERT INTO evaluation_policy(selector,version,ttl_seconds,rule,actor)
 SELECT 'linux.services','linux-evidence.v1',180,'none',id FROM workspace_principal WHERE designation='local-operator';
