-- Add an optional, explicitly authorized snapshot collector. Existing authority,
-- profiles, pauses and evidence are unchanged.
DO $$ DECLARE c record; d text; BEGIN
 FOR c IN SELECT conrelid::regclass AS tbl,conname,pg_get_constraintdef(oid) AS def FROM pg_constraint WHERE conrelid IN ('collection_run'::regclass,'collector_result'::regclass,'collection_schedule'::regclass) AND contype='c' LOOP
  d:=c.def;
  IF d LIKE '%asterisk.identity%' THEN d:=replace(d,'''asterisk.identity''::text','''asterisk.registrations''::text, ''asterisk.identity''::text'); END IF;
  IF d<>c.def THEN EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I',c.tbl,c.conname); EXECUTE format('ALTER TABLE %s ADD CONSTRAINT %I %s',c.tbl,c.conname,d); END IF;
 END LOOP;
 SELECT pg_get_constraintdef(oid) INTO d FROM pg_constraint WHERE conrelid='observation'::regclass AND conname='observation_collector_contract';
 ALTER TABLE observation DROP CONSTRAINT observation_collector_contract;
 EXECUTE 'ALTER TABLE observation ADD CONSTRAINT observation_collector_contract CHECK ('||substr(d,8,length(d)-8)||' OR (source_id IS NULL AND collector_id=''asterisk.registrations'' AND key=''asterisk.registration.snapshot'' AND resource ~ ''^(sip_peers|sip_registry|pjsip_endpoints|pjsip_contacts|pjsip_registrations)(/[0-9]{3})?$'' AND kind=''text'' AND unit=''text''))';
 FOR c IN SELECT conname,pg_get_constraintdef(oid) AS def FROM pg_constraint WHERE conrelid='evaluation_policy'::regclass AND contype='c' LOOP
  IF c.def LIKE '%linux.identity%' THEN
   EXECUTE format('ALTER TABLE evaluation_policy DROP CONSTRAINT %I',c.conname);
   IF c.def LIKE '%asset_id IS NULL%' THEN
    EXECUTE 'ALTER TABLE evaluation_policy ADD CHECK ('||substr(c.def,8,length(c.def)-8)||' OR (asset_id IS NULL AND customer_id IS NULL AND environment_id IS NULL AND revision=1 AND rule=''none'' AND selector=''asterisk.registrations''))';
   ELSE
    EXECUTE 'ALTER TABLE evaluation_policy ADD CHECK ('||substr(c.def,8,length(c.def)-8)||' OR selector IN (''asterisk.registrations'',''asterisk.registration.snapshot''))';
   END IF;
  END IF;
 END LOOP;
END $$;
INSERT INTO evaluation_policy(selector,version,ttl_seconds,rule,actor) SELECT 'asterisk.registrations','linux-evidence.v1',180,'none',id FROM workspace_principal WHERE designation='local-operator';
