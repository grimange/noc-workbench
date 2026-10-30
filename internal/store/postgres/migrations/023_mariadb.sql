-- Optional socket observations, disabled until explicit per-enrollment authority.
DO $$ DECLARE c record; d text; BEGIN
 FOR c IN SELECT conrelid::regclass tbl,conname,pg_get_constraintdef(oid) def FROM pg_constraint WHERE conrelid IN ('collection_run'::regclass,'collector_result'::regclass,'collection_schedule'::regclass,'collection_integration'::regclass,'observation'::regclass) AND contype='c' LOOP
  d:=c.def;
  IF c.tbl IN ('collection_run'::regclass,'collection_schedule'::regclass) THEN d:=replace(d,'<= 11','<= 12'); END IF;
  IF c.tbl<>'observation'::regclass AND d LIKE '%asterisk.registrations%' AND d NOT LIKE '%command_id%' THEN d:=replace(d,'''asterisk.registrations''::text','''mariadb.health''::text, ''asterisk.registrations''::text'); END IF;
  IF c.tbl='collection_integration'::regclass AND d LIKE '%asterisk_helper%' THEN d:=replace(d,'''asterisk_helper''::text','''mariadb''::text, ''asterisk_helper''::text'); END IF;
  IF c.tbl='observation'::regclass AND c.conname='observation_collector_contract' THEN d:='CHECK ('||substr(d,8,length(d)-8)||' OR (source_id IS NULL AND collector_id=''mariadb.health'' AND key=''mariadb.snapshot'' AND resource ~ ''^(manifest|channel/[0-9]{3})$'' AND kind=''text'' AND unit=''text''))'; END IF;
  IF c.tbl='observation'::regclass AND d LIKE '%(linux|asterisk)%' THEN d:=replace(d,'(linux|asterisk)','(linux|asterisk|mariadb)'); END IF;
  IF d<>c.def THEN EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I',c.tbl,c.conname); EXECUTE format('ALTER TABLE %s ADD CONSTRAINT %I %s',c.tbl,c.conname,d); END IF;
 END LOOP;
END $$;

-- Only expanded SSH profiles receive a larger aggregate sequential budget.
-- API attempts and smaller profiles retain their existing 20-second maximum.
ALTER TABLE collection_schedule DROP CONSTRAINT collection_schedule_budget_seconds_check;
ALTER TABLE collection_schedule ADD CONSTRAINT collection_schedule_budget_seconds_check
 CHECK (budget_seconds BETWEEN 1 AND 20 OR
        (budget_seconds BETWEEN 21 AND 40 AND source_id IS NULL AND profile_id IS NOT NULL AND cardinality(collector_ids)>8));
UPDATE collection_schedule SET budget_seconds=40,revision=revision+1
 WHERE source_id IS NULL AND profile_id IS NOT NULL AND cardinality(collector_ids)>8 AND budget_seconds=20;
