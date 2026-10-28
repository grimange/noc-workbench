-- Explicit standard grants reuse collection_integration. No legacy grant expands.
-- Preserve prior checks; add only matching observation-gateway provenance pairs.
DO $$
DECLARE c record; d text;
BEGIN
 FOR c IN SELECT conrelid::regclass AS tab, conname, pg_get_constraintdef(oid) AS def
 FROM pg_constraint WHERE contype='c' AND conrelid IN ('collector_result'::regclass,'observation'::regclass)
 LOOP
  IF c.def LIKE '%command_id = (collector_id ||%' THEN
   d := substr(c.def,8,length(c.def)-8);
   EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I',c.tab,c.conname);
   EXECUTE format('ALTER TABLE %s ADD CONSTRAINT %I CHECK ((%s) OR (collector_id=''asterisk.identity'' AND command_id=''asterisk.identity.helper.v1'') OR (collector_id=''asterisk.registrations'' AND command_id=''asterisk.registrations.helper.v1''))',c.tab,c.conname,d);
  END IF;
 END LOOP;
 FOR c IN SELECT conname,pg_get_constraintdef(oid) AS def FROM pg_constraint WHERE contype='c' AND conrelid='connection_audit'::regclass LOOP
  IF c.def LIKE '%operation%' THEN
   EXECUTE format('ALTER TABLE connection_audit DROP CONSTRAINT %I',c.conname);
   EXECUTE format('ALTER TABLE connection_audit ADD CONSTRAINT %I CHECK ((%s) OR operation=''standard'')',c.conname,substr(c.def,8,length(c.def)-8));
  END IF;
 END LOOP;
END $$;
