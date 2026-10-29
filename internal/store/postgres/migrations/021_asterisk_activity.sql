-- Optional channel/conference evidence. No existing grant or schedule expands.
DO $$ DECLARE c record; d text; BEGIN
 FOR c IN SELECT conrelid::regclass tbl,conname,pg_get_constraintdef(oid) def FROM pg_constraint WHERE conrelid IN ('collection_run'::regclass,'collector_result'::regclass,'collection_schedule'::regclass,'collection_integration'::regclass,'observation'::regclass) AND contype='c' LOOP
  d:=c.def;
  IF c.tbl<>'observation'::regclass AND d LIKE '%asterisk.registrations%' AND d NOT LIKE '%command_id%' THEN d:=replace(d,'''asterisk.registrations''::text','''asterisk.activity''::text, ''asterisk.registrations''::text'); END IF;
  IF c.tbl='collection_integration'::regclass AND d LIKE '%asterisk_helper%' THEN d:=replace(d,'''asterisk_helper''::text','''asterisk_activity''::text, ''asterisk_helper''::text'); END IF;
  IF c.tbl IN ('collector_result'::regclass,'observation'::regclass) AND d LIKE '%command_id = (collector_id ||%' THEN d:='CHECK ('||substr(d,8,length(d)-8)||' OR (collector_id=''asterisk.activity'' AND command_id=''asterisk.activity.helper.v1''))'; END IF;
  IF c.tbl='observation'::regclass AND c.conname='observation_collector_contract' THEN d:='CHECK ('||substr(d,8,length(d)-8)||' OR (source_id IS NULL AND collector_id=''asterisk.activity'' AND key=''asterisk.activity.snapshot'' AND resource ~ ''^(manifest|(channel|bridge|conference)/[0-9]{3})$'' AND kind=''text'' AND unit=''text''))'; END IF;
  IF d<>c.def THEN EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I',c.tbl,c.conname); EXECUTE format('ALTER TABLE %s ADD CONSTRAINT %I %s',c.tbl,c.conname,d); END IF;
 END LOOP;
 FOR c IN SELECT conname,pg_get_constraintdef(oid) def FROM pg_constraint WHERE conrelid='asterisk_ami_event'::regclass AND contype='c' LOOP
  IF c.def LIKE '%name = ANY%' THEN
   EXECUTE format('ALTER TABLE asterisk_ami_event DROP CONSTRAINT %I',c.conname);
   EXECUTE 'ALTER TABLE asterisk_ami_event ADD CHECK ('||substr(c.def,8,length(c.def)-8)||' OR name IN (''Newchannel'',''Newstate'',''Hangup'',''BridgeCreate'',''BridgeDestroy'',''BridgeEnter'',''BridgeLeave'',''MeetmeJoin'',''MeetmeLeave'',''ConfbridgeStart'',''ConfbridgeEnd'',''ConfbridgeJoin'',''ConfbridgeLeave''))';
  END IF;
 END LOOP;
END $$;
ALTER TABLE asterisk_ami_event ADD COLUMN activity jsonb NOT NULL DEFAULT '{}'::jsonb CHECK(jsonb_typeof(activity)='object' AND octet_length(activity::text)<=2048 AND activity - ARRAY['channel','uniqueid','linkedid','bridge','conference','state']::text[]='{}'::jsonb);
CREATE TABLE asterisk_activity_state (
 customer_id uuid NOT NULL,environment_id uuid NOT NULL,asset_id uuid NOT NULL,endpoint_id uuid NOT NULL,profile_id uuid PRIMARY KEY,
 profile_revision bigint NOT NULL CHECK(profile_revision>0),
 state jsonb NOT NULL CHECK(jsonb_typeof(state)='object' AND octet_length(state::text)<=1048576),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(profile_id,customer_id,environment_id,asset_id,endpoint_id) REFERENCES connection_profile(id,customer_id,environment_id,asset_id,endpoint_id)
);
-- Immutable snapshots remain in ordinary scoped observations/collection history;
-- normalized lifecycle history remains in the existing AMI event journal.
