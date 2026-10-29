-- Reporting scope is opt-in; no existing grants expand.
DO $$ DECLARE c record; BEGIN
 FOR c IN SELECT conname,pg_get_constraintdef(oid) def FROM pg_constraint WHERE conrelid='collection_integration'::regclass AND contype='c' LOOP
  IF c.def LIKE '%asterisk_helper%' THEN
   EXECUTE format('ALTER TABLE collection_integration DROP CONSTRAINT %I',c.conname);
   EXECUTE format('ALTER TABLE collection_integration ADD CONSTRAINT %I %s',c.conname,replace(c.def,'''asterisk_helper''::text','''asterisk_media''::text, ''asterisk_helper''::text'));
  END IF;
 END LOOP;
 FOR c IN SELECT conname,pg_get_constraintdef(oid) def FROM pg_constraint WHERE conrelid='asterisk_ami_event'::regclass AND contype='c' LOOP
  IF c.def LIKE '%name = ANY%' THEN
   EXECUTE format('ALTER TABLE asterisk_ami_event DROP CONSTRAINT %I',c.conname);
   EXECUTE 'ALTER TABLE asterisk_ami_event ADD CHECK ('||substr(c.def,8,length(c.def)-8)||' OR name IN (''RTCPReceived'',''RTCPSent''))';
  END IF;
 END LOOP;
END $$;
ALTER TABLE asterisk_ami_event ADD COLUMN media jsonb NOT NULL DEFAULT 'null'::jsonb CHECK (media='null'::jsonb OR (name IN ('RTCPReceived','RTCPSent') AND jsonb_typeof(media)='object' AND octet_length(media::text)<=16384 AND media - ARRAY['Uniqueid','Linkedid','SSRC','PacketType','Perspective','SenderPackets','RTTMilliseconds','Blocks','Incomplete']::text[]='{}'::jsonb));
CREATE INDEX asterisk_media_history ON asterisk_ami_event(customer_id,environment_id,asset_id,received_at DESC,id DESC) WHERE name IN ('RTCPReceived','RTCPSent');

ALTER TABLE asterisk_ami_event ADD COLUMN media_runtime text NOT NULL DEFAULT '' CHECK(media_runtime='' OR media_runtime ~ '^[0-9a-f]{64}$');
CREATE FUNCTION valid_asterisk_media_blocks(v jsonb) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
 SELECT CASE WHEN v='null'::jsonb THEN true
 WHEN jsonb_typeof(v->'Blocks')='null' THEN true
 WHEN jsonb_typeof(v->'Blocks')='array' THEN jsonb_array_length(v->'Blocks')<=31 AND NOT EXISTS(
 SELECT 1 FROM jsonb_array_elements(v->'Blocks') b WHERE jsonb_typeof(b)<>'object' OR b - ARRAY['Index','SourceSSRC','FractionLost','CumulativeLost','JitterTimestampUnits','LastSenderReport']::text[]<>'{}'::jsonb)
 ELSE false END
$$;
ALTER TABLE asterisk_ami_event ADD CHECK(valid_asterisk_media_blocks(media));
ALTER TABLE asterisk_ami_event ADD CHECK ((name IN ('RTCPReceived','RTCPSent'))=(media<>'null'::jsonb));

ALTER TABLE asterisk_ami_event ADD COLUMN media_channel text NOT NULL DEFAULT '' CHECK (length(media_channel)<=200 AND (media_channel IN ('','Local (resource omitted)','Unknown channel') OR media_channel ~ '^(SIP|PJSIP)/[A-Za-z0-9_.@+-]+-[0-9a-fA-F]+$'));
-- Optional fixed CLI media snapshots use the existing observation journal.
DO $$ DECLARE c record; d text; BEGIN
 FOR c IN SELECT conrelid::regclass tbl,conname,pg_get_constraintdef(oid) def FROM pg_constraint WHERE conrelid IN ('collection_run'::regclass,'collector_result'::regclass,'collection_schedule'::regclass,'observation'::regclass) AND contype='c' LOOP
  d:=c.def;
  IF c.tbl IN ('collection_run'::regclass,'collection_schedule'::regclass) THEN d:=replace(d,'<= 10','<= 11'); END IF;
  IF c.tbl<>'observation'::regclass AND d LIKE '%asterisk.registrations%' AND d NOT LIKE '%command_id%' THEN d:=replace(d,'''asterisk.registrations''::text','''asterisk.media''::text, ''asterisk.registrations''::text'); END IF;
  IF c.tbl IN ('collector_result'::regclass,'observation'::regclass) AND d LIKE '%command_id = (collector_id ||%' THEN d:='CHECK ('||substr(d,8,length(d)-8)||' OR (collector_id=''asterisk.media'' AND command_id=''asterisk.media.helper.v1''))'; END IF;
  IF c.tbl='observation'::regclass AND c.conname='observation_collector_contract' THEN d:='CHECK ('||substr(d,8,length(d)-8)||' OR (source_id IS NULL AND collector_id=''asterisk.media'' AND key=''asterisk.media.cli'' AND resource ~ ''^(sip|pjsip)(/[0-9]{3})?$'' AND kind=''text'' AND unit=''text''))'; END IF;
  IF d<>c.def THEN EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I',c.tbl,c.conname); EXECUTE format('ALTER TABLE %s ADD CONSTRAINT %I %s',c.tbl,c.conname,d); END IF;
 END LOOP;
END $$;
