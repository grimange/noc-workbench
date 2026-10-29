-- Bounded authentication-event history; no raw lines or authentication material.
DO $$ DECLARE c record; d text; BEGIN
 FOR c IN SELECT conrelid::regclass AS tbl,conname,pg_get_constraintdef(oid) AS def FROM pg_constraint WHERE conrelid IN ('collection_run'::regclass,'collector_result'::regclass,'collection_schedule'::regclass,'collection_integration'::regclass,'observation'::regclass) AND contype='c' LOOP
  d:=c.def;
  IF c.tbl<>'observation'::regclass AND d LIKE '%asterisk.registrations%' AND d NOT LIKE '%command_id%' THEN d:=replace(d,'''asterisk.registrations''::text','''asterisk.auth''::text, ''asterisk.registrations''::text'); END IF;
  IF c.tbl='collection_integration'::regclass AND d LIKE '%asterisk_helper%' THEN d:=replace(d,'''asterisk_helper''::text','''asterisk_auth''::text, ''asterisk_auth_helper''::text, ''asterisk_helper''::text'); END IF;
  IF c.tbl IN ('collector_result'::regclass,'observation'::regclass) AND d LIKE '%command_id = (collector_id ||%' THEN d:='CHECK ('||substr(d,8,length(d)-8)||' OR (collector_id=''asterisk.auth'' AND command_id=''asterisk.auth.helper.v1''))'; END IF;
  IF c.tbl='observation'::regclass AND c.conname='observation_collector_contract' THEN d:='CHECK ('||substr(d,8,length(d)-8)||' OR (source_id IS NULL AND collector_id=''asterisk.auth'' AND key IN (''asterisk.auth.batch'',''asterisk.auth.event'') AND resource ~ ''^(security|security_log|messages|full)?(/[0-9]{3})?$'' AND kind=''text'' AND unit=''text''))'; END IF;
  IF d<>c.def THEN EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I',c.tbl,c.conname); EXECUTE format('ALTER TABLE %s ADD CONSTRAINT %I %s',c.tbl,c.conname,d); END IF;
 END LOOP;
END $$;
CREATE TABLE asterisk_auth_cursor (
 customer_id uuid NOT NULL, environment_id uuid NOT NULL, asset_id uuid NOT NULL,
 endpoint_id uuid NOT NULL, profile_id uuid NOT NULL, profile_revision bigint NOT NULL CHECK(profile_revision>0),
 source text NOT NULL CHECK(source IN ('security','security_log','messages','full')),
 identity text NOT NULL CHECK(identity ~ '^[0-9]{1,20}:[0-9]{1,20}$'),
 generation bigint NOT NULL CHECK(generation>0), byte_offset bigint NOT NULL CHECK(byte_offset>=0),
 anchor text NOT NULL CHECK(anchor ~ '^[a-f0-9]{64}$'), coverage_gap boolean NOT NULL, discard_line boolean NOT NULL,
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(profile_id,source),
 FOREIGN KEY(profile_id,customer_id,environment_id,asset_id,endpoint_id) REFERENCES connection_profile(id,customer_id,environment_id,asset_id,endpoint_id)
);
CREATE TABLE asterisk_auth_status (
 customer_id uuid NOT NULL, environment_id uuid NOT NULL, asset_id uuid NOT NULL,
 endpoint_id uuid NOT NULL, profile_id uuid NOT NULL, profile_revision bigint NOT NULL CHECK(profile_revision>0),
 source text NOT NULL CHECK(source IN ('','security','security_log','messages','full')),
 status text NOT NULL CHECK(status ~ '^[a-z_]{1,80}$'), checked_at timestamptz NOT NULL,
 security_category boolean NOT NULL, rejected_lines int NOT NULL CHECK(rejected_lines>=0),
 PRIMARY KEY(profile_id,profile_revision),
 FOREIGN KEY(profile_id,customer_id,environment_id,asset_id,endpoint_id) REFERENCES connection_profile(id,customer_id,environment_id,asset_id,endpoint_id)
);
CREATE TABLE asterisk_auth_event (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 customer_id uuid NOT NULL, environment_id uuid NOT NULL, asset_id uuid NOT NULL,
 endpoint_id uuid NOT NULL, profile_id uuid NOT NULL, profile_revision bigint NOT NULL CHECK(profile_revision>0),
 source text NOT NULL CHECK(source IN ('security','security_log','messages','full')),
 identity text NOT NULL CHECK(identity ~ '^[0-9]{1,20}:[0-9]{1,20}$'), generation bigint NOT NULL CHECK(generation>0), byte_position bigint NOT NULL CHECK(byte_position>=0),
 event_at timestamptz NOT NULL, ingested_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 event_type text NOT NULL CHECK(event_type IN ('InvalidPassword','InvalidAccountID','ChallengeResponseFailed','SIPRegistrationRejected','PJSIPAuthenticationRejected')),
 account text NOT NULL CHECK(account='' OR account ~ '^[A-Za-z0-9_.+\-]{1,128}$'),
 observed_ip inet, observed_port int CHECK(observed_port BETWEEN 1 AND 65535),
 technology text NOT NULL CHECK(technology IN ('','SIP','PJSIP')),
 severity text NOT NULL CHECK(severity='authentication_failure'),
 reason text NOT NULL CHECK(reason IN ('InvalidPassword','InvalidAccountID','ChallengeResponseFailed','Wrong password','No matching peer found','Username/auth name mismatch','Failed to authenticate','No matching endpoint found')),
 parser_version text NOT NULL CHECK(parser_version='1'),
 run_id uuid NOT NULL,
 coverage_gap boolean NOT NULL,
 FOREIGN KEY(profile_id,customer_id,environment_id,asset_id,endpoint_id) REFERENCES connection_profile(id,customer_id,environment_id,asset_id,endpoint_id),
 FOREIGN KEY(run_id,asset_id,endpoint_id,profile_id,profile_revision) REFERENCES collection_run(id,asset_id,endpoint_id,profile_id,profile_revision) ON DELETE CASCADE,
 UNIQUE(asset_id,endpoint_id,source,identity,generation,byte_position,event_at)
);
CREATE INDEX asterisk_auth_window ON asterisk_auth_event(customer_id,environment_id,asset_id,event_at DESC);
CREATE INDEX asterisk_auth_retention ON asterisk_auth_event(ingested_at);
