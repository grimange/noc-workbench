-- Durable evidence; no remote output or credential material.
ALTER TABLE connection_profile ADD CONSTRAINT profile_owner_key UNIQUE(id,customer_id,environment_id,asset_id,endpoint_id);
CREATE TABLE ssh_execution_guard (
 profile_id uuid PRIMARY KEY REFERENCES connection_profile(id) ON DELETE RESTRICT,
 token uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
 principal_id uuid NOT NULL REFERENCES workspace_principal(id),
 revision bigint NOT NULL CHECK(revision>0),
 started_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE collection_run (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 customer_id uuid NOT NULL, environment_id uuid NOT NULL, asset_id uuid NOT NULL,
 endpoint_id uuid NOT NULL, profile_id uuid NOT NULL, profile_revision bigint NOT NULL CHECK(profile_revision>0),
 endpoint_revision timestamptz NOT NULL,
 principal_id uuid NOT NULL REFERENCES workspace_principal(id),
 request_source text NOT NULL DEFAULT 'operator' CHECK(request_source='operator'),
 started_at timestamptz NOT NULL DEFAULT clock_timestamp(), ended_at timestamptz,
 state text NOT NULL DEFAULT 'running' CHECK(state IN ('running','completed','partial','failed','cancelled','interrupted')),
 category text NOT NULL DEFAULT '' CHECK(category ~ '^[a-z_]{0,80}$'),
 success_count int NOT NULL DEFAULT 0 CHECK(success_count BETWEEN 0 AND 5),
 failure_count int NOT NULL DEFAULT 0 CHECK(failure_count BETWEEN 0 AND 5),
 FOREIGN KEY(profile_id,customer_id,environment_id,asset_id,endpoint_id) REFERENCES connection_profile(id,customer_id,environment_id,asset_id,endpoint_id),
 CHECK((state='running' AND ended_at IS NULL) OR (state<>'running' AND ended_at IS NOT NULL AND ended_at>=started_at)),
 UNIQUE(id,asset_id,endpoint_id,profile_id,profile_revision)
);
CREATE INDEX collection_run_asset_time ON collection_run(asset_id,started_at DESC,id DESC);
CREATE INDEX collection_run_unfinished ON collection_run(started_at) WHERE state='running';
CREATE TABLE collector_result (
 run_id uuid NOT NULL REFERENCES collection_run(id) ON DELETE CASCADE,
 collector_id text NOT NULL CHECK(collector_id IN ('linux.identity','linux.uptime','linux.load','linux.memory','linux.filesystems')),
 version text NOT NULL CHECK(version='1'), command_id text NOT NULL CHECK(command_id=collector_id||'.v1'),
 outcome text NOT NULL CHECK(outcome IN ('success','partial','failed')),
 transport_outcome text NOT NULL CHECK(transport_outcome ~ '^[a-z_]{1,80}$'),
 started_at timestamptz NOT NULL, ended_at timestamptz NOT NULL CHECK(ended_at>=started_at),
 observation_count int NOT NULL CHECK(observation_count BETWEEN 0 AND 2048),
 diagnostics text[] NOT NULL CHECK(cardinality(diagnostics)<=16 AND octet_length(diagnostics::text)<=2048),
 PRIMARY KEY(run_id,collector_id)
);
-- Fixed UTF-8 encoding makes this conversion deterministic within this database.
-- Hash the resource only for bounded index keys; retain its complete text as data.
CREATE FUNCTION collection_resource_hash(text) RETURNS bytea
 LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE
 AS $$ SELECT sha256(convert_to($1,'UTF8')) $$;
CREATE TABLE observation (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), run_id uuid NOT NULL,
 asset_id uuid NOT NULL, endpoint_id uuid NOT NULL, profile_id uuid NOT NULL, profile_revision bigint NOT NULL,
 subject_type text NOT NULL DEFAULT 'asset' CHECK(subject_type='asset'),
 collector_id text NOT NULL, collector_version text NOT NULL CHECK(collector_version='1'), command_id text NOT NULL CHECK(command_id=collector_id||'.v1'),
 key text NOT NULL CHECK(key ~ '^linux\.[a-z0-9_.]{1,100}$'),
 resource text NOT NULL DEFAULT '' CHECK(octet_length(resource)<=4096),
 resource_hash bytea GENERATED ALWAYS AS (collection_resource_hash(resource)) STORED,
 kind text NOT NULL CHECK(kind IN ('text','integer','number')),
 text_value text, integer_value numeric(20,0), number_value double precision,
 unit text NOT NULL CHECK(unit IN ('text','seconds','count','load','bytes','percent')),
 transport text NOT NULL CHECK(transport='ssh'), quality text NOT NULL CHECK(quality='valid'),
 observed_at timestamptz NOT NULL, received_at timestamptz NOT NULL CHECK(received_at>=observed_at),
 ttl_seconds int NOT NULL CHECK(ttl_seconds BETWEEN 1 AND 86400),
 FOREIGN KEY(run_id,asset_id,endpoint_id,profile_id,profile_revision) REFERENCES collection_run(id,asset_id,endpoint_id,profile_id,profile_revision) ON DELETE CASCADE,
 FOREIGN KEY(run_id,collector_id) REFERENCES collector_result(run_id,collector_id) ON DELETE CASCADE,
 UNIQUE(run_id,collector_id,key,resource_hash),
 CHECK((kind='text' AND text_value IS NOT NULL AND octet_length(text_value)<=4096 AND integer_value IS NULL AND number_value IS NULL AND unit='text') OR
       (kind='integer' AND integer_value IS NOT NULL AND integer_value BETWEEN 0 AND 18446744073709551615 AND text_value IS NULL AND number_value IS NULL AND unit IN ('count','bytes','percent')) OR
       (kind='number' AND number_value IS NOT NULL AND number_value>=0 AND number_value<'Infinity'::float8 AND text_value IS NULL AND integer_value IS NULL AND unit IN ('seconds','load','percent'))),
 CHECK(
 (collector_id='linux.identity' AND key IN ('linux.hostname','linux.kernel.release','linux.architecture','linux.os.name','linux.os.version') AND kind='text' AND unit='text' AND resource='') OR
 (collector_id='linux.uptime' AND key='linux.uptime.seconds' AND kind='number' AND unit='seconds' AND resource='') OR
 (collector_id='linux.load' AND ((key IN ('linux.load.1m','linux.load.5m','linux.load.15m') AND kind='number' AND unit='load') OR (key='linux.cpu.logical_count' AND kind='integer' AND unit='count' AND integer_value>0)) AND resource='') OR
 (collector_id='linux.memory' AND key IN ('linux.mem.total_bytes','linux.mem.available_bytes','linux.mem.free_bytes') AND kind='integer' AND unit='bytes' AND resource='') OR
 (collector_id='linux.filesystems' AND resource<>'' AND ((key='linux.filesystem.identifier' AND kind='text' AND unit='text') OR (key IN ('linux.filesystem.total_bytes','linux.filesystem.used_bytes','linux.filesystem.available_bytes') AND kind='integer' AND unit='bytes') OR (key='linux.filesystem.utilization_percent' AND kind='integer' AND unit='percent' AND integer_value<=100)))
 )
);
CREATE INDEX observation_latest ON observation(asset_id,key,resource_hash,observed_at DESC,id DESC);
CREATE INDEX observation_run ON observation(run_id,collector_id);
CREATE INDEX observation_retention ON observation(observed_at);
