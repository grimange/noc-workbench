-- No schedules or autonomous execution are enabled by this migration.
CREATE TABLE scheduler_control (
 id boolean PRIMARY KEY DEFAULT true CHECK(id),
 paused boolean NOT NULL DEFAULT false,
 stopped boolean NOT NULL DEFAULT false,
 revision bigint NOT NULL DEFAULT 1 CHECK(revision>0)
);
INSERT INTO scheduler_control(id) VALUES(true);
CREATE TABLE schedule_pause (
 kind text NOT NULL CHECK(kind IN ('customer','cluster','asset')),
 customer_id uuid REFERENCES customer(id),
 cluster_id uuid REFERENCES cluster(id),
 asset_id uuid REFERENCES asset(id),
 CHECK((kind='customer' AND customer_id IS NOT NULL AND cluster_id IS NULL AND asset_id IS NULL) OR
 (kind='cluster' AND cluster_id IS NOT NULL AND customer_id IS NULL AND asset_id IS NULL) OR
 (kind='asset' AND asset_id IS NOT NULL AND customer_id IS NULL AND cluster_id IS NULL)),
 UNIQUE NULLS NOT DISTINCT(kind,customer_id,cluster_id,asset_id)
);
CREATE TABLE collection_schedule (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 customer_id uuid NOT NULL, environment_id uuid NOT NULL, asset_id uuid NOT NULL UNIQUE,
 endpoint_id uuid NOT NULL, profile_id uuid NOT NULL,
 profile_revision bigint NOT NULL CHECK(profile_revision>0), endpoint_revision timestamptz NOT NULL,
 principal_id uuid NOT NULL REFERENCES workspace_principal(id),
 revision bigint NOT NULL DEFAULT 1 CHECK(revision>0),
 collector_ids text[] NOT NULL CHECK(cardinality(collector_ids) BETWEEN 1 AND 5 AND collector_ids <@ ARRAY['linux.identity','linux.uptime','linux.load','linux.memory','linux.filesystems']::text[]),
 interval_seconds int NOT NULL CHECK(interval_seconds BETWEEN 60 AND 86400),
 budget_seconds int NOT NULL CHECK(budget_seconds BETWEEN 1 AND 20),
 enabled boolean NOT NULL DEFAULT false, authorized boolean NOT NULL DEFAULT false,
 CHECK(NOT enabled OR authorized),
 paused boolean NOT NULL DEFAULT false,
 next_due timestamptz NOT NULL,
 last_dispatch timestamptz, admitted_at timestamptz, completed_at timestamptz,
 retry_count int NOT NULL DEFAULT 0 CHECK(retry_count BETWEEN 0 AND 1),
 state text NOT NULL DEFAULT 'idle' CHECK(state IN ('idle','queued','running','delayed','blocked','completed','partial','failed','cancelled','recovered','paused','disabled')),
 category text NOT NULL DEFAULT '' CHECK(category ~ '^[a-z_]{0,80}$'),
 lag_seconds double precision NOT NULL DEFAULT 0 CHECK(lag_seconds>=0 AND lag_seconds<'Infinity'::float8),
 skipped bigint NOT NULL DEFAULT 0 CHECK(skipped>=0),
 FOREIGN KEY(profile_id,customer_id,environment_id,asset_id,endpoint_id) REFERENCES connection_profile(id,customer_id,environment_id,asset_id,endpoint_id),
 UNIQUE(id,customer_id,environment_id,asset_id),
 UNIQUE(id,asset_id)
);
CREATE INDEX collection_schedule_due ON collection_schedule(next_due,id) WHERE enabled AND authorized;
CREATE FUNCTION schedule_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='UPDATE' AND (NEW.id,NEW.customer_id,NEW.environment_id,NEW.asset_id) IS DISTINCT FROM (OLD.id,OLD.customer_id,OLD.environment_id,OLD.asset_id) THEN
  RAISE EXCEPTION 'immutable schedule ownership' USING ERRCODE='23514';
 END IF;
 IF cardinality(NEW.collector_ids)<>(SELECT count(DISTINCT x) FROM unnest(NEW.collector_ids) x) THEN RAISE EXCEPTION 'duplicate collector' USING ERRCODE='23514'; END IF;
 -- Serialize configuration admission and enforce a finite single-process fleet.
 IF TG_OP='INSERT' THEN PERFORM pg_advisory_xact_lock(110011); END IF;
 IF TG_OP='INSERT' AND (SELECT count(*) FROM collection_schedule)>=1000 THEN RAISE EXCEPTION 'schedule limit' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER schedule_guard BEFORE INSERT OR UPDATE ON collection_schedule FOR EACH ROW EXECUTE FUNCTION schedule_guard();
ALTER TABLE collection_run DROP CONSTRAINT collection_run_request_source_check;
ALTER TABLE collection_run ADD CONSTRAINT collection_run_request_source_check CHECK(request_source IN ('operator','scheduled'));
ALTER TABLE collection_run ADD COLUMN schedule_id uuid;
ALTER TABLE collection_run ADD COLUMN schedule_revision bigint;
ALTER TABLE collection_run ADD COLUMN collector_ids text[] NOT NULL DEFAULT ARRAY['linux.identity','linux.uptime','linux.load','linux.memory','linux.filesystems'];
ALTER TABLE collection_run ADD CONSTRAINT collection_run_schedule_owner FOREIGN KEY(schedule_id,asset_id) REFERENCES collection_schedule(id,asset_id);
ALTER TABLE collection_run ADD CONSTRAINT collection_run_schedule_source CHECK((request_source='operator' AND schedule_id IS NULL AND schedule_revision IS NULL) OR (request_source='scheduled' AND schedule_id IS NOT NULL AND schedule_revision IS NOT NULL AND schedule_revision>0));
ALTER TABLE collection_run ADD CONSTRAINT collection_run_collectors CHECK(cardinality(collector_ids) BETWEEN 1 AND 5 AND collector_ids <@ ARRAY['linux.identity','linux.uptime','linux.load','linux.memory','linux.filesystems']::text[]);
CREATE INDEX collection_run_schedule_time ON collection_run(schedule_id,started_at DESC) WHERE schedule_id IS NOT NULL;
