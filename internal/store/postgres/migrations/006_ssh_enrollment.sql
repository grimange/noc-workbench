-- NW-008 extends the NW-007 reviewed profile/trust contract. No credentials.
ALTER TABLE asset_endpoint ADD CONSTRAINT endpoint_owner_key UNIQUE(id,environment_id,asset_id);
CREATE TABLE connection_profile (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 customer_id uuid NOT NULL,
 environment_id uuid NOT NULL,
 asset_id uuid NOT NULL,
 endpoint_id uuid NOT NULL,
 revision bigint NOT NULL DEFAULT 1 CHECK(revision>0),
 state text NOT NULL CHECK(state IN ('draft','pending_authorization','pending_host_key_verification','connection_verified','rejected','disabled','identity_changed')),
 details jsonb NOT NULL CHECK(jsonb_typeof(details)='object' AND octet_length(details::text)<=32768),
 authorized_by uuid GENERATED ALWAYS AS (nullif(details->>'AuthorizedBy','')::uuid) STORED REFERENCES workspace_principal(id),
 approved_by uuid GENERATED ALWAYS AS (nullif(details->>'ApprovedBy','')::uuid) STORED REFERENCES workspace_principal(id),
 created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(environment_id,customer_id) REFERENCES environment(id,customer_id) ON DELETE RESTRICT,
 FOREIGN KEY(asset_id,environment_id) REFERENCES asset(id,environment_id) ON DELETE RESTRICT,
 FOREIGN KEY(endpoint_id,environment_id,asset_id) REFERENCES asset_endpoint(id,environment_id,asset_id) ON DELETE RESTRICT,
 CHECK(coalesce(details->>'ApprovedKey','')='' OR (coalesce(details->>'ApprovedFingerprint','')<>'' AND coalesce(details->>'Evidence','')<>'' AND approved_by IS NOT NULL AND pg_input_is_valid(coalesce(details->>'ApprovedAt',''),'timestamp with time zone'))),
 CHECK(state<>'connection_verified' OR (coalesce(details->>'ApprovedKey','')<>'' AND coalesce(details->>'ApprovedFingerprint','')<>'' AND pg_input_is_valid(coalesce(details->>'VerifiedAt',''),'timestamp with time zone'))),
 CHECK(state NOT IN ('pending_host_key_verification','connection_verified') OR (authorized_by IS NOT NULL AND pg_input_is_valid(coalesce(details->>'AuthorizedAt',''),'timestamp with time zone')))
);
CREATE INDEX connection_profile_asset ON connection_profile(environment_id,asset_id,id);
CREATE TABLE connection_audit(
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 profile_id uuid NOT NULL REFERENCES connection_profile(id) ON DELETE RESTRICT,
 principal_id uuid NOT NULL REFERENCES workspace_principal(id) ON DELETE RESTRICT,
 revision bigint NOT NULL CHECK(revision>0),
 operation text NOT NULL CHECK(operation IN ('create','submit','authorize','inspect','approve','verify','disable','reject','review')),
 state text NOT NULL, category text NOT NULL CHECK(octet_length(category)<=80),
 at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE FUNCTION connection_owner_guard() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF NEW.id<>OLD.id OR NEW.customer_id<>OLD.customer_id OR NEW.environment_id<>OLD.environment_id OR NEW.asset_id<>OLD.asset_id OR NEW.endpoint_id<>OLD.endpoint_id OR NEW.revision<>OLD.revision+1 THEN
  RAISE EXCEPTION 'immutable enrollment owner or stale revision' USING ERRCODE='23514';
 END IF; RETURN NEW; END $$;
CREATE TRIGGER connection_owner_guard BEFORE UPDATE ON connection_profile FOR EACH ROW EXECUTE FUNCTION connection_owner_guard();
-- Identity edits invalidate the persisted approval even when changed and changed back.
CREATE FUNCTION connection_endpoint_changed() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF NEW IS DISTINCT FROM OLD THEN
  UPDATE connection_profile SET state='identity_changed',revision=revision+1,
   details=details || '{"ApprovedKey":"","ApprovedFingerprint":"","VerifiedAt":null}'::jsonb,
   updated_at=clock_timestamp() WHERE endpoint_id=NEW.id;
 END IF; RETURN NEW; END $$;
CREATE TRIGGER connection_endpoint_changed AFTER UPDATE ON asset_endpoint FOR EACH ROW EXECUTE FUNCTION connection_endpoint_changed();
