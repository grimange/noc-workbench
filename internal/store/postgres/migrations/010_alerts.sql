-- Rules explicitly opt in to existing asset health policies. No default alerts.
CREATE TABLE alert_rule (
 id uuid NOT NULL DEFAULT gen_random_uuid(), revision bigint NOT NULL CHECK(revision>0),
 customer_id uuid NOT NULL, environment_id uuid NOT NULL, asset_id uuid NOT NULL,
 policy_id uuid NOT NULL, policy_revision bigint NOT NULL,
 severity text NOT NULL CHECK(severity IN ('info','warning','critical')),
 debounce_seconds int NOT NULL CHECK(debounce_seconds BETWEEN 0 AND 86400),
 enabled boolean NOT NULL, version text NOT NULL DEFAULT 'evidence-alert.v1' CHECK(version='evidence-alert.v1'),
 actor uuid NOT NULL REFERENCES workspace_principal(id), created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(id,revision), UNIQUE(asset_id,policy_id,revision), UNIQUE(id,revision,asset_id),
 FOREIGN KEY(environment_id,customer_id) REFERENCES environment(id,customer_id) ON DELETE CASCADE,
 FOREIGN KEY(asset_id,environment_id) REFERENCES asset(id,environment_id) ON DELETE CASCADE,
 FOREIGN KEY(policy_id,policy_revision) REFERENCES evaluation_policy(id,revision) ON DELETE CASCADE
);
CREATE FUNCTION alert_rule_chain() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM evaluation_policy p WHERE p.id=NEW.policy_id AND p.revision=NEW.policy_revision AND p.asset_id=NEW.asset_id AND p.environment_id=NEW.environment_id AND p.customer_id=NEW.customer_id AND p.rule IN ('memory_available_low','filesystem_used_high')) THEN RAISE EXCEPTION 'unsupported or foreign alert policy'; END IF;
 IF NEW.revision>1 AND NOT EXISTS(SELECT 1 FROM alert_rule r WHERE r.id=NEW.id AND r.revision=NEW.revision-1 AND r.asset_id=NEW.asset_id AND r.policy_id=NEW.policy_id AND r.created_at<=NEW.created_at) THEN RAISE EXCEPTION 'invalid alert revision chain'; END IF;
 IF NEW.revision=1 AND EXISTS(SELECT 1 FROM alert_rule r WHERE r.id=NEW.id) THEN RAISE EXCEPTION 'alert identity exists'; END IF;
 RETURN NEW; END; $$;
CREATE TRIGGER alert_rule_chain BEFORE INSERT ON alert_rule FOR EACH ROW EXECUTE FUNCTION alert_rule_chain();
CREATE TRIGGER alert_rule_immutable BEFORE UPDATE ON alert_rule FOR EACH ROW EXECUTE FUNCTION evaluation_policy_immutable();
CREATE TABLE alert_cursor (
 asset_id uuid PRIMARY KEY REFERENCES asset(id) ON DELETE CASCADE,
 evaluated_at timestamptz NOT NULL DEFAULT 'epoch'
);
CREATE TABLE alert_instance (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), asset_id uuid NOT NULL REFERENCES asset(id) ON DELETE CASCADE,
 rule_id uuid NOT NULL, rule_revision bigint NOT NULL,
 resource text NOT NULL CHECK(octet_length(resource)<=4096),
 resource_hash bytea GENERATED ALWAYS AS (collection_resource_hash(resource)) STORED,
 state text NOT NULL CHECK(state IN ('pending','active','resolved')),
 evidence_state text NOT NULL CHECK(evidence_state IN ('fresh','stale','unknown','disabled')),
 snapshot jsonb NOT NULL CHECK(octet_length(snapshot::text)<=32768),
 evaluated_at timestamptz NOT NULL, updated_at timestamptz NOT NULL,
 FOREIGN KEY(rule_id,rule_revision,asset_id) REFERENCES alert_rule(id,revision,asset_id) ON DELETE CASCADE,
 UNIQUE(rule_id,resource_hash), UNIQUE(id,asset_id)
);
CREATE INDEX alert_asset ON alert_instance(asset_id,updated_at DESC,id);
CREATE TABLE alert_event (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 alert_id uuid NOT NULL, asset_id uuid NOT NULL,
 kind text NOT NULL CHECK(kind IN ('pending','active','resolved','evidence_changed','revision_changed','acknowledged')),
 actor uuid NOT NULL REFERENCES workspace_principal(id), at timestamptz NOT NULL,
 snapshot jsonb NOT NULL CHECK(octet_length(snapshot::text)<=32768),
 FOREIGN KEY(alert_id,asset_id) REFERENCES alert_instance(id,asset_id) ON DELETE CASCADE
);
CREATE INDEX alert_event_asset ON alert_event(asset_id,id DESC);
CREATE INDEX observation_chart ON observation(asset_id,key,observed_at,id) WHERE kind<>'text';
CREATE INDEX alert_event_retention ON alert_event(at,id);
CREATE INDEX alert_event_instance ON alert_event(alert_id);
CREATE INDEX alert_cursor_due ON alert_cursor(evaluated_at,asset_id);
CREATE INDEX alert_resolved_retention ON alert_instance(updated_at,id) WHERE state='resolved';
