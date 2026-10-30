-- Additive operational policies; no rules or thresholds are activated here.
ALTER TABLE collection_schedule ADD COLUMN monitoring_expected boolean NOT NULL DEFAULT false;
UPDATE collection_schedule SET monitoring_expected=enabled AND authorized WHERE source_id IS NULL;
DO $$ DECLARE c record; d text; BEGIN
 FOR c IN SELECT conname,pg_get_constraintdef(oid) def FROM pg_constraint WHERE conrelid='evaluation_policy'::regclass AND contype='c' LOOP
 d:=c.def;
 IF d LIKE '%selector = ANY%' AND d NOT LIKE '%asset_id IS NULL%' AND d NOT LIKE '%threshold%' THEN
 d:='CHECK ('||substr(d,8,length(d)-8)||' OR selector IN (''monitoring.continuity'',''server.ssh_unreachable'',''service.runtime.unavailable'',''service.ami.disconnected'',''service.authentication.repeated'',''database.query.failed'',''database.replication.failed'',''database.replication.lag_seconds''))';
 ELSIF d LIKE '%rule = ANY%' AND d NOT LIKE '%threshold%' THEN
 d:='CHECK (rule IN (''none'',''filesystem_used_high'',''memory_available_low'',''condition_failed'',''monitoring_interrupted'',''value_high''))';
 ELSIF d LIKE '%threshold%' AND d LIKE '%memory_available_low%' THEN
 d:='CHECK ('||substr(d,8,length(d)-8)||' OR (rule=''condition_failed'' AND threshold=0 AND selector IN (''server.ssh_unreachable'',''service.runtime.unavailable'',''service.ami.disconnected'',''service.authentication.repeated'',''database.query.failed'',''database.replication.failed'')) OR (rule=''monitoring_interrupted'' AND selector=''monitoring.continuity'' AND threshold BETWEEN 180 AND 86400) OR (rule=''value_high'' AND selector=''database.replication.lag_seconds'' AND threshold>0 AND threshold<=86400))';
 END IF;
 IF d<>c.def THEN EXECUTE format('ALTER TABLE evaluation_policy DROP CONSTRAINT %I',c.conname);EXECUTE format('ALTER TABLE evaluation_policy ADD CONSTRAINT %I %s',c.conname,d); END IF;
 END LOOP;
END $$;
CREATE OR REPLACE FUNCTION alert_rule_chain() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM evaluation_policy p WHERE p.id=NEW.policy_id AND p.revision=NEW.policy_revision AND p.asset_id=NEW.asset_id AND p.environment_id=NEW.environment_id AND p.customer_id=NEW.customer_id AND p.rule IN ('memory_available_low','filesystem_used_high','condition_failed','monitoring_interrupted','value_high')) THEN RAISE EXCEPTION 'unsupported or foreign alert policy'; END IF;
 IF NEW.revision>1 AND NOT EXISTS(SELECT 1 FROM alert_rule r WHERE r.id=NEW.id AND r.revision=NEW.revision-1 AND r.asset_id=NEW.asset_id AND r.policy_id=NEW.policy_id AND r.created_at<=NEW.created_at) THEN RAISE EXCEPTION 'invalid alert revision chain'; END IF;
 IF NEW.revision=1 AND EXISTS(SELECT 1 FROM alert_rule r WHERE r.id=NEW.id) THEN RAISE EXCEPTION 'alert identity exists'; END IF;
 RETURN NEW; END; $$;
