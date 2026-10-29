-- Explicit, revision/digest-bound forwarding authorization; no credential values.
CREATE TABLE asterisk_ami_grant (
 profile_id uuid PRIMARY KEY, customer_id uuid NOT NULL,environment_id uuid NOT NULL,asset_id uuid NOT NULL UNIQUE,endpoint_id uuid NOT NULL,
 profile_revision bigint NOT NULL CHECK(profile_revision>0),
 credential_ref text NOT NULL CHECK(credential_ref ~ '^[A-Za-z_][A-Za-z0-9_-]{0,63}$'),
 credential_digest text NOT NULL CHECK(credential_digest ~ '^[a-f0-9]{64}$'),
 enabled boolean NOT NULL,actor uuid NOT NULL REFERENCES workspace_principal(id),updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(profile_id,customer_id,environment_id,asset_id,endpoint_id) REFERENCES connection_profile(id,customer_id,environment_id,asset_id,endpoint_id)
);
CREATE TABLE asterisk_ami_session (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),customer_id uuid NOT NULL,environment_id uuid NOT NULL,asset_id uuid NOT NULL,endpoint_id uuid NOT NULL,profile_id uuid NOT NULL,
 profile_revision bigint NOT NULL CHECK(profile_revision>0),credential_digest text NOT NULL CHECK(credential_digest ~ '^[a-f0-9]{64}$'),
 state text NOT NULL CHECK(state IN ('connecting','authenticating','connected','disconnected','reconnecting','unauthorized','unsupported','paused')),
 reason text NOT NULL CHECK(reason IN ('','application_shutdown','application_restart','transport_disconnected','ami_login_rejected','invalid_ami_frame','monitoring_paused','authorization_revoked','authority_unavailable','persistence_failed','queue_overflow')),
 started_at timestamptz NOT NULL,updated_at timestamptz NOT NULL,connected_at timestamptz,last_event_at timestamptz,ended_at timestamptz,
 dropped bigint NOT NULL DEFAULT 0 CHECK(dropped>=0),coverage_gap boolean NOT NULL DEFAULT false,
 UNIQUE(id,customer_id,environment_id,asset_id,endpoint_id,profile_id,profile_revision),
 FOREIGN KEY(profile_id,customer_id,environment_id,asset_id,endpoint_id) REFERENCES connection_profile(id,customer_id,environment_id,asset_id,endpoint_id),
 CHECK((state IN ('connecting','authenticating','connected'))=(ended_at IS NULL)),
 CHECK(ended_at IS NULL OR coverage_gap)
);
CREATE UNIQUE INDEX asterisk_ami_one_live ON asterisk_ami_session(asset_id) WHERE ended_at IS NULL;
CREATE INDEX asterisk_ami_session_history ON asterisk_ami_session(customer_id,environment_id,asset_id,started_at DESC);
CREATE TABLE asterisk_ami_transition (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,session_id uuid NOT NULL REFERENCES asterisk_ami_session(id) ON DELETE CASCADE,
 state text NOT NULL CHECK(state IN ('connecting','authenticating','connected','disconnected','reconnecting','unauthorized','unsupported','paused')),
 reason text NOT NULL CHECK(reason IN ('','application_shutdown','application_restart','transport_disconnected','ami_login_rejected','invalid_ami_frame','monitoring_paused','authorization_revoked','authority_unavailable','persistence_failed','queue_overflow')),
 at timestamptz NOT NULL,coverage_gap boolean NOT NULL,dropped bigint NOT NULL CHECK(dropped>=0)
);
CREATE TABLE asterisk_ami_event (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,session_id uuid NOT NULL,
 customer_id uuid NOT NULL,environment_id uuid NOT NULL,asset_id uuid NOT NULL,endpoint_id uuid NOT NULL,profile_id uuid NOT NULL,profile_revision bigint NOT NULL,
 sequence bigint NOT NULL CHECK(sequence>0),name text NOT NULL CHECK(name IN ('FullyBooted','Shutdown','PeerStatus','ContactStatus','Registry')),
 technology text NOT NULL CHECK(technology IN ('','SIP','PJSIP','IAX2')),
 endpoint text NOT NULL CHECK(endpoint='' OR endpoint ~ '^[A-Za-z0-9_.+\-]{1,128}$'),aor text NOT NULL CHECK(aor='' OR aor ~ '^[A-Za-z0-9_.+\-]{1,128}$'),
 address text NOT NULL CHECK(octet_length(address)<=64),
 state text NOT NULL CHECK(state IN ('','Fully booted','Shutdown reported','Registered','Unregistered','Reachable','Unreachable','Lagged','Unknown','Rejected','NonQualified','Removed','Updated','Created','Request Sent','Auth. Sent','Timeout','No Authentication')),
 rtt_ms double precision CHECK(rtt_ms>=0 AND rtt_ms<=4294967.295),
 source_at timestamptz,received_at timestamptz NOT NULL,ingested_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 parser_version text NOT NULL CHECK(parser_version='1'),coverage_gap boolean NOT NULL,
 UNIQUE(session_id,sequence),
 FOREIGN KEY(session_id,customer_id,environment_id,asset_id,endpoint_id,profile_id,profile_revision) REFERENCES asterisk_ami_session(id,customer_id,environment_id,asset_id,endpoint_id,profile_id,profile_revision) ON DELETE CASCADE
);
CREATE INDEX asterisk_ami_event_history ON asterisk_ami_event(customer_id,environment_id,asset_id,received_at DESC,id DESC);
