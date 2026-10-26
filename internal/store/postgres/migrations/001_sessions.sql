CREATE TABLE operator_session (
    token_hash text PRIMARY KEY CHECK (length(token_hash) = 64),
    csrf_token text NOT NULL CHECK (length(csrf_token) >= 32),
    expires_at timestamptz NOT NULL
);
CREATE INDEX operator_session_expiry ON operator_session(expires_at);
