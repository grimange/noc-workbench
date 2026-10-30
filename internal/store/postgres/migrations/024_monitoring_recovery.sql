-- A disabled monitoring schedule is not withdrawal of AMI authorization.
ALTER TABLE asterisk_ami_session DROP CONSTRAINT asterisk_ami_session_reason_check;
ALTER TABLE asterisk_ami_session ADD CONSTRAINT asterisk_ami_session_reason_check CHECK(reason IN ('','application_shutdown','application_restart','transport_disconnected','ami_login_rejected','invalid_ami_frame','monitoring_paused','monitoring_disabled','authorization_revoked','authority_unavailable','persistence_failed','queue_overflow'));
ALTER TABLE asterisk_ami_transition DROP CONSTRAINT asterisk_ami_transition_reason_check;
ALTER TABLE asterisk_ami_transition ADD CONSTRAINT asterisk_ami_transition_reason_check CHECK(reason IN ('','application_shutdown','application_restart','transport_disconnected','ami_login_rejected','invalid_ami_frame','monitoring_paused','monitoring_disabled','authorization_revoked','authority_unavailable','persistence_failed','queue_overflow'));
