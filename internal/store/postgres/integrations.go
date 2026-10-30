package postgres

import (
	"context"
	"github.com/jackc/pgx/v5"
	"noc-workbench/internal/collection"
	"noc-workbench/internal/connections"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
	"strings"
)

type integrationQuery interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func (s *Store) IntegrationAllowed(ctx context.Context, p workspace.Principal, t sshcli.Target, name string) error {
	return integrationAllowed(ctx, s.pool, p, t, name)
}
func integrationAllowed(ctx context.Context, q integrationQuery, p workspace.Principal, t sshcli.Target, name string) error {
	if p.ID != workspace.OperatorID || !monitoringIntegration(name) {
		return workspace.ErrDenied
	}
	var yes bool
	e := q.QueryRow(ctx, `SELECT true FROM collection_integration i JOIN connection_profile p ON p.id=i.profile_id WHERE i.profile_id=$1 AND i.asset_id=$2 AND i.endpoint_id=$3 AND i.integration=$4 AND i.enabled AND i.profile_revision=$5 AND p.revision=$5 AND p.state='connection_verified' FOR SHARE OF i,p`, t.ProfileID, t.AssetID, t.EndpointID, name, t.ProfileVersion).Scan(&yes)
	if e != nil || !yes {
		return workspace.ErrDenied
	}
	return nil
}
func (s *Store) SetIntegration(ctx context.Context, p workspace.Principal, h collection.HistoryScope, t sshcli.Target, name string, enabled bool) error {
	if collectionAccess(p, h) != nil || !monitoringIntegration(name) || h.AssetID != t.AssetID {
		return workspace.ErrDenied
	}
	r, e := s.Enrollment(ctx, t.EndpointID, t.ProfileID)
	if e != nil || r.Target() != t || r.CustomerID != h.CustomerID || r.EnvironmentID != h.EnvironmentID {
		return workspace.ErrDenied
	}
	if enabled && r.State != "connection_verified" {
		return workspace.ErrDenied
	}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return ErrUnavailable
	}
	defer tx.Rollback(context.Background())
	if e = lockEnrollmentOwners(ctx, tx, r); e != nil {
		return e
	}
	var revision int64
	if e = tx.QueryRow(ctx, `SELECT revision FROM connection_profile WHERE id=$1 FOR UPDATE`, t.ProfileID).Scan(&revision); e != nil || revision != t.ProfileVersion {
		return workspace.ErrDenied
	}
	_, e = tx.Exec(ctx, `INSERT INTO collection_integration(profile_id,customer_id,environment_id,asset_id,endpoint_id,integration,profile_revision,enabled,actor) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(profile_id,integration) DO UPDATE SET profile_revision=excluded.profile_revision,enabled=excluded.enabled,actor=excluded.actor,updated_at=clock_timestamp(),revision=collection_integration.revision+1`, t.ProfileID, h.CustomerID, h.EnvironmentID, t.AssetID, t.EndpointID, name, t.ProfileVersion, enabled, p.ID)
	if e != nil {
		return ErrUnavailable
	}
	return tx.Commit(ctx)
}

func monitoringIntegration(name string) bool {
	return name == "mariadb" || name == "asterisk_media" || name == "asterisk_activity" || name == "asterisk_auth" || name == "asterisk_auth_helper" || name == "asterisk" || name == "vicidial_discovery" || name == "runtime_services" || name == "baseline" || name == "asterisk_helper"
}

// StandardMonitoringAllowed is a projection of the existing four scoped grants,
// not a second permission system. Parser versions are deliberately not authority.
func (s *Store) StandardMonitoringAllowed(ctx context.Context, p workspace.Principal, t sshcli.Target) error {
	for _, name := range []string{"baseline", "runtime_services", "vicidial_discovery", "asterisk"} {
		if e := s.IntegrationAllowed(ctx, p, t, name); e != nil {
			return e
		}
	}
	return nil
}

// SetStandardMonitoring explicitly expands the reviewed capability catalog for
// one verified enrollment. It preserves its revision, trust, history and pauses.
// The optional helper is separately disclosed execution scope, never inferred
// from a failed CLI command or silently granted to existing enrollments.
func (s *Store) SetStandardMonitoring(ctx context.Context, p workspace.Principal, h collection.HistoryScope, t sshcli.Target, helper bool) error {
	return s.setStandardMonitoring(ctx, p, h, t, helper, nil, nil)
}

// SetStandardMonitoringWithAuth discloses fixed log discovery/reads in the same
// consolidated action. Prior narrow helper grants never gain log privileges.
func (s *Store) SetStandardMonitoringWithAuth(ctx context.Context, p workspace.Principal, h collection.HistoryScope, t sshcli.Target, helper, auth, authHelper bool) error {
	if authHelper && !auth {
		return workspace.ErrDenied
	}
	return s.setStandardMonitoring(ctx, p, h, t, helper, []bool{auth, authHelper}, nil)
}

// SetStandardMonitoringWithActivity is one explicit expansion of the existing
// consolidated workflow; existing grants are never silently broadened.
func (s *Store) SetStandardMonitoringWithActivity(ctx context.Context, p workspace.Principal, h collection.HistoryScope, t sshcli.Target, helper, auth, authHelper, activity bool) error {
	if authHelper && !auth {
		return workspace.ErrDenied
	}
	return s.setStandardMonitoring(ctx, p, h, t, helper, []bool{auth, authHelper}, &activity)
}
func (s *Store) setStandardMonitoring(ctx context.Context, p workspace.Principal, h collection.HistoryScope, t sshcli.Target, helper bool, auth []bool, activity *bool, media ...bool) error {
	if collectionAccess(p, h) != nil || h.AssetID != t.AssetID {
		return workspace.ErrDenied
	}
	r, e := s.Enrollment(ctx, t.EndpointID, t.ProfileID)
	if e != nil || r.Target() != t || r.State != "connection_verified" || r.CustomerID != h.CustomerID || r.EnvironmentID != h.EnvironmentID {
		return workspace.ErrDenied
	}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return ErrUnavailable
	}
	defer tx.Rollback(context.Background())
	if e = lockEnrollmentOwners(ctx, tx, r); e != nil {
		return e
	}
	var current int64
	if e = tx.QueryRow(ctx, `SELECT revision FROM connection_profile WHERE id=$1 AND state='connection_verified' FOR UPDATE`, r.ID).Scan(&current); e != nil || current != t.ProfileVersion {
		return workspace.ErrDenied
	}
	for _, name := range []string{"baseline", "runtime_services", "vicidial_discovery", "asterisk"} {
		if e = grantMonitoring(ctx, tx, p, r, name, true); e != nil {
			return e
		}
	}
	if helper {
		if e = grantMonitoring(ctx, tx, p, r, "asterisk_helper", true); e != nil {
			return e
		}
	} else {
		if _, e = tx.Exec(ctx, `UPDATE collection_integration SET enabled=false,revision=revision+1,actor=$2,updated_at=clock_timestamp() WHERE profile_id=$1 AND integration='asterisk_helper' AND enabled`, r.ID, p.ID); e != nil {
			return ErrUnavailable
		}
	}
	// Reuse an existing active baseline profile without resetting its next due,
	// collector selection, revision or independent profile pause.
	var scheduled bool
	if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM collection_schedule WHERE asset_id=$1 AND profile_id=$2 AND profile_revision=$3 AND enabled AND authorized AND collector_ids @> ARRAY['linux.baseline','linux.services'])`, r.AssetID, r.ID, r.Revision).Scan(&scheduled); e != nil {
		return ErrUnavailable
	}
	if !scheduled {
		r.Details.BaselineAuthorized = true
		if e = authorizeBaseline(ctx, tx, p, r); e != nil {
			return e
		}
	}
	if len(auth) == 2 {
		for i, name := range []string{"asterisk_auth", "asterisk_auth_helper"} {
			if e = grantMonitoring(ctx, tx, p, r, name, auth[i]); e != nil {
				return e
			}
		}
		if auth[0] {
			_, e = tx.Exec(ctx, `UPDATE collection_schedule SET collector_ids=array_append(collector_ids,'asterisk.auth'),revision=revision+1,budget_seconds=20 WHERE asset_id=$1 AND profile_id=$2 AND profile_revision=$3 AND NOT ('asterisk.auth'=ANY(collector_ids))`, r.AssetID, r.ID, r.Revision)
		} else {
			_, e = tx.Exec(ctx, `UPDATE collection_schedule SET collector_ids=array_remove(collector_ids,'asterisk.auth'),revision=revision+1,budget_seconds=20 WHERE asset_id=$1 AND profile_id=$2 AND profile_revision=$3 AND 'asterisk.auth'=ANY(collector_ids)`, r.AssetID, r.ID, r.Revision)
		}
		if e != nil {
			return ErrUnavailable
		}
	}
	if activity != nil {
		if e = grantMonitoring(ctx, tx, p, r, "asterisk_activity", *activity); e != nil {
			return e
		}
		if *activity {
			_, e = tx.Exec(ctx, `UPDATE collection_schedule SET collector_ids=array_append(collector_ids,'asterisk.activity'),revision=revision+1,budget_seconds=20 WHERE asset_id=$1 AND profile_id=$2 AND profile_revision=$3 AND NOT ('asterisk.activity'=ANY(collector_ids))`, r.AssetID, r.ID, r.Revision)
		} else {
			_, e = tx.Exec(ctx, `UPDATE collection_schedule SET collector_ids=array_remove(array_remove(collector_ids,'asterisk.activity'),'asterisk.media'),revision=revision+1,budget_seconds=20 WHERE asset_id=$1 AND profile_id=$2 AND profile_revision=$3 AND 'asterisk.activity'=ANY(collector_ids)`, r.AssetID, r.ID, r.Revision)
		}
		if e != nil {
			return ErrUnavailable
		}
	}
	if len(media) >= 1 {
		if e = grantMonitoring(ctx, tx, p, r, "asterisk_media", media[0]); e != nil {
			return e
		}
		if media[0] {
			_, e = tx.Exec(ctx, `UPDATE collection_schedule SET collector_ids=array_append(collector_ids,'asterisk.media'),revision=revision+1,budget_seconds=20 WHERE asset_id=$1 AND profile_id=$2 AND profile_revision=$3 AND NOT ('asterisk.media'=ANY(collector_ids))`, r.AssetID, r.ID, r.Revision)
		} else {
			_, e = tx.Exec(ctx, `UPDATE collection_schedule SET collector_ids=array_remove(collector_ids,'asterisk.media'),revision=revision+1,budget_seconds=20 WHERE asset_id=$1 AND profile_id=$2 AND profile_revision=$3 AND 'asterisk.media'=ANY(collector_ids)`, r.AssetID, r.ID, r.Revision)
		}
		if e != nil {
			return ErrUnavailable
		}
	}
	if len(media) == 2 {
		if e = grantMonitoring(ctx, tx, p, r, "mariadb", media[1]); e != nil {
			return e
		}
		if media[1] {
			_, e = tx.Exec(ctx, `UPDATE collection_schedule SET collector_ids=array_append(collector_ids,'mariadb.health'),revision=revision+1,budget_seconds=20 WHERE asset_id=$1 AND profile_id=$2 AND profile_revision=$3 AND NOT ('mariadb.health'=ANY(collector_ids))`, r.AssetID, r.ID, r.Revision)
		} else {
			_, e = tx.Exec(ctx, `UPDATE collection_schedule SET collector_ids=array_remove(collector_ids,'mariadb.health'),revision=revision+1,budget_seconds=20 WHERE asset_id=$1 AND profile_id=$2 AND profile_revision=$3 AND 'mariadb.health'=ANY(collector_ids)`, r.AssetID, r.ID, r.Revision)
		}
		if e != nil {
			return ErrUnavailable
		}
	}

	// Normalize after all additions/removals, including reauthorization of an
	// already expanded profile. Never change cadence, authority or pause state.
	if _, e = tx.Exec(ctx, `UPDATE collection_schedule SET budget_seconds=CASE WHEN cardinality(collector_ids)>8 THEN 40 ELSE LEAST(budget_seconds,20) END,revision=revision+1 WHERE asset_id=$1 AND profile_id=$2 AND profile_revision=$3 AND source_id IS NULL AND budget_seconds<>CASE WHEN cardinality(collector_ids)>8 THEN 40 ELSE LEAST(budget_seconds,20) END`, r.AssetID, r.ID, r.Revision); e != nil {
		return ErrUnavailable
	}

	_, e = tx.Exec(ctx, `INSERT INTO connection_audit(profile_id,principal_id,revision,operation,state,category) VALUES($1,$2,$3,'standard',$4,$5)`, r.ID, p.ID, r.Revision, r.State, map[bool]string{true: "standard_helper", false: "standard_local_cli"}[helper])
	if e != nil {
		return ErrUnavailable
	}
	return tx.Commit(ctx)
}

func grantMonitoring(ctx context.Context, tx pgx.Tx, p workspace.Principal, r connections.Record, name string, enabled bool) error {
	_, e := tx.Exec(ctx, `INSERT INTO collection_integration(profile_id,customer_id,environment_id,asset_id,endpoint_id,integration,profile_revision,enabled,actor) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(profile_id,integration) DO UPDATE SET profile_revision=excluded.profile_revision,enabled=excluded.enabled,actor=excluded.actor,revision=collection_integration.revision+1,updated_at=clock_timestamp() WHERE collection_integration.profile_revision<>excluded.profile_revision OR collection_integration.enabled<>excluded.enabled`, r.ID, r.CustomerID, r.EnvironmentID, r.AssetID, r.EndpointID, name, r.Revision, enabled, p.ID)
	if e != nil {
		return ErrUnavailable
	}
	return nil
}
func collectorsAllowed(ctx context.Context, q integrationQuery, p workspace.Principal, t sshcli.Target, ids []string) error {
	for _, id := range ids {
		if id == "mariadb.health" {
			if e := integrationAllowed(ctx, q, p, t, "mariadb"); e != nil {
				return e
			}
		}
		if id == "asterisk.media" {
			if err := integrationAllowed(ctx, q, p, t, "asterisk_media"); err != nil {
				return err
			}
			if err := integrationAllowed(ctx, q, p, t, "asterisk_activity"); err != nil {
				return err
			}
		}
		if id == "asterisk.activity" {
			if err := integrationAllowed(ctx, q, p, t, "asterisk_activity"); err != nil {
				return err
			}
		}
		if id == "asterisk.auth" {
			if err := integrationAllowed(ctx, q, p, t, "asterisk_auth"); err != nil {
				return err
			}
		}
		if strings.HasPrefix(id, "asterisk.") {
			if err := integrationAllowed(ctx, q, p, t, "asterisk"); err != nil {
				return err
			}
		}
		if id == "linux.baseline" {
			if err := integrationAllowed(ctx, q, p, t, "baseline"); err != nil {
				return err
			}
		}
		if id == "linux.services" {
			if err := integrationAllowed(ctx, q, p, t, "runtime_services"); err != nil {
				return err
			}
		}
		if id == "vicidial.discovery" {
			if err := integrationAllowed(ctx, q, p, t, "vicidial_discovery"); err != nil {
				return err
			}
		}
	}
	return nil
}

// Scheduling requires successful capability evidence from the opted-in current
// enrollment revision. Manual inspection establishes capabilities first.
func (s *Store) integrationCapabilities(ctx context.Context, p workspace.Principal, t sshcli.Target, ids []string) error {
	for _, id := range ids {
		if id == "asterisk.media" {
			if err := s.IntegrationAllowed(ctx, p, t, "asterisk_media"); err != nil {
				return err
			}
			if err := s.IntegrationAllowed(ctx, p, t, "asterisk_activity"); err != nil {
				return err
			}
		}
		if id == "asterisk.activity" {
			if err := s.IntegrationAllowed(ctx, p, t, "asterisk_activity"); err != nil {
				return err
			}
		}
		if id == "asterisk.auth" {
			continue
		} // Source unavailability must remain observable on its schedule.
		if !strings.HasPrefix(id, "asterisk.") {
			continue
		}
		var yes bool
		e := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM observation WHERE asset_id=$1 AND endpoint_id=$2 AND profile_id=$3 AND profile_revision=$4 AND key='asterisk.version' AND quality='valid')`, t.AssetID, t.EndpointID, t.ProfileID, t.ProfileVersion).Scan(&yes)
		if e != nil || !yes {
			return workspace.ErrDenied
		}
		e = s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM collector_result c JOIN collection_run r ON r.id=c.run_id WHERE r.asset_id=$1 AND r.endpoint_id=$2 AND r.profile_id=$3 AND r.profile_revision=$4 AND c.collector_id=$5 AND (c.outcome='success' OR ($5='asterisk.registrations' AND c.outcome='partial' AND EXISTS (SELECT 1 FROM observation o WHERE o.run_id=r.id AND o.collector_id=c.collector_id AND o.key='asterisk.registration.snapshot' AND o.resource NOT LIKE '%/%' AND o.quality='valid' AND CASE WHEN o.key='asterisk.registration.snapshot' THEN o.text_value::jsonb->>'status' END='supported'))))`, t.AssetID, t.EndpointID, t.ProfileID, t.ProfileVersion, id).Scan(&yes)
		if e != nil || !yes {
			return workspace.ErrDenied
		}
	}
	return nil
}

func (s *Store) SetStandardMonitoringWithMedia(ctx context.Context, p workspace.Principal, h collection.HistoryScope, t sshcli.Target, helper, auth, authHelper, active, media bool) error {
	if authHelper && !auth || media && !active {
		return workspace.ErrDenied
	}
	return s.setStandardMonitoring(ctx, p, h, t, helper, []bool{auth, authHelper}, &active, media)
}

// SetStandardMonitoringWithMariaDB adds only the disclosed fixed socket reader.
func (s *Store) SetStandardMonitoringWithMariaDB(ctx context.Context, p workspace.Principal, h collection.HistoryScope, t sshcli.Target, helper, auth, authHelper, active, media, database bool) error {
	if authHelper && !auth || media && !active {
		return workspace.ErrDenied
	}
	return s.setStandardMonitoring(ctx, p, h, t, helper, []bool{auth, authHelper}, &active, media, database)
}
