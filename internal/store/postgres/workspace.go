package postgres

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"noc-workbench/internal/inventory"
	"noc-workbench/internal/workspace"
)

const workspaceCols = `v.kind,v.id::text,v.customer_id::text,coalesce(v.environment_id::text,''),v.label,v.customer,v.environment,v.lifecycle,v.summary`

// Scope predicate is applied before ordering/limits and note matching, never after retrieval.
const workspaceScope = `($1::boolean OR v.customer_id::text=ANY($2::text[]) OR v.environment_id::text=ANY($3::text[]))`

func scopeArgs(s workspace.Scope) []any { return []any{s.All, s.Customers, s.Environments} }
func scanTarget(row pgx.Row) (v workspace.Target, err error) {
	err = row.Scan(&v.Kind, &v.ID, &v.CustomerID, &v.EnvironmentID, &v.Label, &v.Customer, &v.Environment, &v.Lifecycle, &v.Summary)
	if err != nil {
		return v, topologyError(err)
	}
	v.URL = "/customers/" + v.CustomerID
	if v.Kind != "customers" {
		v.URL += "/environments/" + v.EnvironmentID
		if v.Kind != "environments" {
			v.URL += "/topology/" + v.Kind + "/" + v.ID
		}
	}
	return v, nil
}
func collectTargets(rows pgx.Rows) (items []workspace.Target, err error) {
	defer rows.Close()
	for rows.Next() {
		v, e := scanTarget(rows)
		if e != nil {
			return nil, e
		}
		items = append(items, v)
	}
	return items, topologyError(rows.Err())
}
func (s *Store) WorkspaceSearch(ctx context.Context, scope workspace.Scope, p workspace.Principal, q string, offset int) ([]workspace.Target, bool, error) {
	if !inventory.ValidID(p.ID) || offset < 0 || offset > 1000 || len(q) > 300 {
		return nil, false, workspace.ErrDenied
	}
	args := append(scopeArgs(scope), q, p.ID, offset)
	rows, e := s.pool.Query(ctx, `SELECT `+workspaceCols+` FROM workspace_inventory v WHERE `+workspaceScope+` AND ($4='' OR v.document @@ to_tsquery('simple',$4) OR (v.kind='assets' AND EXISTS(SELECT 1 FROM cluster_membership m WHERE m.asset_id=v.id AND to_tsvector('simple',m.role) @@ to_tsquery('simple',$4))) OR EXISTS(SELECT 1 FROM operator_note n JOIN workspace_target t ON t.id=n.target_id WHERE t.kind=v.kind AND t.resource_id=v.id AND (n.visibility='shared' OR n.principal_id=$5::uuid) AND to_tsvector('simple',n.body) @@ to_tsquery('simple',$4))) ORDER BY v.kind,lower(v.label),v.id LIMIT 26 OFFSET $6`, args...)
	if e != nil {
		return nil, false, topologyError(e)
	}
	items, e := collectTargets(rows)
	more := len(items) > 25 && offset+25 <= 1000
	if len(items) > 25 {
		items = items[:25]
	}
	return items, more, e
}
func (s *Store) WorkspaceTarget(ctx context.Context, scope workspace.Scope, kind, id string) (workspace.Target, error) {
	if !inventory.ValidID(id) {
		return workspace.Target{}, inventory.ErrNotFound
	}
	return scanTarget(s.pool.QueryRow(ctx, `SELECT `+workspaceCols+` FROM workspace_inventory v WHERE `+workspaceScope+` AND v.kind=$4 AND v.id=$5`, append(scopeArgs(scope), kind, id)...))
}
func (s *Store) WorkspaceTargets(ctx context.Context, scope workspace.Scope, p workspace.Principal, pins bool) ([]workspace.Target, error) {
	if !inventory.ValidID(p.ID) {
		return nil, workspace.ErrDenied
	}
	query := `SELECT ` + workspaceCols + ` FROM workspace_pin x JOIN workspace_target t ON t.id=x.target_id JOIN workspace_inventory v ON v.kind=t.kind AND v.id=t.resource_id WHERE ` + workspaceScope + ` AND x.principal_id=$4 ORDER BY x.created_at,x.target_id LIMIT 100`
	if !pins {
		query = `SELECT ` + workspaceCols + ` FROM workspace_recent x JOIN workspace_target t ON t.id=x.target_id JOIN workspace_inventory v ON v.kind=t.kind AND v.id=t.resource_id WHERE ` + workspaceScope + ` AND x.principal_id=$4 ORDER BY x.visited_at DESC,x.target_id LIMIT 20`
	}
	rows, e := s.pool.Query(ctx, query, append(scopeArgs(scope), p.ID)...)
	if e != nil {
		return nil, topologyError(e)
	}
	return collectTargets(rows)
}
func (s *Store) WorkspaceNotes(ctx context.Context, scope workspace.Scope, p workspace.Principal, t workspace.Target) ([]workspace.Note, error) {
	if _, e := s.WorkspaceTarget(ctx, scope, t.Kind, t.ID); e != nil {
		return nil, e
	}
	rows, e := s.pool.Query(ctx, `SELECT n.id::text,n.principal_id::text,n.body,n.visibility,to_char(n.updated_at AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS "UTC"') FROM operator_note n JOIN workspace_target t ON t.id=n.target_id WHERE t.kind=$1 AND t.resource_id=$2 AND (n.principal_id=$3 OR n.visibility='shared') ORDER BY n.updated_at DESC,n.id LIMIT 100`, t.Kind, t.ID, p.ID)
	if e != nil {
		return nil, topologyError(e)
	}
	defer rows.Close()
	var items []workspace.Note
	for rows.Next() {
		var n workspace.Note
		if e = rows.Scan(&n.ID, &n.PrincipalID, &n.Body, &n.Visibility, &n.UpdatedAt); e != nil {
			return nil, topologyError(e)
		}
		items = append(items, n)
	}
	return items, topologyError(rows.Err())
}
func (s *Store) WorkspaceLinks(ctx context.Context, scope workspace.Scope, p workspace.Principal, t workspace.Target) ([]workspace.Link, error) {
	if _, e := s.WorkspaceTarget(ctx, scope, t.Kind, t.ID); e != nil {
		return nil, e
	}
	rows, e := s.pool.Query(ctx, `SELECT l.id::text,l.label,l.url,l.type,to_char(l.updated_at AT TIME ZONE 'UTC','YYYY-MM-DD HH24:MI:SS "UTC"'),l.pinned,l.enabled FROM external_link l JOIN workspace_target t ON t.id=l.target_id WHERE t.kind=$1 AND t.resource_id=$2 ORDER BY l.pinned DESC,lower(l.label),l.id LIMIT 100`, t.Kind, t.ID)
	if e != nil {
		return nil, topologyError(e)
	}
	defer rows.Close()
	var items []workspace.Link
	for rows.Next() {
		var l workspace.Link
		if e = rows.Scan(&l.ID, &l.Label, &l.URL, &l.Type, &l.UpdatedAt, &l.Pinned, &l.Enabled); e != nil {
			return nil, topologyError(e)
		}
		items = append(items, l)
	}
	return items, topologyError(rows.Err())
}
func (s *Store) WorkspaceChange(ctx context.Context, scope workspace.Scope, p workspace.Principal, t workspace.Target, c workspace.Change) error {
	current, e := s.WorkspaceTarget(ctx, scope, t.Kind, t.ID)
	if e != nil {
		return e
	}
	if !inventory.ValidID(p.ID) {
		return workspace.ErrDenied
	}
	if current.Lifecycle != "active" && c.Operation != "unpin" && c.Operation != "note.remove" && c.Operation != "link.remove" && c.Operation != "visit" {
		return inventory.ErrInactive
	}
	if c.ID != "" && !inventory.ValidID(c.ID) {
		return inventory.ErrNotFound
	}
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return topologyError(e)
	}
	defer tx.Rollback(context.Background())
	var ref string
	e = tx.QueryRow(ctx, `INSERT INTO workspace_target(kind,customer_id,environment_id,cluster_id,asset_id,endpoint_id,service_id,instance_id) VALUES($1,$2,NULLIF($3,'')::uuid,CASE WHEN $1='clusters' THEN $4::uuid END,CASE WHEN $1='assets' THEN $4::uuid END,CASE WHEN $1='endpoints' THEN $4::uuid END,CASE WHEN $1='services' THEN $4::uuid END,CASE WHEN $1='instances' THEN $4::uuid END) ON CONFLICT(kind,resource_id) DO NOTHING RETURNING id::text`, current.Kind, current.CustomerID, current.EnvironmentID, current.ID).Scan(&ref)
	if errors.Is(e, pgx.ErrNoRows) {
		e = tx.QueryRow(ctx, `SELECT id::text FROM workspace_target WHERE kind=$1 AND resource_id=$2`, current.Kind, current.ID).Scan(&ref)
	}
	if e != nil {
		return topologyError(e)
	}
	// Serialize bounded collections, including concurrent creates, before counting.
	if _, e = tx.Exec(ctx, `SELECT id FROM workspace_principal WHERE id=$1 FOR UPDATE`, p.ID); e != nil {
		return topologyError(e)
	}
	if _, e = tx.Exec(ctx, `SELECT id FROM workspace_target WHERE id=$1 FOR UPDATE`, ref); e != nil {
		return topologyError(e)
	}
	var count int
	switch {
	case c.Operation == "pin":
		e = tx.QueryRow(ctx, `SELECT CASE WHEN EXISTS(SELECT 1 FROM workspace_pin WHERE principal_id=$1 AND target_id=$2) THEN 0 ELSE (SELECT count(*) FROM workspace_pin WHERE principal_id=$1) END`, p.ID, ref).Scan(&count)
	case c.Operation == "note.save" && c.ID == "":
		e = tx.QueryRow(ctx, `SELECT count(*) FROM operator_note WHERE target_id=$1`, ref).Scan(&count)
	case c.Operation == "link.save" && c.ID == "":
		e = tx.QueryRow(ctx, `SELECT count(*) FROM external_link WHERE target_id=$1`, ref).Scan(&count)
	}
	if e != nil {
		return topologyError(e)
	}
	if count >= 100 {
		return workspace.ErrLimit
	}
	var affected int64 = 1
	exec := func(q string, args ...any) {
		if e != nil {
			return
		}
		var tag interface{ RowsAffected() int64 }
		tag, e = tx.Exec(ctx, q, args...)
		if e == nil {
			affected = tag.RowsAffected()
		}
	}
	switch c.Operation {
	case "visit":
		// Serialize per-principal retention: concurrent visits cannot exceed the cap.
		if _, e = tx.Exec(ctx, `SELECT id FROM workspace_principal WHERE id=$1 FOR UPDATE`, p.ID); e != nil {
			return topologyError(e)
		}
		exec(`INSERT INTO workspace_recent(principal_id,target_id) VALUES($1,$2) ON CONFLICT(principal_id,target_id) DO UPDATE SET visited_at=clock_timestamp()`, p.ID, ref)
		exec(`DELETE FROM workspace_recent WHERE principal_id=$1 AND target_id NOT IN(SELECT target_id FROM workspace_recent WHERE principal_id=$1 ORDER BY visited_at DESC,target_id LIMIT 20)`, p.ID)
	case "pin":
		exec(`INSERT INTO workspace_pin(principal_id,target_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, p.ID, ref)
	case "unpin":
		exec(`DELETE FROM workspace_pin WHERE principal_id=$1 AND target_id=$2`, p.ID, ref)
	case "note.save":
		body, err := workspace.ValidateNote(c.Body, c.Visibility)
		if err != nil {
			return err
		}
		if c.ID == "" {
			exec(`INSERT INTO operator_note(target_id,principal_id,body,visibility) VALUES($1,$2,$3,$4)`, ref, p.ID, body, c.Visibility)
		} else {
			exec(`UPDATE operator_note SET body=$4,visibility=$5,updated_at=clock_timestamp() WHERE target_id=$1 AND principal_id=$2 AND id=$3`, ref, p.ID, c.ID, body, c.Visibility)
		}
	case "note.remove":
		exec(`DELETE FROM operator_note WHERE target_id=$1 AND principal_id=$2 AND id=$3`, ref, p.ID, c.ID)
	case "link.save":
		if current.Kind != "customers" && current.Kind != "environments" && current.Kind != "clusters" {
			return workspace.ErrDenied
		}
		if err := workspace.ValidateLink(c.Label, c.URL, c.Type); err != nil {
			return err
		}
		if c.ID == "" {
			exec(`INSERT INTO external_link(target_id,principal_id,label,url,type,pinned,enabled) VALUES($1,$2,$3,$4,$5,$6,$7)`, ref, p.ID, c.Label, c.URL, c.Type, c.Pinned, !c.Disabled)
		} else {
			exec(`UPDATE external_link SET label=$4,url=$5,type=$6,pinned=$7,enabled=$8,updated_at=clock_timestamp() WHERE target_id=$1 AND principal_id=$2 AND id=$3`, ref, p.ID, c.ID, c.Label, c.URL, c.Type, c.Pinned, !c.Disabled)
		}
	case "link.remove":
		exec(`DELETE FROM external_link WHERE target_id=$1 AND principal_id=$2 AND id=$3`, ref, p.ID, c.ID)
	case "command.copy":
		if current.Kind != "endpoints" {
			return workspace.ErrDenied
		}
	default:
		return workspace.ErrDenied
	}
	if e != nil {
		return topologyError(e)
	}
	if affected == 0 && (c.Operation == "note.save" || c.Operation == "note.remove" || c.Operation == "link.save" || c.Operation == "link.remove") {
		return inventory.ErrNotFound
	}
	if c.Operation != "visit" {
		if _, e = tx.Exec(ctx, `INSERT INTO workspace_audit(principal_id,target_id,operation) VALUES($1,$2,$3)`, p.ID, ref, c.Operation); e != nil {
			return topologyError(e)
		}
	}
	return topologyError(tx.Commit(ctx))
}

// Related cluster context remains authorized before retrieval, including host roles.
func (s *Store) WorkspaceRelated(ctx context.Context, scope workspace.Scope, t workspace.Target) ([]workspace.Target, error) {
	if _, e := s.WorkspaceTarget(ctx, scope, t.Kind, t.ID); e != nil {
		return nil, e
	}
	if t.Kind != "clusters" {
		return nil, nil
	}
	cols := workspaceCols + `,coalesce((SELECT m.role FROM cluster_membership m WHERE m.cluster_id=$4 AND m.asset_id=v.id),'')`
	rows, e := s.pool.Query(ctx, `SELECT `+cols+` FROM workspace_inventory v WHERE `+workspaceScope+` AND v.environment_id=$5 AND ((v.kind='assets' AND EXISTS(SELECT 1 FROM cluster_membership m WHERE m.cluster_id=$4 AND m.asset_id=v.id)) OR (v.kind='services' AND EXISTS(SELECT 1 FROM service s WHERE s.id=v.id AND s.cluster_id=$4)) OR (v.kind='instances' AND EXISTS(SELECT 1 FROM service_instance i JOIN service s ON s.id=i.service_id WHERE i.id=v.id AND s.cluster_id=$4))) ORDER BY v.kind,lower(v.label),v.id LIMIT 100`, append(scopeArgs(scope), t.ID, t.EnvironmentID)...)
	if e != nil {
		return nil, topologyError(e)
	}
	defer rows.Close()
	var out []workspace.Target
	for rows.Next() {
		var v workspace.Target
		var role string
		e = rows.Scan(&v.Kind, &v.ID, &v.CustomerID, &v.EnvironmentID, &v.Label, &v.Customer, &v.Environment, &v.Lifecycle, &v.Summary, &role)
		if e != nil {
			return nil, topologyError(e)
		}
		v.URL = "/customers/" + v.CustomerID + "/environments/" + v.EnvironmentID + "/topology/" + v.Kind + "/" + v.ID
		if role != "" {
			v.Summary += " · membership role: " + role
		}
		out = append(out, v)
	}
	return out, topologyError(rows.Err())
}
