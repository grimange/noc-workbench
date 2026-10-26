package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"noc-workbench/internal/interchange"
	"noc-workbench/internal/workspace"
	"strings"
)

type InterchangeResult struct {
	Create, Reuse int
	DryRun        bool
}

func interchangeAccess(p workspace.Principal, scope workspace.Scope) error {
	// Partial-scope interchange is intentionally denied until a complete scoped graph
	// policy exists. This is the actual single-operator boundary, not future RBAC.
	if p.ID != workspace.OperatorID || !scope.All {
		return workspace.ErrDenied
	}
	return nil
}
func recordFields(d interchange.Definition) string {
	parts := []string{}
	for _, c := range d.Columns {
		v := c
		if c == "cluster_id" {
			v = "coalesce(cluster_id::text,'')"
		}
		parts = append(parts, "'"+c+"',"+v)
	}
	return "jsonb_build_object(" + strings.Join(parts, ",") + ")"
}
func (s *Store) ExportInventory(ctx context.Context, p workspace.Principal, scope workspace.Scope) (interchange.Document, error) {
	d := interchange.Document{Format: interchange.Format, Version: interchange.Version, Records: []interchange.Record{}}
	if e := interchangeAccess(p, scope); e != nil {
		return d, e
	}
	tx, e := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if e != nil {
		return d, errors.New("Inventory export unavailable.")
	}
	defer tx.Rollback(context.Background())
	for _, def := range interchange.Definitions {
		rows, e := tx.Query(ctx, "SELECT id::text,"+recordFields(def)+" FROM "+def.Table+" ORDER BY id LIMIT 501")
		if e != nil {
			return d, errors.New("Inventory export unavailable.")
		}
		for rows.Next() {
			var r interchange.Record
			var raw []byte
			r.Type = def.Table
			if e = rows.Scan(&r.ID, &raw); e != nil {
				rows.Close()
				return d, e
			}
			dec := json.NewDecoder(strings.NewReader(string(raw)))
			dec.UseNumber()
			if e = dec.Decode(&r.Fields); e != nil {
				rows.Close()
				return d, e
			}
			d.Records = append(d.Records, r)
			if len(d.Records) > interchange.MaxRecords {
				rows.Close()
				return d, errors.New("Inventory exceeds the 500-record portable export limit.")
			}
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return d, errors.New("Inventory export unavailable.")
		}
	}
	if e = tx.Commit(ctx); e != nil {
		return d, errors.New("Inventory export unavailable.")
	}
	d = interchange.Sanitize(d)
	return d, interchange.Validate(d)
}
func (s *Store) ImportInventory(ctx context.Context, p workspace.Principal, scope workspace.Scope, d interchange.Document, dry bool) (InterchangeResult, error) {
	result := InterchangeResult{DryRun: dry}
	if e := interchangeAccess(p, scope); e != nil {
		return result, e
	}
	if e := interchange.Validate(d); e != nil {
		return result, e
	}
	interchange.Sort(&d)
	tx, e := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if e != nil {
		return result, errors.New("Inventory import unavailable.")
	}
	defer tx.Rollback(context.Background())
	// Serialize imports; canonical constraints and triggers still arbitrate other writers.
	if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(617203301)"); e != nil {
		return result, errors.New("Inventory import unavailable.")
	}
	created := []interchange.Record{}
	for i, r := range d.Records {
		def, _ := interchange.DefinitionFor(r.Type)
		raw, _ := json.Marshal(r.Fields)
		var identical bool
		e = tx.QueryRow(ctx, "SELECT "+recordFields(def)+"=$2::jsonb FROM "+def.Table+" WHERE id=$1", r.ID, raw).Scan(&identical)
		if e == nil {
			if !identical {
				return result, fmt.Errorf("Record %d (%s): existing UUID has conflicting content; nothing was imported.", i+1, r.Type)
			}
			result.Reuse++
			continue
		}
		if !errors.Is(e, pgx.ErrNoRows) {
			return result, errors.New("Inventory import unavailable; retry the preview.")
		}
		cols := append([]string{"id"}, def.Columns...)
		args := []any{r.ID}
		marks := []string{"$1"}
		for _, c := range def.Columns {
			v := r.Fields[c]
			if c == "cluster_id" && v == "" {
				v = nil
			}
			if c == "port" {
				n, _ := v.(json.Number).Int64()
				v = int(n)
			}
			if (c == "status" || c == "lifecycle") && v == "archived" && r.Type != "asset_endpoint" {
				v = "active"
			}
			args = append(args, v)
			marks = append(marks, fmt.Sprintf("$%d", len(args)))
		}
		if _, e = tx.Exec(ctx, "INSERT INTO "+def.Table+"("+strings.Join(cols, ",")+") VALUES("+strings.Join(marks, ",")+")", args...); e != nil {
			return result, fmt.Errorf("Record %d (%s): identity/name/address collision or invalid lifecycle/relationship; nothing was imported.", i+1, r.Type)
		}
		created = append(created, r)
		result.Create++
	}
	// Restore archived descendants before ancestors, retaining historical edges.
	for i := len(created) - 1; i >= 0; i-- {
		r := created[i]
		col := "lifecycle"
		if r.Type == "customer" || r.Type == "environment" || r.Type == "asset_endpoint" {
			col = "status"
		}
		if r.String(col) == "archived" {
			if _, e = tx.Exec(ctx, "UPDATE "+r.Type+" SET "+col+"='archived' WHERE id=$1", r.ID); e != nil {
				return result, errors.New("Archived inventory could not be reconstructed; nothing was imported.")
			}
		}
	}
	if dry {
		if e = tx.Rollback(ctx); e != nil {
			return result, errors.New("Preview could not finish.")
		}
		return result, nil
	}
	if e = tx.Commit(ctx); e != nil {
		return result, errors.New("Inventory changed concurrently; nothing was imported. Run preview again.")
	}
	return result, nil
}
