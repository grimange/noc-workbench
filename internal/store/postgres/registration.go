package postgres

import (
	"context"
	"noc-workbench/internal/inventory"
	"noc-workbench/internal/workspace"
)

// RegisterServer serializes registration against the owner so duplicate addresses,
// scope selection and the asset/endpoint insertion are one atomic operation.
func (s *Store) RegisterServer(ctx context.Context, actor workspace.Principal, v workspace.Registration) (out workspace.RegisteredServer, err error) {
	scope, err := (workspace.LocalOperatorPolicy{}).Scope(actor, workspace.Organize)
	if err != nil {
		return out, err
	}
	v, err = workspace.ValidateRegistration(v)
	if err != nil {
		return out, err
	}
	if !scope.Allows(v.CustomerID, v.EnvironmentID) {
		return out, workspace.ErrDenied
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return out, inventory.ErrUnavailable
	}
	defer tx.Rollback(context.Background())
	var status string
	if err = tx.QueryRow(ctx, `SELECT status FROM customer WHERE id=$1 FOR UPDATE`, v.CustomerID).Scan(&status); err != nil {
		return out, inventoryError(err)
	}
	if status != "active" {
		return out, inventory.ErrArchived
	}
	if v.EnvironmentID != "" {
		if err = tx.QueryRow(ctx, `SELECT status FROM environment WHERE id=$1 AND customer_id=$2 FOR UPDATE`, v.EnvironmentID, v.CustomerID).Scan(&status); err != nil {
			return out, inventoryError(err)
		}
		if status != "active" {
			return out, inventory.ErrInactive
		}
	} else {
		rows, e := tx.Query(ctx, `SELECT id::text FROM environment WHERE customer_id=$1 AND status='active' ORDER BY id LIMIT 2`, v.CustomerID)
		if e != nil {
			return out, inventoryError(e)
		}
		var ids []string
		for rows.Next() {
			var id string
			if e = rows.Scan(&id); e != nil {
				break
			}
			ids = append(ids, id)
		}
		e2 := rows.Err()
		rows.Close()
		if e != nil || e2 != nil {
			return out, inventory.ErrUnavailable
		}
		switch len(ids) {
		case 0:
			if err = tx.QueryRow(ctx, `INSERT INTO environment(customer_id,name,kind,status) SELECT $1, candidate.name,'production','active' FROM (SELECT 'Monitoring' AS name,0 AS ordinal UNION ALL SELECT 'Monitoring ' || n::text,n FROM generate_series(2,10002) n) candidate WHERE NOT EXISTS(SELECT 1 FROM environment e WHERE e.customer_id=$1 AND lower(e.name)=lower(candidate.name)) ORDER BY candidate.ordinal LIMIT 1 RETURNING id::text`, v.CustomerID).Scan(&v.EnvironmentID); err != nil {
				return out, inventoryError(err)
			}
		case 1:
			v.EnvironmentID = ids[0]
		default:
			return out, inventory.FieldErrors{"placement": "This customer has several registration groups. Choose the existing group for this server."}
		}
	}
	var duplicate bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM asset_endpoint ep JOIN environment e ON e.id=ep.environment_id WHERE e.customer_id=$1 AND ep.protocol='ssh' AND ep.host=$2 AND ep.port=$3)`, v.CustomerID, v.Host, v.Port).Scan(&duplicate); err != nil {
		return out, inventoryError(err)
	}
	if duplicate {
		return out, inventory.FieldErrors{"address": "This SSH destination is already registered for this customer. Open the existing server."}
	}
	out.Asset, err = scanAsset(tx.QueryRow(ctx, `INSERT INTO asset(environment_id,name,kind,lifecycle) VALUES($1,$2,'server','active') RETURNING `+assetColumns, v.EnvironmentID, v.Name))
	if err != nil {
		return out, err
	}
	out.Endpoint, err = scanEndpoint(tx.QueryRow(ctx, `INSERT INTO asset_endpoint(environment_id,asset_id,protocol,host,port,preferred,status) VALUES($1,$2,'ssh',$3,$4,true,'active') RETURNING `+endpointColumns, v.EnvironmentID, out.Asset.ID, v.Host, v.Port))
	if err != nil {
		return out, err
	}
	if err = tx.Commit(ctx); err != nil {
		return workspace.RegisteredServer{}, inventory.ErrUnavailable
	}
	return out, nil
}
