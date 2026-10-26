package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"noc-workbench/internal/inventory"
)

var _ inventory.Repository = (*Store)(nil)

func inventoryError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return inventory.ErrNotFound
	}
	var p *pgconn.PgError
	if errors.As(err, &p) {
		switch p.ConstraintName {
		case "customer_display_name_key":
			return inventory.FieldErrors{"display_name": "A customer with this name already exists."}
		case "customer_short_code_key":
			return inventory.FieldErrors{"short_code": "This short code is already in use."}
		case "environment_customer_name_key":
			return inventory.FieldErrors{"name": "This customer already has an environment with this name."}
		case "environment_customer_active":
			return inventory.ErrArchived
		}
		if p.Code == "23503" {
			return inventory.ErrNotFound
		}
	}
	return inventory.ErrUnavailable
}

const customerColumns = `id::text, display_name, short_code, notes, status, created_at, updated_at`

func scanCustomer(row pgx.Row) (c inventory.Customer, err error) {
	err = row.Scan(&c.ID, &c.DisplayName, &c.ShortCode, &c.Notes, &c.Status, &c.CreatedAt, &c.UpdatedAt)
	return c, inventoryError(err)
}
func (s *Store) ListCustomers(ctx context.Context) ([]inventory.Customer, error) {
	rows, err := s.pool.Query(ctx, `SELECT c.id::text,c.display_name,c.short_code,c.notes,c.status,c.created_at,c.updated_at,count(e.id) FROM customer c LEFT JOIN environment e ON e.customer_id=c.id GROUP BY c.id ORDER BY lower(c.display_name),c.id`)
	if err != nil {
		return nil, inventoryError(err)
	}
	defer rows.Close()
	items := []inventory.Customer{}
	for rows.Next() {
		var c inventory.Customer
		if err := rows.Scan(&c.ID, &c.DisplayName, &c.ShortCode, &c.Notes, &c.Status, &c.CreatedAt, &c.UpdatedAt, &c.EnvironmentCount); err != nil {
			return nil, inventoryError(err)
		}
		items = append(items, c)
	}
	return items, inventoryError(rows.Err())
}
func (s *Store) Customer(ctx context.Context, id string) (inventory.Customer, error) {
	if !inventory.ValidID(id) {
		return inventory.Customer{}, inventory.ErrNotFound
	}
	return scanCustomer(s.pool.QueryRow(ctx, `SELECT `+customerColumns+` FROM customer WHERE id=$1`, id))
}
func (s *Store) CreateCustomer(ctx context.Context, c inventory.Customer) (inventory.Customer, error) {
	c, err := inventory.ValidateCustomer(c)
	if err != nil {
		return c, err
	}
	return scanCustomer(s.pool.QueryRow(ctx, `INSERT INTO customer(display_name,short_code,notes,status) VALUES($1,$2,$3,$4) RETURNING `+customerColumns, c.DisplayName, c.ShortCode, c.Notes, c.Status))
}
func (s *Store) UpdateCustomer(ctx context.Context, c inventory.Customer) (inventory.Customer, error) {
	if !inventory.ValidID(c.ID) {
		return c, inventory.ErrNotFound
	}
	c, err := inventory.ValidateCustomer(c)
	if err != nil {
		return c, err
	}
	return scanCustomer(s.pool.QueryRow(ctx, `UPDATE customer SET display_name=$2,short_code=$3,notes=$4,status=$5,updated_at=CURRENT_TIMESTAMP WHERE id=$1 RETURNING `+customerColumns, c.ID, c.DisplayName, c.ShortCode, c.Notes, c.Status))
}

const environmentColumns = `id::text,customer_id::text,name,kind,status,created_at,updated_at`

func scanEnvironment(row pgx.Row) (e inventory.Environment, err error) {
	err = row.Scan(&e.ID, &e.CustomerID, &e.Name, &e.Kind, &e.Status, &e.CreatedAt, &e.UpdatedAt)
	return e, inventoryError(err)
}
func (s *Store) ListEnvironments(ctx context.Context, customerID string) ([]inventory.Environment, error) {
	if !inventory.ValidID(customerID) {
		return nil, inventory.ErrNotFound
	}
	rows, err := s.pool.Query(ctx, `SELECT `+environmentColumns+` FROM environment WHERE customer_id=$1 ORDER BY lower(name),id`, customerID)
	if err != nil {
		return nil, inventoryError(err)
	}
	defer rows.Close()
	items := []inventory.Environment{}
	for rows.Next() {
		e, err := scanEnvironment(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, e)
	}
	return items, inventoryError(rows.Err())
}
func (s *Store) Environment(ctx context.Context, customerID, id string) (inventory.Environment, error) {
	if !inventory.ValidID(customerID) || !inventory.ValidID(id) {
		return inventory.Environment{}, inventory.ErrNotFound
	}
	return scanEnvironment(s.pool.QueryRow(ctx, `SELECT `+environmentColumns+` FROM environment WHERE customer_id=$1 AND id=$2`, customerID, id))
}
func (s *Store) CreateEnvironment(ctx context.Context, e inventory.Environment) (inventory.Environment, error) {
	e, err := inventory.ValidateEnvironment(e)
	if err != nil {
		return e, err
	}
	return scanEnvironment(s.pool.QueryRow(ctx, `INSERT INTO environment(customer_id,name,kind,status) VALUES($1,$2,$3,$4) RETURNING `+environmentColumns, e.CustomerID, e.Name, e.Kind, e.Status))
}
func (s *Store) UpdateEnvironment(ctx context.Context, e inventory.Environment) (inventory.Environment, error) {
	if !inventory.ValidID(e.ID) {
		return e, inventory.ErrNotFound
	}
	e, err := inventory.ValidateEnvironment(e)
	if err != nil {
		return e, err
	}
	return scanEnvironment(s.pool.QueryRow(ctx, `UPDATE environment SET name=$3,kind=$4,status=$5,updated_at=CURRENT_TIMESTAMP WHERE customer_id=$1 AND id=$2 RETURNING `+environmentColumns, e.CustomerID, e.ID, e.Name, e.Kind, e.Status))
}
