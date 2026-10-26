package web

import (
	"context"
	"net/http"
	"noc-workbench/internal/interchange"
	"noc-workbench/internal/store/postgres"
	"noc-workbench/internal/workspace"
)

type interchangeRepository interface {
	ExportInventory(context.Context, workspace.Principal, workspace.Scope) (interchange.Document, error)
	ImportInventory(context.Context, workspace.Principal, workspace.Scope, interchange.Document, bool) (postgres.InterchangeResult, error)
}
type interchangeData struct {
	JSON    string
	Preview bool
	Result  postgres.InterchangeResult
}

func (s *Server) inventoryInterchange(w http.ResponseWriter, r *http.Request) {
	d, ok := s.inventoryPage(w, r)
	if !ok {
		return
	}
	d.Active = "interchange"
	repo, ok := s.store.(interchangeRepository)
	if !ok {
		s.inventoryFailure(w, d, nil)
		return
	}
	permission := workspace.InventoryExport
	if r.Method == http.MethodPost {
		permission = workspace.InventoryImport
	}
	scope, e := (workspace.LocalOperatorPolicy{}).Scope(operatorPrincipal(), permission)
	if e != nil {
		http.Error(w, "access denied", 403)
		return
	}
	if r.Method == http.MethodGet && r.URL.Query().Get("download") != "" {
		var raw []byte
		if r.URL.Query().Get("download") == "example" {
			raw = append([]byte(nil), interchange.Example...)
		} else {
			doc, err := repo.ExportInventory(r.Context(), operatorPrincipal(), scope)
			if err != nil {
				d.Error = "Export unavailable or inventory exceeds the portable limit."
				s.renderStatus(w, 422, "interchange.html", d)
				return
			}
			raw, e = interchange.Encode(doc)
		}
		if e != nil {
			d.Error = e.Error()
			s.renderStatus(w, 422, "interchange.html", d)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="noc-workbench-sanitized-v1.json"`)
		_, _ = w.Write(raw)
		return
	}
	if r.Method == http.MethodPost {
		raw := []byte(r.PostForm.Get("document"))
		doc, err := interchange.Parse(raw)
		if err == nil {
			action := r.PostForm.Get("operation")
			if action != "preview" && action != "import" {
				http.Error(w, "invalid operation", 400)
				return
			}
			d.Interchange.Result, err = repo.ImportInventory(r.Context(), operatorPrincipal(), scope, doc, action == "preview")
			if err == nil {
				d.Interchange.JSON = string(raw)
				d.Interchange.Preview = action == "preview"
				if action == "import" {
					d.Notice = "Inventory import committed. Existing records were not overwritten."
				} else {
					d.Notice = "Preview complete. No database changes were retained."
				}
			}
		}
		if err != nil {
			d.Error = err.Error()
			s.renderStatus(w, 422, "interchange.html", d)
			return
		}
	}
	s.render(w, "interchange.html", d)
}
