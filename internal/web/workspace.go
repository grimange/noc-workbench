package web

import (
	"errors"
	"net/http"
	"noc-workbench/internal/inventory"
	"noc-workbench/internal/workspace"
)

type workspaceData struct {
	Target workspace.Target

	Notes []workspace.Note
	Links []workspace.Link

	CanLink bool
}

func (s *Server) workspaceService() (workspace.Service, bool) {
	repo, ok := s.store.(workspace.Repository)
	return workspace.Service{Repository: repo, Policy: workspace.LocalOperatorPolicy{}}, ok
}

// Authentication establishes this one persistent actor. Sessions are deliberately
// not durable owners. Future account authentication must supply its own principal.
func operatorPrincipal() workspace.Principal { return workspace.Principal{ID: workspace.OperatorID} }
func (s *Server) operatorWorkspace(w http.ResponseWriter, r *http.Request) {
	d, ok := s.inventoryPage(w, r)
	if !ok {
		return
	}
	d.Active = "workspace"
	svc, ok := s.workspaceService()
	if !ok {
		s.inventoryFailure(w, d, inventory.ErrUnavailable)
		return
	}
	p := operatorPrincipal()
	kind, id := r.PathValue("targetkind"), r.PathValue("targetid")
	var err error
	if kind == "" {
		http.Redirect(w, r, "/servers", 303)
		return
	}
	d.Workspace.Target, err = svc.Target(r.Context(), p, kind, id)
	if err == nil {
		t := d.Workspace.Target
		d.Workspace.CanLink = kind == "customers" || kind == "environments" || kind == "clusters"
		if r.Method == http.MethodPost {
			op := r.PostForm.Get("operation")
			switch op {
			case "note.save", "note.remove", "link.save", "link.remove":
			default:
				http.Error(w, "This operation has been retired", http.StatusGone)
				return
			}
			err = svc.Change(r.Context(), p, t, workspace.Change{Operation: op, ID: r.PostForm.Get("id"), Body: r.PostForm.Get("body"), Visibility: r.PostForm.Get("visibility"), Label: r.PostForm.Get("label"), URL: r.PostForm.Get("url"), Type: r.PostForm.Get("type"), Pinned: r.PostForm.Get("pinned") == "on", Disabled: r.PostForm.Get("disabled") == "on"})
			if err == nil {
				http.Redirect(w, r, t.QuickURL()+"?saved=1", http.StatusSeeOther)
				return
			}
		}
		if err == nil {
			d.Workspace.Notes, err = svc.Notes(r.Context(), p, t)
		}
		if err == nil {
			d.Workspace.Links, err = svc.Links(r.Context(), p, t)
		}
	}
	if err != nil {
		if errors.Is(err, inventory.ErrNotFound) || errors.Is(err, inventory.ErrUnavailable) || errors.Is(err, inventory.ErrInactive) {
			s.inventoryFailure(w, d, err)
			return
		}
		if errors.Is(err, workspace.ErrDenied) {
			http.Error(w, "access denied", 403)
			return
		}
		d.Error = "The workspace change could not be saved. Check the fields and selected resource."
		// Domain validation errors contain only fixed operator-facing text.
		var fields inventory.FieldErrors
		if errors.As(err, &fields) {
			d.Error = fields.Error()
		} else {
			d.Error = err.Error()
		}
		s.renderStatus(w, 422, "workspace.html", d)
		return
	}
	if r.URL.Query().Get("saved") == "1" {
		d.Notice = "Notes or links saved."
	}
	s.render(w, "workspace.html", d)
}
