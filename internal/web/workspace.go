package web

import (
	"errors"
	"net/http"
	"noc-workbench/internal/inventory"
	"noc-workbench/internal/workspace"
	"strconv"
)

type workspaceData struct {
	Target                            workspace.Target
	Results, Pins, Recent, Related    []workspace.Target
	Notes                             []workspace.Note
	Links                             []workspace.Link
	Query, Command                    string
	Offset, Next, Previous            int
	More, CanPin, CanLink, CanCommand bool
}

func (s *Server) workspaceService() (workspace.Service, bool) {
	repo, ok := s.store.(workspace.Repository)
	return workspace.Service{Repository: repo, Policy: workspace.LocalOperatorPolicy{}}, ok
}

// Authentication establishes this one persistent actor. Sessions are deliberately
// not durable owners. Future account authentication must supply its own principal.
func operatorPrincipal() workspace.Principal { return workspace.Principal{ID: workspace.OperatorID} }
func (s *Server) workspaceVisit(r *http.Request, kind, id string) {
	svc, ok := s.workspaceService()
	if !ok {
		return
	}
	t, e := svc.Target(r.Context(), operatorPrincipal(), kind, id)
	if e == nil {
		_ = svc.Change(r.Context(), operatorPrincipal(), t, workspace.Change{Operation: "visit"})
	}
}
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
		d.Workspace.Query = r.URL.Query().Get("q")
		offset := 0
		if raw := r.URL.Query().Get("offset"); raw != "" {
			offset, err = strconv.Atoi(raw)
			if err != nil || offset < 0 || offset > 1000 {
				http.Error(w, "Invalid search offset", 400)
				return
			}
		}
		d.Workspace.Offset = offset
		d.Workspace.Next = offset + 25
		d.Workspace.Previous = max(0, offset-25)
		d.Workspace.Results, d.Workspace.More, err = svc.Search(r.Context(), p, d.Workspace.Query, offset)
		if err == nil {
			d.Workspace.Pins, err = svc.Targets(r.Context(), p, true)
		}
		if err == nil {
			d.Workspace.Recent, err = svc.Targets(r.Context(), p, false)
		}
	} else {
		d.Workspace.Target, err = svc.Target(r.Context(), p, kind, id)
		if err == nil {
			t := d.Workspace.Target
			d.Workspace.CanPin = kind == "customers" || kind == "clusters" || kind == "assets"
			d.Workspace.CanLink = kind == "customers" || kind == "environments" || kind == "clusters"
			if kind == "endpoints" && t.Lifecycle == "active" {
				repo, yes := s.store.(inventory.TopologyRepository)
				if yes {
					ep, e := repo.GetEndpoint(r.Context(), t.EnvironmentID, t.ID)
					if e != nil {
						err = e
					} else {
						d.Workspace.CanCommand = ep.Protocol == "ssh" && ep.Status == "active"
					}
				}
			}
			if r.Method == http.MethodPost {
				c := workspace.Change{Operation: r.PostForm.Get("operation"), ID: r.PostForm.Get("id"), Body: r.PostForm.Get("body"), Visibility: r.PostForm.Get("visibility"), Label: r.PostForm.Get("label"), URL: r.PostForm.Get("url"), Type: r.PostForm.Get("type"), Pinned: r.PostForm.Get("pinned") == "on"}
				if c.Operation == "command.copy" && !d.Workspace.CanCommand {
					err = workspace.ErrDenied
				}
				if err == nil {
					err = svc.Change(r.Context(), p, t, c)
				}
				if err == nil && c.Operation == "command.copy" {
					ep, e := s.store.(inventory.TopologyRepository).GetEndpoint(r.Context(), t.EnvironmentID, t.ID)
					if e == nil {
						d.Workspace.Command, e = workspace.SSHCommand(ep)
					}
					err = e
				} else if err == nil {
					http.Redirect(w, r, t.QuickURL()+"?saved=1", http.StatusSeeOther)
					return
				}
			} else {
				err = svc.Change(r.Context(), p, t, workspace.Change{Operation: "visit"})
			}
			if err == nil {
				d.Workspace.Related, err = svc.Related(r.Context(), p, t)
			}
			if err == nil {
				d.Workspace.Notes, err = svc.Notes(r.Context(), p, t)
			}
			if err == nil {
				d.Workspace.Links, err = svc.Links(r.Context(), p, t)
			}
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
		d.Notice = "Workspace change saved."
	}
	s.render(w, "workspace.html", d)
}
