package web

import (
	"net/http"
	"noc-workbench/internal/workspace"
)

type contextualLinks struct {
	Target workspace.Target
	Links  []workspace.Link
}

func (s *Server) serverNotes(r *http.Request, d *pageData) error {
	svc, ok := s.workspaceService()
	if !ok {
		return nil
	}
	p := operatorPrincipal()
	v := d.Server.Detail
	t, e := svc.Target(r.Context(), p, "assets", v.ID)
	if e != nil {
		return e
	}
	d.Server.NotesTarget = t
	d.Server.Notes, e = svc.Notes(r.Context(), p, t)
	if e != nil {
		return e
	}
	targets := []struct{ kind, id string }{{"customers", v.CustomerID}, {"environments", v.EnvironmentID}}
	for _, c := range v.Clusters {
		targets = append(targets, struct{ kind, id string }{"clusters", c.ID})
	}
	for _, ref := range targets {
		t, e := svc.Target(r.Context(), p, ref.kind, ref.id)
		if e != nil {
			return e
		}
		links, e := svc.Links(r.Context(), p, t)
		if e != nil {
			return e
		}
		d.Server.ContextLinks = append(d.Server.ContextLinks, contextualLinks{Target: t, Links: links})
	}
	return nil
}
