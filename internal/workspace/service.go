package workspace

import "context"

type Repository interface {
	WorkspaceRelated(context.Context, Scope, Target) ([]Target, error)
	WorkspaceSearch(context.Context, Scope, Principal, string, int) ([]Target, bool, error)
	WorkspaceTarget(context.Context, Scope, string, string) (Target, error)
	WorkspaceTargets(context.Context, Scope, Principal, bool) ([]Target, error)
	WorkspaceNotes(context.Context, Scope, Principal, Target) ([]Note, error)
	WorkspaceLinks(context.Context, Scope, Principal, Target) ([]Link, error)
	WorkspaceChange(context.Context, Scope, Principal, Target, Change) error
}
type Service struct {
	Repository Repository
	Policy     Policy
}

func (s Service) Search(ctx context.Context, p Principal, raw string, offset int) ([]Target, bool, error) {
	scope, e := s.Policy.Scope(p, Search)
	if e != nil {
		return nil, false, e
	}
	q, e := Query(raw)
	if e != nil {
		return nil, false, e
	}
	if offset < 0 || offset > 1000 {
		return nil, false, ErrDenied
	}
	return s.Repository.WorkspaceSearch(ctx, scope, p, q, offset)
}
func (s Service) Target(ctx context.Context, p Principal, kind, id string) (Target, error) {
	scope, e := s.Policy.Scope(p, Search)
	if e != nil {
		return Target{}, e
	}
	return s.Repository.WorkspaceTarget(ctx, scope, kind, id)
}
func (s Service) Targets(ctx context.Context, p Principal, pins bool) ([]Target, error) {
	scope, e := s.Policy.Scope(p, Organize)
	if e != nil {
		return nil, e
	}
	return s.Repository.WorkspaceTargets(ctx, scope, p, pins)
}
func (s Service) Notes(ctx context.Context, p Principal, t Target) ([]Note, error) {
	scope, e := s.Policy.Scope(p, NotesRead)
	if e != nil {
		return nil, e
	}
	return s.Repository.WorkspaceNotes(ctx, scope, p, t)
}
func (s Service) Links(ctx context.Context, p Principal, t Target) ([]Link, error) {
	scope, e := s.Policy.Scope(p, Search)
	if e != nil {
		return nil, e
	}
	return s.Repository.WorkspaceLinks(ctx, scope, p, t)
}
func (s Service) Change(ctx context.Context, p Principal, t Target, c Change) error {
	permission := Organize
	switch c.Operation {
	case "note.save", "note.remove":
		permission = NotesWrite
	case "link.save", "link.remove":
		permission = LinksWrite
	case "command.copy":
		permission = CommandCopy
	case "pin", "unpin", "visit":
	default:
		return ErrDenied
	}
	scope, e := s.Policy.Scope(p, permission)
	if e != nil || !scope.Allows(t.CustomerID, t.EnvironmentID) {
		return ErrDenied
	}
	if c.Operation == "note.save" {
		c.Body, e = ValidateNote(c.Body, c.Visibility)
		if e != nil {
			return e
		}
	}
	if c.Operation == "link.save" {
		if t.Kind != "customers" && t.Kind != "environments" && t.Kind != "clusters" {
			return ErrDenied
		}
		if e = ValidateLink(c.Label, c.URL, c.Type); e != nil {
			return e
		}
	}
	if c.Operation == "pin" && t.Kind != "customers" && t.Kind != "clusters" && t.Kind != "assets" {
		return ErrDenied
	}
	if c.Operation == "command.copy" && t.Kind != "endpoints" {
		return ErrDenied
	}
	return s.Repository.WorkspaceChange(ctx, scope, p, t, c)
}

func (s Service) Related(ctx context.Context, p Principal, t Target) ([]Target, error) {
	scope, e := s.Policy.Scope(p, Search)
	if e != nil {
		return nil, e
	}
	return s.Repository.WorkspaceRelated(ctx, scope, t)
}
