package web

import (
	"net/http"
	"noc-workbench/internal/workspace"
	"sort"
	"strings"
)

type fleetCounts struct{ Reachable, Unreachable, Unknown, Issues, Total int }

// A fleet request is bounded to 1,000 scoped servers. Each evidence batch has a
// fixed query count, independent of the number of hosts within that batch.
func (s *Server) fleet(r *http.Request, scope workspace.Scope, q string) ([]consoleServer, error) {
	repo := s.store.(workspace.ServerRepository)
	out := []consoleServer{}
	for offset := 0; offset < 1000; offset += 25 {
		servers, more, e := repo.Servers(r.Context(), scope, q, offset)
		if e != nil {
			return nil, e
		}
		rows, e := s.consoleServers(r, scope, servers)
		if e != nil {
			return nil, e
		}
		out = append(out, rows...)
		if !more {
			return out, nil
		}
	}
	return nil, workspace.ErrLimit
}
func fleetPage(rows []consoleServer, filter, order string, offset int) ([]consoleServer, fleetCounts, bool) {
	counts := fleetCounts{Total: len(rows)}
	selected := []consoleServer{}
	for _, r := range rows {
		switch r.View.Availability {
		case "Reachable":
			counts.Reachable++
		case "SSH unreachable":
			counts.Unreachable++
		default:
			counts.Unknown++
		}
		if r.View.Issues != "" && r.View.Issues != "Unknown" && r.View.Issues != "0 failed units" {
			counts.Issues++
		}
		match := filter == "" || filter == "all" || filter == "reachable" && r.View.Availability == "Reachable" || filter == "unreachable" && r.View.Availability == "SSH unreachable" || filter == "unknown" && (r.View.Availability == "Unknown" || r.View.Availability == "Paused") || filter == "attention" && r.View.Attention > 0
		if match {
			selected = append(selected, r)
		}
	}
	sort.SliceStable(selected, func(i, j int) bool {
		a, b := selected[i], selected[j]
		if order == "" || order == "attention" {
			if a.View.Attention != b.View.Attention {
				return a.View.Attention > b.View.Attention
			}
		}
		if order == "checked" && !a.View.Checked.Equal(b.View.Checked) {
			return a.View.Checked.After(b.View.Checked)
		}
		if strings.ToLower(a.Name) != strings.ToLower(b.Name) {
			return strings.ToLower(a.Name) < strings.ToLower(b.Name)
		}
		return a.ID < b.ID
	})
	if offset >= len(selected) {
		return []consoleServer{}, counts, false
	}
	end := offset + 25
	more := end < len(selected)
	if !more {
		end = len(selected)
	}
	return selected[offset:end], counts, more
}
func validFleetOptions(r *http.Request) bool {
	filter, order := r.URL.Query().Get("availability"), r.URL.Query().Get("sort")
	return (filter == "" || filter == "all" || filter == "reachable" || filter == "unreachable" || filter == "unknown" || filter == "attention") && (order == "" || order == "attention" || order == "name" || order == "checked")
}
