package collection

import (
	"context"
	"time"

	"noc-workbench/internal/workspace"
)

// Source identifies a cluster-scoped collection authority. It is not an asset,
// SSH endpoint or credential. Its immutable revision binds durable attempts to
// the configuration that actually authorized them.
type Source struct {
	ID, CustomerID, EnvironmentID, ClusterID, CredentialReference string
	Revision                                                      int64
	Enabled                                                       bool
}

// AcquireSource uses the same finite queue, scope fairness and emergency-stop
// cancellation as manual and scheduled asset collection.
func (s *Service) AcquireSource(ctx context.Context, source Source) (context.Context, func(), error) {
	if source.ID == "" || source.CustomerID == "" || source.ClusterID == "" {
		return ctx, nil, ErrBusy
	}
	return s.admission.acquire(ctx, "source:"+source.ID, Requested(ctx).Source == "scheduled", AdmissionScope{Customer: source.CustomerID, Clusters: []string{source.ClusterID}})
}

// SourceHistoryRepository persists non-SSH evidence in the authoritative
// collection_run / collector_result / observation history, never a second store.
type SourceHistoryRepository interface {
	CollectionSource(context.Context, workspace.Principal, string, int64) (Source, error)
	BeginSourceCollection(context.Context, workspace.Principal, Source, []string) (Run, error)
	FinishSourceCollection(context.Context, workspace.Principal, Run, int) error
	SourceHistory(context.Context, workspace.Principal, Source, time.Time) (History, error)
}
