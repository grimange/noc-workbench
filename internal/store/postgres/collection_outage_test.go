package postgres

import (
	"context"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"noc-workbench/internal/collection"
	linux "noc-workbench/internal/collectors/linux"
	"noc-workbench/internal/transport/sshcli"
	"noc-workbench/internal/workspace"
)

type outageExecutor struct {
	once       sync.Once
	disconnect func()
}

func (e *outageExecutor) Execute(ctx context.Context, p workspace.Principal, target sshcli.Target, id string) (sshcli.Result, error) {
	e.once.Do(e.disconnect)
	return (historyExecutor{}).Execute(ctx, p, target, id)
}

// The proxy targets only the disposable fixture's loopback database. Disconnecting
// it creates a real connection outage after the durable run starts, without
// stopping shared PostgreSQL or using production database credentials.
func TestIntegrationDatabaseOutageDuringCollection(t *testing.T) {
	db, h, target := collectionFixture(t)
	cfg := db.pool.Config()
	upstream := net.JoinHostPort(cfg.ConnConfig.Host, strconv.Itoa(int(cfg.ConnConfig.Port)))
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	var mu sync.Mutex
	blocked := false
	active := map[net.Conn]bool{}
	setBlocked := func(value bool) {
		mu.Lock()
		defer mu.Unlock()
		blocked = value
		if value {
			for c := range active {
				_ = c.Close()
			}
		}
	}
	t.Cleanup(func() { setBlocked(true); listener.Close() })
	go func() {
		for {
			downstream, e := listener.Accept()
			if e != nil {
				return
			}
			mu.Lock()
			deny := blocked
			mu.Unlock()
			if deny {
				downstream.Close()
				continue
			}
			remote, e := net.DialTimeout("tcp", upstream, time.Second)
			if e != nil {
				downstream.Close()
				continue
			}
			mu.Lock()
			if blocked {
				mu.Unlock()
				downstream.Close()
				remote.Close()
				continue
			}
			active[downstream] = true
			active[remote] = true
			mu.Unlock()
			go func() {
				done := make(chan struct{})
				go func() { io.Copy(remote, downstream); remote.Close(); close(done) }()
				io.Copy(downstream, remote)
				downstream.Close()
				<-done
				mu.Lock()
				delete(active, downstream)
				delete(active, remote)
				mu.Unlock()
			}()
		}
	}()
	old := db.pool
	cfg.ConnConfig.Host = "127.0.0.1"
	cfg.ConnConfig.Port = uint16(listener.Addr().(*net.TCPAddr).Port)
	db.pool, e = pgxpool.NewWithConfig(context.Background(), cfg)
	if e != nil {
		t.Fatal(e)
	}
	old.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	p := workspace.Principal{ID: workspace.OperatorID}
	good, e := collection.NewService(historyExecutor{}, linux.Registry(), db).Collect(ctx, p, target)
	if e != nil {
		t.Fatal(e)
	}
	broken := collection.NewService(&outageExecutor{disconnect: func() { setBlocked(true) }}, linux.Registry(), db)
	failed, e := broken.Collect(ctx, p, target)
	if e == nil || failed.ID == "" {
		t.Fatal("database outage reported success", e)
	}
	setBlocked(false)
	if e = db.RecoverCollections(ctx); e != nil {
		t.Fatal("database restoration", e)
	}
	runs, e := db.CollectionHistory(ctx, p, h, "")
	if e != nil || runs[0].State != "interrupted" || len(runs[0].Results) != 0 {
		t.Fatal("outage recovery invented evidence", e, runs)
	}
	facts, e := db.LatestEvidence(ctx, p, h)
	if e != nil || len(facts) == 0 {
		t.Fatal("outage lost prior observations", e)
	}
	for _, o := range facts {
		if o.RunID != good.ID {
			t.Fatal("uncommitted outage facts leaked")
		}
	}
	if _, e = collection.NewService(historyExecutor{}, linux.Registry(), db).Collect(ctx, p, target); e != nil {
		t.Fatal("explicit restored collection", e)
	}
}
