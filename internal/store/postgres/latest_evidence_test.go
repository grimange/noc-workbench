package postgres

import (
	"context"
	"reflect"
	"sort"
	"testing"
	"time"

	"noc-workbench/internal/collection"
	linux "noc-workbench/internal/collectors/linux"
	"noc-workbench/internal/workspace"
)

// Compare the indexed seek with the original definition, including older
// eligible evidence hidden behind a newer, not-yet-visible version.
func TestIntegrationLatestEvidenceSeekParity(t *testing.T) {
	db, h, target := collectionFixture(t)
	ctx := context.Background()
	actor := workspace.Principal{ID: workspace.OperatorID}
	svc := collection.NewService(historyExecutor{rootMount: true}, linux.Registry(), db)
	before := time.Now().UTC()
	if _, err := svc.Collect(ctx, actor, target); err != nil {
		t.Fatal(err)
	}
	middle := time.Now().UTC()
	newest, err := svc.Collect(ctx, actor, target)
	if err != nil {
		t.Fatal(err)
	}
	future := time.Now().UTC().Add(time.Hour)
	// Independently exclude a newer row by each observation visibility field.
	for _, q := range []string{
		`UPDATE observation SET recorded_at=$2 WHERE run_id=$1 AND key='linux.load.1m'`,
		`UPDATE observation SET received_at=$2 WHERE run_id=$1 AND key='linux.mem.total_bytes'`,
		`UPDATE observation SET observed_at=$2,received_at=$2 WHERE run_id=$1 AND key='linux.mem.available_bytes'`,
	} {
		if _, err = db.pool.Exec(ctx, q, newest.ID, future); err != nil {
			t.Fatal(err)
		}
	}
	for _, at := range []time.Time{before, middle, time.Now().UTC(), future.Add(time.Second)} {
		actual, e := db.EvaluationEvidence(ctx, actor, h, at)
		if e != nil {
			t.Fatal(e)
		}
		var want []string
		rows, e := db.pool.Query(ctx, `SELECT DISTINCT ON(o.key,o.resource_hash) o.id::text FROM observation o JOIN collection_run r ON r.id=o.run_id WHERE r.customer_id=$1 AND r.environment_id=$2 AND o.asset_id=$3 AND o.collector_id NOT IN ('mariadb.health','asterisk.auth','asterisk.activity','asterisk.media') AND o.observed_at<=$4 AND o.received_at<=$4 AND o.recorded_at<=$4 AND r.ended_at<=$4 AND r.evidence_recorded_at<=$4 ORDER BY o.key,o.resource_hash,o.observed_at DESC,o.id DESC LIMIT 2049`, h.CustomerID, h.EnvironmentID, h.AssetID, at)
		if e != nil {
			t.Fatal(e)
		}
		for rows.Next() {
			var id string
			if e = rows.Scan(&id); e != nil {
				t.Fatal(e)
			}
			want = append(want, id)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			t.Fatal(e)
		}
		var got []string
		for _, o := range actual.Evidence {
			got = append(got, o.ID)
		}
		sort.Strings(want)
		sort.Strings(got)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("asof %s: seek %v reference %v", at, got, want)
		}
		summary, _, e := db.ServerEvidence(ctx, workspace.Scope{All: true}, []string{h.AssetID}, at)
		if e != nil || len(summary) != 1 {
			t.Fatal(summary, e)
		}
		// Apply the original console projection to the reference-equivalent full
		// evidence set, and compare exact IDs (empty or missing data must fail).
		var consoleWant, consoleGot []string
		for _, o := range actual.Evidence {
			switch o.Key {
			case "linux.load.1m", "linux.service.runtime", "vicidial.discovery.snapshot", "linux.baseline.status", "linux.baseline.cpu_percent", "linux.baseline.units", "linux.mem.available_bytes", "linux.mem.total_bytes":
				consoleWant = append(consoleWant, o.ID)
			case "linux.filesystem.identifier", "linux.filesystem.total_bytes", "linux.filesystem.used_bytes", "linux.filesystem.available_bytes", "linux.filesystem.utilization_percent":
				if o.Resource == "/" {
					consoleWant = append(consoleWant, o.ID)
				}
			}
		}
		for _, o := range summary[0].Evidence {
			consoleGot = append(consoleGot, o.ID)
		}
		sort.Strings(consoleWant)
		sort.Strings(consoleGot)
		if !reflect.DeepEqual(consoleGot, consoleWant) {
			t.Fatalf("console asof %s: seek %v reference %v", at, consoleGot, consoleWant)
		}
	}
}
