package web

import (
	"context"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5"
	"noc-workbench/internal/inventory"
	"noc-workbench/internal/store/postgres"
	"noc-workbench/internal/workspace"
)

// Exercise the complete authenticated handler with its unchanged three-second
// request budget, pool of five and retained history rather than only its store.
func TestIntegrationServerDetailsRetainedHistoryConcurrent(t *testing.T) {
	ctx := context.Background()
	var path string
	h := inventoryFixtureDatabase(t, func(db *postgres.Store, _ *Options, dsn string) {
		must := func(err error) {
			t.Helper()
			if err != nil {
				t.Fatal(err)
			}
		}
		c, e := db.CreateCustomer(ctx, inventory.Customer{DisplayName: "Synthetic concurrency", ShortCode: "CONCUR", Status: "active"})
		must(e)
		env, e := db.CreateEnvironment(ctx, inventory.Environment{CustomerID: c.ID, Name: "Lab", Kind: "lab", Status: "active"})
		must(e)
		a, e := db.SaveAsset(ctx, inventory.Asset{EnvironmentID: env.ID, Name: "Synthetic history server", Kind: "server", Lifecycle: "active"})
		must(e)
		ep, e := db.SaveEndpoint(ctx, inventory.Endpoint{EnvironmentID: env.ID, AssetID: a.ID, Host: "192.0.2.45", Protocol: "ssh", Port: 22, Status: "active"})
		must(e)
		conn, e := pgx.Connect(ctx, dsn)
		must(e)
		defer conn.Close(ctx)
		var profile string
		must(conn.QueryRow(ctx, `INSERT INTO connection_profile(customer_id,environment_id,asset_id,endpoint_id,state,details) VALUES($1,$2,$3,$4,'connection_verified',jsonb_build_object('Host','192.0.2.45','Port',22,'EndpointUpdatedAt',$6::timestamptz,'ApprovedKey','synthetic-public-key','ApprovedFingerprint','synthetic','Evidence','Synthetic repository fixture','ApprovedBy',$5::text,'AuthorizedBy',$5::text,'ApprovedAt',clock_timestamp(),'AuthorizedAt',clock_timestamp(),'VerifiedAt',clock_timestamp())) RETURNING id::text`, c.ID, env.ID, a.ID, ep.ID, workspace.OperatorID, ep.UpdatedAt).Scan(&profile))
		_, e = conn.Exec(ctx, `WITH runs AS (
   INSERT INTO collection_run(customer_id,environment_id,asset_id,endpoint_id,profile_id,profile_revision,endpoint_revision,principal_id,started_at,ended_at,state,success_count,collector_ids)
   SELECT $1,$2,$3,$4,$5,1,$6,$7,now()-n*interval '1 minute',now()-n*interval '1 minute'+interval '1 second','completed',1,ARRAY['linux.filesystems'] FROM generate_series(1,1000) n RETURNING *
  ), results AS (
   INSERT INTO collector_result(run_id,collector_id,version,command_id,outcome,transport_outcome,started_at,ended_at,observation_count,diagnostics)
   SELECT id,'linux.filesystems','1','linux.filesystems.v1','success','success',started_at,ended_at,120,ARRAY[]::text[] FROM runs RETURNING run_id
  ) INSERT INTO observation(run_id,asset_id,endpoint_id,profile_id,profile_revision,collector_id,collector_version,command_id,key,resource,kind,integer_value,unit,transport,quality,observed_at,received_at,ttl_seconds)
   SELECT r.id,r.asset_id,r.endpoint_id,r.profile_id,1,'linux.filesystems','1','linux.filesystems.v1',k.key,CASE WHEN n=1 THEN '/' ELSE '/synthetic/'||n END,'integer',k.value,k.unit,'ssh','valid',r.started_at,r.ended_at,180
   FROM runs r JOIN results x ON x.run_id=r.id CROSS JOIN generate_series(1,30) n CROSS JOIN (VALUES ('linux.filesystem.total_bytes',1000,'bytes'),('linux.filesystem.used_bytes',100,'bytes'),('linux.filesystem.available_bytes',900,'bytes'),('linux.filesystem.utilization_percent',10,'percent')) k(key,value,unit)`, c.ID, env.ID, a.ID, ep.ID, profile, ep.UpdatedAt, workspace.OperatorID)
		must(e)
		path = "/servers/" + a.ID
	})
	cookie := authenticate(t, h)
	for _, destination := range []string{"/", path, path + "/history?key=linux.filesystem.utilization_percent&resource=%2F"} {
		t.Run(destination, func(t *testing.T) {
			start := make(chan struct{})
			results := make(chan int, 12)
			for i := 0; i < 12; i++ {
				go func() { <-start; results <- request(h, "GET", destination, nil, cookie).Code }()
			}
			close(start)
			for i := 0; i < 12; i++ {
				if status := <-results; status != http.StatusOK {
					t.Errorf("concurrent %s returned %d", destination, status)
				}
			}
		})
	}
}
