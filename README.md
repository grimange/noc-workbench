# NOC Workbench

A local-first, agentless infrastructure workspace. M0 implements a host-native Go application, PostgreSQL persistence, a server-rendered local operator interface, authentication, sessions and CSRF-protected operator workflows. It does not collect remote observations. No production access is configured or authorized by default.

## Prerequisites and startup

Install Go 1.25.8+, Docker with Compose, Python 3 (for lifecycle tests), and Make. The backend runs on the host; only PostgreSQL runs in Compose. All dependencies and assets are local after initial dependency/image downloads.

From the repository root, in Bash:

```bash
# Generated credentials stay in this shell; do not commit or paste them in logs.
export NOC_DB_PASSWORD=$(python3 -c 'import secrets; print(secrets.token_hex(24))')
export NOC_DATABASE_URL="postgres://noc_workbench:${NOC_DB_PASSWORD}@127.0.0.1:55432/noc_workbench?sslmode=disable"
read -r -s -p 'Choose operator password (12–72 bytes): ' operator_password; printf '\n'
export NOC_PASSWORD_HASH=$(printf '%s\n' "$operator_password" | go run ./cmd/hash-password)
unset operator_password
make up
```

Open **http://127.0.0.1:8080**. Sign in with the chosen password. The Dashboard and `/servers` list authorized servers in a searchable, paginated monitoring table with customer, primary endpoint, current CPU, RAM and root-disk evidence, collection status and observation age. Search by server name, IP, hostname or customer; select a server to inspect persisted runtime services first, followed by historical VICIdial installation/roles. Process and systemd signals remain separate; failures preserve earlier observations and disabled monitoring does not present historical Running as current. Technical evidence and inventory settings remain in collapsed disclosures. These pages and their bounded SSE updates do not initiate collection. Service health remains Unknown unless established by the existing monitoring policies. Add servers directly at `/servers/new`, then use their Connection settings for explicit SSH trust and baseline monitoring authority. Manage contains customers, advanced records, scheduler controls and import/export. Existing scoped monitoring deep links remain available. `/healthz` returns application DB readiness, never infrastructure/service health. No CDN is required. A small same-origin script reconciles persisted monitoring displays through the existing SSE delivery; normal navigation remains available without JavaScript.

Save the generated DB password and operator hash in your own protected secret store before closing the shell. Reuse the same DB password on ordinary restarts: changing the Compose environment does not change credentials in an existing PostgreSQL volume. No default login exists. An ignored `.env` may hold `NOC_DB_PASSWORD` for Compose, but the Go application does **not** automatically read `.env`; export its configuration explicitly. Never commit that file.

Ctrl-C stops the backend gracefully. `make run` starts it again with migrations checked automatically. `make db-down` stops/removes the Compose container without deleting its named data volume; `make db-up` recreates it and retains data. There is no automatic destructive migration rollback: back up the DB before upgrades and restore to roll back a schema release.

## Configuration

| Environment variable | Default / requirement |
|---|---|
| `NOC_LISTEN` | `127.0.0.1:8080`; literal loopback IP and valid port |
| `NOC_BASE_URL` | `http://127.0.0.1:8080`; HTTP origin must match listener; HTTPS accepts a separate proxy origin with a canonical lowercase DNS name or IP; omit port 443 and include any nondefault port |
| `NOC_DATABASE_URL` | Required PostgreSQL URL with explicit user, password, literal loopback IP/port, database and only `sslmode=disable`, `require` or `verify-full` |
| `NOC_PASSWORD_HASH` | Required bcrypt hash, cost 10–14; helper generates cost 12 |
| `NOC_SESSION_TTL` | `8h`; allowed 1 minute–24 hours |
| `NOC_SSH_CREDENTIAL_CATALOG` | Optional absolute path to an administrator-provisioned, protected SSH credential-reference catalog; absent means enrollment cannot select credentials |
| `NOC_STARTUP_TIMEOUT` | `10s`; allowed 1–60 seconds; store additionally caps DB startup at 10 seconds |
| `NOC_DB_PASSWORD` | Required by Compose only; generate locally |
| `NOC_DB_PORT` | Compose loopback port, default `55432`; update DB URL if changed |

HTTP localhost uses HttpOnly, SameSite=Strict host-only cookies. An HTTPS base URL enables Secure cookies and HSTS; TLS must terminate at an operator-configured trusted local proxy preserving Host and Origin. For example, keep `NOC_LISTEN=127.0.0.1:8080` and set `NOC_BASE_URL=https://noc.example.invalid:8443` for an explicitly authorized proxy deployment. Configure a real locally resolved hostname and trusted certificate for your environment; the example is synthetic. Preserve the original Host header with its port (`proxy_set_header Host $http_host` in Nginx). The Go listener itself serves HTTP; HTTPS mode rejects direct browser access at the backend origin. Proxy configuration, client access rules and TLS provisioning are deployment responsibilities; see [the security boundary](docs/SECURITY.md). The application ignores forwarded headers and never uses them to select its trusted origin.

The login form and every mutation require CSRF tokens and the exact configured Origin. API/HTTP clients must supply both their session cookie and CSRF token (form field `csrf` or `X-CSRF-Token`) and the Origin header. Login attempts are globally bounded to ten per minute and one concurrent bcrypt operation. Authentication failures intentionally share a generic response. Sessions expire at a fixed TTL; logout revokes the DB session.

Database loss returns sanitized 503 responses; no unavailable collection target is labeled down. Startup retries are bounded; startup failures exit nonzero. Restart after PostgreSQL recovers. Logs contain structured lifecycle events and sanitized errors, never connection strings, passwords or request bodies.

## Verification

```bash
make check                    # formatting, vet, unit tests, build
./scripts/test-m0              # isolated real PostgreSQL, integration + process/HTTP lifecycle
# Optional existing isolated local test DB (tests create and remove their own schemas):
NOC_TEST_DATABASE_URL="$NOC_DATABASE_URL" make integration
```

`make check` skips PostgreSQL integration tests when `NOC_TEST_DATABASE_URL` is absent; this is not integration acceptance. `scripts/test-m0` creates a unique Compose project, generated credentials and an available loopback port, verifies fresh migrations, auth/CSRF, DB outage and restart persistence, then deletes **its own** test volume. It requires Docker access and Python 3. Tests do not access SSH, vendor APIs, employer/customer systems or external databases. CI runs this same command. First-time dependency/image downloads require registry access.

The application embeds versioned migrations, templates and CSS. `internal/app` owns lifecycle/configuration, `internal/web` owns HTTP, `internal/security` owns token primitives, and `internal/store/postgres` owns persistence and migrations. M1 inventory and M2 SSH are governed by [the data contract](docs/DATA_MODEL.md) and [the SSH policy contract](docs/SSH_PROFILE_POLICY.md); neither feature is implemented in M0.

## Customer and environment inventory (NW-004)

Sign in and open **Customers** to create, browse, edit, archive or restore customer records and their environments. Customer names are unique without case sensitivity; short codes normalize to uppercase and are unique (2–24 ASCII letters, digits, underscores or hyphens, beginning with a letter). Names are limited to 120 bytes and optional plain-text notes to 4096 bytes.

Each environment has one immutable customer owner, a name unique within that customer (case insensitive, at most 80 bytes), and a `lab`, `test` or `production` classification. Customers and environments have `active` or `archived` status. Archiving retains records and uniqueness reservations. Archived customers remain readable; restore a customer before modifying its environments. There is no destructive delete action. Classification does not authorize access to infrastructure.

Inventory pages and writes require the existing operator session. Writes require the existing exact Origin and CSRF checks; invalid or duplicate fields return HTTP 422 with field feedback, wrong-owner or missing records return 404, archived-parent writes return 409, and unavailable storage returns 503 without database details. Customer/environment relationships are also enforced by PostgreSQL constraints and an immutable-owner trigger. All queries use bound parameters. Inventory POST bodies are bounded to 16 KiB to accommodate URL-encoded notes; configure the reverse proxy to allow at least 16 KiB. Authentication retains its 8 KiB application limit.

`./scripts/test-m0` creates its own disposable PostgreSQL deployment and runs the Go checks, real database inventory/HTTP tests, fresh and M0-upgrade migrations, direct-SQL negative tests, transaction rollback, and process/database restart persistence. It never resets the installed application's volume. Migration 003 adds only inventory tables, indexes and a trigger; sessions and workspace settings are preserved. Back up the database before deploying a schema release. Roll back using a matching database backup and binary; an older binary deliberately refuses unknown migration history.

The inventory now supports environment-owned clusters, stable assets, multiple endpoints, explicit cluster memberships with roles, logical services, service instances, and many-to-many instance/host bindings. These records remain under **Manage → Advanced records** for compatibility and occasional administration; normal server registration does not require navigating them. Each section provides create, detail and edit pages; membership and host-binding removal retains the referenced records. Archive/restore entities through their edit form. Restore owning records before creating active assignments. Existing relationships are retained when an owner is archived.

Endpoint enrollment records an address and port only. It does not connect, resolve, discover, establish SSH trust, or report service health. Asset identity remains independent of addresses; shared hosts and multiple cluster memberships are supported. All topology pages require authentication; mutations retain the existing Origin and CSRF checks. See `docs/DATA_MODEL.md` for lifecycle, uniqueness and ownership constraints.

## Server operations and scoped notes (NW-40)

Use **Servers → Add Server** to enter a name, destination, SSH port and customer. Registration creates only canonical server/endpoint records; it performs no network access and grants no collection authority. A sole active internal registration group is reused. A customer without an active group gets one deterministic internal group; archived groups remain unchanged. Where several existing groups make placement ambiguous, choose the existing group in the registration form. Customer ownership remains immutable. Duplicate SSH destinations within a customer are rejected.

Connection settings reuse the existing credential catalog, explicit authorization, independent fingerprint approval and verification. Baseline monitoring then uses the accepted automatic 60-second profile. Server Details provides monitoring history/rules, connection settings and contextual Pause/Resume without copying internal IDs. Resume clears only that server's own profile/asset pauses; customer/cluster/global pauses, emergency stop and authorization restrictions remain visible and authoritative. Advanced controls remain under Manage.

Server Details includes scoped operational notes and approved links from its existing customer, group and declared cluster contexts. Notes support plain text (4096 bytes), editing/removal and private/shared visibility. Private notes are restricted to their principal; shared notes require resource scope. There is currently one operator; multi-account RBAC remains deferred. External links retain customer/environment/cluster ownership and never become implicitly server-owned. Approved HTTP(S) URLs cannot contain credentials, query parameters or fragments; opening a link grants no authority or automatic authentication.

Legacy workspace search redirects to server search, settings redirects to Dashboard, and `/monitoring` redirects to Alerts after authentication. Obsolete settings writes, pin/recents browsing and manual SSH-command preparation are retired. Their historical tables remain intact; passive page reads no longer record visits. Notes/link editing remains at scoped compatibility URLs. Internal ownership, search, import/export and audit storage are retained where supported consumers remain. No database migration is required for this consolidation.


## Sanitized inventory import/export

Open **Import & export** to download deterministic, sanitized version-1 topology
JSON or the reusable synthetic example. Preview a selected file or pasted JSON,
review create/reuse counts, and confirm an atomic import. Conflicts reject the
whole transaction; unchanged repeated imports are no-ops. No endpoints are contacted.
This format excludes notes, tags, credentials, sessions and private workspace data;
it is not a backup. See [the interchange contract](docs/INVENTORY_INTERCHANGE.md)
for supported entities, pseudonymization, limits, collision and lifecycle policies.

JSON is limited to 256 KiB and 500 records. Only the interchange POST route permits
up to 1 MiB of URL-encoded form data; other application body limits remain unchanged.
The reverse proxy must permit 1 MiB for that route. No new migration is required.

## Read-only SSH transport (NW-007)

`internal/transport/sshcli` provides a Go OpenSSH adapter, not a web shell or a collector. Its only command is the immutable `lab.probe.v1` (`printf 'NOC_WORKBENCH_SSH_LAB_OK\n'`). Inventory browsing, imports and endpoint creation never invoke it. The general inventory policy grants neither `connections.profile.use` nor `connections.execute`; NW-008 adds a separate explicit connection policy for the stable local operator.

Profiles use structured values rather than arbitrary SSH configuration: asset/endpoint/profile UUIDs and revision, customer/environment scope, approved host and resolved IP, port, user, protected identity-file reference and SHA-256, bare public host key and independently verified fingerprint. `FileApproval` re-reads a protected enrollment file and current PostgreSQL inventory before every attempt. Changed endpoint values, archived owners, disabled endpoints, stale revisions or altered profile digests fail closed. This NW-007 diagnostic keeps credentials and approvals outside Git and database tables; NW-008 adds database-backed public approval records for the web workflow. Approval files must be owned by the executing account or root and deny group/other access. Their digest detects changes; it is **not a signature** and the local file administrator is trusted. Approvals should be revoked before changing an enrolled endpoint; an in-flight command may finish after its initial approval.

OpenSSH runs with `-F /dev/null`, pinned destination, temporary protected known-host and credential snapshots, strict host-key checking, public-key-only noninteractive authentication, no agent, TTY, forwarding, executable hooks or multiplexing. DNS must still resolve exclusively to the approved IP; connections use that pinned IP. Jump hosts are unsupported and cannot be supplied through a profile. `Inspect` returns bounded, untrusted key candidates; `Trust` requires independent fingerprint evidence and never automatically enrolls or replaces a key.

Each shared executor defaults to five concurrent assets, one command per asset, a five-second total budget (including queueing), a five-second connection budget and 64 KiB combined output. Limits can be reduced; callers must reuse the executor to share its concurrency budget. Cancellation/output limits kill the child process group and reap the direct child. Results contain actor/target/command metadata, UTC timestamps, duration, exit status and a typed failure category. Raw stderr is discarded; stdout is transient caller data and must not be logged by default. Exit 255 without a recognized diagnostic is `internal_transport_error`. These are transport outcomes, never service-health assessments. Future collectors may register separate reviewed budgets up to the plan's 20-second initial allowance; collectors use this same executor.

Run deterministic tests with `go test -race ./internal/transport/sshcli`. Explicitly authorize the disposable loopback-only real OpenSSH fixture with:

```bash
NOC_SSH_LAB=1 go test -race -count=1 -v ./internal/transport/sshcli
```

This requires `/usr/bin/ssh`, `/usr/bin/ssh-keygen`, `/usr/bin/ssh-keyscan` and `/usr/sbin/sshd`. It creates temporary keys and an ordinary-user SSH server on an ephemeral `127.0.0.1` port, then removes its resources. The temporary daemon disables `StrictModes` because test directories live beneath `/tmp`; the client retains strict host-key verification. It does not change system SSH configuration or personal SSH files.

For explicitly provisioned local lab verification, the application binary supports `--ssh-lab-profile /protected/enrollment.json` only with `NOC_SSH_LAB=1` and normal application environment configuration. This opt-in diagnostic uses the current PostgreSQL inventory, stable operator principal and separate loopback-only `LabPolicy`. It runs only the registered probe and logs sanitized attempt metadata. The HTTP service never enables this CLI path; the separate NW-008 enrollment service supplies persisted authorization to the same transport. See the exported `Enrollment`/`Profile` types for the versioned profile revision fields and `ProfileDigest` for approval binding. Never use customer targets or production credentials for the lab.


## SSH enrollment (NW-008)

Open **SSH enrollment** from an asset detail page. Select an existing active SSH endpoint, an explicitly approved resolved IP, and an administrator-provisioned credential reference. Save draft → submit → explicitly authorize contact → inspect the untrusted presented key → enter the fingerprint obtained from an independent server console or trusted source and an attestation → approve → verify. Only the explicit inspection and verification actions contact the configured destination. Verification executes only `lab.probe.v1`; it is not operational health, discovery or polling.

The running service reads `NOC_SSH_CREDENTIAL_CATALOG` on every operation. Provision this JSON array outside Git with mode `0600`, owned by the application account or root and readable by the application account (normally application-owned). Example structure, with placeholder paths and digest that must be replaced by the administrator:

```json
[{"ID":"approved-lab","User":"observer","IdentityFile":"/protected/ssh/observer","IdentitySHA256":"<64 hexadecimal characters from the approved private key file>","Enabled":true,"ExpiresAt":"2027-01-01T00:00:00Z"}]
```

Private keys must likewise be protected regular files owned by the application account or root, readable by that account, without group/other access or symlinks. The catalog is bounded to 32 references and 64 KiB; no private keys, passwords, filesystem paths or arbitrary SSH options are accepted from the browser. The database retains only the reference and its digest, public host-key evidence, stable approving actor and sanitized attempt category. Catalog changes, revocation or expiry require explicit profile review. No credentials are automatically provisioned or endpoints automatically authorized by deployment.

Profiles are bound to immutable customer/environment/asset/endpoint ownership and an optimistic revision. Endpoint edits suspend trust even when changed back. Review clears prior inspection, authorization and approval; independently inspect and approve again. A changed pinned IP requires a new profile. Concurrent stale submissions fail with a reload message. Archived owners block new contacts and successful verification commits. Disabling/rejecting remains available; history is retained in `connection_audit`. An already-started probe may finish after a concurrent change, but its result cannot mark a stale revision verified.

Migration `006_ssh_enrollment.sql` preserves prior checksums and data. To exercise the disposable PostgreSQL/ordinary-user OpenSSH enrollment tests, run `NOC_SSH_LAB=1 ./scripts/test-m0`. Optional browser verification uses the local Playwright harness via `NOC_ENROLLMENT_BROWSER_SCRIPT`; no browser dependency is required to run the application. Existing single-operator permission grants are explicit; this is not multi-user RBAC.

### On-demand Linux discovery (NW-009)

Open an asset's **Linux facts** page and choose **Collect Linux Facts** for a
`connection_verified` SSH profile. This explicit authenticated, CSRF-protected
request runs five static versioned command specifications through the existing
shared NW-007 executor and NW-008 live approval checks. Each command has a
five-second deadline and 64 KiB combined output cap. The entire request has a
ten-second collection budget; later collectors can report cancellation if the
budget expires. At most five discovery requests and one per asset are active;
duplicate requests are rejected without starting another collection.

The page shows identity, uptime seconds, load averages and logical CPU count,
memory bytes, and per-mount filesystem capacity bytes and reported percentage.
Load averages are not CPU utilization. `MemAvailable` and `MemFree` remain
separate; missing availability is explicitly unsupported. OS release data is
parsed as data, never sourced. Filesystem output uses fixed C locale and
1024-byte blocks, preserves mount paths containing spaces, and is capped at
256 records. Ambiguous numeric field boundaries are rejected. Incomplete or invalid rows have diagnostics; virtual, network and
temporary mounts are not classified as persistent storage or health evidence.

Every valid observation carries asset, endpoint, exact profile revision,
collector/version, command-spec ID, transport, typed value, unit, quality,
sampling start and receive timestamps (application UTC clock). Collector
failures preserve successful readings from other collectors and never produce
zero substitutes or service-health conclusions. Raw stderr and parser input
are excluded from diagnostics. Unknown collectors cannot start commands.

### Durable evidence and recovery (NW-010)

Authorized manual collection creates a PostgreSQL run before SSH executes. Migration
007 adds collection runs, five distinct collector results and typed observations
with exact endpoint/profile revision and static command provenance. All results
and the terminal run state commit together; a write failure returns a sanitized
error and leaves the run unfinished. Single-process startup marks unfinished runs
`interrupted`, without repeating remote commands. Collection states are `running`,
`completed`, `partial`, `failed`, `cancelled` and `interrupted`; transport outcomes,
observation validity, freshness and operational health remain separate.

The Linux facts page shows the latest attempted collection, 20 requests per history
page and the last valid reading for each key/mount. Failed attempts preserve older
valid facts with their original timestamps. Evidence is fresh only until its stored
TTL expires; the page labels age and freshness without evaluating health. Historical
profile revisions do not grant execution authority. No SSH runs on GET or refresh.

Default policies are `NOC_OBSERVATION_TTL_SECONDS=180`,
`NOC_COLLECTION_RUN_DAYS=30` and `NOC_COLLECTION_SAMPLE_DAYS=7`.
TTL supports 1–86400 seconds; retention supports 1–365 days and sample retention
cannot exceed run retention. Each explicit request performs a bounded maintenance
transaction (at most 2000 expired nonlatest observations and 200 empty expired run
summaries). Latest valid key/mount series and their parent provenance are retained
indefinitely, even beyond the windows. This preserves last-known evidence; changing
mount names can increase the number of retained series. The display caps at 2048
series and explicitly reports incomplete output. Maintenance runs within bounded manual and scheduled collection requests.

Before each approved SSH operation, a durable uncertainty marker is committed in
the existing profile's scope. A changed or unknown host key clears approval and
requires explicit enrollment review. If persisting invalidation fails, the marker
blocks further contacts. At single-process startup, any surviving marker clears
approval and advances the profile revision atomically with an audit event. Disabled
and rejected profiles remain disabled/rejected. If recovery cannot commit, startup
fails closed. Even a previously approved key reappearing cannot bypass review,
independent fingerprint approval and connection verification. The marker is never
an alternative approval or credential store. A crash during an otherwise safe SSH
operation can conservatively require reapproval. Multiple application processes
sharing execution are not supported by this in-process M2 architecture.

Back up PostgreSQL before migration. Existing migration checksums remain unchanged;
an older binary rejects the new schema, so rollback requires the matching binary
and pre-upgrade database backup. Raw SSH stdout/stderr and database errors are not
stored as diagnostics; only bounded stable codes are retained.

Parser and orchestration tests run with `go test ./...`. For authorized local
acceptance, `NOC_SSH_LAB=1 ./scripts/test-m0` runs a disposable loopback OpenSSH
server under the current ordinary account and isolated PostgreSQL schemas,
including actual HTTP discovery and independent `/proc`, hostname, kernel and
filesystem comparisons. Test-created keys, daemons, schemas and DB volumes are
removed by their fixtures. No existing enrollment is contacted by these tests.


### Bounded Linux scheduling (NW-011)

Scheduling is optional. Existing inventory and verified SSH enrollments receive no
schedule during migration. On an asset’s Linux Facts page, select registered Linux
collectors, a 60–86400-second interval, and explicitly authorize continuous polling.
Each asset has at most one profile. Editing captures the current verified enrollment
and endpoint revision; queued work revalidates these and all live scope controls
before committing a durable attempt. Disabled/archived scopes, revoked authority,
changed identity and unavailable credentials cannot authorize SSH execution.

The in-process scheduler uses one one-second timer, at most 1000 profiles and a
32-profile pending queue. Manual and scheduled requests share a five-asset admission
limit, one active request per asset and a separate 32-request admission queue.
Alternating manual/scheduled admissions preserve progress for both. Scheduled jobs
rotate customers and clusters. Shared admission caps both manual and scheduled work
at three active jobs per customer and two per cluster (all memberships count). These caps can leave capacity unused in small
single-scope fleets. More than 1000 cluster memberships blocks a profile. Scope pause
controls are bounded to 3000 records. These initial limits are fixed policy bounds.

Initial and resumed execution is staggered over the configured interval. Subsequent
cadences add deterministic positive jitter of up to 10%; overdue polls coalesce into
one new attempt. Restart never replays interrupted commands or missed intervals.
At most one retry follows an entirely failed attempt whose individual transport
outcomes are explicitly transient connection/DNS failures, after 5–7 seconds.
Authentication, host identity, permission, configuration, parser and command-deadline
failures do not retry. Every actual attempt uses NW-010 history with `scheduled`
source, profile ID/revision and the exact approved collector subset.

The Scheduler workspace shows measured capacity, due/dispatch times, lag, skipped
queue decisions and retries. Global, customer, cluster, asset and profile pauses
prevent new scheduled work while allowing active work to finish. Resume coalesces
due work. Global emergency stop also rejects manual collection, cancels active
requests and survives restart until explicitly released. Pause and emergency stop
are independent controls; resuming a pause cannot release a stop. These states
express execution policy and collection lag, without evaluating operational health.

Only one application process may own execution. A dedicated PostgreSQL advisory-lock
session enforces this before trust/interrupted-run recovery and scheduler startup.
Loss of that session cancels collection and exits unsuccessfully; the deployed
systemd service restarts and reacquires ownership after database recovery. No SSH
starts without committing its durable run. Startup reconciliation preserves the M2
trust uncertainty gate and marks interrupted evidence accurately. Run one active
application against a database; multiple active instances are unsupported.

`go test -race ./internal/collection ./internal/scheduler` exercises fake-clock and
barrier-controlled queue, cancellation and mixed-scope load cases. Authorized
`NOC_SSH_LAB=1 ./scripts/test-m0` adds actual PostgreSQL migration/authority/recovery
checks and scheduled ordinary-user loopback SSH collection. Synthetic capacity
results establish boundedness and fairness, not a production fleet sizing guarantee.

### Evidence evaluation (NW-012)

The asset Linux Facts page links to a read-only evidence evaluation view. Collection
outcome, observation quality, freshness and operational health are separate fields.
Viewing or evaluating evidence never dispatches SSH. Use an explicit RFC3339 `at`
timestamp for historical selection or a future projection of currently retained
samples. Results include observation/run provenance and policy identity/revision.

Canonical `linux-evidence.v1` policies expire static identity facts after 86400
seconds and dynamic uptime/load/memory/filesystem facts after 180 seconds. Validity
is half-open: evidence is stale exactly at observed time plus TTL. The original stored TTL envelope is retained for provenance; evaluation applies
the explicitly identified policy revision, so a TTL revision may change a sample’s
freshness without changing its timestamp. Polling intervals
do not extend TTL; contradictory cadence is displayed. Failed attempts, pauses and
restarts never refresh previous readings. Asset overrides take precedence over
canonical family defaults; an observation-key override takes precedence over its
family. Disabled overrides produce unknown freshness rather than falling through.

Authenticated, CSRF-protected forms append immutable asset policy revisions with
optimistic concurrency. Supported optional conditions are filesystem utilization
percent at or above a configured threshold, and available memory bytes at or below
a configured threshold. No health thresholds are enabled by default. These narrow
resource conditions require fresh valid evidence and current verified profile
context; generic facts always leave comprehensive host/application health unknown.
No load-to-CPU conversion, service inference or collection commands are added by evaluation.

Historical selection uses observed, received, database-recorded and terminal-run
recording timestamps; it is not a historical PostgreSQL transaction snapshot.
Only committed rows visible to the current repeatable-read query are read. Existing
samples conservatively acquire recording timestamps at migration 009; pre-upgrade
availability cannot be reconstructed. Retention is not reversed or backfilled.
Current inventory/trust context is conservative and is not reconstructed historically.
Policies and retained evidence are sufficient to reproduce a result with the same
explicit context and timestamp; no computed current-state table is maintained.

### Historical monitoring and alerts (NW-013)

Asset Linux Facts links to Monitoring history & alerts. Numeric load, memory and
filesystem samples come from the existing PostgreSQL observations. Select 1, 6,
24 or 168 hours and a filesystem mount where applicable. Queries reject ranges
above 1000 samples; narrow the range rather than silently downsampling. Locally
bundled SVG charts preserve gaps after expired sampling intervals or failed runs.
The exact-value table retains units, UTC source timestamps and observation/run
provenance; timestamps can render in UTC or the browser's local timezone. Retained
latest samples do not imply continuous historical coverage.

Create an explicit NW-012 memory-availability or filesystem-utilization policy,
then opt in an alert rule on the asset monitoring page. Rules have immutable
`evidence-alert.v1` revisions, severity and 0–86400-second duration debounce. There
are no default enabled alerts. The bounded in-process evaluator consumes persisted
canonical evaluation results; it never initiates SSH. It rotates through 20 due
asset cursors per one-second tick, so transitions can be delayed under load or
database failure. Freshness uses exact NW-012 boundaries at each evaluation.

One durable alert identity per rule/resource prevents duplicate active instances.
Continuously usable degraded evidence satisfies debounce; evidence gaps and policy
revisions reset pending time. Active alerts persist with stale/unknown/disabled
evidence until fresh valid evidence establishes recovery. Rule and policy revisions
reconcile the same identity. Acknowledgment is idempotent operator awareness,
separate from recovery. Events retain normalized evidence and policy references.
Bounded on-demand maintenance expires events and old resolved instances after 90
days; active and pending conditions remain. Views show the latest 100 instances and
100 transitions per asset. The alert center lists the first 50 assets by name.

Authenticated asset SSE streams carry reconciliation notifications, never metric
payloads or guaranteed replay. Browsers fetch authoritative HTML on connection,
reconnection and changes, updating charts and alert/evaluation sections. At most 32
streams share bounded 65-second connections; sessions are revalidated every five
seconds and slow writes have three-second deadlines. `X-Accel-Buffering: no`
requests proxy streaming. No external CDN, event broker or remote command is added.

Operational alert policies also support monitoring continuity, corroborated SSH
network unreachability, observed Asterisk runtime failure, expected AMI disconnect,
five supported authentication failures within five minutes, MariaDB query-readiness
failure, per-channel replica failure and explicitly configured replica lag.
These are opt-in conditions using existing normalized observations and authority;
no remote actions or notification delivery are added. Monitoring continuity reads
persisted scheduling intent independently of target dispatch. Its grace is the
largest of the configured threshold, three schedule intervals, or execution budget
plus one interval. Intentional pause, emergency stop and revoked authority hold
incident state rather than implying remote failure or recovery.

Filesystem capacity policies require matching filesystem identity evidence and
exclude known pseudo/transient devices and runtime credential mounts. Unfamiliar
persistent mount paths remain eligible. Every mount remains available in source
evidence. Stale or missing measurements never establish recovery; a successful
empty replica result establishes only that no local replica channels were returned.
Thresholds, debounce and severity remain explicit operator configuration.

### Optional Asterisk inspection (NW-014)

The asset Linux Facts page offers a separate, explicit Asterisk opt-in for each
verified SSH enrollment revision. Existing assets and Linux schedules stay
unchanged. Enable the adapter, then select **Collect Asterisk Facts** to inspect
version, aggregate active channels, PJSIP module availability and optional outbound
registration totals. The compatibility baseline is Asterisk **20.20.1**, verified
against an isolated real runtime. Parsers accept the tested 20.x output grammar;
other major versions are explicitly unsupported. No compatibility with other
release output variants is claimed.

The four optional collectors are `asterisk.identity`, `asterisk.channels`,
`asterisk.modules` and `asterisk.pjsip`, all version 1. They use fixed `asterisk -rx`
inspection commands through the existing approved OpenSSH connection. There is no
sudo fallback. The remote account must already have control-socket access and
restricted CLI permissions. A powerful CLI account is not made read-only by the
application allowlist; administrators must configure their own remote permissions.
The disposable acceptance lab uses default-deny CLI permissions and disables remote
console shell execution. The application never changes remote permissions.

Active channels are **not call counts**. Only the version token and aggregate
counts/capabilities enter observations; raw channel, registration and caller
identifiers are discarded. Missing installation, inaccessible CLI, permission
denial, unsupported command/version and malformed output retain distinct bounded
diagnostics. Optional PJSIP absence never becomes a zero reading or host-down
verdict; a supported empty registration result is an actual zero count.

Manual capability collection must succeed for each selected Asterisk collector
before enabling it in an existing scheduled profile. Schedules share the same
five-asset capacity, per-asset serialization, pause and emergency-stop controls as
Linux collection. Disabling the integration makes its schedules ineligible; queued
SSH commands recheck opt-in after capacity waiting. Enrollment changes require
fresh opt-in and capability evidence. Linux-only manual collection remains the
default, including on hosts without Asterisk.

Asterisk observations use existing durable history, monitoring charts and SSE
reconciliation. Channels and registration totals use `count`, version uses `text`,
and capability flags use integer 0/1 counts. Version/module facts have canonical
86400-second freshness; channels/registrations use 180 seconds. These are freshness
policies, not polling guarantees. Comprehensive service health remains Unknown.
Operational alerts require explicit policies; no call-center conclusions or
expected registration totals are inferred.

### Optional VICIdial cluster context (NW-015)

Open **VICIdial cluster context** from a cluster's inventory detail page to
register an optional installation. Registration defaults to disabled. Explicitly
enable its presentation, and record a known version with its source and optional
UTC verification time, or leave version information Unknown. Updates preserve
immutable metadata revisions and reject stale concurrent edits. Disabling keeps
the installation's metadata and generic inventory intact.

Document dialer, web/application, database or combined roles on the existing
cluster memberships. Assets may participate in multiple clusters, and service
instances retain their existing host bindings. VICIdial context does not create
another asset, role, link or metrics system. Manage RTM and administration links
in the cluster's existing Quick Access: approve, edit, disable or remove HTTP(S)
browser destinations without credentials, query parameters or fragments.
Existing links remain enabled after upgrade.

The enabled context previews up to 20 participating assets and 40 retained
readings per asset, with links to complete bounded inventory/evaluation/history
pages. Linux observations, currently authorized optional Asterisk observations
and unresolved alerts come from the existing evidence pipeline. Each reading
retains its source, quality, freshness and policy revision. Missing observations
are Unknown; channel counts are not customer call counts; generic host facts do
not establish VICIdial campaign or dialer health. No VICIdial API/database
integration, RTM scraping, automatic login, remote discovery or collection is
performed by registration or page viewing. Linux and Asterisk monitoring remain
independent, with their existing explicit authorization and scheduling controls.

## Optional VICIdial Non-Agent API summaries (NW-016)

The VICIdial cluster context links to **VICIdial API summary**. Explicitly enable
an administrator-provisioned credential reference, then refresh manually or
separately authorize cluster-scoped polling. Registration and page/SSE reads never
contact the API. API and SSH collection share five active slots, a finite queue,
per-resource serialization, fairness, pause and persistent emergency stop. The API
attempt budget is 20 seconds, with five-second requests and at least one second
between its three fixed POST functions. Intervals are 60–86400 seconds; one
eligible transient retry uses the existing scheduler. Authentication, permission,
parser and revision failures are not retryable.

Only `version`, `campaigns_list` for one approved campaign, and
`logged_in_agents` for that campaign are registered. Parser
`vicidial-api.v2` supports the documentation/source-based **2.14-210 / build
260925-1400** contract and the installed-source-inspected **2.14-211 / build
261021-1827** contract. The live version/build must match the protected grant
exactly. Endpoint logging review and actual runtime acceptance are required
before real credentials are authorized. API availability
and visible agent totals never establish campaign or service health.

**Credential logging boundary:** the reviewed upstream Non-Agent API source copies
POST fields into its API URL log, including the password. POST alone does not
prevent server-side credential disclosure. Do not authorize a real endpoint until
its credential-redacting logging behavior has been independently reviewed. The
catalog's review digest records an administrator approval; it cannot prove that
an external server has been corrected. `api_url_log=0` alone does not address all
observed logging paths. NW-016 does not modify remote VICIdial installations.

Set `NOC_VICIDIAL_API_CREDENTIAL_CATALOG` to an absolute protected JSON file outside
PostgreSQL and Git. It contains an array of entries with `ID`, `IntegrationID`
(the collection source identity shown in the UI), `Revision`, `Enabled`,
`Endpoint`, `ApprovedIP`, `Campaign`, `User`, `Password`, `ExpiresAt`,
`LoggingReviewDigest`, `ContractVersion`, `ContractBuild` and `Synthetic`.
The file must be regular, owned by root or the application user, and deny all
group/other permissions. Protect its containing directories against replacement
by other users. Never paste this file or real credentials into chat or logs.
A configuration change creates a new immutable source revision and withdraws
old polling authorization; update the catalog to match before reauthorizing.
Rotation/revocation is checked before each request and after responses; an
invalidated response contributes no observations.

Real endpoints require verified HTTPS, the exact `/vicidial/non_agent_api.php`
path, one approved IP and DNS answers exclusively matching that pin. Proxy use,
redirects, URL credentials/query parameters and metadata/link-local destinations
are rejected. Only explicitly marked disposable synthetic fixtures may use
pinned loopback HTTP. A private-VPN plaintext exception is not implemented.
No arbitrary API functions or browser-supplied destinations are accepted.

Responses are transient and limited to 256 KiB / 1000 rows. Persisted data is
limited to version/build, approved campaign configured/active counts, and visible
logged-in/in-call/paused agent counts. Names, lead identifiers, caller IDs,
sessions and raw payloads are discarded. `NO VIEWABLE CAMPAIGNS` is a permission
failure. The legacy contract treats `NO LOGGED IN AGENTS` as insufficient
scope. For the inspected 2.14-211 build only, its exact empty response yields
zero API-account-visible agents after successful same-attempt campaign visibility
verification; it does not establish campaign-wide absence. Other application
`ERROR` responses fail collection even when HTTP status is 200. Independent
successful collectors and earlier valid readings survive later failure.

Migration 013 extends canonical collection history, observations and schedules
with a scoped cluster source; it does not create another telemetry store. Three
canonical freshness policies use 86400 seconds for version/build and 180 seconds
for campaign/visible-agent summaries. No alert or health threshold is seeded.
Charts show exact retained samples for the selected configuration revision, up to
1000 samples over seven days, with gaps rather than interpolation. Authenticated
SSE only requests reconciliation from PostgreSQL. Existing asset policies and
Linux/Asterisk monitoring remain independent.

## Optional VICIdial server discovery (NW-36 Slice A)

Server Details provides **Refresh Discovery** for an authorized, verified SSH
enrollment revision. This explicit action opts that revision into the optional
adapter; viewing the page reads saved observations and never executes SSH.
Installation roles are separate from runtime service health. Failed collection
retains the previous valid observation with its original timestamp and freshness.

The reviewed command extracts only approved version and non-secret configuration
fields. The confirmation contract currently covers ViciBox 12.0.2, deployed
VICIdial application marker 2.14-968a, and local SVN source revision 4034.
The source revision is context, not proof that every deployed file matches SVN.
Other revisions retain Candidate/Unknown conclusions. Inaccessible files,
unsupported addresses and database permissions remain explicit uncertainty;
the adapter never uses sudo or database credentials.

Configured roles and deployment use the ViciBox installer's shared
`asterisk.vicibox` registry, bound to the configured local address, database and
port. The address must belong to the observed host. Web/Telephony require the
corresponding installed component; Archive also requires its supported web alias.
A single registered address with all core roles and a Primary designation can
establish configured Standalone only without contradictory replication evidence.
Distinct registered peer addresses support configured Cluster Member, without
contacting or enrolling peers. Legacy/manual nodes and operational drift remain
unverified. Database package presence alone never establishes Primary/Replica;
confirmation additionally requires positive, agreeing replication evidence.

Evidence is one minimized canonical observation with collector/evaluator versions,
timestamp, reasons and hashed candidate peer references. No passwords, arbitrary
registry fields, recordings, raw configuration or peer addresses are retained.
PostgreSQL migration 014 extends existing observation constraints and freshness
policy; it does not create inventory members, schedules or remote authority.
Runtime service monitoring and its monitoring-first Dashboard/Server Details
presentation are described below.

## Runtime service monitoring (NW-36 Slice B)

New SSH enrollments explicitly authorize **Standard Server Monitoring** as part
of enrollment: Linux resources, processes, services, readable schedules, supported
VICIdial discovery and the reviewed read-only Asterisk catalog. Once host identity and connectivity are verified, the same
transaction creates the persistent 60-second NW-011 schedule. Collection continues
without a browser and after application restart. Existing enrollments retain their
original permissions; a one-time consolidated expansion is available in Connection
Settings. Existing grants are reused without changing the enrollment revision.
Parser-only updates do not require another grant; a changed endpoint, host identity
or credential scope still invalidates authority.
Maintenance pause/resume, global emergency stop and the shared five-asset admission
limit remain authoritative. Separately approved optional collectors are preserved;
a combined profile exceeding the existing ten-collector limit is rejected atomically.
Static installation discovery stays on demand. The interval is a target: scheduling
jitter, capacity, connectivity and execution can delay observations. Passive page
reads never contact monitored servers.

The baseline capability samples `/proc/stat` counters over one second for CPU
utilization, separately from load averages. It supplements existing memory and
filesystem collectors with swap, PSI memory pressure where readable, and top CPU/RSS
process identities (PID and executable name, never command arguments). Process CPU
is a share of whole-host capacity, not a per-core percentage. Sampling is bounded to
4,096 readable processes and retains at most ten CPU and ten memory leaders.

Services lists actual systemd service units with separate load/active/substate and
installed-file state; active/exited does not establish a running daemon. Scheduled
jobs lists bounded readable system cron definitions, the SSH user's crontab and
supported timer properties. Arbitrary commands, arguments and environment values
are withheld. Schedule configuration does not establish execution success, and
other users' unreadable schedules remain unverified. At most 512 service units and
192 schedule definitions are retained. Missing capabilities remain unavailable.

Migration 016 adds the revision-bound baseline capability and canonical observation
contracts. It grants no permissions or schedules to legacy enrollments. Resource
measurements, unit/process/job snapshots and numeric history use existing PostgreSQL
observations, policies and SSE. Older values omitted by a newer baseline sample are
historical, even before their original freshness TTL expires.

The fixed read-only collector inspects bounded systemd unit metadata, approved
binary availability and process identities for Asterisk, MariaDB/MySQL and Apache.
It retains the observed canonical unit name, independent unit/process signals,
collector version and provenance. Asterisk CLI, SQL connectivity, HTTP responses,
replication, AMI and service control are not enabled by this profile. A running
process does not establish application responsiveness. ViciBox can have Asterisk
running while `asterisk.service` is inactive; both signals remain visible.

VICIdial process matching currently supports the readable SVN 4034 source layout:
`AST_update.pl`, `AST_VDauto_dial.pl`, `AST_VDauto_dial_FILL.pl`,
`AST_manager_send.pl` and `AST_manager_listen.pl`. Exact paths under
`/usr/share/astguiclient/` are matched in approved process positions; arguments
are discarded remotely. Other
source revisions return Unsupported for these process checks while generic Linux
checks remain available. Missing executables, missing units or an absent process
alone do not establish uninstallation. Without unit authority, negative process
evidence remains Unknown. Restricted or failed inspection never proves Stopped.

Migration 015 extends canonical observations and policy selectors without adding
service inventory tables or automatically enabling polling. Runtime evidence uses
the existing versioned policy evaluator (default TTL 180 seconds). Failed attempts
preserve prior observations and original timestamps. Disabled, paused, blocked,
untrusted or stale evidence has Unknown current runtime state; its last observed
state remains available. Dashboard and Server Details present current runtime monitoring before historical installation discovery;
NW-37 Stage A adds optional registration snapshots; Stage B adds optional normalized authentication events; Stage C adds restricted live AMI events; Stage D adds channel, bridge and conference observations. RTP diagnostics remain deferred.


### Monitoring console (NW-36 Slice C)

Dashboard queries are paginated at 25 servers and retrieve monitoring evidence in
one bounded bulk snapshot. Server Details prioritizes the latest runtime attempt,
last successful runtime collection, original observation timestamps and discovered
resources, processes, real systemd units and readable schedule definitions. A failed attempt is displayed separately from retained valid evidence.
An inactive unit cannot override an observed running process. Stale or disabled
readings retain historical values inside evidence disclosures, with no current
Running assertion. These signals do not establish comprehensive application health.

Historical VICIdial installation, topology and role classifications appear below
runtime monitoring. Collector/evaluator versions, source references, identifiers,
uncertainty and full UTC timestamps remain in collapsed technical evidence.
Routine timestamps use Philippine time (PHT, UTC+08:00). Installation metadata
freshness is labelled separately from runtime policy freshness. Restricted
same-origin SSE notifications reconcile persisted HTML, including freshness and
monitoring authorization changes; passive navigation never starts remote checks.

### UI Foundation E1 (NW-38)

The shared console uses a light theme by default, with a local dark-theme preference,
global server search and Dashboard, Servers and Alerts navigation. Secondary
administration remains under the collapsed Manage menu. Refresh Display reads
persisted evidence only. Server Details presents valid current CPU, memory and
storage gauges; missing, stale or paused measurements do not generate gauges.
Resource measurements and All Filesystems retain original values and timestamps
on demand. Services shows searchable systemd units; Processes shows sortable top
CPU consumers and expandable memory/application observations. Scheduled Jobs,
History and VICIdial have separate direct sections. Without JavaScript, all
sections remain readable. Existing history views provide retained time series;
embedded overview sparklines are deferred to Monitoring Console E2. No new
collectors, permissions, schedules, database tables or remote access are added.

### SIP/PJSIP registration snapshots (NW-37 Stage A)

Server Details → Services → **Asterisk monitoring** presents separately observed
SIP peers, SIP outbound registry, PJSIP endpoints, contacts and outbound
registrations. Authorize **Standard Server Monitoring** once in Connection
Settings. **Verify and schedule snapshots** then reuses that authority, verifies
version and snapshot capability, and extends the existing baseline profile at a
60-second target interval. It does not clear maintenance, global pause or
emergency-stop controls. The reviewed Asterisk catalog also includes the existing
fixed `core show channels count` and `module show like pjsip` collectors; only
registration snapshots are added to this profile. Passive pages and SSE never
execute collection.

The fixed snapshot commands are `sip show peers`, `sip show registry`,
`pjsip show endpoints`, `pjsip show contacts`, and `pjsip show registrations`.
Parsing supports Asterisk 18/20 output conventions with deterministic fixtures;
actual deployment compatibility depends on successful authorized capability
inspection. Direct CLI access uses the existing SSH account without sudo. An
administrator-installed fixed-command gateway is available when direct socket
access is inappropriate; it requires a separate explicit checkbox within the
consolidated grant. It is never selected as an automatic fallback after an error.
No AMI or Asterisk configuration changes are performed by collection.

Snapshots retain sanitized endpoint/AoR identities, host/contact locators,
reported states, supported reachability/RTT, original timestamps and versioned
provenance in the existing observation/history tables. URI userinfo, parameters,
authentication objects and caller-ID fields are omitted. The bundle is bounded
at 64 KiB and five seconds, with at most 256 rows per command. Oversized or
malformed families fail explicitly and retain older evidence; successful empty
snapshots replace prior object lists. PJSIP CLI addresses can be truncated.

An endpoint is not a registered account. PJSIP contact presence does not prove
whether the contact is static or dynamically registered; registration remains
Unknown. Reachability and outbound registration validity remain separate.
Unsupported commands have no fabricated zero counts. Disabled, stale,
superseded or failed snapshots are labelled historical, and snapshot changes
show observation-time brackets rather than exact event times. Detailed evidence
is expandable, including the actual direct/gateway command identifier. Direct
access requires permission to use Asterisk's control socket; the application does
not change remote permissions.

The optional `scripts/asterisk-observe` gateway accepts exactly `identity`, `registrations` or
`activity`, executes only the fixed version/snapshot CLI commands, and
has a four-second remote deadline in addition to SSH execution/output limits.
It must be installed by an explicitly authorized administrator at the reviewed
root-owned, non-writable path with exact argument-specific sudoers delegation.
Do not grant general Asterisk CLI, shell, group or control-socket access. Gateway
selection requires both the current Asterisk grant and its explicit gateway grant,
rechecked at transport execution. The activity bundle requires its own consolidated monitoring opt-in. Migration 018 preserves existing grants and observation checks while
adding only the two matching gateway provenance pairs and the consolidated grant
audit operation. It grants no new authority during startup.


### Authentication events (NW-37 Stage B)

Server Details → Services → Asterisk monitoring includes authentication failures,
5/15/60-minute filters and account/observed-IP/event-type groups. Five supported
failures within five minutes mark a repeated-failure signal, not an attack verdict.
Unknown identities are kept separate. Observed source IP can identify a proxy,
SBC or NAT device. Technical details retain UTC while routine times use PHT.

Enable **Asterisk authentication logs** in the existing Standard Server Monitoring
form. This explicitly expands a previously snapshot-only grant and adds the
optional collector to the existing schedule without clearing any pauses. Existing
installations gain no log-reading authority on upgrade. Direct reads use the
approved SSH account; a separate disclosed log-reader option selects the optional
administrator-installed `scripts/asterisk-auth-read` gateway. The Stage A helper
grant does not authorize log access. Neither option changes logger configuration,
permissions, Asterisk state or call control. Python 3 and timeout are required on
the observed host. No daemon, cron job or background remote process is installed.

The fixed reader inspects only `/etc/asterisk/logger.conf` and configured regular
files named `security`, `security_log`, `messages` or `full` beneath
`/var/log/asterisk`. It prefers configured security-category files, then configured
notice/warning messages/full files. Arbitrary configured paths, includes and
symlinks are not followed; incomplete configuration is reported. Custom destinations
need a reviewed fixed-source extension. Readability and availability are separate
from a successful empty inspection. Live compatibility requires actual source
inspection; synthetic fixtures do not establish lab compatibility.

Supported security EventVersion 1 failures are InvalidPassword, InvalidAccountID
and ChallengeResponseFailed; ChallengeSent and SuccessfulAuth are excluded.
RequestBadFormat is recognized as a malformed-request security event and excluded
from authentication-failure counts; it does not establish a password failure.
Security EventTV epoch-microsecond/RFC3339 timestamps are supported. Explicit
chan_sip registration warnings retain the requested account URI and distinguish
Wrong password, Username/auth name mismatch and No matching peer found. Explicit
PJSIP failed-request warnings distinguish Failed to authenticate and No matching
endpoint found; From headers are not promoted into account identity. Warning
formats require year-bearing timestamps and an observed numeric timezone;
yearless warning destinations are unsupported, including empty windows. Parsers follow the
[Asterisk security event schema](https://docs.asterisk.org/Latest_API/API_Documentation/AMI_Events/InvalidPassword/)
and [Asterisk 18 chan_sip failure paths](https://github.com/asterisk/asterisk/blob/18/channels/chan_sip.c).

Each dispatch reads at most two 24-KiB chunks within existing SSH deadlines and
64-KiB output bounds. First synchronization uses a bounded tail; skipped history
is a coverage gap. Durable enrollment/source cursors retain device/inode,
generation, offset and a SHA-256 boundary anchor. Retained uncompressed .1/.0
rotation is drained; missing rotation and copy-truncation produce explicit gaps.
Unfinished lines are reread without storing raw fragments. Oversized lines and an
unfinished rotated EOF are discarded with an explicit gap so collection can
progress. Backlog continues on subsequent existing scheduler ticks.

Migration 019 commits normalized events, cursor CAS and source status atomically
with canonical observations. Event identity includes server/endpoint, source,
file identity, generation, byte position and event timestamp. Restart reopens the
committed cursor; uncommitted work can be replayed. Normalized event retention uses the existing
sample-retention setting and bounded maintenance. No raw lines, SIP headers,
digests, challenge responses or unrelated calls are retained. SQL window totals
cover all retained events, while the displayed group list is bounded at 100.

Current coverage requires a successful inspection within 180 seconds. Source
errors, failed transport, pause/revocation, incomplete lines, unsupported formats,
backlog never establish a current zero-failure result. Successful caught-up reads
after a gap show current collection with explicit incomplete historical coverage;
their observed counts cannot establish a complete zero-failure result. Known gap history
remains explicit for that enrollment/source across revisions. Passive GET and SSE only read persisted
data. Stage B adds no account blocking or remote security action. Restricted AMI transport is described below.


### Restricted live AMI events (NW-37 Stage C)

Server Details → Asterisk now supports a separate, explicit AMI forwarding grant.
An administrator must first configure a loopback-only AMI listener, a dedicated
AMI identity initially using `read=system`, `write=none`, and account-specific include filters
for `FullyBooted`, `PeerStatus`, `ContactStatus`, `Registry`, and `Shutdown`.
The application sends only fixed Login and Ping actions; it provides no AMI
command or call-control interface. Legacy `eventfilter = ^Event: Name` syntax
works on the verified Asterisk 18 installation; newer filtering syntax must be
verified against the installed revision before use.

A dedicated SSH identity must allow only local direct forwarding to that exact
loopback port. Use administrator-owned authorized keys with
`restrict,port-forwarding,permitopen="127.0.0.1:5038",command="/bin/false"`
(adjust only to the inspected port), plus an SSHD `Match User` block setting
`AllowTcpForwarding local`, `PermitOpen 127.0.0.1:5038`, `PermitListen none`,
`ForceCommand /bin/false`, and disabling TTY, agent/X11 forwarding and password
login. Preserve any existing `AllowUsers` restrictions when adding this identity.
Validate `sshd -t` and effective `sshd -T -C` settings before reload. The regular
collector executor continues to disable all forwarding.

Set `NOC_ASTERISK_AMI_CREDENTIAL_CATALOG` to a protected mode-0600 JSON array,
owned by root or the application user. Each entry has `ID`, `ProfileID`,
`ProfileVersion`, `SSHUser`, absolute `IdentityFile`, lowercase SHA-256
`IdentitySHA256`, numeric `Port`, `Username`, `Secret`, and `Enabled` fields.
Protect the dedicated private key identically. Credentials never enter the
browser or database; only the credential reference and digest are persisted.
Enrollment revision, protected catalog, current trust, monitoring authorization,
pause and emergency-stop state govern the worker. Changing the catalog requires
explicit reauthorization of its new digest.

One managed connection per authorized server runs without a browser. It uses
strict enrolled host-key verification and OpenSSH `-W` to the protected loopback
port. Establishment is limited to 10 seconds, heartbeats run every 20 seconds
with a 10-second response deadline, and reconnect backoff is bounded to 1–32
seconds. Shutdown and revocation close and join the transport; restart recovery
ends prior sessions with an explicit coverage gap. AMI failure does not mark
Linux unreachable. Existing 60-second SSH collectors retain their schedule.

Only normalized allowlisted operational fields are retained. SIP URI credentials,
caller/dialplan payloads, authentication material and unknown events are omitted.
Stage D retains only the operational channel identifiers described below.
The 128-event queue records drops as coverage gaps; database failure disconnects
the non-replayable stream. Receipt timestamps are distinct from optional Asterisk
timestamps. Session sequences make persistence retries idempotent within a
session; AMI does not supply durable cross-session replay identities. The UI
shows current connection state, recent events, UTC provenance and transitions.
Events are retained for seven days, sessions for thirty days, with bounded
cleanup during ingestion. Passive GET/SSE reads do not connect or collect.

The verified lab emitted `FullyBooted` on login. ContactStatus, PeerStatus and
Registry normalization have deterministic fixtures; a fixture does not establish
that a particular live installation emits those families. RTP/RTCP observations are described in Stage E below.


### Channels, bridges and conferences (NW-37 Stage D)

The existing Asterisk panel adds bounded channel search, reported states, observed
duration, endpoint-resource association, bridge membership and independent
MeetMe/ConfBridge counts. The Standard Server Monitoring form has one explicit
**Channels and conferences** expansion. Existing grants and schedules are not
silently expanded. AMI Login requests `system,call` events only while this grant
is current; ordinary Stage C sessions continue to request `system` alone.

Administrator setup extends only the dedicated manager account to
`read=system,call`, retaining `write=none`, loopback binding and restricted SSH.
Classic anchored event filters additionally admit `Newchannel`, `Newstate`,
`Hangup`, `BridgeCreate`, `BridgeDestroy`, `BridgeEnter`, `BridgeLeave`,
`MeetmeJoin`, `MeetmeLeave`, `ConfbridgeStart`, `ConfbridgeEnd`,
`ConfbridgeJoin` and `ConfbridgeLeave`. Runtime still sends only Login and Ping;
no call-control or generic CLI action is available.

The fixed `asterisk.activity.v1` / `asterisk.activity.helper.v1` snapshot bundle
uses `core show version`, `core show channels concise`, `bridge show all`,
`meetme list concise` and `confbridge list`. It runs on the existing 60-second
scheduler, bounded to five seconds/64 KiB and 256 objects per family. The helper
has an additional four-second process-group deadline. Unsupported conference
commands remain Unsupported; failed, malformed or truncated bundles never
establish zero activity. A successful empty snapshot replaces the current set
without manufacturing Hangup history.

Canonical channel identities are scoped to enrollment, endpoint and the observed
Asterisk process generation. Uniqueid identifies a channel; Linkedid records
related lifecycles without inventing a call or SIP-account identity. SIP/PJSIP
channel resources are labelled unverified until a matching fresh registration
snapshot establishes the endpoint definition. This does not prove authentication,
registration reachability or trunk classification. Local resources, caller names,
numbers, dialplan contexts and application data are omitted. CLI snapshots provide
conference counts; participant identities are available only from observed events.

Snapshots and events serialize in one PostgreSQL transaction boundary. The
persisted event journal replays activity received since snapshot start. Activity
within the remote-read interval conservatively leaves the baseline incomplete
until a stable snapshot succeeds, rather than claiming an exact atomic remote
snapshot. Queued older events cannot overwrite a newer baseline, and lifecycle
tombstones reject delayed resurrection. Disconnect, restart, queue loss, unknown
lifecycle evidence and failed snapshots invalidate current-state claims. A fresh
baseline in the current AMI session is required to restore them. Current snapshot
freshness expires after 180 seconds independently of AMI connection health.
Historical observations and normalized event timestamps remain unchanged.

On the verified Asterisk 18.26.4-vici lab, the fixed snapshot returned no active
channels, bridges or conferences; both conference commands were supported.
Populated channel, bridge and conference transitions are tested with deterministic
fixtures. An empty live lab does not verify emission of each populated event
family. No calls or participants are generated for validation.

### RTP/RTCP media observations (NW-37 Stage E)

The existing Asterisk panel adds an explicit Media reporting expansion within
Standard Server Monitoring. It requires channel monitoring and requests
`system,call,reporting` through the existing restricted AMI session. Administrators
must add only `reporting` to the dedicated account's read classes, preserve
`write=none`, and append anchored include filters for `RTCPReceived` and `RTCPSent`.
A connected session confirms transport/login, not that reporting permission,
filters or an endpoint actually produced an RTCP event.

RTCP reports retain bounded operational fields and exact channel Uniqueid,
Asterisk process generation, session and SSRC provenance. Endpoint attribution
reuses verified channel evidence; Linkedid alone never establishes ownership.
Received report blocks describe the remote receiver's report about Asterisk's
transmitted stream. Sent blocks describe Asterisk's local receive observations.
SR sender packet counts remain separate from report-block loss. Fraction lost is
an interval fraction divided by 256; cumulative loss uses the signed 24-bit RTCP
representation. Missing measurements remain unknown. Jitter remains in RTP
timestamp units when no verified clock rate is available. Received RTT converts
seconds to milliseconds only with fresh block-zero LSR evidence; delay fields
are not treated as independent RTT measurements. Asterisk 18's serializer may
omit report blocks after block zero; such reports retain an incomplete flag.

The optional fixed CLI bundle uses `sip show channelstats` and
`pjsip show channelstats` through the existing gateway's exact `media` argument.
The standard schedule grows to eleven bounded collectors. CLI identities are
truncated by the installed commands, so their rows remain uncorrelated and
omit peer, Call-ID, channel and bridge text. Only source-labelled packet counters,
loss counters and source-reported percentages persist. CLI jitter and RTT are
omitted because those summaries do not establish the stream provenance used by
RTCP reports. A failed command or incomplete bundle cannot establish an empty
snapshot. An exit-zero unsupported command remains Unsupported.

The media table exposes up to 100 recent journal entries within the existing
seven-day event retention. Evidence expires independently of connection health:
current RTCP observations require a fresh reconciled active channel in the same
runtime/session and reports younger than 60 seconds. CLI snapshots expire after
180 seconds. Hangup, disconnect, pause, revocation or stale reconciliation leaves
prior reports historical. Reconnection cannot reconstruct missed RTCP reports.
Session/sequence replay is idempotent; AMI supplies no durable cross-session
replay identity. No raw frames, caller numbers, dialed numbers, media content or
quality scores are stored. Direct media or absent RTCP can legitimately leave a
channel without measurements; missing data never means zero loss or healthy.

### Optional MariaDB socket monitoring (NW-017)

Server Details → Services includes MariaDB query readiness, global activity,
replica-channel status and bounded recent history. Enable the MariaDB checkbox in
Standard Server Monitoring after administrator setup. The existing scheduler
collects every 60 seconds; passive HTTP and SSE reads never execute SQL. Process
and systemd state remain separate from an authenticated connection and `SELECT 1`.
Readiness, activity availability and replica status are independent observations.
A failed collection preserves prior evidence as historical rather than refreshing
its timestamp. Current evidence expires after 180 seconds.

The reviewed MariaDB 10.x reader is `scripts/mariadb-observe`, installed as
root-owned, non-writable `/usr/local/sbin/noc-mariadb-observe`. Its root-owned
`/etc/noc-workbench-mariadb.json` contains only the verified local socket path, for
example `{"socket":"/run/mysql/mysql.sock"}`. A dedicated OS account `nwdbmon`
(with no login shell) authenticates to `'nwdbmon'@'localhost'` using `unix_socket`.
The database identity requires only `REPLICA MONITOR` (reported as `SLAVE MONITOR`
by some MariaDB revisions), with no application-database grants. Inspect effective
inherited privileges as well: MariaDB PUBLIC or role grants can otherwise confer
unexpected access. Administrator setup must establish effective read-only access
before enabling collection.

Delegate only the no-argument reader to the enrolled SSH observer, using a validated
sudoers rule such as:

```sudoers
observer ALL=(nwdbmon) NOPASSWD: NOSETENV: /usr/local/sbin/noc-mariadb-observe ""
```

This separate opt-in capability does not grant arbitrary SQL or root execution.
The helper uses fixed SQL, a four-second shared deadline and bounded output. It
reads no application tables and stores no credentials, query text or raw database
error messages. Connection/authentication/permission/query/timeout failures use
sanitized diagnostic codes. Replica errors retain error numbers and operational
classification while omitting potentially sensitive server error text.

Global measurements distinguish current connections, running threads, the
connection high-water mark, cumulative connection attempts and aborted attempts,
uptime and configured capacity. Missing values remain unavailable; counters are
not displayed as rates. `SHOW ALL REPLICAS STATUS` is parsed by column name and
retains each channel independently. NULL lag is unavailable, zero lag alone does
not establish health, and positive lag is labeled Delayed. A successful empty
result means no local replica channels were returned; it does not establish a
Primary or Standalone role or exclude downstream replicas. Role remains Unknown
without sufficient topology evidence; configured local replica channels support
Replica classification. Migration 023 extends the existing scoped observation
journal and creates no separate database-monitoring store.

Focused helper tests: `python3 scripts/mariadb-observe_test.py`. Go parser,
authorization, stale evidence, transport and PostgreSQL integration tests run
through the existing verification commands, including `./scripts/test-m0`.

Full Linux and expanded scheduled SSH profiles (seven to twelve approved collectors)
use a 40-second aggregate deadline, including admission, sequential SSH handshakes
and evidence persistence. Profiles with at most six collectors retain a 20-second maximum; manual
collection remains 10 seconds and cluster API attempts remain 20 seconds.
Per-command SSH deadlines, output limits, concurrency, pause and cancellation
remain unchanged. The 60-second cadence does not guarantee completion under
slow or failing sources; timeout, lag and freshness evidence remain explicit.
