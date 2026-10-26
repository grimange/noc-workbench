# NOC Workbench

A local-first, agentless infrastructure workspace. M0 implements a host-native Go application, PostgreSQL persistence, a server-rendered local operator interface, authentication, sessions and CSRF-protected workspace settings. It does not collect remote observations. No production access is configured or authorized by default.

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

Open **http://127.0.0.1:8080**. Sign in with the chosen password. Save a workspace label to exercise authenticated persistence. `/healthz` returns application DB readiness, never infrastructure/service health. No JS or CDN is required.

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

The login form and every mutation require CSRF tokens and the exact configured Origin. API/HTTP clients must supply both their session cookie and CSRF token (form field `csrf` or `X-CSRF-Token`) and the Origin header. Login attempts are globally bounded to ten per minute and one concurrent bcrypt operation. Authentication failures intentionally share a generic response. Sessions expire at a fixed TTL; logout revokes the DB session. A workspace setting is local application state, independent of future customer inventory.

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

Inventory pages and writes require the existing operator session. Writes require the existing exact Origin and CSRF checks; invalid or duplicate fields return HTTP 422 with field feedback, wrong-owner or missing records return 404, archived-parent writes return 409, and unavailable storage returns 503 without database details. Customer/environment relationships are also enforced by PostgreSQL constraints and an immutable-owner trigger. All queries use bound parameters. Inventory POST bodies are bounded to 16 KiB to accommodate URL-encoded notes; configure the reverse proxy to allow at least 16 KiB. Authentication and settings retain their 8 KiB application limit.

`./scripts/test-m0` creates its own disposable PostgreSQL deployment and runs the Go checks, real database inventory/HTTP tests, fresh and M0-upgrade migrations, direct-SQL negative tests, transaction rollback, and process/database restart persistence. It never resets the installed application's volume. Migration 003 adds only inventory tables, indexes and a trigger; sessions and workspace settings are preserved. Back up the database before deploying a schema release. Roll back using a matching database backup and binary; an older binary deliberately refuses unknown migration history.

The inventory now supports environment-owned clusters, stable assets, multiple endpoints, explicit cluster memberships with roles, logical services, service instances, and many-to-many instance/host bindings. Open a customer's environment and choose **Open topology**. Each section provides create, detail and edit pages; membership and host-binding removal retains the referenced records. Archive/restore entities through their edit form. Restore owning records before creating active assignments. Existing relationships are retained when an owner is archived.

Endpoint enrollment records an address and port only. It does not connect, resolve, discover, establish SSH trust, or report service health. Asset identity remains independent of addresses; shared hosts and multiple cluster memberships are supported. All topology pages require authentication; mutations retain the existing Origin and CSRF checks. See `docs/DATA_MODEL.md` for lifecycle, uniqueness and ownership constraints.

## Operator workspace (NW-006)

Open **Search & Quick Access** or use the navigation search field. Search covers customers, environments, clusters, assets, endpoints, services, instances, asset tags/membership roles and visible operational notes. Matching uses indexed, case-insensitive word prefixes, including hostname/address tokens; it is not arbitrary substring matching. Results show entity type, customer/environment context and lifecycle, with direct inventory and Quick Access navigation. Queries accept up to 120 bytes/eight terms, return 25 results per page and permit offsets up to 1000.

Pin customers, clusters and assets from Quick Access. The last 20 visited inventory records are retained automatically. Collections allow at most 100 pins per operator and 100 notes/links per resource; remove an existing record before adding another at the limit. Archived targets remain labeled and readable; restore their owners before adding assignments. Notes support plain text (4096 bytes), editing and removal, with stable author identity and private/shared visibility. Private notes are restricted to their principal; shared notes require resource scope. There is currently one operator, so these semantics do not establish isolation between multiple login accounts.

Customers, environments and clusters can hold approved HTTP(S) external links, including optional RTM links pinned first. URLs cannot contain user information, query parameters or fragments. Links open in a separate tab without credentials, automatic authentication or availability checks. Their visibility grants no authority in the linked system.

An active SSH endpoint provides **Prepare SSH command** and clipboard/manual copying. The command uses only validated inventory host/port, disables inherited SSH configuration and forwarding, and requires strict host-key checking against independently verified local known-host entries. It never starts a connection or supplies credentials. Reviewed connection profiles, aliases and application-managed trust remain M2 work.

Migration 005 adds a stable local-operator principal, scoped target references, pins, recent targets, notes, links, actor-attributed change records and search indexes. Sessions and authentication tables are unchanged. New workspace operations pass through a principal/permission/resource-scope service boundary; scope predicates apply before search pagination and result retrieval. The current policy authorizes the one operator. Multiple accounts, scoped role assignments and user administration are deferred; full RBAC is not implemented. Back up PostgreSQL before upgrading and retain the matching binary for rollback.


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

Each shared executor defaults to five concurrent assets, one command per asset, a five-second total budget (including queueing), a five-second connection budget and 64 KiB combined output. Limits can be reduced; callers must reuse the executor to share its concurrency budget. Cancellation/output limits kill the child process group and reap the direct child. Results contain actor/target/command metadata, UTC timestamps, duration, exit status and a typed failure category. Raw stderr is discarded; stdout is transient caller data and must not be logged by default. Exit 255 without a recognized diagnostic is `internal_transport_error`. These are transport outcomes, never service-health assessments. Future collectors may register separate reviewed budgets up to the plan's 20-second initial allowance; no collectors or scheduler are included here.

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
series and explicitly reports incomplete output. Maintenance is demand-driven;
there is no scheduler, background collection or automatic retry.

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
