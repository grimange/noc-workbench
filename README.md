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
