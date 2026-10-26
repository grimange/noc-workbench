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
| `NOC_BASE_URL` | `http://127.0.0.1:8080`; HTTP origin must match listener; HTTPS requires a separate literal loopback IP/port for a local TLS proxy; canonical IP/port spelling and non-default ports required |
| `NOC_DATABASE_URL` | Required PostgreSQL URL with explicit user, password, literal loopback IP/port, database and only `sslmode=disable`, `require` or `verify-full` |
| `NOC_PASSWORD_HASH` | Required bcrypt hash, cost 10–14; helper generates cost 12 |
| `NOC_SESSION_TTL` | `8h`; allowed 1 minute–24 hours |
| `NOC_STARTUP_TIMEOUT` | `10s`; allowed 1–60 seconds; store additionally caps DB startup at 10 seconds |
| `NOC_DB_PASSWORD` | Required by Compose only; generate locally |
| `NOC_DB_PORT` | Compose loopback port, default `55432`; update DB URL if changed |

HTTP localhost uses HttpOnly, SameSite=Strict host-only cookies. An HTTPS base URL enables Secure cookies and HSTS; TLS must terminate at an operator-configured trusted local proxy preserving Host and Origin. For example, keep `NOC_LISTEN=127.0.0.1:8080`, set `NOC_BASE_URL=https://127.0.0.1:8443`, and have a trusted loopback TLS proxy on port 8443 forward to port 8080 with the original Host header. The Go listener itself serves HTTP; HTTPS mode intentionally rejects direct browser access at the backend origin. M0 does not provide LAN mode, a proxy, or TLS provisioning. Do not expose the listener publicly or enable a proxy without designing that deployment boundary.

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
