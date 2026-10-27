# v1.1 data contract

Source: `IMPLEMENTATION_PLAN.md` v1.1 Sections 5, 14–15. M0 implements migration tracking, hashed-token operator sessions and singleton local workspace settings. These tables do not represent customers or monitored services.

M1 must keep customer → environment ownership explicit, with distinct assets (hosts), logical services, service instances and instance-to-host bindings. An asset can host several instances; a service may span multiple instances and hosts. Do not collapse a service or instance into a host label.

Use composite unique keys `(id, environment_id)` and composite foreign keys for cluster memberships, optional service-cluster relationships, service-instance ownership and instance-host bindings. Endpoints belong to an asset; connection profiles must reference an endpoint of that same asset. Cross-customer/environment associations, including direct SQL writes bypassing HTTP, must fail transactionally. Incident and integration ownership must preserve the same boundaries. Nullable associations must not bypass ownership validation.

Collection outcome, observation quality, policy-evaluated service health and freshness remain four independent dimensions. Runs retain endpoint, exact approved profile/collector/spec versions and timestamps. Evaluated health references fresh evidence and policy version; unreachable collection does not establish service down. Expired evidence cannot establish current healthy/down. No M0 table preempts these contracts.

Migrations live in `internal/store/postgres/migrations/` and are embedded in the binary. Names are sorted, history is contiguous and checksummed, and all pending migrations apply in one transaction under a transaction-scoped advisory lock. Unknown/modified migrations fail startup. Never edit an applied migration; add an ordered migration. Pool size and statement/connect/startup deadlines are bounded. Before applying future changes, test empty initialization, upgrade, rollback on failure and direct-SQL scope rejection. For release rollback, restore a pre-upgrade backup with the matching binary; M0 does not run destructive down migrations.


NW-004 migration `003_customer_environment.sql` implements UUID-backed `customer` and `environment` tables. Customer fields are display name, normalized uppercase short code, optional notes, active/archived status and creation/update timestamps. Display names have case-insensitive global uniqueness; codes have global uniqueness. Environment fields are immutable customer ownership, name, lab/test/production classification, active/archived status and timestamps. Environment names are case-insensitively unique within their owner; `(id, customer_id)` is a candidate key for future scoped references. The customer foreign key restricts deletion. Lengths, normalized codes, statuses and classifications have SQL checks.

Archival is non-destructive and reversible. Archived names/codes remain reserved. A trigger rejects changing an environment's ID or owner and rejects environment writes under an archived customer. It locks the parent row through the transaction, serializing writes against customer archival. No clusters, assets, service instances or remote enrollment are introduced. Existing M0 migrations remain immutable, and upgrade tests retain settings and sessions.

NW-005 migration `004_topology.sql` adds distinct `cluster`, `asset`, `asset_endpoint`, `cluster_membership`, `service`, `service_instance` and `service_instance_host` tables. Each is explicitly environment-scoped; composite foreign keys protect every relationship, including nullable service-cluster assignments. UUID identities and owning environment/asset/service references are immutable. Services may change their optional cluster within the same environment. Cluster/asset/service names are case-insensitively unique per environment; instance names and nonempty instance keys are unique per service. Membership and binding pairs are unique. One asset may belong to multiple clusters; one instance may bind multiple hosts, and one host may bind multiple instances and services.

Topology lifecycle values are `active` and `archived`. Archival never deletes or cascades: existing edges remain historical inventory, and an archived owner makes those relationships ineligible for active use. New or edited active assignments require active customers, environments and referenced topology owners. Trigger-held shared parent locks serialize assignment writes against archival. Archiving a dependent record and removing a membership/binding remain available. Restore ancestors before restoring dependents. No health, trust or observed operational state is inferred from lifecycle.

Endpoints accept SSH, HTTP, HTTPS, TCP or UDP with explicit port 1–65535 and IPv4/IPv6/DNS host validation. Endpoint tuples are unique per asset; addresses are never globally unique and never merge asset identities. Only one active endpoint per asset may be preferred. Enrollment is inventory-only and performs no resolution, connection or discovery. Manual memberships and host bindings have `source=manual` (memberships) and null verification timestamps; enrollment cannot claim independently verified observations. Tags are bounded plain-text inventory labels. No credential or connection-profile schema is introduced in this slice.

NW-006 migration `005_operator_workspace.sql` seeds one immutable stable local-operator identity independent of sessions or display names. A typed target registry references actual inventory rows using restrictive foreign keys, composite customer/environment ownership and exact-kind shape checks. Target identity/scope and note/link owner/target cannot be reassigned. Pins and recent visits are unique per principal/target; repository transactions serialize recent-history retention at 20 records. New notes, links and pins lock their owners and reject archived resources; archival retains history and removal remains available.

Notes reference an author and target with explicit private/shared visibility. Reads require target scope plus author ownership or shared visibility; edits/removal require author ownership. External links are scoped to customers/environments/clusters, retain their approving actor and have bounded labels/HTTP(S) URLs and typed classifications. Workspace audit rows record actor, target, operation and timestamp without note bodies, credentials or URLs. Command preparation is recorded as `command.copy`; this does not prove a clipboard write or connection execution. PostgreSQL full-text indexes cover canonical inventory, membership roles and notes; query scope is applied before result ordering/limits. Current single-operator authorization is not multi-user RBAC or PostgreSQL RLS.


NW-008 migration `006_ssh_enrollment.sql` adds `connection_profile` and `connection_audit`. Composite endpoint/environment/asset and environment/customer foreign keys enforce ownership. Profile owners cannot be reassigned; every update advances an optimistic revision. Endpoint updates invalidate existing trust. Public approval metadata records stable authorizing/approving principals with foreign keys; audit rows reference the same persistent principal. Catalog/private key contents are never stored in PostgreSQL. Enrollment repository transactions lock active customer, environment, asset and endpoint rows before committing transitions, serializing commits against archival and endpoint edits. An in-flight contact is not cancelled by an inventory edit, but its stale result cannot commit as verified. Connection outcomes remain separate from lifecycle and operational health.

NW-010 migration `007_collection_history.sql` adds `collection_run`,
`collector_result`, `observation` and `ssh_execution_guard`. Composite profile
ownership and run provenance keys reject cross-environment/customer/asset evidence.
Each authorized request has a stable UUID, initiating principal, manual source,
endpoint/profile revision and UTC lifecycle timestamps. Five versioned collector
results are unique per run; typed observations have UUIDs, exact collector/command
provenance, numeric/text values, stable key/unit constraints and valid quality.
Completion inserts all results and observations and updates the run atomically.
Failed writes leave a recoverable unfinished run, never a successful empty result.
Startup marks unfinished runs interrupted without SSH retries.

Latest-valid evidence is queried from indexed historical observations, independently
of the last attempt. No second latest-value store exists. Default TTL is 180 seconds;
freshness is calculated on reads. Demand-driven bounded maintenance removes old
nonlatest samples after seven days and empty run summaries after thirty days.
Latest key/mount series and the parent run/results remain indefinitely for provenance.
Retention and TTL are configurable. History uses 20-row scoped keyset pagination;
latest evidence display is bounded with explicit truncation. Diagnostics contain
bounded codes only, never general raw remote output.

The SSH guard is a durable pre-contact uncertainty marker. Single-process startup
reconciliation atomically clears surviving profiles' approval, advances revisions,
audits recovery and deletes markers. Disabled/rejected states remain authoritative.
Failure to reconcile prevents startup. It extends existing approval authority rather
than establishing a second trust model.

NW-012 migration `009_evaluation_policy.sql` adds immutable `evaluation_policy`
revisions. Composite customer/environment/asset foreign keys enforce ownership;
identity/selector/scope remain fixed across a contiguous revision chain. Only five
canonical family defaults are seeded; health thresholds require an explicit asset
policy. Asset-row locking serializes API revision changes. Policies are bounded to
4096 revisions per asset. Historical lookup selects the latest applicable revision
recorded by the evaluation timestamp, with key > family and asset > canonical
precedence. Disabled overrides mask defaults. Policy edits cannot dispatch collection.

Observation `recorded_at` and run `evidence_recorded_at` distinguish measurement time
from database recording time. Historical queries exclude future measurements,
receipts and terminal-result recordings, using scoped latest-series queries without
another evidence store. These are event timestamps inside transactions, not commit
visibility history. Existing rows conservatively become available at upgrade.
Current lifecycle/trust context is supplied separately; historical trust is not
inferred. Retained samples may be projected into the future to verify exact expiry.
Evaluation is pure, bounded to 2048 series and 32 applicable policies, versioned and
clock-free. Overall service health remains unknown; narrow configured resource
conditions never imply application availability.


NW-013 migration `010_alerts.sql` adds immutable scoped `alert_rule` revisions,
`alert_cursor` evaluation rotation, one `alert_instance` per rule/resource hash,
and transactional `alert_event` history. Composite foreign keys and a policy-scope
trigger reject foreign asset/environment/customer policies and alert events.
Asset-row locking serializes rule revision, evaluation and acknowledgment. State
and event snapshots are normalized and bounded to 32 KiB; no command output is
stored. Policy changes retain alert identity and event provenance. Observations
remain the sole measurement store; a partial numeric history index supports
bounded charts. Alert history maintenance removes at most 1000 expired events and
100 old resolved instances per pass, preserving concurrently reactivated alerts.

NW-014 migration `011_optional_collectors.sql` adds vendor-neutral
`collection_integration` opt-in records, bound by a composite foreign key to the
existing customer/environment/asset/endpoint/profile identity. Opt-in captures the
verified profile revision, actor, update time and configuration revision. Existing
rows are never enabled by migration. A changed enrollment revision invalidates the
opt-in without creating a second trust authority.

Existing runs, collector results and observations accommodate four optional
Asterisk collectors alongside the five Linux collectors. Database checks preserve
Linux contracts and validate adapter key/type/unit/resource combinations. No new
telephony evidence table exists. Four canonical family freshness policies extend
the existing policy vocabulary; no health thresholds or alert rules are seeded.
Capability eligibility is established from successful persisted results for the
current profile revision before scheduling. History and chart queries retain their
existing ownership, retention and resource bounds.

NW-015 migration `012_vicidial_context.sql` adds optional adapter-owned
`vicidial_integration` metadata. An installation's stable ID and canonical
customer/environment/cluster references persist across append-only revisions.
Composite foreign keys enforce scope; a cluster-row lock serializes revision
creation and prevents concurrent duplicate registration. SQL constraints and a
trigger enforce revision chaining, immutable updates, bounded text, actor
provenance and version-source/verification consistency. Registration defaults to
disabled. Enabled revisions require active parents; disabling is allowed after
archival. At most 4096 metadata revisions are accepted for an installation.

Documented node roles remain in `cluster_membership.role`; service and
service-instance host bindings remain canonical. Approved operational URLs stay
in `external_link`, which gains `enabled NOT NULL DEFAULT true` to preserve
existing links and support explicit withdrawal. VICIdial context has no new
telemetry, credential, scheduling or alert tables and never grants execution
authority. Existing observation/evaluation/alert repositories supply read-only
context; unknown or stale evidence retains its original interpretation.
