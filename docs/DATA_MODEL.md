# v1.1 data contract

Source: `IMPLEMENTATION_PLAN.md` v1.1 Sections 5, 14–15. M0 implements only migration tracking, hashed-token operator sessions and singleton local workspace settings. These tables do not represent customers or monitored services.

M1 must keep customer → environment ownership explicit, with distinct assets (hosts), logical services, service instances and instance-to-host bindings. An asset can host several instances; a service may span multiple instances and hosts. Do not collapse a service or instance into a host label.

Use composite unique keys `(id, environment_id)` and composite foreign keys for cluster memberships, optional service-cluster relationships, service-instance ownership and instance-host bindings. Endpoints belong to an asset; connection profiles must reference an endpoint of that same asset. Cross-customer/environment associations, including direct SQL writes bypassing HTTP, must fail transactionally. Incident and integration ownership must preserve the same boundaries. Nullable associations must not bypass ownership validation.

Collection outcome, observation quality, policy-evaluated service health and freshness remain four independent dimensions. Runs retain endpoint, exact approved profile/collector/spec versions and timestamps. Evaluated health references fresh evidence and policy version; unreachable collection does not establish service down. Expired evidence cannot establish current healthy/down. No M0 table preempts these contracts.

Migrations live in `internal/store/postgres/migrations/` and are embedded in the binary. Names are sorted, history is contiguous and checksummed, and all pending migrations apply in one transaction under a transaction-scoped advisory lock. Unknown/modified migrations fail startup. Never edit an applied migration; add an ordered migration. Pool size and statement/connect/startup deadlines are bounded. Before applying future changes, test empty initialization, upgrade, rollback on failure and direct-SQL scope rejection. For release rollback, restore a pre-upgrade backup with the matching binary; M0 does not run destructive down migrations.
