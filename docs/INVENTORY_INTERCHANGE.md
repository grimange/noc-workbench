# Sanitized inventory interchange

The authenticated **Import & export** page supports portable, inventory-only JSON.
It never connects to enrolled endpoints or starts monitoring. It is not a backup.
Use the established PostgreSQL backup procedure to preserve original inventory,
operator settings, notes, sessions, and credentials.

## Version 1 contract

The top-level object contains `format: "noc-workbench.sanitized-inventory"`,
`version: 1`, and `records: []`. Each record has `type`, a lowercase UUID `id`,
and a `fields` object. Limits are 500 records and 256 KiB of UTF-8 JSON.
Unknown fields, duplicate JSON keys, unsupported versions, malformed values,
excessive nesting, duplicate UUIDs, and unresolved or cross-environment references
are rejected. All references must resolve inside the same document.

The compiled field contract is `internal/interchange/interchange.go`:

| Type | Fields |
| --- | --- |
| customer | display_name, short_code, status |
| environment | customer_id, name, kind, status |
| cluster | environment_id, name, type, lifecycle |
| asset | environment_id, name, kind, lifecycle |
| asset_endpoint | environment_id, asset_id, protocol, host, port, preferred, status |
| cluster_membership | environment_id, cluster_id, asset_id, role |
| service | environment_id, cluster_id, name, service_type, lifecycle |
| service_instance | environment_id, service_id, name, role, instance_key, lifecycle |
| service_instance_host | environment_id, service_instance_id, asset_id, binding_role |

All listed fields are required. `cluster_id` on a service can be an empty string
for an environment-scoped service. Port is an integer; preferred is a boolean;
other fields are strings validated against the existing inventory contract.
Customer short codes use uppercase letters. Status/lifecycle is active or archived.
The format preserves the topology and supported classifications, not all metadata.
Timestamps are generated on import; notes, tags and verified-at values are omitted.

## Sanitization

Export uses a consistent read-only PostgreSQL snapshot. It orders records by
entity type and UUID, with deterministic JSON field ordering. UUIDs are mapped
through a domain-separated SHA-256 pseudonym; references use the same mapping.
Names, customer codes, endpoint addresses, instance keys, roles, and free-text
classifications are replaced. Endpoint hosts become `endpoint-<UUID>.example.invalid`.
Closed classifications (such as environment kind, asset kind, and protocol),
ports, preference flags, lifecycle, cardinality, and relationship structure remain.

Authentication data, passwords/hashes, sessions, credentials, private keys,
operational notes, tags, user preferences, external links, and audits are never
selected for export. This is pseudonymization, not a guarantee of anonymity:
cardinality and structure remain visible, and known source UUIDs can be correlated.
Review exported topology before sharing. No unrestricted original-data export exists.
Repeated export of unchanged inventory is byte-identical. Import preserves document
UUIDs. Exporting an imported document pseudonymizes those UUIDs again; graph structure
is preserved, but byte identity across an export/import/export cycle is not promised.

## Preview, collisions, and atomicity

Select the JSON file or paste JSON, then choose **Preview import**. Preview parses
the entire graph and executes the proposed inserts and database constraints in a
serializable transaction which is rolled back. No inventory changes are retained;
preview can acquire locks and produce normal transactional database work.
The report counts records to create or reuse. Validation stops at the first error
and identifies its record number/type without echoing SQL or sensitive values.
There are no silent skips. **Confirm inventory import** revalidates in a new atomic
transaction; a concurrent edit can therefore invalidate an earlier preview.

Missing UUIDs are created. An existing UUID with identical included fields is reused;
excluded metadata is preserved. Conflicting UUID content or natural-key collisions
reject the whole transaction. Existing records are never overwritten or guessed by
hostname/address. Duplicate relationships are rejected. Reimporting the unchanged
same document creates no duplicates. Imports are serialized against other imports;
existing database constraints arbitrate all other inventory writes.

New archived graphs are constructed transactionally before lifecycle is restored
from descendants to ancestors. Historical associations are retained. Adding new
assignments to an already archived record remains prohibited by existing lifecycle
rules. No tables, migration checksums, or accepted authentication contracts change.
Interchange requires the stable local operator and full inventory scope. Partial
scope is denied until a complete authorized graph policy exists; this is not
multi-user RBAC.

## Synthetic example

`internal/interchange/example.json` is also available through **Download synthetic
example**. It contains two synthetic customers with production/test environments,
communications/database/application clusters, seven assets including one archived
asset, multiple endpoints, multiple cluster memberships, four logical services,
instances, and multi-host bindings. It uses RFC 5737 addresses and `.example.invalid`
names. It contains no credentials or live operational data.

To try it, start an explicitly selected disposable development application/database,
log in, select that file on Import & export, preview, and confirm. Nothing seeds
any database automatically. Do not import it into the deployed inventory casually.

Run `./scripts/test-m0` for isolated PostgreSQL round trips, rollback, lifecycle,
migrations, backup/restore and accepted-feature regression tests. `go test ./...`
alone skips database integration tests unless `NOC_TEST_DATABASE_URL` names a
permitted loopback disposable PostgreSQL database.
