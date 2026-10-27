# v1.1 SSH profile and trust contract

Source: `IMPLEMENTATION_PLAN.md` v1.1 Sections 3, 7–8. M0 contains no SSH execution. This contract constrains M1 identity fields and M2 implementation.

Automated collection must use a reviewed application-controlled minimal OpenSSH profile, fixed executable and identity references, fixed approved endpoint and restricted environment. Arbitrary inherited operator configuration is excluded by default. Review all Include targets before invocation; `ssh -G` alone is not a safety validator. Refuse executable hooks (Match exec, ProxyCommand, KnownHostsCommand, LocalCommand, RemoteCommand), shell expansion, unapproved routes and forwarding/multiplexing. An explicitly reviewed ProxyJump topology must pin and independently verify every relevant endpoint.

Require independently evidenced host-key verification, protected known_hosts/profile files, BatchMode=yes, StrictHostKeyChecking=yes, no TTY, no agent forwarding or unsolicited forwarding. Store credential references, never private keys. Destination/DNS, route, key, identity or profile changes suspend collection until review. Enrollment authorization and exact approved revision are rechecked at execution; merely entering an endpoint must not connect.

Collectors use static versioned allowlisted command specs without interpolated browser input. Bound process count, output, timeouts and cancellation of complete child process trees. No hidden sudo, arbitrary shell API, remote mutation, installed daemon, cron or persistent script. Tests use fake executables and isolated authorized lab endpoints, including malicious configuration, changed key/route, dynamic resolution and hung child cases. Production access always requires separate explicit target/scope authorization.

NW-010 adds a durable pre-contact uncertainty marker to the existing profile.
Each inspect, verify or collector command commits a marker before network contact;
an internal context token identifies the active guarded operation. A failed trust
invalidation or marker cleanup retains the marker and blocks further execution.
Single-process startup atomically clears surviving approvals, advances revisions,
records an audit event and removes markers. Recovery cannot enable disabled/rejected
profiles. If PostgreSQL/reconciliation is unavailable, the application fails closed.
A returning old key requires explicit review, independent fingerprint approval and
verification. No network reconciliation or automatic retry occurs. This conservative
recovery can require reapproval after any interrupted SSH operation. Multiple active
application processes sharing SSH execution are outside the current M2 architecture.

NW-014 optional Asterisk commands are fixed inspections: `core show version`,
`core show channels count`, `module show like pjsip`, and `pjsip show registrations`.
Each runs through the existing transport with a five-second/64-KiB bound and a
fixed locale/PATH. Version framing permits parser-owned capability diagnostics;
command strings contain no operator interpolation. No call control, reload,
restart, module mutation, socket permission changes or privilege escalation is
permitted. Explicit adapter opt-in supplements enrollment and is checked again
at the post-capacity execution boundary. A remote CLI account needs independently
restricted privileges; application allowlisting does not limit that account's
capabilities outside NOC Workbench.
