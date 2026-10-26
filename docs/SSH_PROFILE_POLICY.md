# v1.1 SSH profile and trust contract

Source: `IMPLEMENTATION_PLAN.md` v1.1 Sections 3, 7–8. M0 contains no SSH execution. This contract constrains M1 identity fields and M2 implementation.

Automated collection must use a reviewed application-controlled minimal OpenSSH profile, fixed executable and identity references, fixed approved endpoint and restricted environment. Arbitrary inherited operator configuration is excluded by default. Review all Include targets before invocation; `ssh -G` alone is not a safety validator. Refuse executable hooks (Match exec, ProxyCommand, KnownHostsCommand, LocalCommand, RemoteCommand), shell expansion, unapproved routes and forwarding/multiplexing. An explicitly reviewed ProxyJump topology must pin and independently verify every relevant endpoint.

Require independently evidenced host-key verification, protected known_hosts/profile files, BatchMode=yes, StrictHostKeyChecking=yes, no TTY, no agent forwarding or unsolicited forwarding. Store credential references, never private keys. Destination/DNS, route, key, identity or profile changes suspend collection until review. Enrollment authorization and exact approved revision are rechecked at execution; merely entering an endpoint must not connect.

Collectors use static versioned allowlisted command specs without interpolated browser input. Bound process count, output, timeouts and cancellation of complete child process trees. No hidden sudo, arbitrary shell API, remote mutation, installed daemon, cron or persistent script. Tests use fake executables and isolated authorized lab endpoints, including malicious configuration, changed key/route, dynamic resolution and hung child cases. Production access always requires separate explicit target/scope authorization.
