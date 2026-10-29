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

NW-37 Stage A adds the optional fixed `asterisk.registrations.v1` bundle:
`core show version`, `sip show peers`, `sip show registry`,
`pjsip show endpoints`, `pjsip show contacts`, `pjsip show registrations`.
It reuses explicit per-enrollment Asterisk authority, approved host-key trust,
noninteractive OpenSSH restrictions and bounded output (64 KiB / five seconds).
The Server Details authorization POST verifies the enrollment and schedule
revisions, preserves all pauses, and schedules only after capability evidence.
Raw CLI dumps, auth object names, caller IDs and URI credentials are not retained.


NW-37 Stage B adds `asterisk.auth.v1`, a static Python 3 fixed-source reader with
cursor JSON on stdin rather than shell interpolation. It reads logger.conf and
only configured regular security/security_log/messages/full destinations beneath
/var/log/asterisk, plus fixed .1/.0 retained generations. Descriptor-based reads,
O_NOFOLLOW, numeric bounds, 24-KiB chunks, two-chunk dispatches and existing process
cancellation/output limits bound execution. No remote mutation occurs.
`asterisk_auth` supplements current enrollment and Asterisk grants; startup never
enables it. `asterisk.auth.helper.v1` additionally requires the separately disclosed
`asterisk_auth_helper` grant and exact no-argument sudo delegation to the reviewed
root-owned `scripts/asterisk-auth-read` wrapper plus fixed root-owned Python file,
executed as the Asterisk service account with the fixed command
`/usr/bin/sudo -n -u asterisk -- /usr/local/sbin/noc-asterisk-auth-read`.
Delegate only `(asterisk) NOPASSWD: NOSETENV: /usr/local/sbin/noc-asterisk-auth-read ""`;
the empty argument pattern rejects command-line arguments. The service account
must already be able to read the configuration and selected log.
The Stage A helper cannot read logs. An administrator must separately authorize
installation/delegation; no unrestricted sudo, executable config, caller paths,
new groups, logger reload or permission change is involved. Both grants are
rechecked after transport capacity admission and at persistence. JSON cursor
stdin is enabled only for these two commands, retaining no TTY and all host-key,
identity, route, forwarding and environment restrictions.


NW-37 Stage C adds a separate explicitly authorized AMI capability. It reuses the
current enrollment and independent host-key approval, but uses a dedicated
protected SSH key and AMI account. Its fixed `-W 127.0.0.1:<protected port>` stream
has no remote command or interactive shell; browser data cannot choose the
forwarding destination. Ordinary finite collectors still disable forwarding.
Administrator SSHD/key restrictions must permit only this destination and deny
remote forwarding, TTY, agent/X11 forwarding and shell commands. The account's
AMI `write=none` is required; application action allowlisting alone is insufficient
for coarse AMI write classes. Runtime sends only Login and Ping. The current
enrollment revision, catalog digest, grants and monitoring lifecycle are rechecked
while connected. Persistent sessions do not occupy a finite collection guard;
the application ownership lock and unique live-session index protect recovery.


NW-37 Stage D adds an explicit `asterisk_activity` expansion within Standard
Server Monitoring. It enables the fixed version/channel/bridge/MeetMe/ConfBridge
snapshot bundle and the dedicated AMI connection's `system,call` subscription.
Revocation changes the managed binding, closes the old stream and prevents queued
activity data from entering the journal. Current authority is checked again at
SSH execution and transactional persistence. No additional AMI connection exists.

`asterisk.activity.helper.v1` executes exactly
`/usr/bin/sudo -n -- /usr/local/sbin/noc-asterisk-observe activity`.
Administrator installation adds only the exact `activity` argument to existing
root-owned gateway delegation; no per-conference identifier or browser CLI text
is accepted. The helper is root-owned mode 0755, its sudoers file mode 0440,
validated by `visudo`. It has a four-second process-group deadline, with the
existing five-second/64-KiB transport limits. Command failure cannot establish a
successful empty snapshot. The direct command uses the same fixed read-only
commands and ordinary no-forwarding executor.

The dedicated manager identity may receive only `system,call` event-read classes
and the anchored allowlist of Stage C/D families. `write=none` remains mandatory;
call-read permission does not authorize any AMI call-control action. Loopback
binding, exact protected forwarding destination and separate restricted SSH key
remain unchanged. Runtime sends only Login and Ping. Setup reloads manager
configuration, accounting for any connection interruption; it does not restart
Asterisk or change unrelated manager accounts.

For classic Asterisk 18 event filters, use an exact event-header delimiter such
as `eventfilter = ^Event: Newchannel[[:space:]]`. These regular expressions match
the complete event frame; appending `$` directly after the event name rejects
normal frames containing subsequent headers. Validate filters against full CRLF
frames, including similarly prefixed event names that must remain excluded.
