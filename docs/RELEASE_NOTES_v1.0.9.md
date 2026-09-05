# jiejie-masque v1.0.9

Narrow maintenance correctness release for F-501. No dataplane architecture
was redesigned.

## F-501: conntrack cleanup result classification

Fixed conntrack cleanup result classification.

Previously, `CleanupConntrack` called `cancel()` before reading `ctx.Err()`.
A normal non-zero conntrack result could therefore be misclassified as a
timeout because the context became `context.Canceled` after the explicit
cancel. This could prevent the second cleanup direction from running when the
first direction reported a benign no-match.

The command-result contract is now explicit:

- context state is captured before explicit cancel;
- only `context.DeadlineExceeded` is a timeout;
- explicit `0 flow entry` or `0 flow entries` output is a benign no-match;
- `-s` benign no-match continues to `-d`;
- ordinary conntrack failure remains a real error;
- cleanup order remains `-s`, then `-d`.

Regression coverage includes plural and singular no-match, both directions,
real command failure, deterministic timeout, cancel-after-command behavior,
call ordering, invalid IPv4-family rejection, repeated targeted tests, race
testing, and full CI.

F-501 removes one confirmed source of incomplete conntrack cleanup. It does
not claim to fix all stale conntrack behavior.

## Deferred findings

F-404 remains `REPRODUCTION REQUIRED / NON-RELEASE-BLOCKING`. It now concerns
genuine cleanup failure, process restart, shadow-IP reuse, and cross-generation
stale conntrack effects—not the fixed result-classification bug.

F-502 retains the immutable historical v1.0.8 documentation residual, while
the tag-only consistency gate prevents recurrence for future releases.

## Explicit non-changes

Session-NAT manager, cleanup worker, `cleanupPending`, `reuse_delay`, startup
conntrack flush, retry/quarantine behavior, CONNECT-IP dataplane, CONNECT-UDP,
CONNECT-TCP, DNS Gateway, `TargetPolicy`, `PacketPool`, queue sizes, owned
DATAGRAM path, GSO, and fork dependency SHAs are unchanged.

## Dependency provenance

```text
connect-ip-go: 57381910bb5fca61b4d3d03fe098929bc294ad11
pseudo-version: v0.0.0-20260905040753-57381910bb5f
quic-go: ac11e929d6decc0eb5f8235259ef82671dad3bca
pseudo-version: v0.0.0-20260905040559-ac11e929d6de
```
