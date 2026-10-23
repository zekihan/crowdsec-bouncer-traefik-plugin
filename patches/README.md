# simpleredis ACL patch

Base: `github.com/maxlerebourg/simpleredis` v1.0.12,
commit `94fbffdc41f91d0b50ccecf8f77302ed9d4df342`.

`make vendor` regenerates dependencies and applies `simpleredis-acl.patch`.
Do not run plain `go mod vendor` for a release: it removes this patch.
The local simpleredis derivative has matching source and protocol tests.
Until that derivative has a published immutable version, this tracked patch is
part of the plugin source distribution. No module replacement is required.

The patch adds optional ACL usernames, RESP encoding and bounded reply parsing,
returns command failures, and shares one two-second deadline across connection,
authentication, database selection and command execution. Runtime dependencies
remain standard-library only. The nil guard before the `net.Error` assertion is
required by the tested Yaegi interpreter.

Before publishing, run native tests, Yaegi tests and the GitOps plan's actual
Traefik/container, ACL, fault, performance and soak acceptance gates. A local
Traefik smoke test is not release acceptance.
