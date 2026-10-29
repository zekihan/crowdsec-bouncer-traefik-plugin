# local plugin artifact

Build from the reviewed source tree, after `make vendor` and the acceptance tests:

```sh
docker build --platform linux/amd64 -f packaging/Dockerfile \
  --build-arg SOURCE_REVISION="$(git rev-parse HEAD)" \
  -t local/crowdsec-plugin:redis-acl .
```

The image contains source, HTML templates, the exact vendored dependencies and
upstream license notices. It is an init-container artifact, not a Traefik binary.
Its non-root entry point verifies SHA-256 checksums, copies the source to
`/destination`, then verifies the copied bytes. Mount a dedicated emptyDir there,
with fsGroup 65532; mount that volume read-only into Traefik at:

`/plugins-local/src/github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin`

Register `--experimental.localPlugins.crowdsec.moduleName=github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin`.
Remove only the remote CrowdSec plugin registration. Preserve other plugins and
existing mounts. The current module/import paths intentionally remain unchanged.
No catalog or module download is needed for this plugin at pod startup.

The `make vendor` target reapplies `patches/simpleredis-acl.patch`. Plain
`go mod vendor` would discard the local client fix. The client uses a 1.9-second
internal deadline to satisfy the two-second end-to-end operation budget.

GitOps uses a tagless OCI index digest from the published
`docker.io/zekihan/crowdsec-traefik-local-plugin` repository. The Argo acceptance
record identifies each artifact's source revision, source manifest, registry
digest and validation results. Preserve the original `redis-acl` tag when
publishing a replacement. A new digest cannot be pulled until its publication
is verified. Rebuilding with a new revision label changes the digest: revalidate
that artifact and update the GitOps pin.

## isolated acceptance

Requires Docker, Go and Python 3.12+. Test services run only on a unique Docker
network, with host ports published on 127.0.0.1. Fixture credentials are synthetic.
The runner does not use kubeconfig, secret stores or production endpoints.

```sh
python3 tests/acceptance/run.py --output /tmp/redis-acl-functional
python3 tests/acceptance/isolation.py --output /tmp/redis-acl-isolation
python3 tests/acceptance/refresh.py --output /tmp/redis-refresh-regression
python3 tests/acceptance/validation.py --output /tmp/redis-validation-regression
python3 tests/acceptance/recreation.py --output /tmp/redis-acl-recreation
python3 tests/acceptance/load.py --mode paired --output /tmp/redis-acl-paired
python3 tests/acceptance/load.py --mode recovery --output /tmp/redis-acl-recovery
python3 tests/acceptance/load.py --mode soak --output /tmp/redis-acl-soak
```

The paired command takes about 90 minutes (three 30-minute pairs); the soak
takes about 32 minutes including warm-up and idle cleanup. Recovery takes about
two minutes. Skipping a long test leaves its release gate incomplete.

The target is the inspected Traefik v3.7.14 amd64 digest; Redis uses the GitOps
8.10.2-alpine version pinned by digest. The load suite uses 2 CPUs and 512 MiB for
Traefik, five-second metrics samples and the plan's unshortened durations. Host
architecture is recorded. Emulated amd64 results are not native cluster capacity
measurements. JSON reports and sanitized logs are saved under the chosen output
path; disposable containers, volumes and networks are removed on completion.
Do not publish or deploy on a failed or incomplete gate.

Refresh state is scoped to each middleware instance. Its serialized refresh loop
follows the Traefik configuration context and stops on retirement, so a recreated
middleware cannot keep refreshing an old Redis identity or prefix. The shared
Redis marker still avoids unnecessary decision refreshes across instances.

## coordinated refresh protocol

Redis 7+ is required for script ACL preflight; the pinned fixture is Redis 8.10.2.
The future restricted identity needs `+get +set +del +select +eval` and only its
own key prefix. Do not enable unsafe Yaegi imports or Redis admin commands.

Each refresh obtains a 30-second random-token lease on the writer endpoint.
Commit and release verify ownership, including after lease expiry/replacement.
The refresh requests a complete `startup=true` snapshot, so another attempt can
recover after a consumed delta or process loss. A namespaced snapshot index
tracks decision keys for reconciliation; CAPTCHA and unrelated cache keys are
not enumerated or flushed. Redis scripts preflight ACL commands, track keys
before changing decisions, and publish the success marker last. Keep the index
with the decision keys; removing it independently loses reconciliation history.

Full snapshots increase API traffic and script work. The local regression tests
do not qualify performance for large decision sets. A fetch exceeding the lease
is rejected; subsequent refreshes retry. Record the full comparison and soak
outcomes for each replacement. Legacy unindexed keys expire normally unless
explicitly deleted by the API. Start with the planned cold, prefixed namespace
at ACL cutover.

Snapshot validation requires an object with both `new` and `deleted` lists.
Explicit null lists are valid empty lists; null top-level bodies, missing fields
and incorrectly typed lists fail without changing decisions or success markers.
Lease contention does not increment failure counters or complete startup.
For finite `updateMaxFailure`, a warm instance loses health after no observed
success for 30 seconds plus `(updateMaxFailure + 1) * updateIntervalSeconds`.
This allows an in-flight owner its lease while preventing repeated failed owners
from keeping followers healthy indefinitely. A successful refresh or shared
success marker restores health; `updateMaxFailure: -1` keeps explicit fail-open. A cold instance with `streamStartupBlock`
enabled remains unhealthy until a successful refresh or success marker is
observed. Explicit startup fail-open behavior is preserved. Unknown lease replies
are errors, not contention.

## Cold stream follower regression

`tests/acceptance/follower_startup.py` holds a synthetic refresh owner across
Traefik startup with a 300-second update interval. It verifies that cold requests
and readiness fail closed, then recover immediately after the owner publishes a
committed marker. IPv4/IPv6 bans remain enforced and recovery makes no extra
LAPI poll. Native ping stays healthy while the middleware is blocked.

Set `CROWDSEC_TEST_ARTIFACT` to test an unpublished image without replacing the
existing `local/crowdsec-plugin:redis-acl` tag. The default is unchanged. Fixtures
use isolated Docker networks, volumes, loopback ports and dummy credentials.
They do not use Kubernetes, real identities or live Redis.

```sh
CROWDSEC_TEST_ARTIFACT=local/crowdsec-plugin:repo2-follower-fix \
  python3 tests/acceptance/follower_startup.py --output logs/follower-startup
```

This functional regression does not qualify production capacity or replace the
separately required artifact promotion and rollout acceptance gates.

The fault soak classifies requests by their actual execution interval, including
requests already in flight when an outage begins. Its outage/recovery window is
unchanged; new requests after the recovery deadline must succeed. Banned clients,
transport errors and the three-second request budget retain their checks. Run the
synthetic boundary regressions without Docker:

```sh
python3 -m unittest discover -s tests/acceptance -p test_load.py
```

## OPS-160 opt-in connection pool candidate

Pooling stays disabled unless all required bounds are explicitly configured:
`redisCachePoolMaxActive`, `redisCachePoolMaxIdle`,
`redisCachePoolMaxWaiters`, `redisCachePoolIdleTimeoutSeconds` and
`redisCachePoolMaxLifetimeSeconds`. Zero active with all other values zero keeps
legacy behavior. Invalid or incomplete bounds fail configuration validation.
The limits apply to each reader/writer endpoint of each middleware instance,
and multiply again across Traefik processes. Do not copy synthetic test limits
into production without its concurrency/resource evidence.

Each socket belongs to one initialized endpoint, identity and database. AUTH
runs on every checkout to preserve immediate password revocation; SELECT also runs on every checkout to preserve command-ACL revocation.
The savings are TCP/DNS churn and buffer allocation; AUTH/SELECT rates remain. No stale decision cache, retry or command replay is
added. Waiting, DNS/dialing, AUTH, SELECT and command I/O share the existing
1.9-second operation budget. Request cancellation interrupts pooled lookups.
Queue overflow follows the existing unreachable failure branch. Retirement
first lets the canceled refresh release its fenced lease, then closes its pools.

Regenerate the tracked vendor patch from the actual client source, then vendor:

```sh
python3 packaging/update-simpleredis-patch.py /path/to/simpleredis
make vendor
cmp vendor/github.com/maxlerebourg/simpleredis/simpleredis.go /path/to/simpleredis/simpleredis.go
cmp vendor/github.com/maxlerebourg/simpleredis/pool.go /path/to/simpleredis/pool.go
```

The patch generator currently targets the pinned upstream v1.0.12. A dependency
upgrade requires reviewing its base as well as the resulting patch. The new
library source remains authoritative; editing only `vendor/` is insufficient.

`CROWDSEC_TEST_POOL=1` opts the disposable acceptance fixtures into synthetic
bounds (4 active/idle, 16 waiters, 5-second idle, 30-second lifetime per endpoint).
Application traffic uses a digest-pinned `whoami-open` container. The fixture
still provides synthetic LAPI/CAPTCHA and Redis fault injection.

Additional acceptance commands:

```sh
python3 tests/acceptance/pool_credentials.py --artifact local/crowdsec-plugin:ops-160-v7 --output /tmp/pool-credentials
python3 tests/acceptance/pool_benchmark.py --candidate local/crowdsec-plugin:ops-160-v7 --output /tmp/pool-comparison
```

The benchmark compares the same artifact with pooling disabled/enabled by
default. `--baseline <image>` permits an explicitly different reference artifact;
that comparison includes all intervening source differences. It alternates
three pairs, with two Traefik processes and traffic to both middleware instances,
then checks idle bounds. Redis rates include the documented admin sampling
connections. DNS query packets are counted by a sidecar with NET_RAW confined
to each disposable Traefik network namespace; only query names/counts are logged.
It never captures production traffic. These synthetic comparisons do not replace
the separately named long paired suite or 30-minute fault soak. No publication,
GitOps promotion or production verification is implied by a local test.

Pooling requires an initialized authentication identity (username or password)
and an explicit database, including `0` for the default database. Unpooled legacy
clients retain their existing anonymous/default-database behavior.
