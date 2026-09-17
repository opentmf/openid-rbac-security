# Signing-key readiness, metrics and the boot line — implementation plan (3.3.0)

| | |
|---|---|
| **Status** | Implemented on `feat/jwks-readiness`; §5 records what implementation changed |
| **Target** | **3.3.0** (MINOR: a new health indicator, two metrics, one opt-in property, two new optional dependencies — additive; PATCH would misdescribe a release that adds surface) |
| **Owed since** | ruling 44 (2026-09-16, dnms-assist 1.3.0): with 3.2.1's cache-first keys the library answered a typed 503 + `Retry-After` on every authenticated request for an hour while the signing keys could not be fetched — the pod stayed Ready, anonymous still got 401, and nothing in Kubernetes or on a dashboard showed it |
| **Verified against** | Spring Boot 4.1.1 (`spring-boot-health` — indicators, `HealthEndpointGroupsPostProcessor`, `ConditionalOnEnabledHealthIndicator`; `spring-boot-micrometer-metrics`), Micrometer 1.17.1, the library's own `IssuerKeys` (3.2.x) |
| **Out of scope** | opentmf-versions: the BOM cut waits until it is known whether more opentmf releases are needed (coordinator, 2026-09-17) |

## 1. The gap

`IssuerKeys` (3.2.x) knows everything about an outage — whether a set was ever loaded, when it was last
loaded, why the last refresh failed — and tells nobody but the request that hits it. Kubernetes readiness,
the dashboards and the boot log are blind. Three outputs close it, each read from `IssuerKeys` and nothing
else, so they cannot disagree with what the wire does.

## 2. Design

### 2.1 What `IssuerKeys` records (the single source)

The `LoadTracking` source (innermost, below every Nimbus layer) already records the first success. It now
records a small `Snapshot`: `loadedAt` (the last successful load), `keys` (count of the last loaded set),
`lastFailure` (class + message of the last failed load, and when), and the JWKS **host** (never the path).
Failures are recorded on the way out of the delegate and rethrown unchanged — the classification in
`KeyOutageClassifier` is untouched. A local resource (`classpath:`/`file:`/`jar:`) reports its scheme as
the host.

`IssuerKeys.state(now)` derives one of three, aligned with what the wire answers:

| state | condition | the wire |
|---|---|---|
| `FRESH` | a set is loaded and `now − loadedAt ≤ cache-ttl + refresh timeout` | today's answers |
| `STALE` | a set is loaded, older than that, younger than `outage-ttl` | today's answers, from the stale set |
| `UNAVAILABLE` | never loaded, or older than `outage-ttl` | typed 503 on every bearer request |

### 2.2 Health indicator `jwks` — opt-in, readiness-grouped

`JwksHealthIndicator` (one bean, composite over the issuers, so it shows as `jwks` with one component per
issuer name): `UP` when every issuer is `FRESH`; `UP` with details `stale: true`, `age`, `lastFailure` when an
issuer is `STALE` (a cached set still serves, readiness must not flip — a custom `DEGRADED` status was
rejected: Boot's aggregator orders unknown statuses last and maps them to 200, so it would read as healthy
anyway while confusing every dashboard that groups by status); `DOWN` with `issuer`, `lastFailure` and
`since` when any issuer is `UNAVAILABLE` — exactly when bearer requests answer 503.

**Opt-in**: `opentmf.security.jwks.readiness: true` (default `false`). Off, nothing changes for any adopter:
no indicator, no group change. On, the indicator is registered (subject to Boot's own
`management.health.jwks.enabled`) **and** added to the `readiness` group through a
`HealthEndpointGroupsPostProcessor` that wraps the existing group's membership — no adopter has to touch
`management.endpoint.health.group.readiness.include`. An application without the readiness group (probes
not enabled, not on Kubernetes) still gets the indicator under `/actuator/health`. The indicator is gated by
the same opt-in rather than always-on because an adopter whose probe is `/actuator/health` itself (not the
readiness group) would otherwise go NotReady on the day of the bump without a decision — the brief's rule.

### 2.3 Metrics — always on when Micrometer is present

Registered per issuer (tag `issuer` = the configured name) on the application's `MeterRegistry`:

- `opentmf.security.jwks.keys` (gauge) — number of keys in the loaded set, 0 before the first load
  (Prometheus: `opentmf_security_jwks_keys`);
- `opentmf.security.jwks.keys.age` (gauge, seconds) — age of the loaded set, `NaN` before the first load;
- `opentmf.security.jwks.fetch.failures` (counter) — failed loads.

A `MeterBinder` bean, conditional on `MeterRegistry` on the classpath. No property: a metric that exists
only when someone remembers to enable it is not a dashboard.

### 2.4 The boot line

The warm-up already logs by issuer name. It now also names the JWKS **host** and the proxy in use, so the
ruling-44 case ("Unable to tunnel through proxy") is readable at boot:

```
Signing keys of issuer 'keycloak' loaded (2 keys) from dnms.test via proxy 10.0.0.1:3128.
Signing keys of issuer 'entra' could not be loaded from login.microsoftonline.com (direct): IOException: Unable to tunnel through proxy. Bearer tokens from this issuer answer 503 until a refresh succeeds.
```

The host only — never the path, never a query — and never in a response body; the 3.2.0 rule "the body names
the issuer, not the URL" stands. Local resources log their scheme (`classpath`) instead of a host.

### 2.5 Dependencies

`spring-boot-health` and `micrometer-core` become **optional** compile dependencies (BOM-managed, no version);
the new `JwksObservabilityAutoConfiguration` is `@ConditionalOnClass` on each half separately, so an adopter
without actuator or without Micrometer is unaffected, and the `StackIsolationTest` bytecode check is extended
to the new classes (health and metrics types must not leak into the core auto-configurations).

## 3. Tests — red first

- `IssuerKeysTest`: the snapshot after a load (keys, loadedAt, host), after a failure (lastFailure kept, the
  loaded set kept), `state()` across the three windows with a short `cache-ttl`/`outage-ttl`.
- `JwksHealthIndicatorTest` (stubbed `JwksServer`): UP fresh; UP-with-details stale after the server fails
  and the cache expires; DOWN never-loaded with the issuer and the failure in the details; DOWN beyond
  `outage-ttl`.
- `JwksObservabilityAutoConfigurationTest` (context runner): default → no `jwks` indicator, readiness group
  untouched; opt-in → indicator present and a member of `readiness` when the group exists; opt-in without
  the readiness group → indicator only; `management.health.jwks.enabled=false` wins; Micrometer present →
  the three meters; Micrometer absent (FilteredClassLoader) → context starts, no meters.
- `ServletJwksReadinessIT` (real Tomcat, actuator on the management port, probes enabled, opt-in): cold →
  `/actuator/health/readiness` 503 with `jwks: DOWN` and the issuer named; server comes up → 200 UP;
  `/actuator/health/liveness` 200 throughout; the same application without the opt-in → readiness 200 UP
  during the outage (the guarantee).
- The boot line: a log capture asserting the host and "via proxy"/"direct" on success and failure.

## 4. Release

3.3.0 → CHANGELOG (`### Added`: the indicator + opt-in, the metrics, the boot line; the two optional
dependencies) → README ("Signing keys" gains a "Readiness and metrics" subsection with the metric names) →
readiness per the accelerated recipe (gated verify once on the sha to be cut, sonar zero, both versions goals
with `-U` and every profile — bump everything behind except pitest 1.19.6) → "cut ready". Not in a BOM.

## 5. What implementation changed

1. **Membership is order-independent.** Boot's probes post-processor and this one both sit at
   `LOWEST_PRECEDENCE`, and bean registration order — which decides ties — put ours first in a real
   application (not in the context runner): the readiness group did not exist yet, and the wrap was a
   no-op. The post-processor now creates the readiness group itself when it is absent and probes are
   enabled (Boot's default), with exactly Boot's members plus `jwks`; Boot's processor then keeps it as a
   pre-configured group. Either order works.
2. **Membership is by path.** The health endpoint asks a group about a composite's components as
   `jwks/<issuer>`, so `isMember` must accept the prefix, or the composite is a member while every
   component is filtered out — the readiness aggregate then stays `UP` with `jwks` `DOWN` in it.
3. **The probe drives the retry of a cold outage.** Nothing else reloads an empty cache before the next
   bearer request, so a NotReady pod receiving no traffic would never heal. A probe that finds an issuer
   `UNAVAILABLE` triggers one background retry (one in flight, paced by Nimbus's rate limiter); the
   probe itself never waits on the network.
4. **Probe groups show the status alone** (Boot's `AvailabilityProbesHealthEndpointGroup`), so the
   details are asserted on `/actuator/health` and the readiness probe on its status.
5. **URLs in Nimbus's failure messages are reduced to their host** before they reach the log line or the
   health details — Nimbus quotes the full JWKS URL.
