# Cache-first signing keys — the three-round record (3.2.0)

| | |
|---|---|
| **Status** | Implemented on `feat/jwks-cache-first` |
| **Target** | **3.2.0** (MINOR, additive; adopter checklist = the BOM bump only) — Gökhan's ruling 2026-09-16: the last library change of the wave, analysed three times before a line of code |
| **Verified against** | Spring Security 7.1.1 (`oauth2-jose`, `oauth2-resource-server`, `core`, `web`), Spring Framework 7.0.9, nimbus-jose-jwt 10.9.1 — sources unpacked with the recipe in `http-method-semantics-plan.md` §0 |
| **Origin** | dnms-assist 1.2.1 under an egress NetworkPolicy blocking both issuers (measured 2026-09-15): `500` on every bearer request; 1.2.2 shipped an interim filter rendering `503` |

## 1. The defect, as the sources describe it

- Servlet, `http(s)` `jwk-set-uri`: `NimbusJwtDecoder.withJwkSetUri` → Spring's `SpringJWKSource` over
  `RestTemplateWithDefaultTimeouts` (`SimpleClientHttpRequestFactory`, connect/read from
  `sun.net.client.default{Connect,Read}Timeout`, 30 s each), wrapped in Nimbus's `JWKSourceBuilder` with
  cache ON (5 min / 15 s) but `rateLimited(false)`, `refreshAheadCache(false)`, `retrying`/`outageTolerant`
  default off. So: the keys are fetched on the FIRST request thread; every 5 minutes the next request re-fetches
  on its own thread; a failure with nothing cached is `RemoteKeySourceException` → `JwtException` →
  `JwtAuthenticationProvider` → `AuthenticationServiceException`, which
  `AuthenticationEntryPointFailureHandler` rethrows (`rethrowAuthenticationServiceException = true`) → the
  container's `500`; an unknown `kid` forces an unrated refresh.
- Reactive: `NimbusReactiveJwtDecoder(url)` → `ReactiveRemoteJWKSource` over `WebClient.create()` — no proxy of any
  kind, no read timeout, fetch on the event loop, `Mono` cached only after a success.
- Proxy: the servlet fetch honoured the JVM proxy properties (`HttpURLConnection` with the default
  `ProxySelector`); neither twin read `HTTPS_PROXY`/`NO_PROXY` (the JDK never does without
  `java.net.useSystemProxies`).
- TLS: both twins trust the JVM trust store and nothing else; the assist egress fix (2026-09-16) proved the private
  CA is in the images — the 1.2.1 failure was the NetworkPolicy alone. TLS is out of scope here, deliberately.
- `ResourceUtils.isFileURL` is true for `file`/`vfsfile`/`vfs` only, so a `classpath:` JWK set inside a Boot fat jar
  (`jar:file:…`) fell onto the HTTP path, whose request factory casts a `JarURLConnection` to
  `HttpURLConnection` — `500` on every bearer request. Test-only shape; nobody had hit it.

## 2. What is built

- `jwks/IssuerKeys` — one Nimbus `JWKSourceBuilder` source per issuer, innermost to outermost: the library's
  `LoadTracking` (records the first successful load, never reset) → `URLBasedJWKSetSource` over
  `JwkSetRetriever` → `OutageTolerantJWKSetSource` (outage TTL) → `RateLimitedJWKSetSource` (refresh interval) →
  `RefreshAheadCachingJWKSetSource` (cache TTL, scheduled background refresh) → `JWKSetBasedJWKSource`.
  `retrying(false)`: the immediate retry would double a cold request thread's worst case (see §3 round 3).
- `jwks/JwkSetRetriever` — `http(s)` through Nimbus's `DefaultResourceRetriever` with explicit timeouts and the
  resolved `Proxy`; any other resource through Spring's `Resource.getInputStream()`.
- `jwks/ProxyResolver` — per-issuer override > JVM properties (`ProxySelector.getDefault()`) >
  `HTTPS_PROXY`/`HTTP_PROXY` with `NO_PROXY` > direct.
- `jwks/KeyOutageClassifier` + `KeyOutageAwareJwtDecoder` / `KeyOutageAwareReactiveJwtDecoder` — the decoder
  decorators that walk the cause chain and raise `JwkSetUnavailableException` (a `ResponseStatusException`,
  `503`, `Retry-After`, typed problem body naming the issuer) or `BadJwtException` (unknown key id, `401`).
- `jwks/ServletKeyOutageFilter` / `ReactiveKeyOutageFilter` — before the bearer filter, around the chain: render
  the typed `503` through `ServletErrorRenderer` (extracted from the 3.1.0 matrix filter) / let the error signal
  reach the application's `WebExceptionHandler`s with `Retry-After` already on the response.
- `jwks/JwkSetWarmer` + `config/JwksAutoConfiguration` + `jwks/TrustedIssuerKeys` — the keys built ONCE per
  application, shared by both stacks' supports (both JWT auto-configurations load in every application) and by
  both ports; warm-up on `ApplicationReadyEvent`, `WARN` async / `FAIL` inline.
- Properties: `opentmf.security.jwks.{cache-ttl, outage-ttl, refresh-interval, connect-timeout, read-timeout,
  proxy, on-startup-failure}` and `issuers[].proxy`; every default equals the previous behaviour for a reachable
  issuer.

## 3. The three rounds (what each verified, what each changed)

**Round 1 — the coupling inventory.** Every environment coupling in the library, each "unchanged, safe because"
or "changes in 3.2.0": the fetch (both twins — changes), `iss` validation (string compare, no discovery —
unchanged), audiences (unchanged), the `jwk-set-uri`/`issuers` XOR (unchanged), local JWK sets (changes,
compatibly), clock skew (60 s on `Clock.systemUTC()` — unchanged), OPTIONS/CORS/HEAD/the matrix (run before the
bearer filter — unchanged), the responder vs an adopter's `/error` view (same resolver path as 3.1.0 —
unchanged mechanism), the management ACL (unchanged), TLS (unchanged), DNS/timeouts (defaults preserved),
reactive thread pools (changes: `boundedElastic`), System properties/env (changes: the env is read for the
proxy). Two hard requirements from the template session: the `503` must not be an `AuthenticationException`
(the template's mapper turns those into `401`), and `classpath:`/`file:` JWK sets must keep resolving with no
network and no warm-up failure.

**Round 2 — the propagation paths, from the classes.** `ProviderManager.authenticate` catches only
`AccountStatusException`, `InternalAuthenticationServiceException`, `AuthenticationException` — it wraps no
other `RuntimeException`; `BearerTokenAuthenticationFilter` catches `OAuth2AuthenticationException` and
`AuthenticationException` only; the outward filters catch nothing. Reactive: `JwtReactiveAuthenticationManager`
maps `JwtException` only; `AuthenticationWebFilter` resumes `AuthenticationException` only. So a non-authentication
exception from a **decoder decorator** reaches a library filter placed before the bearer filter.
**The correction:** `NimbusJwtDecoder.createJwt` catches `RemoteKeySourceException` → `JwtException`,
`JOSEException` → `JwtException`, then a generic `Exception` → `BadJwtException` — an unchecked exception thrown
from *inside* a `JWKSource` would read as "bad token" `401`. Hence: the key source throws nothing of its own,
Nimbus's checked `KeySourceException`s travel (the `JOSEException` branch keeps the cause), and the decorator
classifies the chain. `RateLimitReachedException` needs the "ever loaded" distinction (unknown kid → `401`, cold
outage → `503`). The multi-issuer resolvers answer "Invalid issuer"/"Missing issuer" as
`InvalidBearerTokenException` before any key. The management chains inject the parent's supports — one cache, one
warm-up.

**Round 3 — the final self-review.** `CachingJWKSetSource.loadJWKSetBlocking` single-flights on a `ReentrantLock`:
concurrent cold callers wait up to the refresh timeout (15 s) then get "Timeout while waiting for cache refresh"
(→ `503`); no fan-out. `RateLimitedJWKSetSource` opens a window with `counter = 1` and admits one more — two
attempts per interval, the rest `RateLimitReachedException` immediately. `RetryingJWKSetSource` retries once at
once → OFF, or a cold lock-holder blocks 2 × (connect + read). `OutageTolerantJWKSetSource` returns the cached
clone unless the evaluator demands a different set (an unknown kid during an outage → `503`, honest). The
timeouts default to the JVM properties the old fetch honoured, then 30 s. The one deliberate behaviour change
for a reachable issuer: an environment exporting `HTTPS_PROXY` without `NO_PROXY` for the provider now goes
through that proxy. The blast radius is the JWKS path only: the matrix, the ACLs, the OPTIONS handlers, the
guards and the responders are untouched except for the `ServletErrorRenderer` extraction.

## 4. Precedence, as tested

| situation | answer |
|---|---|
| no token | `401` (no keys needed) |
| token with unknown `iss` (multi-issuer) | `401` before any key |
| keys cached — fresh, or stale within the outage TTL | today's answers exactly: valid `2xx`, bad/expired `401` |
| keys never obtained | `503` + `Retry-After` for every bearer request, whatever the token says |
| unknown `kid`, keys loaded | one rate-limited refresh, then `401` if still unknown |
| unknown `kid`, keys loaded, provider down | `503` (a new key cannot be fetched) |
| keys stale beyond the outage TTL | `503` |
| `JwtService.decodeJwt` during an outage | throws `JwkSetUnavailableException` (not `AuthenticationServiceException`) |

## 5. What implementation changed against the rounds

1. **The keys are built once, stack-neutrally.** Both `ServletJwtAutoConfiguration` and
   `ReactiveJwtAutoConfiguration` load in every application (the 3.0.0 `StackIsolationTest` pins that both
   supports exist on either stack), so per-support `IssuerKeys` would have meant two sources, two refresh threads
   and two warm-ups per issuer, and two `jwkSetWarmer` beans. `TrustedIssuerKeys` from `JwksAutoConfiguration` is
   the single instance; the supports take it as a constructor argument.
2. **Nimbus's refresh timings scale to a short TTL.** `refreshAheadTime + cacheRefreshTimeout` must fit inside the
   TTL; the defaults (30 s + 15 s) hold for any TTL ≥ 45 s and shrink to a third of the TTL below that, so a test
   or a deployer choosing a short `cache-ttl` gets a working source, not an `IllegalArgumentException`. A
   genuinely invalid combination (`refresh-interval ≥ cache-ttl`) fails at startup naming the issuer.
3. **No proxy resolution for local resources.** The JDK's default `ProxySelector` rejects a `file:` URI
   ("protocol = file host = null"); the resolver runs for `http(s)` only.
4. **`JwkSetUnavailableException` sets its problem properties in the constructor** — `ErrorResponseException.getBody()`
   is final.
