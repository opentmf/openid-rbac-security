# Implementation plan — multi-issuer resource-server support (`opentmf.security.issuers[]`)

**Status:** planned 2026-08-02 (Gökhan + Claude, dnotify-analysis session).
Implementation started 2026-08-05 after a source verification pass — see §8 for
the findings that amend §2. Target: **2.3.0** (minor — additive,
backward-compatible).

**Motivation:** VFDE's security architect (Veit, mail 2026-07-31) forbids
Keycloak-brokered HUMAN sign-ins in production — prod user logins go **directly
against Azure AD (Entra ID)** — while machine-to-machine service tokens remain
on the platform-internal Keycloak (proposed carve-out). Result: **dual-audience
services (dnms-catalog, dnms-store, dnms-journal, the CadenzaFlow engine REST)
must validate tokens from TWO issuers** on the same resource server — an Entra
user token on UI-driven calls, a Keycloak workload token on service-to-service
calls. Today the library validates exactly one issuer. Endpoint ACLs must NOT
change: per-issuer claim mapping normalizes both token shapes to the same
internal `read`/`write`/`admin` vocabulary (the server-side twin of the UI
R12.3 rule).

## 1. Current state (verify against source before starting)

- `OpenTmfSecurityProperties`: singular `jwk-set-uri`, `user-claim`,
  `fallback-user-claims`, `authorities-claim`.
- `ServletJwtAutoConfiguration` / `ReactiveJwtAutoConfiguration`: build ONE
  `JwtDecoder` / `ReactiveJwtDecoder` (classpath JWKS supported via the
  `*ResourceRetriever`s).
- `GrantedAuthoritiesConverter`: one authorities claim name.
- `ServletSecurityAutoConfiguration` / `ReactiveSecurityAutoConfiguration`:
  `.oauth2ResourceServer(rs -> rs.jwt(...))` with the single decoder + one
  authentication converter; the management-port chains reuse the same wiring;
  2.2.0's optional custom `AuthenticationEntryPoint`/`AccessDeniedHandler`
  beans sit on BOTH configurers.

## 2. Design

### 2.1 Property model (additive)

```yaml
opentmf:
  security:
    issuers:                                  # NEW — list; each entry = one trusted issuer
      - name: entra                           # optional label (logs/metrics)
        issuer: https://login.microsoftonline.com/<tenantId>/v2.0
        jwk-set-uri: https://login.microsoftonline.com/<tenantId>/discovery/v2.0/keys
        authorities-claim: roles              # Entra app roles arrive as internal role names
        user-claim: oid                       # stable Entra object id (preferred_username as fallback)
        fallback-user-claims: preferred_username, sub
      - name: keycloak
        issuer: https://keycloak.dnms.svc/realms/dnms
        jwk-set-uri: https://keycloak.dnms.svc/realms/dnms/protocol/openid-connect/certs
        authorities-claim: groups
        user-claim: sub
        fallback-user-claims: client_id, azp
        audiences: [dnms-catalog]           # OPTIONAL (see §8.5); when set, `aud` is validated
    # secure-endpoints / whitelist / blacklist / other-endpoints: UNCHANGED —
    # written once against the normalized internal roles, provider-blind.
```

**Backward compatibility (hard requirement):** the existing singular properties
keep working — when `issuers` is absent, the legacy `jwk-set-uri` +
claim properties form an implicit single-issuer entry (no `issuer` matching in
that mode, preserving today's exact behavior incl. classpath JWKS in tests).
Setting BOTH `issuers` and the legacy `jwk-set-uri` = config error (fail fast,
matching the library's strict-props stance). Per-entry validation: `issuer` +
`jwk-set-uri` required; duplicate `issuer` values = fail fast.

### 2.2 Servlet mechanics

- Build per-entry: `JwtDecoder` (Nimbus with JWKS from the entry — reuse the
  existing `ServletResourceRetriever` so `classpath:` JWKS keeps working per
  entry) **with an `iss` claim validator pinned to the entry's `issuer`**, plus
  a per-entry `JwtAuthenticationConverter` (entry's `GrantedAuthoritiesConverter`
  + principal-claim resolution from `user-claim`/fallbacks).
- Wire an **issuer-selecting `AuthenticationManagerResolver`** (the
  `JwtIssuerAuthenticationManagerResolver` idea, but built from our own
  `Map<issuer, AuthenticationProvider>` so per-entry converters attach):
  `.oauth2ResourceServer(rs -> rs.authenticationManagerResolver(resolver)…)`.
  Token with an unknown/absent `iss` → 401 `invalid_token` (never a fallback
  issuer).
- **Management-port chain uses the same resolver** (a scraper JWT can come
  from either issuer).
- **2.2.0 interplay:** the custom entry-point/denied-handler beans keep
  applying unchanged — they attach to `exceptionHandling` + the resource-server
  configurer, orthogonal to decoder selection. Regression tests required.

### 2.3 Reactive mechanics

Mirror with `ReactiveAuthenticationManagerResolver` /
per-entry `ReactiveJwtDecoder`s (existing `ReactiveResourceRetriever`).
**Parity principle applies (2026-07-30): both stacks, same semantics, or a
documented equivalent.** Here the mechanism is symmetric — no equivalent-path
needed.

### 2.4 Entra documentation notes (README — these bite in the field)

- The v2 issuer is **tenant-specific**: `https://login.microsoftonline.com/{tenantId}/v2.0`;
  v1-configured app registrations emit `https://sts.windows.net/{tenantId}/` —
  document the trap and pin v2 (`accessTokenAcceptedVersion: 2`).
- Recommend **Entra App Roles** over raw `groups` (groups overage truncates at
  ~200 into a pointer claim; app roles always arrive inline and can be NAMED
  `read`/`write`/`admin` so mapping is identity).
- `user-claim: oid` (stable) vs `preferred_username` (readable) — recommend
  `oid` + fallbacks as in the sketch.

## 3. Non-goals

- No opaque-token introspection, no OIDC discovery-based dynamic issuer
  trust (static list only — this is a security library; trust is explicit).
- No per-issuer endpoint ACLs — normalization is the model, deliberately.
- No change to the §16-style role vocabulary or the management-port
  asymmetric defaults.

## 4. Tests (extend existing conventions; both stacks)

- Second test issuer: a second classpath JWKS + `TokenUtil` variant minting
  tokens with each issuer's `iss`, key and claim shape (`roles` vs `groups`,
  `oid` vs `sub`).
- Matrix per stack: issuer-A token accepted w/ mapped roles; issuer-B token
  accepted w/ ITS mapping; same endpoint, both issuers; wrong-`iss`/unknown-`iss`
  → 401; expired per issuer; management-port both issuers; 2.2.0 custom
  401/403 beans still applied (regression); **backward-compat IT: legacy
  singular props only, byte-identical behavior**; strict-props failures
  (both-styles-set, duplicate issuer).

## 5. Versioning & docs

- **2.3.0**, Keep-a-Changelog section leading with the compatibility statement
  (no behavior change without `issuers`).
- README: the dual-issuer example above + the Entra notes + one paragraph on
  the normalization principle (ACLs never fork per provider).

## 6. Work breakdown

1. Properties + validation (issuers[] model, legacy bridge, fail-fast rules).
2. Servlet: per-entry decoders/converters + resolver + main/management wiring.
3. Reactive twin.
4. Test matrix (§4), servlet → reactive.
5. README + CHANGELOG + release 2.3.0; then: opentmf-versions bump.

## 7. Follow-ups OUTSIDE this repo (recorded so they aren't lost)

- dnms: template `config-security.yml` gains a commented dual-issuer example;
  combined-rules §16 one-line note (after release).
- opentmf-cadenzaflow: bump to ≥ 2.3.0 so the engine REST accepts the M2M
  issuer + (if ever needed) Entra tokens — see its `docs/entra-sso-plan.md`.
- VFDE workshop: the exact Entra values (tenant id, registrations, app-role
  names) come from the AD-side setup this plan's README documents the shape of.
## 8. Source-verification findings (2026-08-05) — these amend §2

Verified against Spring Boot 4.0.6 / Spring Security 7.0.5 and the 2.2.0 source
before starting. §1's description of current state is accurate as written.

**8.1 `.jwt()` and `.authenticationManagerResolver()` are mutually exclusive.**
`OAuth2ResourceServerConfigurer` asserts *"If an authenticationManagerResolver()
is configured, then it takes precedence"* and fails the build when a
`jwtConfigurer` is also present (same on the reactive spec). So the wiring
branches: legacy single-issuer keeps `.jwt(...)`; `issuers[]` mode uses the
resolver. It is NOT possible to set both as a belt-and-braces measure.

**8.2 `JwtIssuerAuthenticationManagerResolver` gives the 401 semantics for
free.** Both stacks expose a constructor taking our own
`AuthenticationManagerResolver<String>` (issuer → manager), and the wrapper
already throws `InvalidBearerTokenException("Invalid issuer")` /
`("Missing issuer")` → 401 `invalid_token`. §2.2's requirement needs no custom
code beyond supplying the map.

**8.3 `jwkSetUri` is `@NotNull` today.** A pure `issuers[]` configuration would
fail Bean Validation at boot. The constraint moves to a class-level cross-field
rule: exactly one of (`jwk-set-uri`, `issuers`) must be present — preserving the
fail-fast teeth per the global "environment-mandatory fields get a constraint"
rule, now expressed across two fields instead of one.

**8.4 `JwtService` must not regress (NOT in the original plan).**
`JwtServiceImpl` injects the single `JwtDecoder` bean and is public API that
consumers call directly (`jwtService.decodeJwt(token)`). If the `JwtDecoder`
bean stayed one issuer's decoder, `JwtService` would silently fail for
second-issuer tokens. Therefore multi-issuer mode registers an
**issuer-routing composite** `JwtDecoder` / `ReactiveJwtDecoder` (parse `iss`,
delegate to that issuer's decoder, unknown issuer → `BadJwtException`). The
filter chains still use the resolver — the composite exists so `JwtService` and
any consumer injecting a decoder keep working across issuers.

**8.5 Audience validation: optional `audiences` per entry.** Pinning only `iss`
means any token from the Entra tenant — issued for *any* app registration —
would be accepted. Spring's default validators check `iss`/`exp`/`nbf`, never
`aud`. Each entry therefore accepts an optional `audiences` list; when present,
`aud` must intersect it.

*Why optional, and why no `opentmf-http-clients` coupling:* that library caches
tokens under `username + scope + baseUrl` (`TokenUtil.cacheKey`) and sends no
`audience`/`resource` request parameter at all — so `aud` is a deterministic
function of (auth server, client, scope), all already in the key. For Entra the
audience *is* the scope (`api://<app-id>/.default`); for Keycloak it comes from
server-side audience mappers. Two audiences can therefore never collide on one
cache key, no key change is needed, and no dependency between the two libraries
is required in either direction — the contract is the `aud` claim on the wire,
not shared types.

*Why "just add `aud` to the cache key" is NOT an available future fix
(Gökhan, 2026-08-05):* the key must be computed at **lookup** time, before any
token exists, so the audience cannot be back-derived from the issued token —
extracting `aud` after acquisition is too late to have selected the cache entry.
It could only enter as a **caller-supplied request parameter**, and today's
callers do not pass one; many services and libraries depend on that request
contract as it stands. So per-audience token acquisition there is a deliberate
API change, not a local key tweak. This is precisely why the current shape —
audience implied by (auth server, client, scope) — is the good state, and why
`audiences` here stays **optional**: enabling it must not imply any change on
the client side.

**8.6 Test fixtures cannot mint tokens as §4 assumes.** `jwk-set.json` holds
only a public RSA key and `TokenUtil`'s tokens are pre-issued constants with
fixed `iss`. The multi-issuer matrix generates an RSA keypair per test issuer at
runtime (Nimbus), writes a JWKS to a temp file, and points that entry's
`jwk-set-uri` at it via `@DynamicPropertySource`. The legacy backward-compat IT
keeps using today's classpath JWKS and constants unchanged.

**8.7 Per-entry claim inheritance.** Only `jwk-set-uri` and `issuers` are
mutually exclusive. The top-level `user-claim` / `fallback-user-claims` /
`authorities-claim` remain valid as **defaults inherited by entries that omit
them**, so a consumer sets the common vocabulary once and only the deviating
issuer overrides it.

**8.8 Version.** The pom sits at `2.2.1-SNAPSHOT` (post-2.2.0); this feature
bumps it to `2.3.0-SNAPSHOT` with a new `## [2.3.0]` CHANGELOG section.

