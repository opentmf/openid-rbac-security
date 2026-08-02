# Implementation plan — multi-issuer resource-server support (`opentmf.security.issuers[]`)

**Status:** planned 2026-08-02 (Gökhan + Claude, dnotify-analysis session). Not
started. Target: **2.3.0** (minor — additive, backward-compatible).

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
