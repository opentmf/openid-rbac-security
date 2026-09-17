# openid-rbac-security

OpenID Role-Based Access Control (RBAC) security library for Spring Boot.

## Overview

A Spring Boot auto-configuration library that enables Bearer Token authentication using Spring Security OAuth2 Resource Server. It supports both **servlet** and **reactive** web application types automatically.

Configure endpoint security declaratively through properties:

- **Secure endpoints** -- require specific roles for given HTTP method + path combinations.
- **Allowed endpoints** -- bypass security for specific HTTP method + path combinations.
- **Whitelist** -- bypass security for paths regardless of HTTP method.
- **Blacklist** -- deny access to paths regardless of HTTP method.
- **Other endpoints** -- catch-all policy for anything none of the above matched: `allow`, `deny`, or `authenticated`. Defaults to `deny`, which gives any unconfigured protected endpoint **HTTP 403 Forbidden** (the historical behavior).

### Requirements

- Java 17+
- Spring Boot 4.0+

## Getting Started

### Maven Dependency

```xml
<dependency>
  <groupId>org.opentmf.security</groupId>
  <artifactId>openid-rbac-security</artifactId>
  <version><!-- latest version --></version>
</dependency>
```

Or, if you use the OpenTMF BOM:

```xml
<dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>org.opentmf</groupId>
      <artifactId>opentmf-versions</artifactId>
      <version><!-- BOM version --></version>
      <type>pom</type>
      <scope>import</scope>
    </dependency>
  </dependencies>
</dependencyManagement>

<dependencies>
  <dependency>
    <groupId>org.opentmf.security</groupId>
    <artifactId>openid-rbac-security</artifactId>
  </dependency>
</dependencies>
```

### Example Configuration

```yaml
opentmf:
  security:
    jwk-set-uri: https://keycloak:8000/realms/myrealm/protocol/openid-connect/certs
    user-claim: email
    fallback-user-claims: client_id, azp, sub
    authorities-claim: groups

    secure-endpoints:
      - method: POST
        path: /orders
        roles: [write, admin]
      - method: GET
        path: /orders/*/details
        roles: [read, admin]

    allowed-endpoints:
      - method: GET
        path: /orders/**

    whitelist:
      - /actuator/**
      - /info

    blacklist:
      - /swagger-ui/**
```

## Configuration Reference

All properties live under the `opentmf.security` prefix.

| Property | Default | Description |
|---|---|---|
| `jwk-set-uri` | *(required unless `issuers` is set)* | URL or resource path to the JWK Set (e.g. Keycloak certs endpoint, or `classpath:jwk-set.json`). Single-issuer mode; mutually exclusive with `issuers`. |
| `issuers` | *(empty)* | List of trusted issuers for services that accept tokens from more than one identity provider. See [Multiple trusted issuers](#multiple-trusted-issuers). Mutually exclusive with `jwk-set-uri`. |
| `user-claim` | `sub` | JWT claim to use as the principal (user identifier). |
| `fallback-user-claims` | *(empty)* | Ordered list of fallback claims when `user-claim` is absent. Useful for `client_credentials` tokens. |
| `authorities-claim` | `roles` | JWT claim containing the user's roles/authorities. |
| `secure-endpoints` | *(empty)* | List of `{method, path, roles}` entries requiring specific authorities. `method` is one of `GET`, `POST`, `PUT`, `PATCH`, `DELETE`. |
| `allowed-endpoints` | *(empty)* | List of `{method, path}` entries that bypass security. Same five methods. |
| `whitelist` | *(empty)* | List of path patterns that bypass security for all HTTP methods. |
| `blacklist` | *(empty)* | List of path patterns denied for all HTTP methods. |
| `other-endpoints` | `deny` | Catch-all policy for unmatched requests: `allow` (permit anonymously), `deny` (reject — historical default, preserves backward compatibility), `authenticated` (require any valid JWT). |
| `jwks.cache-ttl` | `5m` | How long a fetched JWK set is served before a background refresh. See [Signing keys](#signing-keys). |
| `jwks.outage-ttl` | `24h` | How long the last good JWK set keeps serving while refreshes fail. |
| `jwks.refresh-interval` | `30s` | Minimum interval between forced refreshes (an unknown key id); also the `Retry-After` of a `503`. |
| `jwks.connect-timeout` / `jwks.read-timeout` | *(JVM `sun.net.client.default*Timeout`, then 30s)* | Timeouts of the fetch. |
| `jwks.proxy` | *(unset)* | `host:port` proxy for the single-issuer fetch; per issuer, `issuers[].proxy`. Unset: the JVM proxy properties, then `HTTPS_PROXY`/`NO_PROXY`. |
| `jwks.on-startup-failure` | `warn` | `warn` boots and serves `503` for an issuer whose keys never loaded; `fail` stops the application when no issuer's keys could be loaded. |
| `jwks.readiness` | `false` | Registers the `jwks` health contributor and adds it to the `readiness` group, so a pod without keys goes NotReady instead of serving `503`s. See [Readiness and metrics](#readiness-and-metrics). |

### Nested claims

Both `user-claim`, `fallback-user-claims`, and `authorities-claim` support **dot notation** for nested JWT claims (e.g. `realm_access.roles`, `user.email`).

### Fallback user claims

When the primary `user-claim` is not present in a token (common with `client_credentials` grant), the library tries each `fallback-user-claims` entry in order. If none are found, the JWT `sub` claim is used as a final fallback.

```yaml
opentmf:
  security:
    user-claim: email
    fallback-user-claims: client_id, azp, sub
```

## Signing keys

Every trusted issuer's JWK set is loaded **cache-first, off the request path** (since 3.2.0):

- **Warm-up.** Once the application is ready, each issuer's keys are fetched on a background
  thread and the outcome is logged by the issuer's configured *name* — never its URL:
  `Signing keys of issuer 'entra' loaded (3 keys).` or
  `Signing keys of issuer 'entra' could not be loaded: ConnectException: … Bearer tokens from
  this issuer answer 503 until a refresh succeeds.`
- **Refresh in the background**, ahead of the cache expiry (`jwks.cache-ttl`, 5 minutes); a
  request thread never fetches once a first load has succeeded.
- **Outage tolerance.** While refreshes fail, the last good set keeps serving for
  `jwks.outage-ttl` (24 hours): valid tokens are accepted, bad ones rejected, as if nothing had
  happened. Only an issuer whose keys were *never* obtained answers `503`.
- **Key rotation** is picked up at the first token with an unknown key id, which triggers a
  refresh — at most two per `jwks.refresh-interval` (30 seconds), so a flood of unknown key ids
  cannot become a flood of fetches; the rest answer `401` as bad tokens.
- **Local resources** (`classpath:`, `file:`, a JWK set inside a jar) are read through the
  resource's stream: no network, no warm-up failure, and a rotated mounted file is picked up.

### The `503` when the keys are unavailable

A bearer request from an issuer whose keys have never been obtained cannot be verified, and the
caller's token may well be valid — so the answer is not `401`. It is:

```
HTTP/1.1 503 Service Unavailable
Retry-After: 30
Content-Type: application/problem+json

{"type":"urn:opentmf:security:problem:signing-keys-unavailable","title":"Signing keys unavailable",
 "status":503,"detail":"Signing keys of issuer 'entra' are not available","issuer":"entra"}
```

rendered from inside the library through your application's own error rendering, exactly as the
[status matrix](#the-http-status-matrix)'s `404`/`405` are, on both stacks — no filter of your own is
needed. The exception behind it, `JwkSetUnavailableException`, is an `ErrorResponse`
(`ResponseStatusException`), deliberately **not** an `AuthenticationException`: the security entry
point never sees it and your `@ControllerAdvice` renders it like any `ErrorResponseException`,
including when you decode tokens yourself through `JwtService`. Anonymous callers, whitelisted
paths, the status matrix's `404`/`405`, and an unknown issuer (`401` before any key is looked at)
need no keys and are unaffected; so are the management port's probes.

Before 3.2.0 the same situation surfaced as `AuthenticationServiceException`, which Spring
Security rethrows — the container's `500`, on the first request thread, after the fetch's timeouts.

### Proxies

The fetch resolves its proxy in this order, and stops at the first that applies:

1. the issuer's own `proxy` (`opentmf.security.issuers[].proxy`, or `opentmf.security.jwks.proxy`
   in single-issuer mode), as `host:port`;
2. the JVM's standard proxy properties (`https.proxyHost`/`Port`, `http.nonProxyHosts`, …) — what
   the servlet fetch honoured before 3.2.0;
3. the process environment: `HTTPS_PROXY` (or `HTTP_PROXY` for a plain `http:` URL) with `NO_PROXY`
   exclusions, upper- or lower-case — which the JDK never reads on its own;
4. a direct connection.

> **Upgrading:** a deployment that exports `HTTPS_PROXY` without listing the identity provider's
> host in `NO_PROXY` fetched the JWK set *directly* before 3.2.0 and goes through that proxy from
> 3.2.0 on, like every other egress. If that proxy cannot reach the provider, set `NO_PROXY` or the
> per-issuer `proxy`.

TLS trust is the JVM's trust store, unchanged: a provider behind a private CA is trusted only if that
CA is in the image's trust store.

### Readiness and metrics

Since 3.3.0 the keys tell the platform what the wire is doing.

**Health, opt-in.** `opentmf.security.jwks.readiness: true` registers a `jwks` health contributor
with one component per issuer, and adds it to the `readiness` group when Kubernetes probes are
enabled (Boot's default) — you do not touch `management.endpoint.health.group.readiness.include`,
and Boot's `management.health.jwks.enabled=false` still switches it off. Off by default, so nothing
in your health or readiness changes without a decision. The states:

| state | meaning | health |
|---|---|---|
| `FRESH` | a set is loaded and younger than the cache horizon | `UP` |
| `STALE` | refreshes fail but the cached set still serves — tokens still validate | `UP` with `stale: true`, `age`, `lastFailure` |
| `UNAVAILABLE` | never loaded, or older than the outage TTL — every bearer request answers `503` | `DOWN` with `issuer`, `lastFailure`, `failedAt` |

A readiness probe that finds an issuer `UNAVAILABLE` also retries the load in the background (one
attempt in flight, paced by `jwks.refresh-interval`), so a NotReady pod heals without traffic. The
readiness probe answers with the status alone, as Boot's probe groups do; the details are under
`/actuator/health` (`jwks` → the issuer's component).

**Metrics, always on when Micrometer is present**, per issuer (tag `issuer`):

| meter | type | meaning |
|---|---|---|
| `opentmf.security.jwks.keys` | gauge | keys in the loaded set (0 before the first load) |
| `opentmf.security.jwks.keys.age` | gauge, seconds | since the last successful load (`NaN` before it) |
| `opentmf.security.jwks.fetch.failures` | counter | failed loads |

Prometheus: `opentmf_security_jwks_keys`, `opentmf_security_jwks_keys_age_seconds`,
`opentmf_security_jwks_fetch_failures_total`.

**The boot line** names the host and the route, so a proxy problem is readable at boot:

```
Signing keys of issuer 'keycloak' loaded (2 keys) from dnms.test (via proxy 10.0.0.1:3128).
Signing keys of issuer 'entra' could not be loaded from login.microsoftonline.com (direct): IOException: Unable to tunnel through proxy. Bearer tokens from this issuer answer 503 until a refresh succeeds.
```

The host only — never a path or query, in the log or in the health details — and the `503` body
still names the issuer alone.

### Startup policy

`opentmf.security.jwks.on-startup-failure` is `warn` by default: the application boots, the warm-up
runs in the background, and an issuer whose keys never loaded answers `503` until a refresh succeeds
— so a deployment can boot ahead of its identity provider. Set it to `fail` to stop the application
(naming the issuers) when the keys of **no** issuer could be loaded; one live issuer is enough to
boot.

## Multiple trusted issuers

A service sometimes has to accept tokens from two identity providers at once — for example user-driven calls carrying an Entra ID token while service-to-service calls carry a Keycloak token. Since 2.3.0, `opentmf.security.issuers` declares each trusted issuer with its own signing keys and its own claim mapping:

```yaml
opentmf:
  security:
    # user-claim / fallback-user-claims / authorities-claim stay valid here as the
    # defaults every entry inherits unless it declares its own.
    authorities-claim: groups
    user-claim: sub
    fallback-user-claims: client_id, azp

    issuers:
      - name: entra                     # label for logs only
        issuer: https://login.microsoftonline.com/<tenantId>/v2.0
        jwk-set-uri: https://login.microsoftonline.com/<tenantId>/discovery/v2.0/keys
        authorities-claim: roles        # Entra app roles, named after the internal vocabulary
        user-claim: oid                 # stable object id
        fallback-user-claims: preferred_username, sub
        audiences: [<application-client-id>]
      - name: keycloak
        issuer: https://keycloak.internal/realms/dnms
        jwk-set-uri: https://keycloak.internal/realms/dnms/protocol/openid-connect/certs
        # inherits authorities-claim: groups and user-claim: sub from above

    # Endpoint rules are written once and never fork per provider:
    secure-endpoints:
      - method: POST
        path: /product
        roles: [write]
```

`jwk-set-uri` and `issuers` are mutually exclusive — configure exactly one, or the application fails to start. Everything documented elsewhere in this README (endpoint rules, management-port security, 401/403 customization) behaves identically in both modes.

### Normalization: authorization never forks per provider

Each entry's claim mapping translates its provider's token shape into the **same internal role vocabulary**, so `secure-endpoints` and friends are written once and stay provider-blind. In the example above an Entra token's `roles` claim and a Keycloak token's `groups` claim both end up as the authorities `read`/`write`, and a rule demanding `write` is satisfied by either. Resist the temptation to encode provider names into endpoint rules; if a provider's roles do not match the internal vocabulary, fix that in its claim mapping (or in the provider's role names), not in the ACLs.

### How a token is routed

A token is matched to the entry whose `issuer` equals its `iss` claim, and that entry's decoder then validates the signature, the issuer, the expiry and — when configured — the audience. A token whose `iss` matches no entry, or that carries no `iss` at all, is rejected with `401 invalid_token`. There is deliberately no fallback issuer.

The `JwtDecoder` / `ReactiveJwtDecoder` bean (and therefore `JwtService`) routes the same way, so code decoding tokens outside the filter chain works across every trusted issuer.

### Audience validation

`audiences` is optional and empty by default. When set, a token is rejected unless its `aud` claim contains one of the listed values.

Enabling it is strongly recommended for a provider that mints tokens for many applications from one tenant — Entra above all. Without it, a token issued to a *completely different application* of the same tenant still satisfies the issuer check and is accepted. With it, only tokens actually meant for this service pass.

Roll it out by verifying first: decode a real token from the target environment, read its `aud`, and configure exactly that. A wrong value rejects every request from that issuer. Note that audience is normally a consequence of how the client requested the token (for Entra, the scope `api://<client-id>/.default` determines it), so enabling validation here requires no change in the calling services as long as they already request tokens for this service.

### Entra ID notes

These are the details that bite in practice:

- **The issuer is tenant-specific and version-specific.** v2 emits `https://login.microsoftonline.com/{tenantId}/v2.0`, but an app registration left on token version 1 emits `https://sts.windows.net/{tenantId}/` instead. Pin v2 (`accessTokenAcceptedVersion: 2` in the app manifest) and copy the `iss` from a real decoded token rather than assuming.
- **Prefer App Roles over group claims.** Group claims truncate into a pointer claim past roughly 200 memberships, at which point authorization silently degrades for exactly the most privileged users. App roles always arrive inline in `roles`, and naming them after the internal vocabulary (`read`, `write`, `admin`) makes the mapping an identity.
- **`oid` is the stable principal**, `preferred_username` the readable one; `user-claim: oid` with `preferred_username` as a fallback gives stability without losing legibility in logs.

## Management-port security

When you set Spring Boot's `management.server.port` to a value different from `server.port`, actuator endpoints are served from a separate child `ApplicationContext`. That context does **not** inherit the main port's `SecurityFilterChain`, so without this library actuator would be exposed unauthenticated and `management.endpoint.env.show-values: when_authorized` could never see an authenticated principal.

This library reacts to that configuration and registers a second JWT-authenticated filter chain governing the management port, reusing the same `JwtDecoder` and authorities converter as the main port. No additional wiring is required; just set `management.server.port` and supply a valid `opentmf.security.jwk-set-uri`.

Where that chain lives differs per stack, for a Spring Boot reason worth knowing: on the **servlet** stack, Boot exposes the *parent* context's `springSecurityFilterChain` inside the management child context, so any chain registered in the child is never consulted. The library therefore registers the management `SecurityFilterChain` in the **main** context, matched by the request's local port (highest precedence, so it wins over the main chain for management-port requests only). On the **reactive** stack the child context genuinely builds its own `SecurityWebFilterChain`, so the chain is registered there. Configuration and observable behavior are identical on both stacks.

### Defaults

If you set `management.server.port` and do not configure `opentmf.security.management.*`, the library applies safe defaults:

- `/actuator/health`, `/actuator/health/**`, `/actuator/info` are reachable without a JWT (so kubelet probes / load balancer health checks keep working).
- Every other `/actuator/**` endpoint requires an authenticated JWT.

If you scrape `/actuator/prometheus`, `/actuator/metrics`, or any other non-default endpoint without authentication, add those paths to `whitelist` or configure your scraper to present a JWT — the library logs a `WARN` at startup if it detects this scenario.

### Customizing

The management section mirrors the main-port property names — `blacklist`, `whitelist`, `allowed-endpoints`, `secure-endpoints`, `other-endpoints` — evaluated in the same order, so configuration knowledge transfers directly. The only difference is the default for `other-endpoints`: `authenticated` here vs `deny` on the main port.

```yaml
opentmf:
  security:
    jwk-set-uri: https://keycloak:8000/realms/myrealm/protocol/openid-connect/certs
    # ... main-port configuration ...
    management:
      blacklist:
        - /actuator/shutdown
        - /actuator/heapdump
      whitelist:
        - /actuator/health
        - /actuator/health/**
        - /actuator/info
        - /actuator/prometheus
      allowed-endpoints:
        - method: GET
          path: /actuator/loggers
      secure-endpoints:
        - method: POST
          path: /actuator/loggers/**
          roles: [admin]
        - method: GET
          path: /actuator/env
          roles: [admin]
        - method: GET
          path: /actuator/env/**
          roles: [admin]
      other-endpoints: authenticated  # allow | deny | authenticated (default)

management:
  server:
    port: 9090
  endpoints:
    web:
      exposure:
        include: health, info, env, loggers, metrics, prometheus
  endpoint:
    env:
      show-values: when_authorized
      roles: [admin]
```

| Property | Default | Description |
|---|---|---|
| `management.blacklist` | *(empty)* | Paths denied for all HTTP methods. Mirrors the main-port `blacklist`. |
| `management.whitelist` | `/actuator/health`, `/actuator/health/**`, `/actuator/info` | Paths reachable without a JWT. Mirrors the main-port `whitelist`. |
| `management.allowed-endpoints` | *(empty)* | Method-specific paths that bypass authentication. Mirrors the main-port `allowed-endpoints`. |
| `management.secure-endpoints` | *(empty)* | Role-gated method-specific paths. Mirrors the main-port `secure-endpoints`. |
| `management.other-endpoints` | `authenticated` | Catch-all policy for unmatched requests: `allow` (permit anonymously), `deny` (reject), `authenticated` (require any valid JWT). The main port hard-codes `deny`; the management default is `authenticated` because actuator endpoints are well-known and most consumers want every exposed endpoint reachable with any valid JWT without enumerating each one. Set to `deny` for full main-port-style symmetry, or `allow` in trusted-network deployments. |

### Composing with Spring Boot's redaction

Spring Boot's `management.endpoint.env.show-values: when_authorized` (and `show-components`) checks the current `SecurityContext` for the configured `roles`. Without this library on a separate management port, no filter populates that context and every value is redacted. With this library:

- A request with the configured admin role hits the management filter chain → `SecurityContextHolder` is populated → `EnvironmentEndpoint` sees the authority → values are unredacted.
- A request with a different role authenticates but doesn't satisfy the endpoint's role check → values are redacted.
- A request without a JWT is rejected with `401` at the filter chain level and never reaches the endpoint.

### When ports coincide

If you do not set `management.server.port`, or you set it equal to `server.port`, actuator shares the main connector and the main filter chain already governs it. In that mode the management auto-configuration stays inert; configure `/actuator/**` paths via the standard `whitelist`, `secure-endpoints`, or `allowed-endpoints` properties on the main port. The library logs a `WARN` whenever an `opentmf.security.management.*` block is configured but the two ports are not actually separate — whether `management.server.port` is unset *or* explicitly set to the same value as `server.port`. The warning indicates that the entire `opentmf.security.management` block is being ignored and the deployer should take action.

## Customizing 401/403 responses

Authentication (401) and URL-authorization (403) failures are decided inside the Spring Security filter chain, **before** the `DispatcherServlet` / `DispatcherHandler` — so a `@RestControllerAdvice` never sees them, and by default they produce the RFC 6750 response: correct status code plus `WWW-Authenticate` header, **empty body**.

Since 2.2.0 the library lets a consumer take over the rendering of these responses. The switch is **bean presence** — no configuration properties:

- **Servlet** consumers define an `AuthenticationEntryPoint` (401) and/or an `AccessDeniedHandler` (403) bean.
- **Reactive** consumers define a `ServerAuthenticationEntryPoint` (401) and/or a `ServerAccessDeniedHandler` (403) bean.

If a bean of the respective type is present, the library applies it at **both** relevant points of its filter chain (the bearer-token path *and* the exception-translation path — see the matrix below). If no bean is present, behavior is exactly the pre-2.2.0 default. Each handler is independent: you may define only one of the two.

If **multiple candidate beans** of one type exist, the library refuses to guess: it logs a `WARN` naming all candidates and falls back to the default for that handler. Mark exactly one candidate `@Primary` to resolve the ambiguity.

### Plain beans

Render whatever body format your service standardizes on:

```java
@Bean
AuthenticationEntryPoint problemDetailEntryPoint() {
  return (request, response, exception) -> {
    response.setStatus(401);
    response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
    response.getWriter().write("""
        {"status":401,"title":"Unauthorized"}""");
  };
}

@Bean
AccessDeniedHandler problemDetailAccessDeniedHandler() {
  return (request, response, exception) -> {
    response.setStatus(403);
    response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
    response.getWriter().write("""
        {"status":403,"title":"Forbidden"}""");
  };
}
```

The reactive equivalents implement `ServerAuthenticationEntryPoint` / `ServerAccessDeniedHandler` and write to the `ServerWebExchange` response.

### One place for all error rendering

Most services want security errors to look exactly like every other error. The recommended recipe differs per stack because the underlying dispatch machinery differs.

**Servlet — delegate to your advice.** Delegate both handlers to the `handlerExceptionResolver` bean; the exception is then routed into your `@RestControllerAdvice` like any MVC exception:

```java
@Bean
AuthenticationEntryPoint delegatingEntryPoint(
    @Qualifier("handlerExceptionResolver") HandlerExceptionResolver resolver) {
  return (request, response, exception) ->
      resolver.resolveException(request, response, null, exception);
}

@Bean
AccessDeniedHandler delegatingAccessDeniedHandler(
    @Qualifier("handlerExceptionResolver") HandlerExceptionResolver resolver) {
  return (request, response, exception) ->
      resolver.resolveException(request, response, null, exception);
}
```

Caveats: your advice must then handle `AuthenticationException` and `AccessDeniedException` explicitly, and your catch-all `Exception` handler must not accidentally downgrade them to 500.

**Reactive — share the renderer, not the dispatch path.** WebFlux has no `HandlerExceptionResolver`, and `@ControllerAdvice` exception handling lives inside the `DispatcherHandler`, which a security failure in the `WebFilter` chain never reaches. Instead, extract the body rendering into one component and call it from *both* your advice and the security beans:

```java
@Bean
ServerAuthenticationEntryPoint problemDetailEntryPoint(ErrorBodyRenderer renderer) {
  return (exchange, exception) -> renderer.write(exchange, HttpStatus.UNAUTHORIZED, exception);
}

@Bean
ServerAccessDeniedHandler problemDetailAccessDeniedHandler(ErrorBodyRenderer renderer) {
  return (exchange, exception) -> renderer.write(exchange, HttpStatus.FORBIDDEN, exception);
}
```

Convergence happens at the renderer instead of the dispatch path — same single source of truth for the body shape.

> **Why not `Mono.error(...)`?** Re-emitting the exception from the reactive handlers to let Boot's `ErrorWebExceptionHandler` render it looks tempting but is a trap: `DefaultErrorAttributes` derives the HTTP status from `ResponseStatusException` / `@ResponseStatus`, which `AuthenticationException` and `AccessDeniedException` carry neither of — **the default outcome is a 500, not 401/403**, and the `WWW-Authenticate` challenge is lost. Use the shared-renderer pattern.

### Which failure takes which path

| Scenario | Status | Handled by | Rendered by (when customized) |
|---|---|---|---|
| No handler serves the path | 404 | This library, before authentication — see [The HTTP-status matrix](#the-http-status-matrix) | your `HandlerExceptionResolver`s / `WebExceptionHandler`s, as for any `NoHandlerFoundException` |
| Path exists, method not implemented on it | 405 (no `Allow`) | This library, before authentication | same — as for any `HttpRequestMethodNotSupportedException` / `MethodNotAllowedException` |
| No token on a protected URL | 401 | `ExceptionTranslationFilter` / `ExceptionTranslationWebFilter` | entry point |
| Invalid / expired / malformed token | 401 | Bearer-token filter | entry point |
| Invalid token on a **`permitAll`** URL | 401 | Bearer-token filter — a present-but-bad token is always authenticated | entry point |
| Valid token, insufficient role | 403 | `AuthorizationFilter` → exception translation | access-denied handler |
| Valid token, plain `OPTIONS` the rules deny | 200 + `Allow` | This library, decorating the access-denied handler | **nobody**: the library writes it and your handler is not invoked |
| **Anonymous** request on a `denyAll` / blacklisted URL | 401 (not 403!) | Exception translation treats anonymous denials as authentication failures | entry point |
| `@PreAuthorize` denial inside a handler method | 403 | Reaches your `@RestControllerAdvice` as `AccessDeniedException` | your advice (unchanged by this feature) |

### Management port takes no custom handlers

A consumer-supplied entry point or denied handler applies to the **main port only**. The management-port chain keeps the RFC 6750 defaults (status + `WWW-Authenticate`, empty body): it serves probes and scrapers that read status codes, not bodies.

That is about *custom rendering*, not about status codes. The management port follows the same [HTTP-status matrix](#the-http-status-matrix) as the main port, answered from the management context's own handler mappings: an actuator path that is not exposed answers **404**, a method the actuator does not serve on an exposed path **405**, and only then 401/403. Its 404/405 bodies are rendered through the management context's exception resolvers, which on the servlet stack walk up to the main context's — so your `@ControllerAdvice` renders them there too. If you alert on 401/403s from the management port, add 404 and 405 to the alert.

## The HTTP-status matrix

Access rules are deployment configuration; the controllers are the code. When the two disagree
about *why* a request cannot be served, this library answers from the code, because that is what
the caller is actually asking about. Since 3.1.0 that answer is a fixed matrix, evaluated in this
order for **every** request — before authentication, before the access rules, on both stacks and
on both ports — and it is not configurable:

| # | condition | answer |
|---|---|---|
| 1 | no handler serves the path | **404** — anonymous or authenticated |
| 2 | the path is served, the HTTP method is not implemented on it — unknown method names (`PROPFIND`, `BREW`, …) included | **405**, with **no `Allow` header** |
| 3 | path and method exist; no token, or an invalid one | **401** |
| 4 | a valid token whose roles do not satisfy the rule | **403** |

```
GET  /nope                  -> 404   (with or without a token)
PUT  /car/{id}              -> 405   (the resource has GET and DELETE; no Allow header)
BREW /car                   -> 405   (unknown method name, same answer)
GET  /car/{id}   no token   -> 401
GET  /car/{id}   role-less  -> 403
```

Whitelisted, blacklisted and rule-less paths are all subject to rows 1 and 2 first: a whitelisted
prefix with no handler behind it is still 404, and an unimplemented method on a blacklisted path
is still 405. The rules only ever see a request whose path and method both exist.

### What "the path is served" means

The library consults the same `HandlerMapping`s the `DispatcherServlet` / `DispatcherHandler`
dispatches with, in the same order, and stops at the first that claims the path — exactly as the
dispatcher would. Annotation-based controllers are matched on the path alone, so their declared
methods are known without a method-mismatch; functional routes, resource handlers and any other
`HandlerMapping` are asked for a handler the way the dispatcher asks them. Two details worth
knowing:

- **Static resources.** Boot maps a resource handler to `/**` by default, which would make every
  path "served". A resource handler therefore claims a path only when the resource actually
  resolves, through the handler's own resolvers and locations — `/swagger-ui/index.html` exists,
  `/nope` does not — and it implements `GET` and `HEAD`, so `POST /probe.txt` is 405.
- **A method-less `@RequestMapping`** accepts every method, so nothing is ever 405 on it.

A request the container dispatches to a servlet other than Spring MVC's — an H2 console, a JAX-RS
or SOAP engine — is not the matrix's to answer: it goes straight to the access rules and to that
servlet. And should the handler mappings be unreadable for a request (a context still starting,
a lookup failure), the request is likewise left to the rules rather than answered from a guess.

### The body is the application's own

The 404 and 405 are rendered by handing the application the very exceptions Spring would raise —
`NoHandlerFoundException` and `HttpRequestMethodNotSupportedException` (servlet), a
`ResponseStatusException` and `MethodNotAllowedException` (reactive) — through the same
`HandlerExceptionResolver`s / `WebExceptionHandler`s the dispatcher renders through. A
`@RestControllerAdvice extends ResponseEntityExceptionHandler`, a `ProblemDetail` handler or a
TMF-`Error` renderer answers these exactly the way it answers everything else, on the management
port too. The 405 exception names **no supported methods**, so no resolver can derive an `Allow`
from it.

An application with no error rendering of its own gets what it would get natively: Spring's
default resolver and, on the servlet stack, the container's error page — which in a Boot
application is Boot's default error JSON. If you want the matrix's bodies to be yours, render
`NoHandlerFoundException` and `HttpRequestMethodNotSupportedException` (or the reactive
`ResponseStatusException`s) in your error handler; the DNMS service template does.

### Plain `OPTIONS`

Spring answers a plain `OPTIONS` on any mapped path with `200` and an `Allow` header, so the
matrix treats `OPTIONS` as an existing method: it follows rows 3 and 4. Without a token it is
**401**; with a valid token it gets **Spring's own answer** — `200` and the `Allow` Spring's
`HttpOptionsHandler` would send (the declared methods, plus `HEAD` where `GET` is declared, plus
`OPTIONS`) — whether the rules permit the path (Spring answers natively) or deny it (the library
answers, decorating the access-denied handler, and your handler is not invoked for it). `OPTIONS`
the application maps itself is left to the application. The `Allow` ban is for 405 only; the
method set behind a protected path is still only read with a token.

### Unknown method names and the firewall

Spring Security's strict firewall rejects an HTTP method it does not know with **400** before any
filter runs. This library registers an `HttpFirewall` (`StrictHttpFirewall`) on the servlet stack
and a `ServerWebExchangeFirewall` on the reactive stack with `setUnsafeAllowAnyHttpMethod(true)`,
so that `PROPFIND` or `BREW` reach the matrix and are answered 404 or 405 like any other method.
Nothing else the firewall guards changes. If you define your own firewall bean it takes
precedence, and unknown method names keep whatever answer it gives. `TRACE` is the container's:
Tomcat refuses it before any filter runs, with headers of its own.

### `GET` rules cover `HEAD`

A rule written for `GET` is registered for `HEAD` as well, with the same roles:

```yaml
opentmf:
  security:
    secure-endpoints:
      - method: GET          # HEAD /car/** is covered by this rule too
        path: /car/**
        roles: [read]
```

Spring MVC and WebFlux both serve a `HEAD` request from the handler mapped to `GET`, so before
3.0.0 the security chain refused requests the framework was perfectly willing to answer — which
showed up as 403s from monitoring agents, reverse proxies and health checkers. This is not
optional and there is no property to turn it off.

> **Upgrading from 2.x: this tightens as well as loosens.** Because a `GET` rule never matched
> `HEAD` before, a `HEAD` request fell through to `other-endpoints` — served anonymously under
> `allow`, or accepted with any valid token under `authenticated`. It now carries the `GET` rule's
> roles, so a probe that relied on that fall-through gets **401** (anonymous) or **403** (token
> without the role). The management section defaults to `other-endpoints: authenticated`, so a
> role-restricted management `GET` rule tightens `HEAD` there by default. Give the probe the role,
> or `whitelist` the path.

Method values must be spelled **exactly** as the constants; any spelling that differs but would
still bind through Boot's lenient conversion — `get`, `G-E-T`, a stray space — fails at startup
with a message naming the entry. This strictness exists for upgraders: before 3.0.0 the value
bound through `HttpMethod.valueOf`, which preserves case, and the request matchers compare verbs
by exact string — so a lowercase rule silently never matched and its path fell through to
`other-endpoints`. Boot's relaxed enum binding would have brought such a dead rule to life on
upgrade with no warning (an `allowed-endpoints` entry becoming anonymous `permitAll`), so the
library refuses to guess: fix the case after reviewing that the rule is actually intended.

For the same reason `method` accepts only **`GET`, `POST`, `PUT`, `PATCH`, `DELETE`**. `HEAD` is
implied by `GET`; allowing it to be named separately would let a configuration declare different
roles for the two, of which only the first registered would ever apply. `OPTIONS` and `TRACE` are
rejected too — `OPTIONS` is answered by the matrix above, and `TRACE` belongs to the container.

### Retired: `unmatched-method-response`

3.0.0's `unmatched-method-response` (`method-not-allowed` / `deny`, on both sections) chose between
405 and a uniform 403 for a method the application does not implement. The matrix is not
configurable, so the property is gone — and because Boot ignores an unknown property without a
word, a configuration that still sets it **fails at startup** with a message saying so, rather than
silently losing the opt-out it thought it had. Remove the property.

### CORS pre-flight is a different problem

`OPTIONS` cannot be named in the access rules, and for a CORS pre-flight it does not need to be.
Where CORS is configured, the pre-flight is answered by Spring's CORS filter before the matrix or
the rules see it; where it is *not* configured, a pre-flight is a plain `OPTIONS` to the matrix
(401 without a token) and no access rule could help anyway: a browser needs
`Access-Control-Allow-Origin`, which only a `CorsConfigurationSource` bean (or MVC
`addCorsMappings`) can produce. **If your service is called from a browser on another origin,
configure CORS** — this library will not make pre-flight work, on either stack.

The two stacks differ here, which is worth knowing when comparing them. On servlet, Spring's
`CorsFilter` is always installed and terminates a pre-flight before the security chain runs, so an
unconfigured service answers `200` with no CORS headers. On reactive no CORS filter is installed
without a `CorsConfigurationSource` bean, so the pre-flight reaches the matrix and the rules.
Configuring CORS makes both behave the same.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for the full version history.

## License

[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0)
