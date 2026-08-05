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
| `secure-endpoints` | *(empty)* | List of `{method, path, roles}` entries requiring specific authorities. |
| `allowed-endpoints` | *(empty)* | List of `{method, path}` entries that bypass security. |
| `whitelist` | *(empty)* | List of path patterns that bypass security for all HTTP methods. |
| `blacklist` | *(empty)* | List of path patterns denied for all HTTP methods. |
| `other-endpoints` | `deny` | Catch-all policy for unmatched requests: `allow` (permit anonymously), `deny` (reject — historical default, preserves backward compatibility), `authenticated` (require any valid JWT). |

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
| No token on a protected URL | 401 | `ExceptionTranslationFilter` / `ExceptionTranslationWebFilter` | entry point |
| Invalid / expired / malformed token | 401 | Bearer-token filter | entry point |
| Invalid token on a **`permitAll`** URL | 401 | Bearer-token filter — a present-but-bad token is always authenticated | entry point |
| Valid token, insufficient role | 403 | `AuthorizationFilter` → exception translation | access-denied handler |
| **Anonymous** request on a `denyAll` / blacklisted URL | 401 (not 403!) | Exception translation treats anonymous denials as authentication failures | entry point |
| `@PreAuthorize` denial inside a handler method | 403 | Reaches your `@RestControllerAdvice` as `AccessDeniedException` | your advice (unchanged by this feature) |

### Management port is not affected

The management-port chain deliberately keeps the RFC 6750 defaults (status + `WWW-Authenticate`, empty body): it serves probes and scrapers that read status codes, not bodies. Custom entry points / denied handlers apply to the main port only.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for the full version history.

## License

[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0)
