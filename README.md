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
| `jwk-set-uri` | *(required)* | URL or resource path to the JWK Set (e.g. Keycloak certs endpoint, or `classpath:jwk-set.json`). |
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

## Management-port security

When you set Spring Boot's `management.server.port` to a value different from `server.port`, actuator endpoints are served from a separate child `ApplicationContext`. That context does **not** inherit the main port's `SecurityFilterChain`, so without this library actuator would be exposed unauthenticated and `management.endpoint.env.show-values: when_authorized` could never see an authenticated principal.

This library reacts to that configuration and registers a second JWT-authenticated `SecurityFilterChain` (servlet) / `SecurityWebFilterChain` (reactive) in the management child context, reusing the same `JwtDecoder` and authorities converter as the main port. No additional wiring is required; just set `management.server.port` and supply a valid `opentmf.security.jwk-set-uri`.

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

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for the full version history.

## License

[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0)
