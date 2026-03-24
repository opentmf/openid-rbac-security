# openid-rbac-security

OpenID Role-Based Access Control (RBAC) security library for Spring Boot.

## Overview

A Spring Boot auto-configuration library that enables Bearer Token authentication using Spring Security OAuth2 Resource Server. It supports both **servlet** and **reactive** web application types automatically.

Configure endpoint security declaratively through properties:

- **Secure endpoints** -- require specific roles for given HTTP method + path combinations.
- **Allowed endpoints** -- bypass security for specific HTTP method + path combinations.
- **Whitelist** -- bypass security for paths regardless of HTTP method.
- **Blacklist** -- deny access to paths regardless of HTTP method.

Any endpoint that is protected but not explicitly configured will return **HTTP 403 Forbidden**.

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

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for the full version history.

## License

[Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0)
