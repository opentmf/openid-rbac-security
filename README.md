# openid-rbac-security
OpenID, Role Based Access Control (RBAC) Security Library

## Description
This autoconfiguration library uses Spring Boot Security and Spring Boot oauth2 resource server for enabling Bearer Token authentication.

Depending on the web application type, a servlet or reactive security scheme will be configured.

The following can be specified using configuration properties:
- The required roles can be specified for the particular API endpoints, together with the HTTP methods.
- The allowed endpoints can be specified together with the HTTP method.
- The whitelisted endpoints can be specified or all HTTP methods.

**Important:** Protected but not configured endpoints will cause HTTP 403, Forbidden. If you don't want this to happen, define all protected endpoints in the openid-rbac-security.

## Usage

### pom.xml
Add this dependency:
```xml
<project>

  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.opentmf</groupId>
        <artifactId>opentmf-versions</artifactId>
        <type>pom</type>
        <scope>import</scope>
        <version>RELEASE</version>
      </dependency>
    </dependencies>
  </dependencyManagement>

  <dependencies>
    <dependency>
      <groupId>org.opentmf.security</groupId>
      <artifactId>openid-rbac-security</artifactId>
    </dependency>
  </dependencies>

</project>
```

### Sample Configuration
```yaml
---
opentmf:
  security:
    jwk-set-uri: https://keycloak:8000/realms/test/protocol/openid-connect/certs
    user-claim: email
    fallback-user-claims: client_id, azp, appid, sub
    authorities-claim: groups
    secure-endpoints:
      - method: POST
        path: /order
        roles:
          - write
          - ENTERPRISE-GUI/ADMIN_ALL
          - ENTERPRISE-API/ADMIN_ALL
      - method: GET
        path: /engine-rest/process-definition/*/xml
        roles:
          - read
          - ENTERPRISE-GUI/ADMIN_ALL
          - ENTERPRISE-API/ADMIN_ALL
      - method: PUT
        path: /engine-rest/task/*
        roles:
          - write
          - ENTERPRISE-GUI/ADMIN_ALL
          - ENTERPRISE-API/ADMIN_ALL
  
    allowed-endpoints:
      - method: GET
        path: /order/**
      - method: PUT
        path: /greetings
  
    whitelist:
      - /error
      - /info
      - /actuator
      - /actuator/**

    blacklist:
      - /swagger-ui.html
      - /swagger-ui/**
      - /swagger-resources/**
      - /webjars/**
```

### Configuration Properties

#### `user-claim`
The JWT claim name to use as the principal (user identifier). Defaults to `sub` if not specified.

**Example:** `user-claim: email`

#### `fallback-user-claims`
A list of fallback claim names to use when the primary `user-claim` is not present in the JWT token. This is particularly useful when using `client_credentials` grant type, where user-specific claims (like `email`) may not be present.

The fallback claims are tried in order until one is found. If none of the fallback claims are found, the JWT `sub` (subject) claim is used as a final fallback.

**Supports nested claims** using dot notation (e.g., `user.email`, `client_info.client_id`, `realm_access.client_id`).

**Example:** `fallback-user-claims: client_id, azp, appid, user.email, sub`

**Use Case:** When your application needs to support both:
- **Password grant tokens** (user authentication) - contains `email` claim
- **Client credentials tokens** (service-to-service) - contains `client_id`, `azp`, or `appid` but not `email`

**Configuration Example:**
```yaml
opentmf:
  security:
    user-claim: email              # Primary claim for user tokens
    fallback-user-claims:          # Fallback claims for service tokens
      - client_id                   # Simple claim
      - azp                         # Simple claim
      - appid                       # Simple claim
      - user.email                  # Nested claim (if user object contains email)
      - client_info.client_id       # Nested claim (if client_info object contains client_id)
      - sub                         # Final fallback (always present in valid JWTs)
```

#### `authorities-claim`
The JWT claim name that contains the user roles/authorities. Defaults to `roles` if not specified.

**Example:** `authorities-claim: groups`

Supports nested claims using dot notation (e.g., `realm_access.roles`).

## Version History
### 1.0.0
  - Initial revision
### 1.0.1
  - Started including source code
  - Started allowing local file for jwk-set-uri
### 1.0.2
  - **Incompatible change**: Configuration prefix is now **pia.security**.
### 1.0.3
  - Removed blocking hardcoded swagger endpoints
  - Added new configuration property `blacklist` that allows specifying endpoints to be blocked
### 1.0.4
  - **Bugfix**: We now support deeper levels for pia.security.authorities-claim
### 1.0.5
  - **Bugfix**: Fix the support for handling deeper levels for pia.security.authorities-claim
### 1.0.6
  - **Improvement**: Both whitelist and blacklist have been made optional.
### 1.0.7
  - **Bugfix**: Fixed conditional typo on configureWhitelist on ServletSecurityAutoConfiguration
### 1.0.8
  - **Bugfix**: Fixed jwk-set-uri local file retrievals for enabling easier IT tests.
### 1.0.9
  - **Bugfix**: Fixed cors headers configuration to obey the application configuration.
### 1.1.0
- Initial Open Source Release, replacing pia with opentmf

### 1.1.1
- **New Feature**: Added `fallback-user-claims` configuration property to support fallback claim extraction when the primary `user-claim` is not present in the JWT token. This enables support for both password grant tokens (with user claims like `email`) and client_credentials grant tokens (with service claims like `client_id`, `azp`, `appid`). The fallback mechanism tries claims in order and falls back to JWT `sub` if none are found.
