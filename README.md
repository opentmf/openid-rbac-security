# pia-security
Role based Access Control (RBAC) Security Library

## Description
This autoconfiguration library uses Spring Boot Security and Spring Boot oauth2 resource server for enabling Bearer Token authentication.

Depending on the web application type, a servlet or reactive security scheme will be configured.

The following can be specified using configuration properties:
- The required roles can be specified for the particular API endpoints, together with the HTTP methods.
- The allowed endpoints can be specified together with the HTTP method.
- The whitelisted endpoints can be specified or all HTTP methods.

**Important:** Protected but not configured endpoints will cause HTTP 403, Forbidden. If you don't want this to happen, define all protected endpoints in the pia-security.

## Usage

### pom.xml
Add this dependency:
```xml
<project>

  <dependencyManagement>
    <dependency>
      <groupId>com.pia.commons</groupId>
      <artifactId>pia-commons-versions</artifactId>
      <version>RELEASE</version>
      <type>pom</type>
      <scope>import</scope>
    </dependency>
  </dependencyManagement>

  <dependencies>
    <dependency>
      <groupId>com.pia.commons</groupId>
      <artifactId>pia-security</artifactId>
    </dependency>
  </dependencies>

</project>
```

### Sample Configuration
```yaml
---
pia:
  security:
    jwk-set-uri: https://keycloak:8000/realms/test/protocol/openid-connect/certs
    user-claim: sub
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

## Version History
- 1.0.0
  - Initial revision
- 1.0.1
  - Started including source code
  - Started allowing local file for jwk-set-uri
- 1.0.2
  - **Incompatible change**: Configuration prefix is now **pia.security**.
- 1.0.3
  - Removed blocking hardcoded swagger endpoints
  - Added new coniguration property `blacklist` that allows specifying endpoints to be blocked
- 1.0.4
  - **Bugfix**: We now support deeper levels for pia.security.authorities-claim
- 1.0.5
  - **Bugfix**: Fix the support for handling deeper levels for pia.security.authorities-claim
- 1.0.6
  - **Improvement**: Both whitelist and blacklist have been made optional.
- 1.0.7
  - **Bugfix**: Fixed conditional typo on configureWhitelist on ServletSecurityAutoConfiguration
- 1.0.8
  - **Bugfix**: Fixed jwk-set-uri local file retrievals for enabling easier IT tests.
- 1.0.9
  - **Bugfix**: Fixed cors headers configuration to obey the application configuration.
