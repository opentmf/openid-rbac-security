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
  ...
  <properties>
    ...
    <pia-security.version>1.0.1</pia-security.version>
    ...
  </properties>

  <dependencies>
    ...
    <dependency>
      <groupId>com.pia.commons</groupId>
      <artifactId>pia-security</artifactId>
      <version>${pia-security.version}</version>
    </dependency>
    ...
  </dependencies>
  ...
</project>
```

### Sample Configuration
```yaml
---
pia-security:
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

```


## Version History
- 1.0.0
  - Initial revision
- 1.0.1
  - Started including source code
  - Started allowing local file for jwk-set-uri