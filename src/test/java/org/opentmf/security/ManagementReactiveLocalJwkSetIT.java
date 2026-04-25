package org.opentmf.security;

import static org.opentmf.security.util.TokenUtil.READ_TOKEN;
import static org.opentmf.security.util.TokenUtil.WRITE_TOKEN;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalManagementPort;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.reactive.server.WebTestClient;

/**
 * Reactive integration test for the management-port {@link
 * org.springframework.security.web.server.SecurityWebFilterChain}. Uses the file-based
 * JWK set so the test does not require Docker / Keycloak.
 *
 * @author Gokhan Demir
 */
@SpringBootTest(
    webEnvironment = WebEnvironment.RANDOM_PORT,
    properties = {
        "spring.main.allow-bean-definition-overriding=true",
        "management.server.port=0",
        "management.endpoints.web.exposure.include=health,info,env,metrics",
        "opentmf.security.management.secure-endpoints[0].method=GET",
        "opentmf.security.management.secure-endpoints[0].path=/actuator/env",
        "opentmf.security.management.secure-endpoints[0].roles=write",
        "opentmf.security.management.secure-endpoints[1].method=GET",
        "opentmf.security.management.secure-endpoints[1].path=/actuator/env/**",
        "opentmf.security.management.secure-endpoints[1].roles=write"
    })
@ActiveProfiles({"reactive", "local"})
@TestInstance(Lifecycle.PER_CLASS)
class ManagementReactiveLocalJwkSetIT {

  @LocalServerPort int serverPort;
  @LocalManagementPort int managementPort;

  WebTestClient managementClient;
  WebTestClient mainClient;

  @BeforeAll
  void initClients() {
    managementClient = WebTestClient.bindToServer()
        .baseUrl("http://localhost:" + managementPort)
        .build();
    mainClient = WebTestClient.bindToServer()
        .baseUrl("http://localhost:" + serverPort)
        .build();
  }

  @Test
  void healthReachableWithoutJwt() {
    managementClient.get().uri("/actuator/health").exchange().expectStatus().isOk();
  }

  @Test
  void infoReachableWithoutJwt() {
    managementClient.get().uri("/actuator/info").exchange().expectStatus().isOk();
  }

  @Test
  void metricsRejectedWithoutJwt() {
    managementClient.get().uri("/actuator/metrics").exchange().expectStatus().isUnauthorized();
  }

  @Test
  void metricsAcceptedWithAuthenticatedJwt() {
    managementClient.get().uri("/actuator/metrics")
        .headers(h -> h.setBearerAuth(READ_TOKEN))
        .exchange()
        .expectStatus().isOk();
  }

  @Test
  void envRejectedForReadOnlyRole() {
    managementClient.get().uri("/actuator/env")
        .headers(h -> h.setBearerAuth(READ_TOKEN))
        .exchange()
        .expectStatus().isForbidden();
  }

  @Test
  void envAcceptedForWriteRole() {
    managementClient.get().uri("/actuator/env")
        .headers(h -> h.setBearerAuth(WRITE_TOKEN))
        .exchange()
        .expectStatus().isOk();
  }

  @Test
  void mainPortStillRejectsAnonymousProtectedRequests() {
    mainClient.get().uri("/protectedButNotConfigured")
        .exchange()
        .expectStatus().isUnauthorized();
  }
}
