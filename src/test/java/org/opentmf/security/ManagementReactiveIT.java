package org.opentmf.security;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import java.net.URI;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.opentmf.security.service.TokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalManagementPort;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

/**
 * Keycloak-backed reactive integration test for the management-port {@link
 * org.springframework.security.web.server.SecurityWebFilterChain}. Each test class uses
 * its own {@link KeycloakContainer} bound to a Testcontainers-allocated random host port
 * so developer machines running other compose stacks don't collide with the build.
 *
 * @author Gokhan Demir
 */
@SpringBootTest(
    webEnvironment = WebEnvironment.RANDOM_PORT,
    properties = {
        "spring.main.allow-bean-definition-overriding=true",
        "management.server.port=0",
        "management.endpoints.web.exposure.include=health,info,env,metrics",
        "management.endpoint.env.show-values=when_authorized",
        "management.endpoint.env.roles=write",
        "opentmf.security.management.secure-endpoints[0].method=GET",
        "opentmf.security.management.secure-endpoints[0].path=/actuator/env",
        "opentmf.security.management.secure-endpoints[0].roles=write",
        "opentmf.security.management.secure-endpoints[1].method=GET",
        "opentmf.security.management.secure-endpoints[1].path=/actuator/env/**",
        "opentmf.security.management.secure-endpoints[1].roles=write"
    })
@ActiveProfiles("reactive")
@TestInstance(Lifecycle.PER_CLASS)
class ManagementReactiveIT {

  private static final KeycloakContainer KEYCLOAK = new KeycloakContainer()
      .withRealmImportFile("realm/rehearsal.json");

  static {
    KEYCLOAK.start();
  }

  @DynamicPropertySource
  static void registerKeycloakProperties(DynamicPropertyRegistry registry) {
    registry.add("opentmf.security.jwk-set-uri", () ->
        KEYCLOAK.getAuthServerUrl() + "/realms/rehearsal-realm/protocol/openid-connect/certs");
  }

  @LocalServerPort int serverPort;
  @LocalManagementPort int managementPort;
  @Autowired TokenService reactiveTokenService;

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
    String token = readerToken();
    managementClient.get().uri("/actuator/metrics")
        .headers(h -> h.setBearerAuth(token))
        .exchange()
        .expectStatus().isOk();
  }

  @Test
  void envRejectedForReaderRole() {
    String token = readerToken();
    managementClient.get().uri("/actuator/env")
        .headers(h -> h.setBearerAuth(token))
        .exchange()
        .expectStatus().isForbidden();
  }

  @Test
  void envAcceptedForWriterRoleAndValuesUnredacted() {
    String token = writerToken();
    managementClient.get().uri("/actuator/env")
        .headers(h -> h.setBearerAuth(token))
        .exchange()
        .expectStatus().isOk()
        .expectBody(String.class)
        .value(body -> org.assertj.core.api.Assertions.assertThat(body)
            .doesNotContain("\"value\":\"******\""));
  }

  @Test
  void mainPortStillRejectsAnonymousProtectedRequests() {
    mainClient.get().uri("/protectedButNotConfigured")
        .exchange()
        .expectStatus().isUnauthorized();
  }

  @Test
  void mainPortAcceptsValidJwt() {
    String token = writerToken();
    mainClient.get().uri("/car")
        .headers(h -> h.setBearerAuth(token))
        .exchange()
        .expectStatus().isOk();
  }

  private String readerToken() {
    return reactiveTokenService.getToken(tokenUri(), "read");
  }

  private String writerToken() {
    return reactiveTokenService.getToken(tokenUri(), "write");
  }

  private static URI tokenUri() {
    return URI.create(
        KEYCLOAK.getAuthServerUrl() + "/realms/rehearsal-realm/protocol/openid-connect/token");
  }
}
