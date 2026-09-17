package org.opentmf.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

import java.time.Duration;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer.OrderAnnotation;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.junit.jupiter.api.TestMethodOrder;
import org.opentmf.security.util.JwksServer;
import org.opentmf.security.util.TestIssuer;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalManagementPort;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.client.RestTemplate;

/**
 * Readiness follows the signing keys once the adopter opts in: a pod whose keys were never
 * obtained is NotReady ({@code /actuator/health/readiness} 503 with {@code jwks: DOWN} naming the
 * issuer), liveness is untouched, and the pod becomes Ready without a restart once the issuer
 * serves. The metrics endpoint shows the per-issuer meters. Through a real Tomcat with the
 * actuator on the management port and Kubernetes probes enabled.
 *
 * @author Gokhan Demir
 */
@SpringBootTest(
    webEnvironment = WebEnvironment.RANDOM_PORT,
    properties = {
        "spring.main.web-application-type=servlet",
        "management.server.port=0",
        "management.endpoints.web.exposure.include=health,metrics",
        "management.endpoint.health.probes.enabled=true",
        "management.endpoint.health.show-details=always",
        "management.endpoint.health.show-components=always",
        "opentmf.security.management.whitelist[0]=/actuator/**",
        "opentmf.security.jwks.readiness=true",
        "opentmf.security.jwks.refresh-interval=200ms",
        "opentmf.security.jwks.connect-timeout=1s",
        "opentmf.security.jwks.read-timeout=1s"
    })
@TestInstance(Lifecycle.PER_CLASS)
@TestMethodOrder(OrderAnnotation.class)
class ServletJwksReadinessIT {

  static final TestIssuer ISSUER = TestIssuer.create("ready", "https://ready.test/realm");
  static final JwksServer JWKS = JwksServer.start(ISSUER.jwkSetJson());

  static {
    JWKS.fail(503);
  }

  @DynamicPropertySource
  static void trustTheServer(DynamicPropertyRegistry registry) {
    registry.add("opentmf.security.issuers[0].name", () -> "ready-idp");
    registry.add("opentmf.security.issuers[0].issuer", ISSUER::getIssuer);
    registry.add("opentmf.security.issuers[0].jwk-set-uri", JWKS::url);
  }

  @LocalManagementPort int managementPort;
  RestTemplate restTemplate;

  @BeforeAll
  void beforeAll() {
    restTemplate = new RestTemplate();
    restTemplate.setErrorHandler(response -> false);
  }

  @AfterAll
  static void afterAll() {
    JWKS.close();
  }

  @Order(10)
  @Test
  void cold_readinessIsDown_namingTheIssuer_livenessIsUp() {
    await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> {
      // The readiness probe answers with the status alone, as Boot's probe groups do; the
      // details are on the full health endpoint.
      ResponseEntity<String> readiness = get("/actuator/health/readiness");
      assertThat(readiness.getStatusCode().value()).isEqualTo(503);
      assertThat(readiness.getBody()).contains("\"DOWN\"");
      ResponseEntity<String> health = get("/actuator/health");
      assertThat(health.getBody())
          .contains("\"jwks\"").contains("\"ready-idp\"")
          .contains("\"state\":\"UNAVAILABLE\"").doesNotContain(JwksServer.PATH);
    });
    assertThat(get("/actuator/health/liveness").getStatusCode().value()).isEqualTo(200);
  }

  @Order(20)
  @Test
  void cold_theMetersShowNoKeysAndTheFailures() {
    ResponseEntity<String> keys = get("/actuator/metrics/opentmf.security.jwks.keys?tag=issuer:ready-idp");
    ResponseEntity<String> failures = get("/actuator/metrics/opentmf.security.jwks.fetch.failures");

    assertThat(keys.getStatusCode().value()).isEqualTo(200);
    assertThat(keys.getBody()).contains("\"value\":0.0");
    assertThat(failures.getStatusCode().value()).isEqualTo(200);
  }

  @Order(30)
  @Test
  void onceTheIssuerServes_readinessComesUp_withoutARestart() {
    JWKS.serve(ISSUER.jwkSetJson());

    await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> {
      assertThat(get("/actuator/health/readiness").getStatusCode().value()).isEqualTo(200);
      assertThat(get("/actuator/health").getBody())
          .contains("\"state\":\"FRESH\"").contains("\"keys\":1");
    });
    assertThat(get("/actuator/metrics/opentmf.security.jwks.keys?tag=issuer:ready-idp").getBody())
        .contains("\"value\":1.0");
  }

  private ResponseEntity<String> get(String path) {
    return restTemplate.getForEntity("http://localhost:" + managementPort + path, String.class);
  }
}
