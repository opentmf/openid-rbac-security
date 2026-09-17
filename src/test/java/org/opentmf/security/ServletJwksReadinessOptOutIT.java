package org.opentmf.security;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
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
 * The guarantee behind the default: without the opt-in nothing in health or readiness changes
 * for an adopter — a cold outage leaves {@code /actuator/health} and the readiness probe UP, no
 * {@code jwks} component appears — while the metrics are still there.
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
        "management.endpoint.health.show-components=always",
        "opentmf.security.management.whitelist[0]=/actuator/**",
        "opentmf.security.jwks.connect-timeout=1s",
        "opentmf.security.jwks.read-timeout=1s"
    })
class ServletJwksReadinessOptOutIT {

  static final TestIssuer ISSUER = TestIssuer.create("optout", "https://optout.test/realm");
  static final JwksServer JWKS = JwksServer.start(ISSUER.jwkSetJson());

  static {
    JWKS.fail(503);
  }

  @DynamicPropertySource
  static void trustTheServer(DynamicPropertyRegistry registry) {
    registry.add("opentmf.security.jwk-set-uri", JWKS::url);
  }

  @LocalManagementPort int managementPort;

  @AfterAll
  static void afterAll() {
    JWKS.close();
  }

  @Test
  void withoutTheOptIn_aColdOutageChangesNeitherHealthNorReadiness() {
    RestTemplate restTemplate = new RestTemplate();
    restTemplate.setErrorHandler(response -> false);

    ResponseEntity<String> health = restTemplate.getForEntity(
        "http://localhost:" + managementPort + "/actuator/health", String.class);
    ResponseEntity<String> readiness = restTemplate.getForEntity(
        "http://localhost:" + managementPort + "/actuator/health/readiness", String.class);
    ResponseEntity<String> keys = restTemplate.getForEntity(
        "http://localhost:" + managementPort + "/actuator/metrics/opentmf.security.jwks.keys",
        String.class);

    assertThat(health.getStatusCode().value()).isEqualTo(200);
    assertThat(health.getBody()).doesNotContain("\"jwks\"");
    assertThat(readiness.getStatusCode().value()).isEqualTo(200);
    assertThat(keys.getStatusCode().value()).isEqualTo(200);
  }
}
