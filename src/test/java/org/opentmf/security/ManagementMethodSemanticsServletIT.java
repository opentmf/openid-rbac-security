package org.opentmf.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.opentmf.security.util.TokenUtil.WRITE_TOKEN;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalManagementPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

/**
 * The management port answers method semantics from the <em>management</em> context's handler
 * mappings, not the main context's.
 *
 * <p>On the servlet stack this is the case most easily got wrong: the management chain is
 * registered in the main {@code ApplicationContext} (Boot exposes the parent's filter chain on
 * the management port), while the actuator endpoints it guards are mapped in the management
 * child context. Consulting the wrong one would advertise the business API's methods on the
 * management port. {@code /car} exists on the main port and nowhere on this one, so a denied
 * request for it here must answer {@code 403} — never a {@code 405} naming the main port's verbs.
 *
 * <p>Runs with {@code management.other-endpoints: DENY}, since the default of
 * {@code AUTHENTICATED} lets unmatched requests through to the actuator, where the question does
 * not arise.
 *
 * @author Gokhan Demir
 */
@SpringBootTest(
    webEnvironment = WebEnvironment.RANDOM_PORT,
    properties = {
        "server.servlet.context-path=/opentmf/commons",
        "management.server.port=0",
        "management.endpoints.web.exposure.include=health,info,metrics",
        "opentmf.security.management.other-endpoints=DENY",
        "opentmf.security.management.secure-endpoints[0].method=GET",
        "opentmf.security.management.secure-endpoints[0].path=/actuator/metrics",
        "opentmf.security.management.secure-endpoints[0].roles=write"
    })
@ActiveProfiles({"servlet", "local"})
@TestInstance(Lifecycle.PER_CLASS)
class ManagementMethodSemanticsServletIT {

  private static final ResponseErrorHandler NEVER_ERROR = response -> false;

  @LocalManagementPort int managementPort;
  RestTemplate restTemplate;

  @BeforeAll
  void beforeAll() {
    restTemplate = new RestTemplate();
    restTemplate.setErrorHandler(NEVER_ERROR);
  }

  @Test
  void unimplementedMethodOnAnActuatorPath_returnsMethodNotAllowedWithAllow() {
    ResponseEntity<String> response = exchange(HttpMethod.PUT, "/actuator/metrics");

    assertThat(response.getStatusCode().value()).isEqualTo(405);
    assertThat(allowOf(response)).contains("GET");
  }

  /** The main port's controllers must not be visible from here. */
  @Test
  void aPathServedOnlyByTheMainPort_staysForbidden() {
    ResponseEntity<String> response = exchange(HttpMethod.PUT, "/car");

    assertThat(response.getStatusCode().value()).isEqualTo(403);
    assertThat(response.getHeaders().getFirst(HttpHeaders.ALLOW)).isNull();
  }

  @Test
  void unimplementedMethodWithoutToken_staysUnauthorized() {
    HttpHeaders headers = new HttpHeaders();
    ResponseEntity<String> response = restTemplate.exchange(
        managementUri("/actuator/metrics"), HttpMethod.PUT, new HttpEntity<>(headers), String.class);

    assertThat(response.getStatusCode().value()).isEqualTo(401);
    assertThat(response.getHeaders().getFirst(HttpHeaders.ALLOW)).isNull();
  }

  private ResponseEntity<String> exchange(HttpMethod method, String path) {
    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(WRITE_TOKEN);
    return restTemplate.exchange(
        managementUri(path), method, new HttpEntity<>(headers), String.class);
  }

  private String managementUri(String path) {
    return "http://localhost:" + managementPort + path;
  }

  private static Set<String> allowOf(ResponseEntity<String> response) {
    String header = response.getHeaders().getFirst(HttpHeaders.ALLOW);
    assertThat(header).isNotNull();
    return Arrays.stream(header.split(",")).map(String::trim).collect(Collectors.toSet());
  }
}
