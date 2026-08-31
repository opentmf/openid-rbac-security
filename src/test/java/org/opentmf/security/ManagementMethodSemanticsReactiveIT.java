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
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.reactive.server.EntityExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;

/**
 * Method semantics on the reactive management port, which had no coverage of its own.
 *
 * <p>Unlike the servlet side, this chain is registered inside the management child context, so
 * it sees the actuator's handler mappings by construction. The lookup is still local-only —
 * {@code getBeanProvider().stream()} walks into the parent context and excludes a parent bean
 * only when the child defines one under the same name — and {@code /car} is served on the main
 * port and nowhere here, so a denied request for it must stay {@code 403}.
 *
 * <p>Runs with {@code management.other-endpoints: DENY}, since the {@code AUTHENTICATED} default
 * lets unmatched requests through to the actuator, where the question does not arise.
 *
 * @author Gokhan Demir
 */
@SpringBootTest(
    webEnvironment = WebEnvironment.RANDOM_PORT,
    properties = {
        "spring.main.allow-bean-definition-overriding=true",
        "management.server.port=0",
        "management.endpoints.web.exposure.include=health,info,metrics",
        "opentmf.security.management.other-endpoints=DENY",
        "opentmf.security.management.secure-endpoints[0].method=GET",
        "opentmf.security.management.secure-endpoints[0].path=/actuator/metrics",
        "opentmf.security.management.secure-endpoints[0].roles=write"
    })
@ActiveProfiles({"reactive", "local"})
@TestInstance(Lifecycle.PER_CLASS)
class ManagementMethodSemanticsReactiveIT {

  @LocalManagementPort int managementPort;
  WebTestClient webTestClient;

  @BeforeAll
  void beforeAll() {
    webTestClient = WebTestClient
        .bindToServer()
        .baseUrl("http://localhost:" + managementPort)
        .build();
  }

  @Test
  void unimplementedMethodOnAnActuatorPath_returnsMethodNotAllowedWithAllow() {
    EntityExchangeResult<byte[]> result = exchange(HttpMethod.PUT, "/actuator/metrics");

    assertThat(result.getStatus().value()).isEqualTo(405);
    assertThat(allowOf(result)).contains("GET");
  }

  /** The main port's controllers must not be visible from here. */
  @Test
  void aPathServedOnlyByTheMainPort_staysForbidden() {
    EntityExchangeResult<byte[]> result = exchange(HttpMethod.PATCH, "/car");

    assertThat(result.getStatus().value()).isEqualTo(403);
    assertThat(result.getResponseHeaders().getFirst(HttpHeaders.ALLOW)).isNull();
  }

  @Test
  void unimplementedMethodWithoutToken_staysUnauthorized() {
    EntityExchangeResult<byte[]> result = webTestClient.method(HttpMethod.PUT)
        .uri("/actuator/metrics")
        .exchange()
        .expectBody()
        .returnResult();

    assertThat(result.getStatus().value()).isEqualTo(401);
    assertThat(result.getResponseHeaders().getFirst(HttpHeaders.ALLOW)).isNull();
  }

  private EntityExchangeResult<byte[]> exchange(HttpMethod method, String path) {
    return webTestClient.method(method).uri(path)
        .header(HttpHeaders.AUTHORIZATION, "Bearer " + WRITE_TOKEN)
        .exchange()
        .expectBody()
        .returnResult();
  }

  private static Set<String> allowOf(EntityExchangeResult<byte[]> result) {
    String header = result.getResponseHeaders().getFirst(HttpHeaders.ALLOW);
    assertThat(header).isNotNull();
    return Arrays.stream(header.split(",")).map(String::trim).collect(Collectors.toSet());
  }
}
