package org.opentmf.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.opentmf.security.HttpStatusMatrixCells.Caller;
import org.opentmf.security.HttpStatusMatrixCells.Cell;
import org.opentmf.security.api.reactive.ReactiveErrorRenderer;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalManagementPort;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.reactive.server.EntityExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;

/**
 * The HTTP-status matrix on the reactive management port. Unlike the servlet side, this chain
 * is registered inside the management child context, so it sees the actuator's handler
 * mappings by construction; the lookup is still local-only, and {@code /car} — served on the
 * main port and nowhere here — must answer {@code 404}. Replaces the 3.0.0
 * {@code ManagementMethodSemanticsReactiveIT}; see the servlet twin for the rewritten cells.
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
class ManagementHttpStatusMatrixReactiveIT {

  @LocalManagementPort int managementPort;
  WebTestClient webTestClient;

  @BeforeAll
  void beforeAll() {
    webTestClient = WebTestClient
        .bindToServer()
        .baseUrl("http://localhost:" + managementPort)
        .build();
  }

  static Stream<Cell> cells() {
    return HttpStatusMatrixCells.managementPort();
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("cells")
  void matrix(Cell cell) {
    EntityExchangeResult<byte[]> result = exchange(cell.method(), cell.path(), cell.caller());

    assertThat(result.getStatus().value()).as("status").isEqualTo(cell.status());
    if (cell.status() == 405) {
      assertThat(result.getResponseHeaders().getFirst(HttpHeaders.ALLOW))
          .as("405 carries no Allow").isNull();
    }
    switch (cell.body()) {
      case APPLICATION_ERROR -> assertThat(
          result.getResponseHeaders().getFirst(ReactiveErrorRenderer.RENDERER_HEADER))
          .as("rendered by the application's own exception handler")
          .isEqualTo(ReactiveErrorRenderer.RENDERER);
      case CHALLENGE -> {
        assertThat(result.getResponseHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE)).isNotNull();
        assertThat(result.getResponseBody()).isNull();
      }
      case ALLOW -> {
        assertThat(result.getResponseHeaders().getFirst(HttpHeaders.ALLOW)).isNotNull();
        assertThat(result.getResponseBody()).isNull();
      }
      case ANY -> {
        // The status is the assertion.
      }
    }
  }

  private EntityExchangeResult<byte[]> exchange(String method, String path, Caller caller) {
    WebTestClient.RequestBodySpec request =
        webTestClient.method(HttpMethod.valueOf(method)).uri(path);
    if (caller.token != null) {
      request.header(HttpHeaders.AUTHORIZATION, "Bearer " + caller.token);
    }
    return request.exchange().expectBody().returnResult();
  }
}
