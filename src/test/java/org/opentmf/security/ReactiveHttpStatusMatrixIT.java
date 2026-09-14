package org.opentmf.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Arrays;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.opentmf.security.HttpStatusMatrixCells.Caller;
import org.opentmf.security.HttpStatusMatrixCells.Cell;
import org.opentmf.security.api.reactive.ReactiveErrorRenderer;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.reactive.server.EntityExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;

/**
 * The HTTP-status matrix on the reactive stack, through a real Netty server. The reactive twin
 * of {@link ServletHttpStatusMatrixIT}; see that class for what each cell stands for and which
 * 3.0.0 tests it replaces ({@code ReactiveMethodSemanticsIT}, {@code ReactiveUnmatchedMethodDenyIT}
 * — the latter's pin on Boot dropping the {@code Allow} of a native {@code 405} is moot now
 * that no {@code 405} carries one). The body origin is the application's own
 * {@code WebExceptionHandler}, which marks what it renders.
 *
 * @author Gokhan Demir
 */
@SpringBootTest(
    webEnvironment = WebEnvironment.RANDOM_PORT,
    properties = {
        "opentmf.security.whitelist[0]=/whitelist/**",
        "opentmf.security.blacklist[0]=/protectedButNotConfigured"
    })
@ActiveProfiles({"reactive", "local"})
@TestInstance(Lifecycle.PER_CLASS)
class ReactiveHttpStatusMatrixIT {

  @LocalServerPort int serverPort;
  WebTestClient webTestClient;

  @BeforeAll
  void beforeAll() {
    webTestClient = WebTestClient.bindToServer().baseUrl("http://localhost:" + serverPort).build();
  }

  static Stream<Cell> cells() {
    return HttpStatusMatrixCells.mainPort();
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
      case APPLICATION_ERROR -> {
        assertThat(result.getResponseHeaders().getFirst(ReactiveErrorRenderer.RENDERER_HEADER))
            .as("rendered by the application, not by Boot's default error page")
            .isEqualTo(ReactiveErrorRenderer.RENDERER);
        assertThat(result.getResponseHeaders().getContentType())
            .isEqualTo(MediaType.APPLICATION_PROBLEM_JSON);
        assertThat(new String(result.getResponseBody())).contains("\"status\":" + cell.status());
      }
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

  @Test
  void optionsAllow_isSpringsOwnSetForTheMapping() {
    EntityExchangeResult<byte[]> result = exchange("OPTIONS", "/car", Caller.WRITER);

    assertThat(result.getStatus().value()).isEqualTo(200);
    assertThat(Arrays.stream(result.getResponseHeaders().getFirst(HttpHeaders.ALLOW).split(","))
        .map(String::trim))
        .containsExactlyInAnyOrderElementsOf(HttpStatusMatrixCells.OPTIONS_ALLOW_ON_CAR);
  }

  @Test
  void trace_isNotServed() {
    EntityExchangeResult<byte[]> result = exchange("TRACE", "/car", Caller.WRITER);

    assertThat(result.getStatus().is2xxSuccessful()).isFalse();
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
