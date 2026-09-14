package org.opentmf.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
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
import org.opentmf.security.api.GlobalExceptionHandler;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

/**
 * The HTTP-status matrix on the servlet stack, through a real Tomcat — so unknown method
 * names, the firewall, the context path and the container's error dispatch are all in play,
 * as they are behind an ingress. Every cell asserts the status, the origin of the body (the
 * application's {@code @ControllerAdvice} marks what it renders; Spring Boot's default JSON
 * must never appear) and that no {@code 405} carries an {@code Allow} header.
 *
 * <p>Replaces the 3.0.0 {@code ServletMethodSemanticsIT} and {@code ServletUnmatchedMethodDenyIT}:
 * the cells that pinned {@code Allow} on a {@code 405}, {@code 401} for an anonymous
 * unimplemented method, {@code 403} for an unknown path and a uniform {@code 403} for a
 * blacklisted path are rewritten to the matrix; the {@code deny} opt-out is gone with the
 * property, and the differential test against Spring's own {@code 405} lost its premise —
 * the library now answers before Spring on every path, whitelisted ones included.
 *
 * @author Gokhan Demir
 */
@SpringBootTest(
    webEnvironment = WebEnvironment.RANDOM_PORT,
    properties = {
        "server.servlet.context-path=/opentmf/commons",
        "opentmf.security.whitelist[0]=/whitelist/**",
        "opentmf.security.blacklist[0]=/protectedButNotConfigured"
    })
@ActiveProfiles({"servlet", "local"})
@TestInstance(Lifecycle.PER_CLASS)
class ServletHttpStatusMatrixIT {

  private static final ResponseErrorHandler NEVER_ERROR = response -> false;

  @LocalServerPort int serverPort;
  RestTemplate restTemplate;

  @BeforeAll
  void beforeAll() {
    // The JDK's HttpURLConnection rejects PATCH and unknown method names outright.
    restTemplate = new RestTemplate(new JdkClientHttpRequestFactory());
    restTemplate.setErrorHandler(NEVER_ERROR);
  }

  static Stream<Cell> cells() {
    return HttpStatusMatrixCells.mainPort();
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("cells")
  void matrix(Cell cell) {
    ResponseEntity<String> response = exchange(cell.method(), cell.path(), cell.caller());

    assertThat(response.getStatusCode().value()).as("status").isEqualTo(cell.status());
    if (cell.status() == 405) {
      assertThat(response.getHeaders().getFirst(HttpHeaders.ALLOW)).as("405 carries no Allow")
          .isNull();
    }
    switch (cell.body()) {
      case APPLICATION_ERROR -> {
        assertThat(response.getHeaders().getFirst(GlobalExceptionHandler.RENDERER_HEADER))
            .as("rendered by the application, not by Boot's default error page")
            .isEqualTo(GlobalExceptionHandler.RENDERER);
        assertThat(response.getHeaders().getContentType())
            .isEqualTo(MediaType.APPLICATION_PROBLEM_JSON);
        assertThat(response.getBody()).contains("\"status\":" + cell.status());
      }
      case CHALLENGE -> {
        assertThat(response.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE)).isNotNull();
        assertThat(response.getBody()).isNull();
      }
      case ALLOW -> {
        assertThat(response.getHeaders().getFirst(HttpHeaders.ALLOW)).isNotNull();
        assertThat(response.getBody()).isNull();
      }
      case ANY -> {
        // The status is the assertion.
      }
    }
  }

  /** The {@code Allow} of an authenticated plain {@code OPTIONS} is Spring's own set. */
  @Test
  void optionsAllow_isSpringsOwnSetForTheMapping() {
    ResponseEntity<String> response = exchange("OPTIONS", "/car", Caller.WRITER);

    assertThat(response.getStatusCode().value()).isEqualTo(200);
    assertThat(Arrays.stream(response.getHeaders().getFirst(HttpHeaders.ALLOW).split(","))
        .map(String::trim))
        .containsExactlyInAnyOrderElementsOf(HttpStatusMatrixCells.OPTIONS_ALLOW_ON_CAR);
  }

  /**
   * {@code TRACE} is the container's: Tomcat refuses it before any filter runs, and whatever it
   * sends — including an {@code Allow} of its own — is not this library's to change. Pinned
   * only as "not served".
   */
  @Test
  void trace_isRefusedBeforeTheLibraryRuns() {
    ResponseEntity<String> response = exchange("TRACE", "/car", Caller.WRITER);

    assertThat(response.getStatusCode().is2xxSuccessful()).isFalse();
  }

  /** Not in the table because it needs state: the field case, {@code PUT} on a GET/DELETE path. */
  @Test
  void theFieldCase_putOnAGetDeletePath_isMethodNotAllowedWithoutAllowAndWithTheApplicationsBody() {
    ResponseEntity<String> response = exchange("PUT", "/car/Mercedes", Caller.WRITER);

    assertThat(response.getStatusCode().value()).isEqualTo(405);
    assertThat(response.getHeaders().getFirst(HttpHeaders.ALLOW)).isNull();
    assertThat(response.getHeaders().getFirst(GlobalExceptionHandler.RENDERER_HEADER))
        .isEqualTo(GlobalExceptionHandler.RENDERER);
    assertThat(response.getBody()).contains("\"status\":405");
  }

  private ResponseEntity<String> exchange(String method, String path, Caller caller) {
    HttpHeaders headers = new HttpHeaders();
    if (caller.token != null) {
      headers.setBearerAuth(caller.token);
    }
    return restTemplate.exchange(
        URI.create("http://localhost:" + serverPort + "/opentmf/commons" + path),
        HttpMethod.valueOf(method),
        new HttpEntity<>(headers),
        String.class);
  }

  @Test
  void bodyOfADefaultDenial_staysEmptyWithAChallenge() {
    ResponseEntity<String> response = exchange("POST", "/car", Caller.READER);

    assertThat(response.getStatusCode().value()).isEqualTo(403);
    assertThat(response.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE)).isNotNull();
    assertThat(response.getBody()).isNull();
  }

  /** The static resource that exists is served once the rules allow it; here they do not. */
  @Test
  void anExistingStaticResource_isNotMistakenForAnUnknownPath() {
    assertThat(exchange("GET", "/probe.txt", Caller.ANONYMOUS).getStatusCode().value())
        .isEqualTo(401);
    assertThat(exchange("GET", "/missing.txt", Caller.ANONYMOUS).getStatusCode().value())
        .isEqualTo(404);
  }
}
