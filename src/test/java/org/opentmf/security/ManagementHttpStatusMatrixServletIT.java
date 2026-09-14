package org.opentmf.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
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
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.server.LocalManagementPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.core.Ordered;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

/**
 * The HTTP-status matrix on the servlet management port, answered from the <em>management</em>
 * context's handler mappings and rendered through its exception resolvers — which walk up to
 * the main context's, so the application's own error body appears on this port too.
 *
 * <p>On the servlet stack the context question is the one most easily got wrong: the
 * management chain is registered in the main {@code ApplicationContext} (Boot exposes the
 * parent's filter chain on the management port), while the actuator endpoints it guards are
 * mapped in the management child context. Consulting the wrong one would serve, or answer
 * {@code 405} for, the business API's routes on the management port. {@code /car} exists on the
 * main port and nowhere here, so it must answer {@code 404} — never a {@code 405} that only the
 * main port's mappings could justify.
 *
 * <p>Replaces the 3.0.0 {@code ManagementMethodSemanticsServletIT}: its cells pinning
 * {@code Allow} on a {@code 405}, {@code 403} for a path only the main port serves and
 * {@code 401} for an anonymous unimplemented method are rewritten to the matrix. Runs with
 * {@code management.other-endpoints: DENY}, so that the {@code 401}/{@code 403} rows are
 * reachable at all.
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
@Import(ManagementHttpStatusMatrixServletIT.LeakProbeConfig.class)
class ManagementHttpStatusMatrixServletIT {

  private static final ResponseErrorHandler NEVER_ERROR = response -> false;

  /**
   * A second, differently named handler mapping in the MAIN context. Real applications grow
   * these — Spring Integration's {@code integrationRequestMappingHandlerMapping}, or a second
   * mapping for a versioned API. It matters because Boot's management child context shadows the
   * parent's {@code requestMappingHandlerMapping} only by sharing its bean <em>name</em>: a
   * mapping under any other name is invisible to that shadowing, and a lookup that walks into
   * ancestors would pull it into the management port's answer.
   */
  @TestConfiguration(proxyBeanMethods = false)
  static class LeakProbeConfig {

    @Bean
    LeakProbeController leakProbeController() {
      return new LeakProbeController();
    }

    @Bean
    RequestMappingHandlerMapping leakProbeRequestMappingHandlerMapping() {
      RequestMappingHandlerMapping mapping = new RequestMappingHandlerMapping() {
        @Override
        protected boolean isHandler(Class<?> beanType) {
          return LeakProbeController.class.equals(beanType);
        }
      };
      mapping.setOrder(Ordered.LOWEST_PRECEDENCE - 1);
      return mapping;
    }
  }

  /** Deliberately not a {@code @RestController}, so only the probe mapping above picks it up. */
  static class LeakProbeController {

    @GetMapping("/leak-probe")
    String probe() {
      return "probe";
    }
  }

  @LocalManagementPort int managementPort;
  RestTemplate restTemplate;

  @BeforeAll
  void beforeAll() {
    // The JDK's HttpURLConnection rejects PATCH and unknown method names outright.
    restTemplate = new RestTemplate(new JdkClientHttpRequestFactory());
    restTemplate.setErrorHandler(NEVER_ERROR);
  }

  static Stream<Cell> cells() {
    return HttpStatusMatrixCells.managementPort();
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
            .as("rendered by the application's advice, reached through the child's resolvers")
            .isEqualTo(GlobalExceptionHandler.RENDERER);
        assertThat(response.getHeaders().getContentType())
            .isEqualTo(MediaType.APPLICATION_PROBLEM_JSON);
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

  /**
   * The discriminating case: a mapping in the main context under a name the child does not
   * shadow. A lookup that walks into ancestor contexts answers {@code 405} here (the path is
   * "known", {@code PUT} is not implemented on it); a local-only lookup answers {@code 404}.
   */
  @Test
  void aMappingNamedOnlyInTheMainContext_doesNotReachTheManagementPort() {
    ResponseEntity<String> response = exchange("PUT", "/leak-probe", Caller.WRITER);

    assertThat(response.getStatusCode().value()).isEqualTo(404);
    assertThat(response.getHeaders().getFirst(HttpHeaders.ALLOW)).isNull();
  }

  private ResponseEntity<String> exchange(String method, String path, Caller caller) {
    HttpHeaders headers = new HttpHeaders();
    if (caller.token != null) {
      headers.setBearerAuth(caller.token);
    }
    return restTemplate.exchange(
        URI.create("http://localhost:" + managementPort + path),
        HttpMethod.valueOf(method),
        new HttpEntity<>(headers),
        String.class);
  }
}
