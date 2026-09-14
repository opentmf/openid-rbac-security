package org.opentmf.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.opentmf.security.api.GlobalExceptionHandler;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.client.RestTemplate;

/**
 * The very first request a fresh context ever sees. Boot registers the {@code DispatcherServlet}
 * with {@code load-on-startup = -1}, so the servlet initialises on that first request — after the
 * security chain, and so after the matrix filter, has already run. The matrix must not depend on
 * the servlet: it reads the {@code HandlerMapping} beans, which exist since the context
 * refreshed. A mapped path on the first request is served, not {@code 404}; an unmapped one is
 * {@code 404} with the application's body. A dedicated property makes this context nobody
 * else's, so the request here is genuinely the first.
 *
 * @author Gokhan Demir
 */
@SpringBootTest(
    webEnvironment = WebEnvironment.RANDOM_PORT,
    properties = {
        "server.servlet.context-path=/opentmf/commons",
        "opentmf.security.whitelist[0]=/first-request-probe/**"
    })
@ActiveProfiles({"servlet", "local"})
@TestInstance(Lifecycle.PER_CLASS)
class ServletFirstRequestIT {

  @LocalServerPort int serverPort;

  @Test
  void theVeryFirstRequest_onAMappedPath_isServedNotFourOhFour() {
    RestTemplate restTemplate = new RestTemplate(new JdkClientHttpRequestFactory());
    restTemplate.setErrorHandler(response -> false);

    ResponseEntity<String> first = exchange(restTemplate, "/car");
    assertThat(first.getStatusCode().value()).as("first request, mapped path").isEqualTo(200);

    ResponseEntity<String> unmapped = exchange(restTemplate, "/nothing/here");
    assertThat(unmapped.getStatusCode().value()).as("unmapped path").isEqualTo(404);
    assertThat(unmapped.getHeaders().getFirst(GlobalExceptionHandler.RENDERER_HEADER))
        .isEqualTo(GlobalExceptionHandler.RENDERER);

    ResponseEntity<String> mappedAgain = exchange(restTemplate, "/car/Mercedes");
    assertThat(mappedAgain.getStatusCode().value()).as("mapped path, no token").isEqualTo(401);
  }

  private ResponseEntity<String> exchange(RestTemplate restTemplate, String path) {
    return restTemplate.exchange(
        URI.create("http://localhost:" + serverPort + "/opentmf/commons" + path),
        HttpMethod.GET, new HttpEntity<>(new HttpHeaders()), String.class);
  }
}
