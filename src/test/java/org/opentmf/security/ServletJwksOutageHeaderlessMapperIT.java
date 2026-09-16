package org.opentmf.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.util.List;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.opentmf.security.util.JwksServer;
import org.opentmf.security.util.TestIssuer;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.ErrorResponseException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.client.RestTemplate;

/**
 * The exception mapper every DNMS service inherited from the template rebuilds an
 * {@code ErrorResponseException} as {@code ResponseEntity.status(body.getStatus()).body(body)} —
 * without the exception's headers. The typed {@code 503} must still reach the wire with
 * {@code Retry-After}, through a real Tomcat and that mapper.
 *
 * @author Gokhan Demir
 */
@SpringBootTest(
    webEnvironment = WebEnvironment.RANDOM_PORT,
    properties = {
        "spring.main.web-application-type=servlet",
        "server.servlet.context-path=/opentmf/commons",
        "opentmf.security.authorities-claim=groups",
        "opentmf.security.jwks.refresh-interval=45s",
        "opentmf.security.jwks.connect-timeout=1s",
        "opentmf.security.jwks.read-timeout=1s"
    })
@Import(ServletJwksOutageHeaderlessMapperIT.HeaderlessMapperConfig.class)
class ServletJwksOutageHeaderlessMapperIT {

  static final TestIssuer ISSUER = TestIssuer.create("headerless", "https://headerless.test/realm");
  static final JwksServer JWKS = JwksServer.start(ISSUER.jwkSetJson());

  static {
    JWKS.fail(503);
  }

  /** The template donor's shape: status and body from the problem detail, nothing else. */
  @TestConfiguration(proxyBeanMethods = false)
  static class HeaderlessMapperConfig {

    @Bean
    HeaderlessMapper headerlessMapper() {
      return new HeaderlessMapper();
    }
  }

  @RestControllerAdvice
  @Order(Ordered.HIGHEST_PRECEDENCE)
  static class HeaderlessMapper {

    @ExceptionHandler(ErrorResponseException.class)
    ResponseEntity<ProblemDetail> handleErrorResponse(ErrorResponseException ex) {
      ProblemDetail body = ex.getBody();
      return ResponseEntity.status(body.getStatus()).body(body);
    }
  }

  @DynamicPropertySource
  static void trustTheServer(DynamicPropertyRegistry registry) {
    registry.add("opentmf.security.jwk-set-uri", JWKS::url);
  }

  @LocalServerPort int serverPort;

  @AfterAll
  static void afterAll() {
    JWKS.close();
  }

  @Test
  void theTyped503_keepsRetryAfter_throughAMapperThatRebuildsTheResponseWithoutHeaders() {
    RestTemplate restTemplate = new RestTemplate(new JdkClientHttpRequestFactory());
    restTemplate.setErrorHandler(response -> false);
    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(ISSUER.mint(claims -> claims.claim("groups", List.of("write"))));

    ResponseEntity<String> response = restTemplate.exchange(
        URI.create("http://localhost:" + serverPort + "/opentmf/commons/car/Mercedes"),
        HttpMethod.GET, new HttpEntity<>(headers), String.class);

    assertThat(response.getStatusCode().value()).isEqualTo(503);
    assertThat(response.getHeaders().get(HttpHeaders.RETRY_AFTER)).containsExactly("45");
    assertThat(response.getBody()).contains("\"status\":503").contains("'single-issuer'");
  }
}
