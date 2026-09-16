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
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.client.RestTemplate;

/**
 * An application whose advice is package-scoped and does not handle
 * {@code ErrorResponseException} at all — a connector shape measured on 3.2.1 — so the typed
 * {@code 503} falls to Spring's default resolver, which copies the exception's headers itself
 * and {@code sendError}s. Through a real Tomcat the wire must carry {@code Retry-After} exactly
 * once (3.2.1 shipped it twice), with Boot's error page rendering the body.
 *
 * <p>{@code /error} is whitelisted here, as a service relying on Boot's error page must, so the
 * container's error dispatch is not itself denied by the access rules.
 *
 * @author Gokhan Demir
 */
@SpringBootTest(
    webEnvironment = WebEnvironment.RANDOM_PORT,
    properties = {
        "spring.main.web-application-type=servlet",
        "server.servlet.context-path=/opentmf/commons",
        "opentmf.security.authorities-claim=groups",
        "opentmf.security.whitelist[0]=/error",
        "opentmf.security.jwks.refresh-interval=45s",
        "opentmf.security.jwks.connect-timeout=1s",
        "opentmf.security.jwks.read-timeout=1s"
    })
@Import(ServletJwksOutageUnhandledAdviceIT.PackageScopedAdviceConfig.class)
class ServletJwksOutageUnhandledAdviceIT {

  static final TestIssuer ISSUER = TestIssuer.create("unhandled", "https://unhandled.test/realm");
  static final JwksServer JWKS = JwksServer.start(ISSUER.jwkSetJson());

  static {
    JWKS.fail(503);
  }

  /**
   * Shadows the test application's global advice with one scoped to a package that owns no
   * handler here, so nothing of the application's handles the exception.
   */
  @TestConfiguration(proxyBeanMethods = false)
  static class PackageScopedAdviceConfig {

    @Bean
    PackageScopedAdvice packageScopedAdvice() {
      return new PackageScopedAdvice();
    }
  }

  @RestControllerAdvice(basePackages = "org.opentmf.security.nowhere")
  @Order(Ordered.HIGHEST_PRECEDENCE)
  static class PackageScopedAdvice {

    @ExceptionHandler(Exception.class)
    ResponseEntity<String> never(Exception ex) {
      return ResponseEntity.internalServerError().body("must not be reached");
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
  void theTyped503_carriesRetryAfterExactlyOnce_whenNoAdviceHandlesIt() {
    RestTemplate restTemplate = new RestTemplate(new JdkClientHttpRequestFactory());
    restTemplate.setErrorHandler(response -> false);
    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(ISSUER.mint(claims -> claims.claim("groups", List.of("write"))));

    ResponseEntity<String> response = restTemplate.exchange(
        URI.create("http://localhost:" + serverPort + "/opentmf/commons/car/Mercedes"),
        HttpMethod.GET, new HttpEntity<>(headers), String.class);

    assertThat(response.getStatusCode().value()).isEqualTo(503);
    assertThat(response.getHeaders().get(HttpHeaders.RETRY_AFTER)).containsExactly("45");
    assertThat(response.getBody()).doesNotContain("must not be reached");
  }
}
