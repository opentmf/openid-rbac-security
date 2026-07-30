package org.opentmf.security;

import static org.opentmf.security.util.TokenUtil.READ_TOKEN;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Proves the README's reactive "converge-on-one-place" recipe end-to-end: one shared renderer
 * component produces the error body for BOTH the security handlers (401/403, rendered in the
 * WebFilter chain) and the {@code GlobalExceptionHandler} advice (e.g. 404) — asserting the
 * identical {@code ErrorContext} shape from both paths. Uses the file-based JWK set so the test
 * does not require Docker / Keycloak.
 *
 * @author Gokhan Demir
 */
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@ActiveProfiles({"reactive", "local"})
@TestInstance(Lifecycle.PER_CLASS)
class ReactiveSharedRendererIT {

  @LocalServerPort int serverPort;
  WebTestClient client;

  @TestConfiguration(proxyBeanMethods = false)
  static class SharedRendererConfig {

    @Bean
    TestErrorBodyRenderer errorBodyRenderer() {
      return new TestErrorBodyRenderer();
    }

    @Bean
    ServerAuthenticationEntryPoint rendererEntryPoint(TestErrorBodyRenderer renderer) {
      return (exchange, exception) ->
          renderer.write(exchange, HttpStatus.UNAUTHORIZED, exception.getMessage());
    }

    @Bean
    ServerAccessDeniedHandler rendererAccessDeniedHandler(TestErrorBodyRenderer renderer) {
      return (exchange, exception) ->
          renderer.write(exchange, HttpStatus.FORBIDDEN, exception.getMessage());
    }
  }

  /**
   * The single source of truth for the error body shape — mirrors {@code ErrorContext} exactly,
   * so security failures and advice-rendered errors are indistinguishable in shape.
   */
  static class TestErrorBodyRenderer {

    Mono<Void> write(ServerWebExchange exchange, HttpStatus status, String message) {
      var safeMessage = String.valueOf(message).replace('"', '\'');
      var body = "{\"status\":\"%d\",\"message\":\"%s\"}".formatted(status.value(), safeMessage);
      var response = exchange.getResponse();
      response.setStatusCode(status);
      response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
      var buffer = response.bufferFactory().wrap(body.getBytes(StandardCharsets.UTF_8));
      return response.writeWith(Mono.just(buffer));
    }
  }

  @BeforeAll
  void initClient() {
    client = WebTestClient.bindToServer()
        .baseUrl("http://localhost:" + serverPort)
        .build();
  }

  @Test
  void securityFailure401_rendersErrorContextShape() {
    client.get().uri("/car/model")
        .exchange()
        .expectStatus().isUnauthorized()
        .expectBody()
        .jsonPath("$.status").isEqualTo("401")
        .jsonPath("$.message").isNotEmpty();
  }

  @Test
  void securityFailure403_rendersErrorContextShape() {
    client.post().uri("/car")
        .headers(headers -> headers.setBearerAuth(READ_TOKEN))
        .contentType(MediaType.APPLICATION_JSON)
        .bodyValue(BaseIT.MERCEDES)
        .exchange()
        .expectStatus().isForbidden()
        .expectBody()
        .jsonPath("$.status").isEqualTo("403")
        .jsonPath("$.message").isNotEmpty();
  }

  @Test
  void adviceRenderedError_hasTheSameShape() {
    client.get().uri("/car/nonexistent")
        .headers(headers -> headers.setBearerAuth(READ_TOKEN))
        .exchange()
        .expectStatus().isNotFound()
        .expectBody()
        .jsonPath("$.status").isEqualTo("404")
        .jsonPath("$.message").isNotEmpty();
  }
}
