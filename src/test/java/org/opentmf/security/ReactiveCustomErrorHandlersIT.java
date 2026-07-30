package org.opentmf.security;

import static org.opentmf.security.util.TokenUtil.EXPIRED_TOKEN;
import static org.opentmf.security.util.TokenUtil.READ_TOKEN;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.server.LocalManagementPort;
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
 * Proves the reactive 401/403 customization hook end-to-end on a real server: a consumer-supplied
 * {@link ServerAuthenticationEntryPoint} / {@link ServerAccessDeniedHandler} pair renders every
 * main-port security failure (both the bearer-token path and the
 * {@code ExceptionTranslationWebFilter} path), while the management port keeps the RFC 6750
 * defaults. Uses the file-based JWK set so the test does not require Docker / Keycloak.
 *
 * @author Gokhan Demir
 */
@SpringBootTest(
    webEnvironment = WebEnvironment.RANDOM_PORT,
    properties = {
        "spring.main.allow-bean-definition-overriding=true",
        "management.server.port=0",
        "management.endpoints.web.exposure.include=health,info,metrics"
    })
@ActiveProfiles({"reactive", "local"})
@TestInstance(Lifecycle.PER_CLASS)
class ReactiveCustomErrorHandlersIT {

  static final String CUSTOM_401_BODY = "{\"status\":\"401\",\"message\":\"custom-unauthorized\"}";
  static final String CUSTOM_403_BODY = "{\"status\":\"403\",\"message\":\"custom-forbidden\"}";

  @LocalServerPort int serverPort;
  @LocalManagementPort int managementPort;

  WebTestClient mainClient;
  WebTestClient managementClient;

  @TestConfiguration(proxyBeanMethods = false)
  static class CustomHandlerConfig {

    @Bean
    ServerAuthenticationEntryPoint customEntryPoint() {
      return (exchange, exception) ->
          writeJson(exchange, HttpStatus.UNAUTHORIZED, CUSTOM_401_BODY);
    }

    @Bean
    ServerAccessDeniedHandler customAccessDeniedHandler() {
      return (exchange, exception) ->
          writeJson(exchange, HttpStatus.FORBIDDEN, CUSTOM_403_BODY);
    }

    private static Mono<Void> writeJson(ServerWebExchange exchange, HttpStatus status,
        String body) {
      var response = exchange.getResponse();
      response.setStatusCode(status);
      response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
      var buffer = response.bufferFactory().wrap(body.getBytes(StandardCharsets.UTF_8));
      return response.writeWith(Mono.just(buffer));
    }
  }

  @BeforeAll
  void initClients() {
    mainClient = WebTestClient.bindToServer()
        .baseUrl("http://localhost:" + serverPort)
        .build();
    managementClient = WebTestClient.bindToServer()
        .baseUrl("http://localhost:" + managementPort)
        .build();
  }

  @Test
  void noToken_onProtectedEndpoint_rendersCustom401Body() {
    mainClient.get().uri("/car/model")
        .exchange()
        .expectStatus().isUnauthorized()
        .expectHeader().contentType(MediaType.APPLICATION_JSON)
        .expectBody(String.class).isEqualTo(CUSTOM_401_BODY);
  }

  @Test
  void invalidToken_rendersCustom401Body() {
    mainClient.get().uri("/car/model")
        .headers(headers -> headers.setBearerAuth(EXPIRED_TOKEN))
        .exchange()
        .expectStatus().isUnauthorized()
        .expectBody(String.class).isEqualTo(CUSTOM_401_BODY);
  }

  @Test
  void insufficientRole_rendersCustom403Body() {
    mainClient.post().uri("/car")
        .headers(headers -> headers.setBearerAuth(READ_TOKEN))
        .contentType(MediaType.APPLICATION_JSON)
        .bodyValue(BaseIT.MERCEDES)
        .exchange()
        .expectStatus().isForbidden()
        .expectBody(String.class).isEqualTo(CUSTOM_403_BODY);
  }

  @Test
  void noToken_onDenyAllEndpoint_rendersCustom401Body() {
    mainClient.get().uri("/protectedButNotConfigured")
        .exchange()
        .expectStatus().isUnauthorized()
        .expectBody(String.class).isEqualTo(CUSTOM_401_BODY);
  }

  @Test
  void managementPort_keepsDefaultEmptyBody401WithChallenge() {
    managementClient.get().uri("/actuator/metrics")
        .exchange()
        .expectStatus().isUnauthorized()
        .expectHeader().exists("WWW-Authenticate")
        .expectBody().isEmpty();
  }
}
