package org.opentmf.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.opentmf.security.util.TokenUtil.EXPIRED_TOKEN;
import static org.opentmf.security.util.TokenUtil.READ_TOKEN;
import static org.opentmf.security.util.TokenUtil.WRITE_TOKEN;

import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
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
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

/**
 * Proves the servlet 401/403 customization hook end-to-end on a real server: a consumer-supplied
 * {@link AuthenticationEntryPoint} / {@link AccessDeniedHandler} pair renders every main-port
 * security failure (both the bearer-token path and the {@code ExceptionTranslationFilter} path),
 * while the management port keeps the RFC 6750 defaults. Uses the file-based JWK set so the test
 * does not require Docker / Keycloak.
 *
 * @author Gokhan Demir
 */
@SpringBootTest(
    webEnvironment = WebEnvironment.RANDOM_PORT,
    properties = {
        "server.servlet.context-path=/opentmf/commons",
        "management.server.port=0",
        "management.endpoints.web.exposure.include=health,info,metrics"
    })
@ActiveProfiles({"servlet", "local"})
@TestInstance(Lifecycle.PER_CLASS)
class ServletCustomErrorHandlersIT {

  static final String CUSTOM_401_BODY = "{\"status\":\"401\",\"message\":\"custom-unauthorized\"}";
  static final String CUSTOM_403_BODY = "{\"status\":\"403\",\"message\":\"custom-forbidden\"}";

  private static final ResponseErrorHandler NEVER_ERROR = response -> false;

  @LocalServerPort int serverPort;
  @LocalManagementPort int managementPort;
  RestTemplate restTemplate;

  @TestConfiguration(proxyBeanMethods = false)
  static class CustomHandlerConfig {

    @Bean
    AuthenticationEntryPoint customEntryPoint() {
      return (request, response, exception) ->
          writeJson(response, HttpStatus.UNAUTHORIZED, CUSTOM_401_BODY);
    }

    @Bean
    AccessDeniedHandler customAccessDeniedHandler() {
      return (request, response, exception) ->
          writeJson(response, HttpStatus.FORBIDDEN, CUSTOM_403_BODY);
    }

    private static void writeJson(HttpServletResponse response, HttpStatus status, String body)
        throws IOException {
      response.setStatus(status.value());
      response.setContentType(MediaType.APPLICATION_JSON_VALUE);
      response.getWriter().write(body);
    }
  }

  @BeforeAll
  void initRestTemplate() {
    restTemplate = new RestTemplate();
    restTemplate.setErrorHandler(NEVER_ERROR);
  }

  @Test
  void noToken_onProtectedEndpoint_rendersCustom401Body() {
    ResponseEntity<String> response = restTemplate.getForEntity(main("/car/model"), String.class);
    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    assertThat(response.getBody()).isEqualTo(CUSTOM_401_BODY);
    assertThat(response.getHeaders().getContentType()).isNotNull();
    assertThat(response.getHeaders().getContentType().isCompatibleWith(MediaType.APPLICATION_JSON))
        .isTrue();
  }

  @Test
  void invalidToken_rendersCustom401Body() {
    ResponseEntity<String> response = getWithToken(main("/car/model"), EXPIRED_TOKEN);
    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    assertThat(response.getBody()).isEqualTo(CUSTOM_401_BODY);
  }

  @Test
  void insufficientRole_rendersCustom403Body() {
    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(READ_TOKEN);
    headers.setContentType(MediaType.APPLICATION_JSON);
    ResponseEntity<String> response = restTemplate.exchange(
        main("/car"), HttpMethod.POST, new HttpEntity<>(BaseIT.MERCEDES, headers), String.class);
    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    assertThat(response.getBody()).isEqualTo(CUSTOM_403_BODY);
  }

  @Test
  void noToken_onDenyAllEndpoint_rendersCustom401Body() {
    ResponseEntity<String> response =
        restTemplate.getForEntity(main("/protectedButNotConfigured"), String.class);
    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    assertThat(response.getBody()).isEqualTo(CUSTOM_401_BODY);
  }

  /**
   * The consumer's handler still owns every denial that is genuinely about authorization: the
   * method is implemented, the caller simply lacks the role.
   */
  @Test
  void implementedMethodWithoutTheRole_stillRendersCustom403Body() {
    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(READ_TOKEN);
    ResponseEntity<String> response = restTemplate.exchange(
        main("/car/Mercedes"), HttpMethod.DELETE, new HttpEntity<>(headers), String.class);
    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    assertThat(response.getBody()).isEqualTo(CUSTOM_403_BODY);
  }

  /**
   * A method the application does not implement is not an authorization question, so the library
   * answers it and the consumer's handler is deliberately bypassed. Also the only place the
   * {@code 405} path is exercised on a real server behind a servlet context path, which the
   * request-path parsing has to strip before matching.
   */
  @Test
  void unimplementedMethod_isAnsweredByTheLibraryAndBypassesTheCustomHandler() {
    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(WRITE_TOKEN);
    ResponseEntity<String> response = restTemplate.exchange(
        main("/car/Mercedes"), HttpMethod.PUT, new HttpEntity<>(headers), String.class);
    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.METHOD_NOT_ALLOWED);
    assertThat(response.getHeaders().getFirst(HttpHeaders.ALLOW)).isNotNull();
    assertThat(response.getBody()).isNotEqualTo(CUSTOM_403_BODY);
  }

  @Test
  void managementPort_keepsDefaultEmptyBody401WithChallenge() {
    ResponseEntity<String> response =
        restTemplate.getForEntity(management("/metrics"), String.class);
    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    assertThat(response.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE)).isNotNull();
    assertThat(response.getBody()).isNullOrEmpty();
  }

  private String main(String path) {
    return "http://localhost:" + serverPort + "/opentmf/commons" + path;
  }

  private String management(String path) {
    return "http://localhost:" + managementPort + "/actuator" + path;
  }

  private ResponseEntity<String> getWithToken(String url, String token) {
    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(token);
    return restTemplate.exchange(url, HttpMethod.GET, new HttpEntity<>(headers), String.class);
  }
}
