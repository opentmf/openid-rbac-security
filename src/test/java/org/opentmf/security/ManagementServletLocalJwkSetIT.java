package org.opentmf.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.opentmf.security.util.TokenUtil.READ_TOKEN;
import static org.opentmf.security.util.TokenUtil.WRITE_TOKEN;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalManagementPort;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

/**
 * Integration test for the management-port {@link
 * org.springframework.security.web.SecurityFilterChain} using the file-based JWK set so
 * the test does not require Docker / Keycloak. Pre-issued JWTs from {@code TokenUtil}
 * supply the authentication.
 *
 * @author Gokhan Demir
 */
@SpringBootTest(
    webEnvironment = WebEnvironment.RANDOM_PORT,
    properties = {
        "server.servlet.context-path=/opentmf/commons",
        "management.server.port=0",
        "management.endpoints.web.exposure.include=health,info,env,metrics",
        "management.endpoint.env.show-values=when_authorized",
        "management.endpoint.env.roles=write",
        "opentmf.security.management.secure-endpoints[0].method=GET",
        "opentmf.security.management.secure-endpoints[0].path=/actuator/env",
        "opentmf.security.management.secure-endpoints[0].roles=write",
        "opentmf.security.management.secure-endpoints[1].method=GET",
        "opentmf.security.management.secure-endpoints[1].path=/actuator/env/**",
        "opentmf.security.management.secure-endpoints[1].roles=write"
    })
@ActiveProfiles({"servlet", "local"})
@TestInstance(Lifecycle.PER_CLASS)
class ManagementServletLocalJwkSetIT {

  @LocalServerPort int serverPort;
  @LocalManagementPort int managementPort;
  RestTemplate restTemplate;

  @BeforeAll
  void initRestTemplate() {
    restTemplate = new RestTemplate();
    restTemplate.setErrorHandler(NEVER_ERROR);
  }

  private static final ResponseErrorHandler NEVER_ERROR = response -> false;

  @Test
  void healthReachableWithoutJwt() {
    ResponseEntity<String> response = restTemplate.getForEntity(management("/health"), String.class);
    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
  }

  @Test
  void infoReachableWithoutJwt() {
    ResponseEntity<String> response = restTemplate.getForEntity(management("/info"), String.class);
    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
  }

  @Test
  void metricsRejectedWithoutJwt() {
    ResponseEntity<String> response = restTemplate.getForEntity(management("/metrics"), String.class);
    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
  }

  @Test
  void metricsAcceptedWithAuthenticatedJwt() {
    ResponseEntity<String> response = exchangeWithToken(management("/metrics"), READ_TOKEN);
    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
  }

  @Test
  void envRejectedForReadOnlyRole() {
    ResponseEntity<String> response = exchangeWithToken(management("/env"), READ_TOKEN);
    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
  }

  @Test
  void envAcceptedForWriteRole() {
    ResponseEntity<String> response = exchangeWithToken(management("/env"), WRITE_TOKEN);
    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
  }

  @Test
  void mainPortStillRejectsAnonymousProtectedRequests() {
    ResponseEntity<String> response =
        restTemplate.getForEntity(main("/protectedButNotConfigured"), String.class);
    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
  }

  @Test
  void mainPortDoesNotExposeActuator() {
    ResponseEntity<String> response = restTemplate.getForEntity(main("/actuator/health"), String.class);
    assertThat(response.getStatusCode())
        .isIn(HttpStatus.NOT_FOUND, HttpStatus.UNAUTHORIZED, HttpStatus.FORBIDDEN);
  }

  private String management(String path) {
    return "http://localhost:" + managementPort + "/actuator" + path;
  }

  private String main(String path) {
    return "http://localhost:" + serverPort + "/opentmf/commons" + path;
  }

  private ResponseEntity<String> exchangeWithToken(String url, String token) {
    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(token);
    return restTemplate.exchange(url, HttpMethod.GET, new HttpEntity<>(headers), String.class);
  }
}
