package org.opentmf.security;

import static org.assertj.core.api.Assertions.assertThat;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import java.net.URI;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.opentmf.security.service.TokenService;
import org.springframework.beans.factory.annotation.Autowired;
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
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

/**
 * Keycloak-backed integration test for the management-port {@link
 * org.springframework.security.web.SecurityFilterChain}. Each test class uses its own
 * {@link KeycloakContainer} bound to a Testcontainers-allocated random host port so
 * developer machines running other compose stacks (which often grab fixed ports such as
 * 8092/8094/8194) don't collide with the build.
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
@ActiveProfiles("servlet")
@TestInstance(Lifecycle.PER_CLASS)
class ManagementServletIT {

  private static final KeycloakContainer KEYCLOAK = new KeycloakContainer()
      .withRealmImportFile("realm/rehearsal.json");

  static {
    KEYCLOAK.start();
  }

  @DynamicPropertySource
  static void registerKeycloakProperties(DynamicPropertyRegistry registry) {
    registry.add("opentmf.security.jwk-set-uri", () ->
        KEYCLOAK.getAuthServerUrl() + "/realms/rehearsal-realm/protocol/openid-connect/certs");
  }

  @LocalServerPort int serverPort;
  @LocalManagementPort int managementPort;
  @Autowired TokenService servletTokenService;

  RestTemplate restTemplate;

  @BeforeAll
  void initRestTemplate() {
    restTemplate = new RestTemplate();
    restTemplate.setErrorHandler(NEVER_ERROR);
  }

  private static final ResponseErrorHandler NEVER_ERROR = response -> false;

  @Test
  void healthReachableWithoutJwt() {
    assertThat(get(management("/health")).getStatusCode()).isEqualTo(HttpStatus.OK);
  }

  @Test
  void infoReachableWithoutJwt() {
    assertThat(get(management("/info")).getStatusCode()).isEqualTo(HttpStatus.OK);
  }

  @Test
  void metricsRejectedWithoutJwt() {
    assertThat(get(management("/metrics")).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
  }

  @Test
  void metricsAcceptedWithAuthenticatedJwt() {
    String token = readerToken();
    assertThat(getWithToken(management("/metrics"), token).getStatusCode())
        .isEqualTo(HttpStatus.OK);
  }

  @Test
  void envRejectedForReaderRole() {
    String token = readerToken();
    assertThat(getWithToken(management("/env"), token).getStatusCode())
        .isEqualTo(HttpStatus.FORBIDDEN);
  }

  @Test
  void envAcceptedForWriterRoleAndValuesUnredacted() {
    String token = writerToken();
    ResponseEntity<String> response = getWithToken(management("/env"), token);

    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    // With write role in Keycloak groups, env endpoint's when_authorized check passes and
    // the redaction marker "******" does not appear in the body. Value-level assertion keeps
    // the test resilient to property-set drift.
    assertThat(response.getBody()).doesNotContain("\"value\":\"******\"");
  }

  @Test
  void mainPortStillRejectsAnonymousProtectedRequests() {
    assertThat(get(main("/protectedButNotConfigured")).getStatusCode())
        .isEqualTo(HttpStatus.UNAUTHORIZED);
  }

  @Test
  void mainPortAcceptsValidJwt() {
    String token = writerToken();
    assertThat(getWithToken(main("/car"), token).getStatusCode()).isEqualTo(HttpStatus.OK);
  }

  private String readerToken() {
    return servletTokenService.getToken(tokenUri(), "read");
  }

  private String writerToken() {
    return servletTokenService.getToken(tokenUri(), "write");
  }

  private static URI tokenUri() {
    return URI.create(
        KEYCLOAK.getAuthServerUrl() + "/realms/rehearsal-realm/protocol/openid-connect/token");
  }

  private String management(String path) {
    return "http://localhost:" + managementPort + "/actuator" + path;
  }

  private String main(String path) {
    return "http://localhost:" + serverPort + "/opentmf/commons" + path;
  }

  private ResponseEntity<String> get(String url) {
    return restTemplate.getForEntity(url, String.class);
  }

  private ResponseEntity<String> getWithToken(String url, String token) {
    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(token);
    return restTemplate.exchange(url, HttpMethod.GET, new HttpEntity<>(headers), String.class);
  }
}
