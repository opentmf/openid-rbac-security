package org.opentmf.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Date;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.opentmf.security.jwt.JwtService;
import org.opentmf.security.util.TestIssuer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalManagementPort;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

/**
 * Servlet multi-issuer matrix: two issuers with deliberately different token shapes are trusted
 * on the same resource server, and the same endpoint rules govern both. Proves that
 * authorization is provider-blind — each issuer's claim mapping normalizes onto the same
 * internal role vocabulary — and that an unrecognized issuer is never given a fallback.
 *
 * <p>{@code alpha} models an Entra-style registration (roles in {@code roles}, principal in
 * {@code oid}, no audience restriction); {@code beta} models a Keycloak-style realm (roles in
 * {@code groups}, principal in {@code sub}, audience pinned).
 *
 * @author Gokhan Demir
 */
@SpringBootTest(
    webEnvironment = WebEnvironment.RANDOM_PORT,
    properties = {
        "spring.main.web-application-type=servlet",
        "management.server.port=0",
        "management.endpoints.web.exposure.include=health,info,metrics"
    })
@TestInstance(Lifecycle.PER_CLASS)
class ServletMultiIssuerIT {

  static final TestIssuer ALPHA = TestIssuer.create("alpha", "https://alpha.example.test/v2.0");
  static final TestIssuer BETA = TestIssuer.create("beta", "https://beta.example.test/realms/dnms");
  static final String BETA_AUDIENCE = "dnms-catalog";

  private static final ResponseErrorHandler NEVER_ERROR = response -> false;

  @LocalServerPort int serverPort;
  @LocalManagementPort int managementPort;
  @Autowired JwtService jwtService;
  RestTemplate restTemplate;

  @DynamicPropertySource
  static void trustBothIssuers(DynamicPropertyRegistry registry) {
    registry.add("opentmf.security.issuers[0].name", () -> "alpha");
    registry.add("opentmf.security.issuers[0].issuer", ALPHA::getIssuer);
    registry.add("opentmf.security.issuers[0].jwk-set-uri", ALPHA::getJwkSetUri);
    registry.add("opentmf.security.issuers[0].authorities-claim", () -> "roles");
    registry.add("opentmf.security.issuers[0].user-claim", () -> "oid");
    registry.add("opentmf.security.issuers[1].name", () -> "beta");
    registry.add("opentmf.security.issuers[1].issuer", BETA::getIssuer);
    registry.add("opentmf.security.issuers[1].jwk-set-uri", BETA::getJwkSetUri);
    registry.add("opentmf.security.issuers[1].authorities-claim", () -> "groups");
    registry.add("opentmf.security.issuers[1].audiences[0]", () -> BETA_AUDIENCE);
  }

  @BeforeAll
  void initRestTemplate() {
    restTemplate = new RestTemplate();
    restTemplate.setErrorHandler(NEVER_ERROR);
  }

  @Test
  void alphaToken_withWriteRole_isAccepted() {
    String token = ALPHA.mint(claims -> claims
        .claim("roles", List.of("write"))
        .claim("oid", "alpha-user-id"));

    assertThat(postCar(token, "AlphaCar").getStatusCode()).isEqualTo(HttpStatus.CREATED);
  }

  @Test
  void betaToken_withItsOwnClaimShape_isAcceptedOnTheSameEndpoint() {
    String token = BETA.mint(claims -> claims
        .claim("groups", List.of("write"))
        .audience(BETA_AUDIENCE));

    assertThat(postCar(token, "BetaCar").getStatusCode()).isEqualTo(HttpStatus.CREATED);
  }

  @Test
  void eitherIssuer_withoutTheRequiredRole_isForbidden() {
    String alpha = ALPHA.mint(claims -> claims.claim("roles", List.of("read")));
    String beta = BETA.mint(claims -> claims
        .claim("groups", List.of("read"))
        .audience(BETA_AUDIENCE));

    assertThat(postCar(alpha, "DeniedCar").getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    assertThat(postCar(beta, "DeniedCar").getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
  }

  @Test
  void unknownIssuer_isRejectedWithoutFallingBackToATrustedOne() {
    String token = ALPHA.mintWithIssuer("https://attacker.example.test/v2.0",
        claims -> claims.claim("roles", List.of("write")));

    assertThat(getCar(token).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
  }

  @Test
  void missingIssuerClaim_isRejected() {
    String token = ALPHA.mintWithIssuer(null, claims -> claims.claim("roles", List.of("write")));

    assertThat(getCar(token).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
  }

  @Test
  void expiredToken_isRejectedPerIssuer() {
    String token = ALPHA.mint(claims -> claims
        .claim("roles", List.of("write"))
        .expirationTime(Date.from(TestIssuer.now().minusSeconds(60))));

    assertThat(getCar(token).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
  }

  @Test
  void wrongAudience_isRejectedForTheIssuerThatPinsIt() {
    String token = BETA.mint(claims -> claims
        .claim("groups", List.of("read"))
        .audience("some-other-application"));

    assertThat(getCar(token).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
  }

  @Test
  void audienceIsNotCheckedForTheIssuerThatDoesNotPinIt() {
    String token = ALPHA.mint(claims -> claims
        .claim("roles", List.of("read"))
        .audience("anything-at-all"));

    // 404 is the controller answering for an unknown model, so the request cleared security.
    assertThat(getCar(token).getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
  }

  @Test
  void managementPort_acceptsTokensFromBothIssuers() {
    String alpha = ALPHA.mint(claims -> claims.claim("roles", List.of("read")));
    String beta = BETA.mint(claims -> claims
        .claim("groups", List.of("read"))
        .audience(BETA_AUDIENCE));

    assertThat(getWithToken(management("/metrics"), alpha).getStatusCode())
        .isEqualTo(HttpStatus.OK);
    assertThat(getWithToken(management("/metrics"), beta).getStatusCode())
        .isEqualTo(HttpStatus.OK);
  }

  @Test
  void managementPort_rejectsAnUnknownIssuer() {
    String token = ALPHA.mintWithIssuer("https://attacker.example.test/v2.0",
        claims -> claims.claim("roles", List.of("read")));

    assertThat(getWithToken(management("/metrics"), token).getStatusCode())
        .isEqualTo(HttpStatus.UNAUTHORIZED);
  }

  @Test
  void jwtService_decodesTokensFromEveryTrustedIssuer() {
    String alpha = ALPHA.mint(claims -> claims.claim("roles", List.of("write")));
    String beta = BETA.mint(claims -> claims
        .claim("groups", List.of("write"))
        .audience(BETA_AUDIENCE));

    assertThat(jwtService.decodeJwt(alpha).getClaimAsStringList("roles")).containsExactly("write");
    assertThat(jwtService.decodeJwt(beta).getClaimAsStringList("groups")).containsExactly("write");
    assertThat(jwtService.getGrantedAuthorities(alpha, "roles")).hasSize(1);
  }

  /** Each test posts its own model so creation stays independent of execution order. */
  private ResponseEntity<String> postCar(String token, String model) {
    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(token);
    headers.setContentType(MediaType.APPLICATION_JSON);
    String body = """
        {"model":"%s","color":"Green","builtYear":2023}""".formatted(model);
    return restTemplate.exchange(main("/car"), HttpMethod.POST,
        new HttpEntity<>(body, headers), String.class);
  }

  /** Reads a model that is never created, so the outcome depends only on security. */
  private ResponseEntity<String> getCar(String token) {
    return getWithToken(main("/car/never-created"), token);
  }

  private ResponseEntity<String> getWithToken(String url, String token) {
    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(token);
    return restTemplate.exchange(url, HttpMethod.GET, new HttpEntity<>(headers), String.class);
  }

  private String main(String path) {
    return "http://localhost:" + serverPort + "/opentmf/commons" + path;
  }

  private String management(String path) {
    return "http://localhost:" + managementPort + "/actuator" + path;
  }
}
