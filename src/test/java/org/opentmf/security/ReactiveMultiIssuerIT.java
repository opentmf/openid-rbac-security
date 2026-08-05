package org.opentmf.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
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
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

/**
 * Reactive twin of {@link ServletMultiIssuerIT} — same two issuers, same claim-shape
 * normalization, same rejection semantics, expressed on the WebFlux stack. Parity here is a
 * requirement of the library, not a convenience.
 *
 * @author Gokhan Demir
 */
@SpringBootTest(
    webEnvironment = WebEnvironment.RANDOM_PORT,
    properties = {
        "spring.main.web-application-type=reactive",
        "spring.main.allow-bean-definition-overriding=true",
        "management.server.port=0",
        "management.endpoints.web.exposure.include=health,info,metrics"
    })
@TestInstance(Lifecycle.PER_CLASS)
class ReactiveMultiIssuerIT {

  static final TestIssuer ALPHA =
      TestIssuer.create("reactive-alpha", "https://alpha.reactive.test/v2.0");
  static final TestIssuer BETA =
      TestIssuer.create("reactive-beta", "https://beta.reactive.test/realms/dnms");
  static final String BETA_AUDIENCE = "dnms-catalog";

  @LocalServerPort int serverPort;
  @LocalManagementPort int managementPort;
  @Autowired JwtService jwtService;

  WebTestClient mainClient;
  WebTestClient managementClient;

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
  void initClients() {
    mainClient = WebTestClient.bindToServer()
        .baseUrl("http://localhost:" + serverPort)
        .build();
    managementClient = WebTestClient.bindToServer()
        .baseUrl("http://localhost:" + managementPort)
        .build();
  }

  @Test
  void alphaToken_withWriteRole_isAccepted() {
    String token = ALPHA.mint(claims -> claims
        .claim("roles", List.of("write"))
        .claim("oid", "alpha-user-id"));

    postCar(token, "ReactiveAlphaCar").expectStatus().isCreated();
  }

  @Test
  void betaToken_withItsOwnClaimShape_isAcceptedOnTheSameEndpoint() {
    String token = BETA.mint(claims -> claims
        .claim("groups", List.of("write"))
        .audience(BETA_AUDIENCE));

    postCar(token, "ReactiveBetaCar").expectStatus().isCreated();
  }

  @Test
  void eitherIssuer_withoutTheRequiredRole_isForbidden() {
    String alpha = ALPHA.mint(claims -> claims.claim("roles", List.of("read")));
    String beta = BETA.mint(claims -> claims
        .claim("groups", List.of("read"))
        .audience(BETA_AUDIENCE));

    postCar(alpha, "ReactiveDeniedCar").expectStatus().isForbidden();
    postCar(beta, "ReactiveDeniedCar").expectStatus().isForbidden();
  }

  @Test
  void unknownIssuer_isRejectedWithoutFallingBackToATrustedOne() {
    String token = ALPHA.mintWithIssuer("https://attacker.reactive.test/v2.0",
        claims -> claims.claim("roles", List.of("write")));

    getCar(token).expectStatus().isUnauthorized();
  }

  @Test
  void missingIssuerClaim_isRejected() {
    String token = ALPHA.mintWithIssuer(null, claims -> claims.claim("roles", List.of("write")));

    getCar(token).expectStatus().isUnauthorized();
  }

  @Test
  void expiredToken_isRejectedPerIssuer() {
    String token = ALPHA.mint(claims -> claims
        .claim("roles", List.of("write"))
        .expirationTime(Date.from(Instant.now().minusSeconds(60))));

    getCar(token).expectStatus().isUnauthorized();
  }

  @Test
  void wrongAudience_isRejectedForTheIssuerThatPinsIt() {
    String token = BETA.mint(claims -> claims
        .claim("groups", List.of("read"))
        .audience("some-other-application"));

    getCar(token).expectStatus().isUnauthorized();
  }

  @Test
  void audienceIsNotCheckedForTheIssuerThatDoesNotPinIt() {
    String token = ALPHA.mint(claims -> claims
        .claim("roles", List.of("read"))
        .audience("anything-at-all"));

    // 404 is the controller answering for an unknown model, so the request cleared security.
    getCar(token).expectStatus().isNotFound();
  }

  @Test
  void managementPort_acceptsTokensFromBothIssuers() {
    String alpha = ALPHA.mint(claims -> claims.claim("roles", List.of("read")));
    String beta = BETA.mint(claims -> claims
        .claim("groups", List.of("read"))
        .audience(BETA_AUDIENCE));

    managementClient.get().uri("/actuator/metrics")
        .headers(headers -> headers.setBearerAuth(alpha))
        .exchange().expectStatus().isOk();
    managementClient.get().uri("/actuator/metrics")
        .headers(headers -> headers.setBearerAuth(beta))
        .exchange().expectStatus().isOk();
  }

  @Test
  void managementPort_rejectsAnUnknownIssuer() {
    String token = ALPHA.mintWithIssuer("https://attacker.reactive.test/v2.0",
        claims -> claims.claim("roles", List.of("read")));

    managementClient.get().uri("/actuator/metrics")
        .headers(headers -> headers.setBearerAuth(token))
        .exchange().expectStatus().isUnauthorized();
  }

  @Test
  void jwtService_decodesTokensFromEveryTrustedIssuer() {
    String alpha = ALPHA.mint(claims -> claims.claim("roles", List.of("write")));
    String beta = BETA.mint(claims -> claims
        .claim("groups", List.of("write"))
        .audience(BETA_AUDIENCE));

    assertThat(jwtService.decodeJwt(alpha).getClaimAsStringList("roles")).containsExactly("write");
    assertThat(jwtService.decodeJwt(beta).getClaimAsStringList("groups")).containsExactly("write");
  }

  private WebTestClient.ResponseSpec postCar(String token, String model) {
    String body = """
        {"model":"%s","color":"Green","builtYear":2023}""".formatted(model);
    return mainClient.post().uri("/car")
        .headers(headers -> headers.setBearerAuth(token))
        .contentType(MediaType.APPLICATION_JSON)
        .bodyValue(body)
        .exchange();
  }

  private WebTestClient.ResponseSpec getCar(String token) {
    return mainClient.get().uri("/car/never-created")
        .headers(headers -> headers.setBearerAuth(token))
        .exchange();
  }
}
