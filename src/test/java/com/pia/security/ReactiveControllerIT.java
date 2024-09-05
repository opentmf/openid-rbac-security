package com.pia.security;

import static com.pia.security.util.TokenUtil.DIFFERENT_PROVIDER_TOKEN;
import static com.pia.security.util.TokenUtil.EXPIRED_READER_TOKEN;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

import com.pia.security.jwt.JwtService;
import com.pia.security.model.PiaSecurityProperties;
import com.pia.security.service.TokenService;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import java.net.URI;
import java.util.List;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.test.web.reactive.server.WebTestClient.ResponseSpec;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("reactive")
@Slf4j
@TestInstance(Lifecycle.PER_CLASS)
class ReactiveControllerIT {

  static {
    @SuppressWarnings("resource")
    KeycloakContainer keycloakContainer = new KeycloakContainer().withRealmImportFile(
        "realm/rehearsal-realm.json");
    keycloakContainer.setPortBindings(List.of("8091:8080"));
    keycloakContainer.start();
  }

  @Autowired private SecurityWebFilterChain reactiveSecurityFilterChain;
  @Autowired private TokenService reactiveTokenService;
  @Autowired private PiaSecurityProperties piaSecurityProperties;
  @Autowired private JwtService jwtService;

  @Autowired private ApplicationContext applicationContext;
  private WebTestClient webTestClient;

  @BeforeAll
  void beforeAll() {
    webTestClient = WebTestClient
        .bindToApplicationContext(applicationContext)
        .apply(springSecurity())
        .configureClient()
        .build();
  }

  @Test
  void contextLoads() {
    assertNotNull(reactiveSecurityFilterChain);
    assertNotNull(reactiveTokenService);
    assertNotNull(piaSecurityProperties);
    assertNotNull(jwtService);
  }

  private static final String MERCEDES = """
      {
        "model":"Mercedes",
        "color":"Green",
        "builtYear":2023
      }
      """;

  @Test
  void testPost_withValidToken_returnsCreated() {
    var token = reactiveTokenService.getToken(getTokenUri(), "write");
    postCar(token).expectStatus().isCreated();
  }

  @Test
  void testPost_withoutNecessaryAuthorities_returnsForbidden() {
    String token = reactiveTokenService.getToken(getTokenUri(), "read");
    postCar(token).expectStatus().isForbidden();
  }

  @Test
  void testPost_withoutToken_returnsUnauthorized() {
    postCar().expectStatus().isUnauthorized();
  }

  @Test
  void testGetCars_withoutToken_returnsOk() {
    get("/car").expectStatus().isOk();
  }

  @Test
  void testGetWhitelist_withoutToken_returnsOk() {
    get("/whitelist").expectStatus().isOk();
  }

  @ParameterizedTest
  @ValueSource(strings = {"read", "write"})
  void testPutCarAndThenGet_withBothTokens_returnsOk(String tokenType) {
    String writeToken = reactiveTokenService.getToken(getTokenUri(), "write");
    putCar(writeToken).expectStatus().isOk();
    String token = reactiveTokenService.getToken(getTokenUri(), tokenType);
    get("/car/Mercedes", token).expectStatus().isOk();
    get("/car/nonexistent", token).expectStatus().isNotFound();
  }

  @Test
  void testProtectedResource_withoutToken_returnsUnauthenticated() {
    get("/car/model").expectStatus().isUnauthorized();
  }

  @Test
  void testProtectedButNotConfigured_withoutToken_returnsUnauthorized() {
    get("/protectedButNotConfigured").expectStatus().isUnauthorized();
  }

  @Test
  void testProtectedButNotConfigured_withToken_returnsForbidden() {
    String token = reactiveTokenService.getToken(getTokenUri(), "write");
    get("/protectedButNotConfigured", token).expectStatus().isForbidden();
  }

  @Test
  void testJwtService_withValidToken_returnsValidResults() {
    var token = reactiveTokenService.getToken(getTokenUri(), "write");
    var jwt = jwtService.decodeJwt(token);
    assertNotNull(jwt.getClaim("groups"));
    assertFalse(jwtService.isExpiredToken(jwt));
    assertTrue(jwtService.isExpiredToken(EXPIRED_READER_TOKEN));
    assertThrows(InvalidBearerTokenException.class, () -> jwtService.isExpiredToken("bad token"));
    assertThrows(IllegalArgumentException.class, () -> jwtService.getJwtPrincipal(""));
    assertNotNull(jwtService.getJwtPrincipal(token));
    assertThrows(InvalidBearerTokenException.class, () -> jwtService.decodeJwt("bad token"));
    assertThrows(InvalidBearerTokenException.class, () -> jwtService.decodeJwt(DIFFERENT_PROVIDER_TOKEN));
    assertEquals(1, jwtService.getGrantedAuthorities(token, "groups").size());
    Optional<Object> optionalClaim = jwtService.getJwtClaim(token, "given_name");
    assertTrue(optionalClaim.isPresent());
    assertEquals("Writer", optionalClaim.get());
    assertNotNull(jwtService.getJwtClaims(token, "roles"));
    assertNotNull(jwtService.getJwtClaims(token, "groups"));
    assertNotNull(jwtService.getJwtClaims(token, "sub"));
  }

  private ResponseSpec postCar(String accessToken) {
    return webTestClient.post()
        .uri("/car")
        .headers(httpHeaders -> httpHeaders.setBearerAuth(accessToken))
        .contentType(MediaType.APPLICATION_JSON)
        .bodyValue(MERCEDES)
        .exchange();
  }

  private ResponseSpec postCar() {
    return webTestClient.post()
        .uri("/car")
        .contentType(MediaType.APPLICATION_JSON)
        .bodyValue(MERCEDES)
        .exchange();
  }

  private ResponseSpec putCar(String accessToken) {
    return webTestClient.put()
        .uri("/car")
        .headers(httpHeaders -> httpHeaders.setBearerAuth(accessToken))
        .contentType(MediaType.APPLICATION_JSON)
        .bodyValue(MERCEDES)
        .exchange();
  }

  private ResponseSpec get(String path) {
    return webTestClient.get()
        .uri(path)
        .accept(MediaType.APPLICATION_JSON)
        .exchange();
  }

  private ResponseSpec get(String path, String accessToken) {
    return webTestClient.get()
        .uri(path)
        .headers(httpHeaders -> httpHeaders.setBearerAuth(accessToken))
        .accept(MediaType.APPLICATION_JSON)
        .exchange();
  }

  private URI getTokenUri() {
    String jwkSetUri = piaSecurityProperties.getJwkSetUri();
    return URI.create(jwkSetUri.substring(0, jwkSetUri.lastIndexOf('/') + 1) + "token");
  }
}
