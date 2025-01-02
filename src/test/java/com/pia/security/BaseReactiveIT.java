package com.pia.security;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

import com.pia.security.service.TokenService;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.http.MediaType;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.test.web.reactive.server.WebTestClient.ResponseSpec;
import org.springframework.util.CollectionUtils;

abstract class BaseReactiveIT extends BaseIT {

  @Autowired SecurityWebFilterChain reactiveSecurityFilterChain;
  @Autowired TokenService reactiveTokenService;
  @Autowired ApplicationContext applicationContext;

  WebTestClient webTestClient;

  @BeforeAll
  void beforeAll() {
    webTestClient = WebTestClient
        .bindToApplicationContext(applicationContext)
        .apply(springSecurity())
        .configureClient()
        .build();
  }

  @Order(10)
  @Test
  void contextLoads() {
    assertNotNull(reactiveSecurityFilterChain);
    assertNotNull(reactiveTokenService);
    assertNotNull(piaSecurityProperties);
    assertNotNull(jwtService);
  }

  @Order(20)
  @Test
  void testPost_withValidToken_returnsCreated() {
    var token = getToken("write");
    postCar(token).expectStatus().isCreated();
  }

  @Order(30)
  @Test
  void testPost_withoutNecessaryAuthorities_returnsForbidden() {
    String token = getToken("read");
    postCar(token).expectStatus().isForbidden();
  }

  @Order(40)
  @Test
  void testPost_withoutToken_returnsUnauthorized() {
    postCar().expectStatus().isUnauthorized();
  }

  @Order(50)
  @Test
  void testGetCars_withoutToken_returnsOk() {
    get("/car").expectStatus().isOk();
  }

  @Order(60)
  @Test
  void testGetWhitelist_withoutToken_returnsValidResult() {
    if (CollectionUtils.isEmpty(piaSecurityProperties.getWhitelist())) {
      get("/whitelist").expectStatus().isUnauthorized();
    } else {
      get("/whitelist").expectStatus().isOk();
    }
  }

  @Order(70)
  @Test
  void testGetBlacklist_withoutToken_returnsUnauthorized() {
    get("/blacklist").expectStatus().isUnauthorized();
  }

  @Order(80)
  @Test
  void testGetBlacklist_withReadToken_returnsForbidden() {
    var token = getToken("read");
    get("/blacklist", token).expectStatus().isForbidden();
  }

  @Order(90)
  @ParameterizedTest
  @ValueSource(strings = {"read", "write"})
  void testPutCarAndThenGet_withBothTokens_returnsOk(String tokenType) {
    String writeToken = getToken("write");
    putCar(writeToken).expectStatus().isOk();
    String token = getToken(tokenType);
    get("/car/Mercedes", token).expectStatus().isOk();
    get("/car/nonexistent", token).expectStatus().isNotFound();
  }

  @Order(100)
  @Test
  void testProtectedResource_withoutToken_returnsUnauthorized() {
    get("/car/model").expectStatus().isUnauthorized();
  }

  @Order(110)
  @Test
  void testProtectedButNotConfigured_withoutToken_returnsUnauthorized() {
    get("/protectedButNotConfigured").expectStatus().isUnauthorized();
  }

  @Order(120)
  @Test
  void testProtectedButNotConfigured_withToken_returnsForbidden() {
    String token = getToken("write");
    get("/protectedButNotConfigured", token).expectStatus().isForbidden();
  }

  @Order(130)
  @Test
  void testDeleteCar_withoutToken_returnsUnauthorized() {
    deleteCar().expectStatus().isUnauthorized();
  }

  @Order(140)
  @Test
  void testDeleteCar_withInsufficientToken_returnsForbidden() {
    String token = getToken("read");
    deleteCar(token).expectStatus().isForbidden();
  }

  @Order(150)
  @Test
  void testDeleteCar_withToken_returnsNoContent() {
    String token = getToken("write");
    deleteCar(token).expectStatus().isNoContent();
  }

  @Order(160)
  @Test
  void testDeleteCar_withToken_returnsNotFound() {
    String token = getToken("write");
    deleteCar(token).expectStatus().isNotFound();
  }

  @Order(170)
  @Test
  void testJwtService_withValidToken_returnsValidResults() {
    var token = getToken("write");
    var jwt = jwtService.decodeJwt(token);
    var groups = jwt.getClaim("groups");
    Assertions.assertNotNull(groups);
    Assertions.assertFalse(jwtService.isExpiredToken(jwt));
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

  private ResponseSpec deleteCar() {
    return webTestClient.delete()
        .uri("/car/Mercedes")
        .exchange();
  }

  private ResponseSpec deleteCar(String accessToken) {
    return webTestClient.delete()
        .uri("/car/Mercedes")
        .headers(httpHeaders -> httpHeaders.setBearerAuth(accessToken))
        .exchange();
  }
}
