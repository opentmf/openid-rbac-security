package org.opentmf.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

import com.nimbusds.jwt.JWTClaimsSet;
import java.time.Duration;
import java.util.List;
import java.util.function.Consumer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer.OrderAnnotation;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.junit.jupiter.api.TestMethodOrder;
import org.opentmf.security.api.reactive.ReactiveErrorRenderer;
import org.opentmf.security.util.JwksServer;
import org.opentmf.security.util.TestIssuer;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalManagementPort;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.EntityExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;

/**
 * The reactive twin of {@link ServletJwksOutageIT}, through a real Netty server: the same
 * sequence — cold, healed, down again, rotated — with the body rendered by the application's
 * own {@code WebExceptionHandler} and the key lookups off the event loop.
 *
 * @author Gokhan Demir
 */
@SpringBootTest(
    webEnvironment = WebEnvironment.RANDOM_PORT,
    properties = {
        "spring.main.web-application-type=reactive",
        "spring.main.allow-bean-definition-overriding=true",
        "management.server.port=0",
        "management.endpoints.web.exposure.include=health,info",
        "opentmf.security.jwks.cache-ttl=1s",
        "opentmf.security.jwks.refresh-interval=200ms",
        "opentmf.security.jwks.connect-timeout=1s",
        "opentmf.security.jwks.read-timeout=1s"
    })
@TestInstance(Lifecycle.PER_CLASS)
@TestMethodOrder(OrderAnnotation.class)
class ReactiveJwksOutageIT {

  static final TestIssuer ISSUER = TestIssuer.create("r-outage", "https://r-outage.test/realm");
  static final TestIssuer ROTATED =
      TestIssuer.create("r-outage-rotated", "https://r-outage.test/realm");
  static final TestIssuer STRANGER =
      TestIssuer.create("r-outage-stranger", "https://r-outage.test/realm");
  static final JwksServer JWKS = JwksServer.start(ISSUER.jwkSetJson());

  static {
    JWKS.fail(503);
  }

  @DynamicPropertySource
  static void trustTheServer(DynamicPropertyRegistry registry) {
    registry.add("opentmf.security.issuers[0].name", () -> "r-outage-idp");
    registry.add("opentmf.security.issuers[0].issuer", ISSUER::getIssuer);
    registry.add("opentmf.security.issuers[0].jwk-set-uri", JWKS::url);
    registry.add("opentmf.security.issuers[0].authorities-claim", () -> "groups");
  }

  @LocalServerPort int serverPort;
  @LocalManagementPort int managementPort;
  WebTestClient client;

  @BeforeAll
  void beforeAll() {
    client = WebTestClient.bindToServer().baseUrl("http://localhost:" + serverPort).build();
  }

  @AfterAll
  static void afterAll() {
    JWKS.close();
  }

  @Order(10)
  @Test
  void cold_aBearerRequest_isTheTyped503_renderedByTheApplication() {
    EntityExchangeResult<byte[]> response = get("/car/Mercedes", ISSUER.mint(writer()));

    assertThat(response.getStatus().value()).isEqualTo(503);
    assertThat(response.getResponseHeaders().getFirst(HttpHeaders.RETRY_AFTER)).isEqualTo("0");
    assertThat(response.getResponseHeaders().getFirst(ReactiveErrorRenderer.RENDERER_HEADER))
        .isEqualTo(ReactiveErrorRenderer.RENDERER);
    assertThat(response.getResponseHeaders().getContentType())
        .isEqualTo(MediaType.APPLICATION_PROBLEM_JSON);
    assertThat(new String(response.getResponseBody())).contains("\"status\":503");
  }

  @Order(20)
  @Test
  void cold_everythingThatNeedsNoKeys_isUnaffected() {
    assertThat(get("/car/Mercedes", null).getStatus().value()).as("anonymous").isEqualTo(401);
    assertThat(get("/car", null).getStatus().value()).as("allowed").isEqualTo(200);
    assertThat(get("/nothing/here", ISSUER.mint(writer())).getStatus().value())
        .as("matrix row 1").isEqualTo(404);
    assertThat(exchange(HttpMethod.PATCH, "/car", ISSUER.mint(writer())).getStatus().value())
        .as("matrix row 2").isEqualTo(405);
    assertThat(WebTestClient.bindToServer().baseUrl("http://localhost:" + managementPort).build()
        .get().uri("/actuator/health").exchange().expectBody().returnResult().getStatus().value())
        .as("management probe").isEqualTo(200);
  }

  @Order(40)
  @Test
  void onceTheIssuerServes_theNextRequestHeals_withoutARestart() {
    JWKS.serve(ISSUER.jwkSetJson());

    await().atMost(Duration.ofSeconds(5)).untilAsserted(() ->
        assertThat(get("/car/Mercedes", ISSUER.mint(writer())).getStatus().value())
            .isIn(200, 404));
  }

  @Order(50)
  @Test
  void anUnknownKeyId_isABadToken_notAnOutage() {
    EntityExchangeResult<byte[]> response = get("/car/Mercedes", STRANGER.mint(writer()));

    assertThat(response.getStatus().value()).isEqualTo(401);
    assertThat(response.getResponseHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE))
        .contains("invalid_token");
  }

  @Order(60)
  @Test
  void whenTheIssuerGoesDownAgain_theStaleSetKeepsServing() {
    int fetchesBefore = JWKS.fetches();
    JWKS.fail(500);

    await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> {
      assertThat(JWKS.fetches()).isGreaterThan(fetchesBefore);
      assertThat(get("/car/Mercedes", ISSUER.mint(writer())).getStatus().value()).isIn(200, 404);
    });
  }

  @Order(70)
  @Test
  void rotation_isPickedUpOnTheFirstUnknownKeyId() {
    JWKS.serve(ROTATED.jwkSetJson());

    await().atMost(Duration.ofSeconds(5)).untilAsserted(() ->
        assertThat(get("/car/Mercedes", ROTATED.mint(writer())).getStatus().value())
            .isIn(200, 404));
  }

  private EntityExchangeResult<byte[]> get(String path, String token) {
    return exchange(HttpMethod.GET, path, token);
  }

  private EntityExchangeResult<byte[]> exchange(HttpMethod method, String path, String token) {
    WebTestClient.RequestBodySpec request = client.method(method).uri(path);
    if (token != null) {
      request.header(HttpHeaders.AUTHORIZATION, "Bearer " + token);
    }
    return request.exchange().expectBody().returnResult();
  }

  private static Consumer<JWTClaimsSet.Builder> writer() {
    return claims -> claims.claim("groups", List.of("write")).claim("email", "w@test");
  }
}
