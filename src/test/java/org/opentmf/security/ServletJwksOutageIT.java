package org.opentmf.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.awaitility.Awaitility.await;

import java.net.URI;
import java.time.Duration;
import com.nimbusds.jwt.JWTClaimsSet;
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
import org.opentmf.security.api.GlobalExceptionHandler;
import org.opentmf.security.jwks.JwkSetUnavailableException;
import org.opentmf.security.jwt.JwtService;
import org.opentmf.security.util.JwksServer;
import org.opentmf.security.util.TestIssuer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalManagementPort;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.client.RestTemplate;

/**
 * An identity provider that is unreachable when the service boots, then comes up, then goes
 * down again — through a real Tomcat, in that order. The JWKS server starts failing, so the
 * application boots cold (WARN policy) and every bearer request answers the typed {@code 503}
 * rendered by the application's advice; the matrix rows, anonymous callers and the whitelist are
 * unaffected; the management port's probes are unaffected; once the server serves, the next
 * refresh heals without a restart; once it fails again, the stale set keeps serving; an unknown
 * key id is a {@code 401}, not an outage; and {@code JwtService} throws the same typed exception
 * an adopter's mapper renders as {@code 503}.
 *
 * @author Gokhan Demir
 */
@SpringBootTest(
    webEnvironment = WebEnvironment.RANDOM_PORT,
    properties = {
        "spring.main.web-application-type=servlet",
        "server.servlet.context-path=/opentmf/commons",
        "management.server.port=0",
        "management.endpoints.web.exposure.include=health,info",
        "opentmf.security.jwks.cache-ttl=1s",
        "opentmf.security.jwks.refresh-interval=200ms",
        "opentmf.security.jwks.connect-timeout=1s",
        "opentmf.security.jwks.read-timeout=1s"
    })
@TestInstance(Lifecycle.PER_CLASS)
@TestMethodOrder(OrderAnnotation.class)
class ServletJwksOutageIT {

  static final TestIssuer ISSUER = TestIssuer.create("outage", "https://outage.test/realm");
  static final TestIssuer ROTATED =
      TestIssuer.create("outage-rotated", "https://outage.test/realm");
  static final TestIssuer STRANGER =
      TestIssuer.create("outage-stranger", "https://outage.test/realm");
  static final JwksServer JWKS = JwksServer.start(ISSUER.jwkSetJson());

  static {
    JWKS.fail(503);
  }

  @DynamicPropertySource
  static void trustTheServer(DynamicPropertyRegistry registry) {
    registry.add("opentmf.security.issuers[0].name", () -> "outage-idp");
    registry.add("opentmf.security.issuers[0].issuer", ISSUER::getIssuer);
    registry.add("opentmf.security.issuers[0].jwk-set-uri", JWKS::url);
    registry.add("opentmf.security.issuers[0].authorities-claim", () -> "groups");
  }

  @LocalServerPort int serverPort;
  @LocalManagementPort int managementPort;
  @Autowired JwtService jwtService;
  RestTemplate restTemplate;

  @BeforeAll
  void beforeAll() {
    restTemplate = new RestTemplate(new JdkClientHttpRequestFactory());
    restTemplate.setErrorHandler(response -> false);
  }

  @AfterAll
  static void afterAll() {
    JWKS.close();
  }

  @Order(10)
  @Test
  void cold_aBearerRequest_isTheTyped503_renderedByTheApplication() {
    ResponseEntity<String> response = get("/car/Mercedes", ISSUER.mint(writer()));

    assertThat(response.getStatusCode().value()).isEqualTo(503);
    assertThat(response.getHeaders().getFirst(HttpHeaders.RETRY_AFTER)).isEqualTo("0");
    assertThat(response.getHeaders().getFirst(GlobalExceptionHandler.RENDERER_HEADER))
        .isEqualTo(GlobalExceptionHandler.RENDERER);
    assertThat(response.getHeaders().getContentType())
        .isEqualTo(MediaType.APPLICATION_PROBLEM_JSON);
    assertThat(response.getBody())
        .contains("\"status\":503")
        .contains(JwkSetUnavailableException.TYPE.toString())
        .contains("'outage-idp'")
        .doesNotContain(JWKS.url());
  }

  @Order(20)
  @Test
  void cold_everythingThatNeedsNoKeys_isUnaffected() {
    assertThat(get("/car/Mercedes", null).getStatusCode().value()).as("anonymous").isEqualTo(401);
    assertThat(get("/car", null).getStatusCode().value()).as("allowed").isEqualTo(200);
    assertThat(get("/nothing/here", ISSUER.mint(writer())).getStatusCode().value())
        .as("matrix row 1 before any key").isEqualTo(404);
    assertThat(exchange(HttpMethod.PATCH, "/car", ISSUER.mint(writer())).getStatusCode().value())
        .as("matrix row 2 before any key").isEqualTo(405);
    assertThat(restTemplate.getForEntity(
        "http://localhost:" + managementPort + "/actuator/health", String.class)
        .getStatusCode().value()).as("management probe").isEqualTo(200);
  }

  @Order(30)
  @Test
  void cold_jwtService_throwsTheTypedException_notAnAuthenticationServiceException() {
    String token = ISSUER.mint(writer());

    assertThatThrownBy(() -> jwtService.decodeJwt(token))
        .isInstanceOf(JwkSetUnavailableException.class);
  }

  @Order(40)
  @Test
  void onceTheIssuerServes_theNextRequestHeals_withoutARestart() {
    JWKS.serve(ISSUER.jwkSetJson());

    await().atMost(Duration.ofSeconds(5)).untilAsserted(() ->
        assertThat(get("/car/Mercedes", ISSUER.mint(writer())).getStatusCode().value())
            .isIn(200, 404));
  }

  @Order(50)
  @Test
  void anUnknownKeyId_isABadToken_notAnOutage() {
    ResponseEntity<String> response = get("/car/Mercedes", STRANGER.mint(writer()));

    assertThat(response.getStatusCode().value()).isEqualTo(401);
    assertThat(response.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE))
        .contains("invalid_token");
  }

  @Order(60)
  @Test
  void whenTheIssuerGoesDownAgain_theStaleSetKeepsServing() {
    int fetchesBefore = JWKS.fetches();
    JWKS.fail(500);

    // A refresh has been attempted and failed since — and the stale set still serves.
    await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> {
      assertThat(JWKS.fetches()).isGreaterThan(fetchesBefore);
      assertThat(get("/car/Mercedes", ISSUER.mint(writer())).getStatusCode().value())
          .isIn(200, 404);
    });
  }

  @Order(70)
  @Test
  void rotation_isPickedUpOnTheFirstUnknownKeyId() {
    JWKS.serve(ROTATED.jwkSetJson());

    await().atMost(Duration.ofSeconds(5)).untilAsserted(() ->
        assertThat(get("/car/Mercedes", ROTATED.mint(writer())).getStatusCode().value())
            .isIn(200, 404));
  }

  private ResponseEntity<String> get(String path, String token) {
    return exchange(HttpMethod.GET, path, token);
  }

  private ResponseEntity<String> exchange(HttpMethod method, String path, String token) {
    HttpHeaders headers = new HttpHeaders();
    if (token != null) {
      headers.setBearerAuth(token);
    }
    return restTemplate.exchange(
        URI.create("http://localhost:" + serverPort + "/opentmf/commons" + path),
        method, new HttpEntity<>(headers), String.class);
  }

  private static Consumer<JWTClaimsSet.Builder> writer() {
    return claims -> claims.claim("groups", List.of("write")).claim("email", "w@test");
  }
}
