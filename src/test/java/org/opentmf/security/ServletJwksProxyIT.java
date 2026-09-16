package org.opentmf.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.util.List;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.opentmf.security.util.ForwardProxy;
import org.opentmf.security.util.JwksServer;
import org.opentmf.security.util.TestIssuer;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.client.RestTemplate;

/**
 * The single-issuer {@code opentmf.security.jwks.proxy} property carries the JWKS fetch through
 * the configured proxy, end to end: the proxy sees the fetch as an absolute-URI request, and the
 * token it enables validates.
 *
 * @author Gokhan Demir
 */
@SpringBootTest(
    webEnvironment = WebEnvironment.RANDOM_PORT,
    properties = {
        "spring.main.web-application-type=servlet",
        "server.servlet.context-path=/opentmf/commons",
        "opentmf.security.authorities-claim=groups"
    })
class ServletJwksProxyIT {

  static final TestIssuer ISSUER = TestIssuer.create("proxied", "https://proxied.test/realm");
  static final JwksServer JWKS = JwksServer.start(ISSUER.jwkSetJson());
  static final ForwardProxy PROXY = ForwardProxy.start();

  @DynamicPropertySource
  static void fetchThroughTheProxy(DynamicPropertyRegistry registry) {
    registry.add("opentmf.security.jwk-set-uri", JWKS::url);
    registry.add("opentmf.security.jwks.proxy", PROXY::hostPort);
  }

  @LocalServerPort int serverPort;

  @AfterAll
  static void afterAll() {
    JWKS.close();
    PROXY.close();
  }

  @Test
  void theFetch_goesThroughTheConfiguredProxy_andTheTokenValidates() {
    RestTemplate restTemplate = new RestTemplate(new JdkClientHttpRequestFactory());
    restTemplate.setErrorHandler(response -> false);
    HttpHeaders headers = new HttpHeaders();
    headers.setBearerAuth(ISSUER.mint(claims -> claims.claim("groups", List.of("write"))));

    ResponseEntity<String> response = restTemplate.exchange(
        URI.create("http://localhost:" + serverPort + "/opentmf/commons/car/Mercedes"),
        HttpMethod.GET, new HttpEntity<>(headers), String.class);

    assertThat(response.getStatusCode().value()).isIn(200, 404);
    assertThat(PROXY.forwarded()).contains("GET " + JWKS.url());
    assertThat(JWKS.requestLines()).isNotEmpty();
  }
}
