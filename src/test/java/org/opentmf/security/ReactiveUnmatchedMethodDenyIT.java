package org.opentmf.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.opentmf.security.util.TokenUtil.WRITE_TOKEN;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.reactive.server.EntityExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;

/**
 * The reactive twin of {@link ServletUnmatchedMethodDenyIT}: the {@code DENY} opt-out, plus the
 * cross-check that what this library answers on a denied request is what WebFlux itself answers
 * when the same request is allowed through. See that class for why the pairing matters.
 *
 * <p><strong>One deliberate divergence, on this stack only.</strong> WebFlux raises
 * {@code MethodNotAllowedException}, whose {@code getHeaders()} does carry {@code Allow} — but
 * Spring Boot's {@code DefaultErrorWebExceptionHandler.renderErrorResponse} builds the response
 * from the status and an error body alone and never copies those headers, so a natively rendered
 * {@code 405} arrives without {@code Allow}. RFC 9110 requires a {@code 405} to carry it, so this
 * library emits it rather than reproducing the omission. The status still matches, and
 * {@link ReactiveMethodSemanticsIT#unimplementedMethodOnPathWithNoRuleOfItsOwn_returnsMethodNotAllowed()}
 * asserts the header this library adds for the same request.
 *
 * @author Gokhan Demir
 */
@SpringBootTest(properties = {
    "opentmf.security.whitelist[0]=/protectedButNotConfigured",
    "opentmf.security.unmatched-method-response=DENY"
})
@ActiveProfiles({"reactive", "local"})
@TestInstance(Lifecycle.PER_CLASS)
class ReactiveUnmatchedMethodDenyIT {

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

  @Test
  void webFluxOwnMethodNotAllowed_hasTheSameStatusButLosesTheAllowHeader() {
    EntityExchangeResult<byte[]> result =
        exchange(HttpMethod.PUT, "/protectedButNotConfigured", null);

    assertThat(result.getStatus().value()).isEqualTo(405);
    // Boot's reactive error rendering drops the exception's headers; see the class javadoc.
    // Pinned so that a Boot release which starts propagating them is noticed here first.
    assertThat(result.getResponseHeaders().getFirst(HttpHeaders.ALLOW)).isNull();
  }

  @Test
  void unimplementedMethod_answersForbiddenAgain() {
    EntityExchangeResult<byte[]> result = exchange(HttpMethod.PUT, "/car/Mercedes", WRITE_TOKEN);

    assertThat(result.getStatus().value()).isEqualTo(403);
    assertThat(result.getResponseHeaders().getFirst(HttpHeaders.ALLOW)).isNull();
  }

  @Test
  void plainOptions_answersForbiddenAgain() {
    EntityExchangeResult<byte[]> result = exchange(HttpMethod.OPTIONS, "/car", WRITE_TOKEN);

    assertThat(result.getStatus().value()).isEqualTo(403);
    assertThat(result.getResponseHeaders().getFirst(HttpHeaders.ALLOW)).isNull();
  }

  /** The HEAD fix is not gated by the property, so it applies here too. */
  @Test
  void headOnPathAllowedForGet_isStillServed() {
    EntityExchangeResult<byte[]> result = exchange(HttpMethod.HEAD, "/car", null);

    assertThat(result.getStatus().value()).isEqualTo(200);
  }

  private EntityExchangeResult<byte[]> exchange(HttpMethod method, String path, String token) {
    WebTestClient.RequestBodySpec request = webTestClient.method(method).uri(path);
    if (token != null) {
      request.header(HttpHeaders.AUTHORIZATION, "Bearer " + token);
    }
    return request.exchange().expectBody().returnResult();
  }

}
