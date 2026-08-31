package org.opentmf.security.config;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

/**
 * Both blacklist rules must deny with a decision the denied-request handlers can recognise by
 * type, on whatever exception route each stack delivers it.
 *
 * @author Gokhan Demir
 */
class BlacklistDenialTest {

  @Test
  void servletRule_deniesWithTheBlacklistDecision() {
    AuthorizationResult result = new ServletBlacklistDenial().authorize(
        () -> null, new RequestAuthorizationContext(new MockHttpServletRequest("PUT", "/closed")));

    assertThat(result.isGranted()).isFalse();
    assertThat(result).isInstanceOf(BlacklistDecision.class);
  }

  /**
   * The reactive rule raises the carrying exception itself, because
   * {@code ReactiveAuthorizationManager#verify} would collapse a returned decision into a bare
   * {@code AccessDeniedException} and the handler could no longer tell the denial apart.
   */
  @Test
  void reactiveRule_raisesTheExceptionCarryingTheBlacklistDecision() {
    var exchange = MockServerWebExchange.from(MockServerHttpRequest.put("/closed"));

    StepVerifier
        .create(new ReactiveBlacklistDenial().authorize(
            Mono.empty(), new AuthorizationContext(exchange)))
        .expectErrorSatisfies(error -> {
          assertThat(error).isInstanceOf(AuthorizationDeniedException.class);
          assertThat(BlacklistDecision.causeOf((AuthorizationDeniedException) error)).isTrue();
        })
        .verify();
  }

  @Test
  void causeOf_recognisesOnlyTheBlacklistDecision() {
    assertThat(BlacklistDecision.causeOf(new AccessDeniedException("denied"))).isFalse();
    assertThat(BlacklistDecision.causeOf(
        new AuthorizationDeniedException("Access Denied", BlacklistDecision.INSTANCE))).isTrue();
  }
}
