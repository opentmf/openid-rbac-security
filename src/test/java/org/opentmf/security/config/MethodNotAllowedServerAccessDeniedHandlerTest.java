package org.opentmf.security.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

/**
 * The reactive twin of {@link MethodNotAllowedAccessDeniedHandlerTest}.
 *
 * @author Gokhan Demir
 */
class MethodNotAllowedServerAccessDeniedHandlerTest {

  private static final AccessDeniedException DENIED = new AccessDeniedException("denied");

  private ServerAccessDeniedHandler delegate;
  private ReactiveSupportedMethodsResolver resolver;

  @BeforeEach
  void setUp() {
    delegate = mock(ServerAccessDeniedHandler.class);
    resolver = mock(ReactiveSupportedMethodsResolver.class);
    when(delegate.handle(any(), any())).thenReturn(Mono.empty());
  }

  @Test
  void unimplementedMethodOnServedPath_answersMethodNotAllowed() {
    given(new SupportedMethods(methods(HttpMethod.GET, HttpMethod.DELETE), false));
    ServerWebExchange exchange = exchange(HttpMethod.PUT);

    StepVerifier.create(handler().handle(exchange, DENIED)).verifyComplete();

    assertThat(exchange.getResponse().getStatusCode().value()).isEqualTo(405);
    assertThat(allow(exchange)).containsExactlyInAnyOrder("GET", "DELETE");
    assertThat(exchange.getResponse().getHeaders().getContentLength()).isZero();
    verifyNoInteractions(delegate);
  }

  @Test
  void implementedMethod_isLeftToTheDelegate() {
    given(new SupportedMethods(methods(HttpMethod.GET, HttpMethod.DELETE), false));

    StepVerifier.create(handler().handle(exchange(HttpMethod.DELETE), DENIED))
        .verifyComplete();

    verify(delegate).handle(any(), any());
  }

  @Test
  void headIsTreatedAsGet_soItIsLeftToTheDelegate() {
    given(new SupportedMethods(methods(HttpMethod.GET), false));

    StepVerifier.create(handler().handle(exchange(HttpMethod.HEAD), DENIED))
        .verifyComplete();

    verify(delegate).handle(any(), any());
  }

  @Test
  void pathNoHandlerServes_isLeftToTheDelegate() {
    given(SupportedMethods.notServed());

    StepVerifier.create(handler().handle(exchange(HttpMethod.PUT), DENIED))
        .verifyComplete();

    verify(delegate).handle(any(), any());
  }

  @Test
  void mappingThatNamesNoMethod_isLeftToTheDelegate() {
    given(new SupportedMethods(Set.of(), true));

    StepVerifier.create(handler().handle(exchange(HttpMethod.PUT), DENIED))
        .verifyComplete();

    verify(delegate).handle(any(), any());
  }

  @Test
  void blacklistedPath_isLeftToTheDelegateWithoutConsultingTheMappings() {
    AccessDeniedException blacklistDenied =
        new AuthorizationDeniedException("Access Denied", BlacklistDecision.INSTANCE);

    StepVerifier.create(handler().handle(exchange(HttpMethod.PUT), blacklistDenied))
        .verifyComplete();

    verify(delegate).handle(any(), any());
    verifyNoInteractions(resolver);
  }

  @Test
  void committedResponse_isLeftAlone() {
    given(new SupportedMethods(methods(HttpMethod.GET), false));
    ServerWebExchange exchange = exchange(HttpMethod.PUT);
    exchange.getResponse().setStatusCode(HttpStatus.OK);
    exchange.getResponse().setComplete().block();

    StepVerifier.create(handler().handle(exchange, DENIED)).verifyComplete();

    assertThat(exchange.getResponse().getStatusCode().value()).isEqualTo(200);
    assertThat(exchange.getResponse().getHeaders().getFirst(HttpHeaders.ALLOW)).isNull();
    verifyNoInteractions(delegate);
  }

  @Test
  void options_answersOkWithTheOptionsAllowSet() {
    given(new SupportedMethods(methods(HttpMethod.GET, HttpMethod.POST), false));
    ServerWebExchange exchange = exchange(HttpMethod.OPTIONS);

    StepVerifier.create(handler().handle(exchange, DENIED)).verifyComplete();

    assertThat(exchange.getResponse().getStatusCode().value()).isEqualTo(200);
    assertThat(allow(exchange)).containsExactlyInAnyOrder("GET", "POST", "HEAD", "OPTIONS");
  }

  @Test
  void optionsThatTheApplicationImplementsItself_isLeftToTheDelegate() {
    given(new SupportedMethods(methods(HttpMethod.GET, HttpMethod.OPTIONS), false));

    StepVerifier.create(handler().handle(exchange(HttpMethod.OPTIONS), DENIED))
        .verifyComplete();

    verify(delegate).handle(any(), any());
  }

  private void given(SupportedMethods supported) {
    when(resolver.resolve(any())).thenReturn(supported);
  }

  private MethodNotAllowedServerAccessDeniedHandler handler() {
    return new MethodNotAllowedServerAccessDeniedHandler(delegate, resolver);
  }

  private static ServerWebExchange exchange(HttpMethod method) {
    return MockServerWebExchange.from(MockServerHttpRequest.method(method, "/car/Mercedes"));
  }

  private static Set<HttpMethod> methods(HttpMethod... methods) {
    return new LinkedHashSet<>(Arrays.asList(methods));
  }

  private static Set<String> allow(ServerWebExchange exchange) {
    String header = exchange.getResponse().getHeaders().getFirst(HttpHeaders.ALLOW);
    assertThat(header).isNotNull();
    return Arrays.stream(header.split(",")).map(String::trim).collect(Collectors.toSet());
  }
}
