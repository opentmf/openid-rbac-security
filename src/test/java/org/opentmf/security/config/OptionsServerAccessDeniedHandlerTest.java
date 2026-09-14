package org.opentmf.security.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import reactor.core.publisher.Mono;

/**
 * The reactive twin of {@link OptionsAccessDeniedHandlerTest}.
 *
 * @author Gokhan Demir
 */
class OptionsServerAccessDeniedHandlerTest {

  private final ServerAccessDeniedHandler delegate = mock(ServerAccessDeniedHandler.class);
  private final ReactiveSupportedMethodsResolver resolver =
      mock(ReactiveSupportedMethodsResolver.class);
  private final OptionsServerAccessDeniedHandler handler =
      new OptionsServerAccessDeniedHandler(delegate, resolver);
  private final AccessDeniedException denied = new AccessDeniedException("Access Denied");

  @Test
  void deniedOptionsOnAServedPath_answersOkWithSpringsAllow() {
    when(resolver.resolve(any())).thenReturn(Mono.just(
        Optional.of(new SupportedMethods(Set.of(HttpMethod.GET, HttpMethod.POST), false))));
    var exchange = MockServerWebExchange.from(MockServerHttpRequest.options("/car"));

    handler.handle(exchange, denied).block();

    assertThat(exchange.getResponse().getStatusCode().value()).isEqualTo(200);
    assertThat(exchange.getResponse().getHeaders().getFirst(HttpHeaders.ALLOW))
        .isEqualTo("GET,HEAD,POST,OPTIONS");
    assertThat(exchange.getResponse().getHeaders().getContentLength()).isZero();
    verifyNoInteractions(delegate);
  }

  @Test
  void theRouteTheMatrixFilterLeft_isUsedInsteadOfResolvingAgain() {
    var exchange = MockServerWebExchange.from(MockServerHttpRequest.options("/car"));
    exchange.getAttributes().put(
        ReactiveHttpStatusMatrixFilter.ROUTE_ATTRIBUTE,
        new SupportedMethods(Set.of(HttpMethod.DELETE), false));

    handler.handle(exchange, denied).block();

    assertThat(exchange.getResponse().getHeaders().getFirst(HttpHeaders.ALLOW))
        .isEqualTo("DELETE,OPTIONS");
    verifyNoInteractions(resolver);
  }

  @Test
  void optionsTheApplicationMapsItself_isLeftToTheDelegate() {
    when(resolver.resolve(any())).thenReturn(
        Mono.just(Optional.of(new SupportedMethods(Set.of(HttpMethod.OPTIONS), false))));
    when(delegate.handle(any(), any())).thenReturn(Mono.empty());
    var exchange = MockServerWebExchange.from(MockServerHttpRequest.options("/car"));

    handler.handle(exchange, denied).block();

    verify(delegate).handle(exchange, denied);
    assertThat(exchange.getResponse().getHeaders().getFirst(HttpHeaders.ALLOW)).isNull();
  }

  @Test
  void anyOtherMethod_isLeftToTheDelegate_withoutConsultingTheMappings() {
    when(delegate.handle(any(), any())).thenReturn(Mono.empty());
    var exchange = MockServerWebExchange.from(MockServerHttpRequest.delete("/car/1"));

    handler.handle(exchange, denied).block();

    verify(delegate).handle(exchange, denied);
    verifyNoInteractions(resolver);
  }

  @Test
  void committedResponse_isLeftAlone() {
    when(resolver.resolve(any())).thenReturn(
        Mono.just(Optional.of(new SupportedMethods(Set.of(HttpMethod.GET), false))));
    var exchange = MockServerWebExchange.from(MockServerHttpRequest.options("/car"));
    exchange.getResponse().setComplete().block();

    handler.handle(exchange, denied).block();

    assertThat(exchange.getResponse().getHeaders().getFirst(HttpHeaders.ALLOW)).isNull();
  }
}
