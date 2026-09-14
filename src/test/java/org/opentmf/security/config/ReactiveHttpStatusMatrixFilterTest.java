package org.opentmf.security.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.MethodNotAllowedException;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

/**
 * The reactive matrix filter with the resolver mocked: the {@code 404} and {@code 405} are the
 * error signals the application's {@code WebExceptionHandler}s render, the {@code 405} names no
 * methods, and everything else proceeds.
 *
 * @author Gokhan Demir
 */
class ReactiveHttpStatusMatrixFilterTest {

  private final ReactiveSupportedMethodsResolver resolver =
      mock(ReactiveSupportedMethodsResolver.class);
  private final ReactiveHttpStatusMatrixFilter filter =
      new ReactiveHttpStatusMatrixFilter(resolver);
  private final AtomicBoolean proceeded = new AtomicBoolean();
  private final WebFilterChain chain = exchange -> Mono.fromRunnable(() -> proceeded.set(true));

  @Test
  void aPathNoHandlerServes_isNotFound_asTheDispatcherWouldRaiseIt() {
    given(SupportedMethods.notServed());

    StepVerifier.create(filter.filter(exchange("GET", "/nothing"), chain))
        .expectErrorSatisfies(ex -> assertThat(ex)
            .isInstanceOf(ResponseStatusException.class)
            .extracting(e -> ((ResponseStatusException) e).getStatusCode().value())
            .isEqualTo(404))
        .verify();
    assertThat(proceeded).isFalse();
  }

  @Test
  void aMethodThePathDoesNotImplement_isMethodNotAllowed_namingNoMethods() {
    given(new SupportedMethods(Set.of(HttpMethod.GET), false));

    StepVerifier.create(filter.filter(exchange("BREW", "/car"), chain))
        .expectErrorSatisfies(ex -> {
          assertThat(ex).isInstanceOf(MethodNotAllowedException.class);
          MethodNotAllowedException notAllowed = (MethodNotAllowedException) ex;
          assertThat(notAllowed.getHttpMethod()).isEqualTo("BREW");
          assertThat(notAllowed.getSupportedMethods()).isEmpty();
          assertThat(notAllowed.getHeaders().isEmpty()).as("no Allow to derive").isTrue();
        })
        .verify();
    assertThat(proceeded).isFalse();
  }

  @Test
  void anImplementedMethod_proceeds_carryingTheRoute() {
    var served = new SupportedMethods(Set.of(HttpMethod.GET), false);
    given(served);
    ServerWebExchange exchange = exchange("GET", "/car");

    StepVerifier.create(filter.filter(exchange, chain)).verifyComplete();

    assertThat(proceeded).isTrue();
    assertThat(exchange.<Object>getAttribute(ReactiveHttpStatusMatrixFilter.ROUTE_ATTRIBUTE))
        .isSameAs(served);
  }

  @Test
  void plainOptions_proceeds() {
    given(new SupportedMethods(Set.of(HttpMethod.GET), false));

    StepVerifier.create(filter.filter(exchange("OPTIONS", "/car"), chain)).verifyComplete();

    assertThat(proceeded).isTrue();
  }

  @Test
  void whenTheMappingsCannotBeConsulted_theRequestProceeds_toTheAccessRules() {
    when(resolver.resolve(any())).thenReturn(Mono.just(Optional.empty()));

    StepVerifier.create(filter.filter(exchange("GET", "/nothing"), chain)).verifyComplete();

    assertThat(proceeded).isTrue();
  }

  private void given(SupportedMethods supported) {
    when(resolver.resolve(any())).thenReturn(Mono.just(Optional.of(supported)));
  }

  private static ServerWebExchange exchange(String method, String path) {
    return MockServerWebExchange.from(
        MockServerHttpRequest.method(HttpMethod.valueOf(method), path));
  }
}
