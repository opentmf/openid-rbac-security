package org.opentmf.security.config;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.server.MethodNotAllowedException;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/**
 * The reactive twin of {@link ServletHttpStatusMatrixFilter}; see that class for the matrix.
 *
 * <p>Rendering needs no plumbing here: the {@code 404} and {@code 405} are raised as the very
 * exceptions the {@code DispatcherHandler} and WebFlux raise natively ({@code
 * ResponseStatusException}, {@code MethodNotAllowedException} without supported methods, so
 * that no {@code Allow} is derived from it), and an error signal from inside the security chain
 * reaches the application's {@code WebExceptionHandler}s exactly as one from the dispatcher
 * would — a consumer's {@code ErrorWebExceptionHandler} renders these the way it renders
 * everything else, and Boot's default one does when there is no other.
 *
 * @author Gokhan Demir
 */
@RequiredArgsConstructor
public class ReactiveHttpStatusMatrixFilter implements WebFilter {

  /** The exchange attribute a proceeding request carries its route under; see the servlet twin. */
  public static final String ROUTE_ATTRIBUTE = ServletHttpStatusMatrixFilter.ROUTE_ATTRIBUTE;

  private final ReactiveSupportedMethodsResolver resolver;

  @Override
  public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
    ServerHttpRequest request = exchange.getRequest();
    return resolver.resolve(exchange).flatMap(route -> {
      if (route.isEmpty()) {
        return chain.filter(exchange);
      }
      MatrixAnswer answer = EndpointRules.answerFor(request.getMethod(), route.get());
      return switch (answer.kind()) {
        case NOT_FOUND -> Mono.error(new ResponseStatusException(HttpStatus.NOT_FOUND));
        case METHOD_NOT_ALLOWED ->
            Mono.error(new MethodNotAllowedException(request.getMethod(), null));
        case PROCEED, OPTIONS -> {
          exchange.getAttributes().put(ROUTE_ATTRIBUTE, route.get());
          yield chain.filter(exchange);
        }
      };
    });
  }
}
