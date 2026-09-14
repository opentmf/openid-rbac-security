package org.opentmf.security.config;

import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * The reactive twin of {@link OptionsAccessDeniedHandler}; see that class for the rationale.
 *
 * @author Gokhan Demir
 */
@RequiredArgsConstructor
public class OptionsServerAccessDeniedHandler implements ServerAccessDeniedHandler {

  private final ServerAccessDeniedHandler delegate;
  private final ReactiveSupportedMethodsResolver resolver;

  @Override
  public Mono<Void> handle(ServerWebExchange exchange, AccessDeniedException exception) {
    return answerFor(exchange).flatMap(answer -> {
      if (answer.kind() != MatrixAnswer.Kind.OPTIONS) {
        return delegate.handle(exchange, exception);
      }
      var response = exchange.getResponse();
      if (response.isCommitted()) {
        // A committed response is read-only: writing the headers would throw and turn the
        // denial into an error signal. The servlet container quietly ignores such late
        // writes, and leaving the response alone is this stack's equivalent.
        return Mono.empty();
      }
      response.getHeaders()
          .set(HttpHeaders.ALLOW, EndpointRules.optionsAllowHeader(answer.allow()));
      response.setStatusCode(HttpStatus.OK);
      response.getHeaders().setContentLength(0);
      return response.setComplete();
    });
  }

  private Mono<MatrixAnswer> answerFor(ServerWebExchange exchange) {
    if (!HttpMethod.OPTIONS.equals(exchange.getRequest().getMethod())) {
      return Mono.just(MatrixAnswer.proceed());
    }
    Mono<Optional<SupportedMethods>> route =
        exchange.getAttribute(ReactiveHttpStatusMatrixFilter.ROUTE_ATTRIBUTE)
            instanceof SupportedMethods resolved
            ? Mono.just(Optional.of(resolved))
            : resolver.resolve(exchange);
    return route.map(supported -> supported
        .map(methods -> EndpointRules.answerFor(HttpMethod.OPTIONS, methods))
        .orElseGet(MatrixAnswer::proceed));
  }
}
