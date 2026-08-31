package org.opentmf.security.config;

import java.util.Optional;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * The reactive twin of {@link MethodNotAllowedAccessDeniedHandler}; see that class for the
 * rationale. The decision itself lives in {@link EndpointRules#allowedFor}, shared by both
 * stacks so they cannot answer the same request differently.
 *
 * @author Gokhan Demir
 */
@RequiredArgsConstructor
public class MethodNotAllowedServerAccessDeniedHandler implements ServerAccessDeniedHandler {

  private final ServerAccessDeniedHandler delegate;
  private final ReactiveSupportedMethodsResolver resolver;

  @Override
  public Mono<Void> handle(ServerWebExchange exchange, AccessDeniedException exception) {
    Optional<Set<HttpMethod>> allowed = resolveAllowed(exchange);
    if (allowed.isEmpty()) {
      return delegate.handle(exchange, exception);
    }
    return Mono.fromRunnable(() -> {
      var response = exchange.getResponse();
      response.getHeaders().set(HttpHeaders.ALLOW, EndpointRules.allowHeader(allowed.get()));
      response.setStatusCode(
          HttpMethod.OPTIONS.equals(exchange.getRequest().getMethod())
              ? HttpStatus.OK
              : HttpStatus.METHOD_NOT_ALLOWED);
      response.getHeaders().setContentLength(0);
    });
  }

  private Optional<Set<HttpMethod>> resolveAllowed(ServerWebExchange exchange) {
    if (ReactiveBlacklistDenial.denied(exchange)) {
      // An explicitly closed path answers uniformly and discloses nothing about itself.
      return Optional.empty();
    }
    return EndpointRules.allowedFor(
        exchange.getRequest().getMethod(), resolver.resolve(exchange));
  }
}
