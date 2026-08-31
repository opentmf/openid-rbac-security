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
    Optional<Set<HttpMethod>> allowed = resolveAllowed(exchange, exception);
    if (allowed.isEmpty()) {
      return delegate.handle(exchange, exception);
    }
    boolean options = HttpMethod.OPTIONS.equals(exchange.getRequest().getMethod());
    return Mono.defer(() -> {
      var response = exchange.getResponse();
      if (response.isCommitted()) {
        // A committed response is read-only: writing the headers would throw and turn the
        // denial into an error signal. The servlet container quietly ignores such late
        // writes, and leaving the response alone is this stack's equivalent.
        return Mono.empty();
      }
      if (options) {
        // Spring's own OPTIONS answer goes through setAllow; use it so the rendering matches.
        response.getHeaders().setAllow(allowed.get());
      } else {
        response.getHeaders().set(HttpHeaders.ALLOW, EndpointRules.allowHeader(allowed.get()));
      }
      response.setStatusCode(options ? HttpStatus.OK : HttpStatus.METHOD_NOT_ALLOWED);
      response.getHeaders().setContentLength(0);
      return Mono.empty();
    });
  }

  private Optional<Set<HttpMethod>> resolveAllowed(
      ServerWebExchange exchange, AccessDeniedException exception) {
    if (BlacklistDecision.causeOf(exception)) {
      // An explicitly closed path answers uniformly and discloses nothing about itself.
      return Optional.empty();
    }
    return EndpointRules.allowedFor(
        exchange.getRequest().getMethod(), resolver.resolve(exchange));
  }
}
