package org.opentmf.security.config;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.PathContainer;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.pattern.PathPattern;
import reactor.core.publisher.Mono;

/**
 * The reactive twin of {@link MethodNotAllowedAccessDeniedHandler}; see that class for the
 * rationale.
 *
 * @author Gokhan Demir
 */
@RequiredArgsConstructor
public class MethodNotAllowedServerAccessDeniedHandler implements ServerAccessDeniedHandler {

  private final ServerAccessDeniedHandler delegate;
  private final ReactiveSupportedMethodsResolver resolver;
  private final List<PathPattern> blacklist;

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
    if (isBlacklisted(exchange)) {
      // An explicitly closed path answers uniformly and discloses nothing about itself.
      return Optional.empty();
    }
    SupportedMethods supported = resolver.resolve(exchange);
    if (!supported.pathServed()) {
      return Optional.empty();
    }
    Set<HttpMethod> declared = supported.declared();
    HttpMethod method = exchange.getRequest().getMethod();
    if (HttpMethod.OPTIONS.equals(method)) {
      return declared.contains(HttpMethod.OPTIONS)
          ? Optional.empty()
          : Optional.of(EndpointRules.optionsAllow(declared));
    }
    if (supported.acceptsAnyMethod() || serves(declared, method)) {
      return Optional.empty();
    }
    return Optional.of(declared);
  }

  private boolean isBlacklisted(ServerWebExchange exchange) {
    PathContainer path = exchange.getRequest().getPath().pathWithinApplication();
    return blacklist.stream().anyMatch(pattern -> pattern.matches(path));
  }

  /**
   * Mirrors Spring's own method matching, where a {@code HEAD} request is served by the
   * handler mapped to {@code GET}.
   */
  private static boolean serves(Set<HttpMethod> declared, HttpMethod method) {
    return declared.contains(method)
        || (HttpMethod.HEAD.equals(method) && declared.contains(HttpMethod.GET));
  }
}
