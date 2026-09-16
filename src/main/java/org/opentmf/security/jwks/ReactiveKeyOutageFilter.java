package org.opentmf.security.jwks;

import org.springframework.http.HttpHeaders;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/**
 * The reactive twin of {@link ServletKeyOutageFilter}: the typed {@code 503} is not an
 * {@code AuthenticationException}, so the authentication filter lets it through; this filter
 * puts {@code Retry-After} on the response — Boot's error rendering keeps headers already set
 * but does not copy an exception's own — and lets the error signal reach the application's
 * {@code WebExceptionHandler}s, which render it as they render every other
 * {@code ResponseStatusException}.
 *
 * @author Gokhan Demir
 */
public class ReactiveKeyOutageFilter implements WebFilter {

  @Override
  public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
    return chain.filter(exchange).onErrorResume(JwkSetUnavailableException.class, unavailable -> {
      var response = exchange.getResponse();
      if (!response.isCommitted()) {
        response.getHeaders().set(HttpHeaders.RETRY_AFTER,
            unavailable.getHeaders().getFirst(HttpHeaders.RETRY_AFTER));
      }
      return Mono.error(unavailable);
    });
  }
}
