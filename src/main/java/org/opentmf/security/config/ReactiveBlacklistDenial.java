package org.opentmf.security.config;

import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * The reactive twin of {@code ServletBlacklistDenial}; see that class for why the deciding rule
 * records the denial rather than the handler re-matching the configured paths.
 *
 * @author Gokhan Demir
 */
public final class ReactiveBlacklistDenial implements ReactiveAuthorizationManager<AuthorizationContext> {

  public static final String ATTRIBUTE = ReactiveBlacklistDenial.class.getName();

  public static final ReactiveBlacklistDenial INSTANCE = new ReactiveBlacklistDenial();

  private ReactiveBlacklistDenial() {
    // Stateless; one instance is enough.
  }

  @Override
  public Mono<AuthorizationResult> authorize(
      Mono<Authentication> authentication, AuthorizationContext context) {
    context.getExchange().getAttributes().put(ATTRIBUTE, Boolean.TRUE);
    return Mono.just(new AuthorizationDecision(false));
  }

  /**
   * Whether the blacklist is what denied this exchange.
   *
   * @param exchange the exchange being answered, never {@code null}
   * @return {@code true} when a blacklist rule made the decision
   */
  public static boolean denied(ServerWebExchange exchange) {
    return Boolean.TRUE.equals(exchange.getAttributes().get(ATTRIBUTE));
  }
}
