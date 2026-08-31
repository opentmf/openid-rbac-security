package org.opentmf.security.config;

import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import reactor.core.publisher.Mono;

/**
 * Denies a blacklisted path with a {@link BlacklistDecision}; see that class for why the
 * deciding rule marks the denial rather than the handler re-matching the configured paths.
 *
 * <p>Hand-written where the servlet side simply uses Spring's
 * {@code SingleResultAuthorizationManager}: unlike the servlet {@code AuthorizationFilter},
 * the reactive {@code ReactiveAuthorizationManager#verify} collapses a denying decision into a
 * bare {@code AccessDeniedException}, losing the decision on the way. So this manager raises
 * the carrying exception itself instead of returning the decision.
 *
 * @author Gokhan Demir
 */
public final class ReactiveBlacklistDenial
    implements ReactiveAuthorizationManager<AuthorizationContext> {

  @Override
  public Mono<AuthorizationResult> authorize(
      Mono<Authentication> authentication, AuthorizationContext context) {
    return Mono.error(
        () -> new AuthorizationDeniedException("Access Denied", BlacklistDecision.INSTANCE));
  }
}
