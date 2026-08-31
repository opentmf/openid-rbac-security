package org.opentmf.security.config;

import java.util.function.Supplier;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

/**
 * Denies a blacklisted path with a {@link BlacklistDecision}, so the denied-request handler can
 * tell this denial apart from every other; see that class for why.
 *
 * <p>Spring Security's {@code AuthorizationFilter} throws the returned decision to the handler
 * inside {@code AuthorizationDeniedException}, so returning the subtype is all that is needed
 * here.
 *
 * @author Gokhan Demir
 */
public final class ServletBlacklistDenial
    implements AuthorizationManager<RequestAuthorizationContext> {

  @Override
  public AuthorizationResult authorize(
      Supplier<? extends Authentication> authentication, RequestAuthorizationContext context) {
    return BlacklistDecision.INSTANCE;
  }
}
