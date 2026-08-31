package org.opentmf.security.config;

import jakarta.servlet.http.HttpServletRequest;
import java.util.function.Supplier;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

/**
 * Denies a blacklisted path and leaves a mark on the request saying so.
 *
 * <p>A denial has to be answered uniformly when the blacklist is what caused it, so that an
 * explicitly closed path discloses nothing about the methods behind it. Recognising that case by
 * matching the configured paths a second time inside the denied-request handler would mean two
 * independently built matchers for one set of rules, which can disagree — the authorization
 * registry resolves its patterns with the parser the application configured, and a second matcher
 * built elsewhere may not. The rule that made the decision records it instead, so the handler
 * reads the decision rather than trying to reconstruct it.
 *
 * @author Gokhan Demir
 */
public final class ServletBlacklistDenial
    implements AuthorizationManager<RequestAuthorizationContext> {

  public static final String ATTRIBUTE = ServletBlacklistDenial.class.getName();

  public static final ServletBlacklistDenial INSTANCE = new ServletBlacklistDenial();

  private ServletBlacklistDenial() {
    // Stateless; one instance is enough.
  }

  @Override
  public AuthorizationResult authorize(
      Supplier<? extends Authentication> authentication, RequestAuthorizationContext context) {
    HttpServletRequest request = context.getRequest();
    request.setAttribute(ATTRIBUTE, request.getRequestURI());
    return new AuthorizationDecision(false);
  }

  /**
   * Whether the blacklist is what denied this request.
   *
   * <p>The mark records the URI it was set for, not just a flag. A servlet request outlives one
   * dispatch — an ERROR dispatch to {@code /error} is re-authorized on the same request object —
   * so a bare flag would still be there, and would label that second denial as blacklist-caused
   * although no blacklist rule matched the path it was actually deciding.
   *
   * @param request the request being answered, never {@code null}
   * @return {@code true} when a blacklist rule denied this dispatch's own path
   */
  public static boolean denied(HttpServletRequest request) {
    return request.getRequestURI().equals(request.getAttribute(ATTRIBUTE));
  }
}
