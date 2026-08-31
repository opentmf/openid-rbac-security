package org.opentmf.security.config;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationDeniedException;

/**
 * The decision a blacklist rule denies with, distinguishable by type.
 *
 * <p>A denial has to be answered uniformly when the blacklist is what caused it, so that an
 * explicitly closed path discloses nothing about the methods behind it. Recognising that case by
 * matching the configured paths a second time inside the denied-request handler would mean two
 * independently built matchers for one set of rules, which can disagree. Instead the rule that
 * made the decision returns this subtype, Spring Security carries it to the handler inside
 * {@link AuthorizationDeniedException}, and the handler reads the decision rather than trying to
 * reconstruct it. The mark travels with the exception, not the request, so a later authorization
 * of the same request — an {@code ERROR} dispatch to {@code /error}, say — starts clean by
 * construction.
 *
 * @author Gokhan Demir
 */
public final class BlacklistDecision extends AuthorizationDecision {

  public static final BlacklistDecision INSTANCE = new BlacklistDecision();

  private BlacklistDecision() {
    super(false);
  }

  /**
   * Whether the given denial was decided by a blacklist rule.
   *
   * @param exception the exception the denied request is being answered with, never {@code null}
   * @return {@code true} when a blacklist rule made the decision
   */
  public static boolean causeOf(AccessDeniedException exception) {
    return exception instanceof AuthorizationDeniedException denied
        && denied.getAuthorizationResult() instanceof BlacklistDecision;
  }
}
