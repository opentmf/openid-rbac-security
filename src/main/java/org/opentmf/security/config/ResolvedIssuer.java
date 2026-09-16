package org.opentmf.security.config;

import java.util.List;
import org.springframework.core.io.Resource;

/**
 * One trusted issuer with every setting already resolved: claim names defaulted, and per-entry
 * values merged over the top-level ones. Both stacks build their decoders and converters from
 * this, so single-issuer and multi-issuer mode share one code path.
 *
 * @param name label used in startup logs only
 * @param issuer the {@code iss} value this entry accepts, or {@code null} in single-issuer mode,
 *     where the issuer is deliberately not checked (pre-2.3.0 behavior)
 * @param jwkSetUri where this issuer's signing keys come from
 * @param userClaim principal claim, already defaulted to {@code sub}
 * @param fallbackUserClaims claims tried when {@code userClaim} is absent, never {@code null}
 * @param authoritiesClaim roles claim, already defaulted to {@code roles}
 * @param audiences accepted {@code aud} values; empty means the audience is not validated
 * @param proxy the {@code host:port} proxy the JWK set is fetched through, or {@code null} to
 *     honour the JVM's proxy properties and the process environment
 * @author Gokhan Demir
 */
public record ResolvedIssuer(
    String name,
    String issuer,
    Resource jwkSetUri,
    String userClaim,
    List<String> fallbackUserClaims,
    String authoritiesClaim,
    List<String> audiences,
    String proxy) {

  /**
   * Whether this entry pins the {@code iss} claim. False only in single-issuer mode.
   */
  public boolean pinsIssuer() {
    return issuer != null;
  }
}
