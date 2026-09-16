package org.opentmf.security.model;

/**
 * What happens at startup when an issuer's signing keys cannot be obtained — the JWK set is
 * unreachable, or a local file is missing. Governs the warm-up only: an outage after the keys
 * were once loaded is always served from the cached set.
 *
 * @author Gokhan Demir
 */
public enum JwksStartupFailure {

  /**
   * Log a warning naming the issuer and keep serving: bearer requests for that issuer answer
   * {@code 503} with {@code Retry-After} until a refresh succeeds. The default, so that a
   * deployment can boot ahead of its identity provider.
   */
  WARN,

  /**
   * Stop the application, naming the issuers, when the keys of <em>no</em> issuer could be
   * obtained. A deployment with at least one live issuer still boots and warns about the rest.
   */
  FAIL
}
