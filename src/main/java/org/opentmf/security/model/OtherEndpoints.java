package org.opentmf.security.model;

/**
 * Authorization policy applied to requests that are not matched by any explicit rule
 * (blacklist, whitelist, allowed-endpoints, secure-endpoints).
 *
 * <p>Used by both the main-port section ({@code opentmf.security.other-endpoints},
 * default {@link #DENY} for backward compatibility with the previously hard-coded
 * behavior) and the management-port section
 * ({@code opentmf.security.management.other-endpoints}, default {@link #AUTHENTICATED} —
 * actuator endpoints are well-known and consumers usually want every endpoint they
 * exposed via {@code management.endpoints.web.exposure.include} to be reachable with any
 * valid JWT, without enumerating each one).
 *
 * @author Gokhan Demir
 */
public enum OtherEndpoints {

  /**
   * Permit any request, no authentication. Useful in trusted-network deployments where
   * the network ACL is the security boundary.
   */
  ALLOW,

  /**
   * Deny any request. Every endpoint must be explicitly listed in
   * {@code allowed-endpoints} or {@code secure-endpoints} to be reachable.
   */
  DENY,

  /**
   * Require an authenticated JWT, no specific role.
   */
  AUTHENTICATED
}
