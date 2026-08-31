package org.opentmf.security.config;

import java.util.Set;
import org.springframework.http.HttpMethod;

/**
 * What the application's handler mappings say about one request path.
 *
 * @param declared the HTTP methods explicitly mapped on the path, possibly empty
 * @param acceptsAnyMethod whether a handler on the path names no method, and so accepts every
 *     one of them
 * @author Gokhan Demir
 */
public record SupportedMethods(Set<HttpMethod> declared, boolean acceptsAnyMethod) {

  private static final SupportedMethods NOT_SERVED = new SupportedMethods(Set.of(), false);

  /**
   * The answer for a path no handler is mapped to — and the safe answer whenever the handler
   * mappings cannot be consulted.
   *
   * @return a result whose {@link #pathServed()} is {@code false}
   */
  public static SupportedMethods notServed() {
    return NOT_SERVED;
  }

  /**
   * Whether any handler is mapped to the path. Derived rather than carried: a mapping that
   * matches the path either names methods, which land in {@link #declared()}, or names none,
   * which sets {@link #acceptsAnyMethod()}. Carrying it separately would admit states no
   * producer can mean — "methods declared, but the path is not served" — that the decision in
   * {@link EndpointRules#allowedFor} would silently read as "leave the denial alone".
   *
   * @return {@code true} when the application serves this path
   */
  public boolean pathServed() {
    return !declared.isEmpty() || acceptsAnyMethod;
  }
}
