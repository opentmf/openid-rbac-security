package org.opentmf.security.config;

import java.util.Set;
import org.springframework.http.HttpMethod;

/**
 * What the application's handler mappings say about one request path.
 *
 * @param declared the HTTP methods explicitly mapped on the path, possibly empty
 * @param pathServed whether any handler is mapped to the path at all
 * @param acceptsAnyMethod whether a handler on the path names no method, and so accepts
 *     every one of them
 * @author Gokhan Demir
 */
public record SupportedMethods(
    Set<HttpMethod> declared, boolean pathServed, boolean acceptsAnyMethod) {

  private static final SupportedMethods NOT_SERVED = new SupportedMethods(Set.of(), false, false);

  /**
   * The answer for a path no handler is mapped to — and the safe answer whenever the handler
   * mappings cannot be consulted.
   *
   * @return a result whose {@link #pathServed()} is {@code false}
   */
  public static SupportedMethods notServed() {
    return NOT_SERVED;
  }
}
