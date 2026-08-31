package org.opentmf.security.config;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;
import org.springframework.http.HttpMethod;

/**
 * What the application's handler mappings say about one request path.
 *
 * @param declared the HTTP methods explicitly mapped on the path, possibly empty; held in
 *     canonical order — see {@link #canonical}
 * @param acceptsAnyMethod whether a handler on the path names no method, and so accepts every
 *     one of them
 * @author Gokhan Demir
 */
public record SupportedMethods(Set<HttpMethod> declared, boolean acceptsAnyMethod) {

  public SupportedMethods {
    declared = canonical(declared);
  }

  /**
   * Imposes the one deterministic order there is: {@link HttpMethod#values()} order — GET,
   * HEAD, POST, PUT, PATCH, DELETE, OPTIONS, TRACE (the last two appearing only when the
   * application itself maps them). The handler mappings are consulted through an unordered view
   * whose iteration order is salted per JVM run (Spring's own registry is the same), so the
   * order has to be imposed somewhere for every {@code Allow} header derived from this record
   * to read identically run after run. Every producer fills {@code declared} from
   * {@code RequestMethod}, whose constants all appear in {@code values()}, so the loop is
   * exhaustive.
   */
  private static Set<HttpMethod> canonical(Set<HttpMethod> declared) {
    Set<HttpMethod> ordered = new LinkedHashSet<>();
    for (HttpMethod method : HttpMethod.values()) {
      if (declared.contains(method)) {
        ordered.add(method);
      }
    }
    return Collections.unmodifiableSet(ordered);
  }

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
