package org.opentmf.security.model;

import org.springframework.http.HttpMethod;

/**
 * The HTTP methods that may be named in {@code allowed-endpoints} and
 * {@code secure-endpoints}, on both the main and the management sections.
 *
 * <p>This is deliberately narrower than Spring's {@link HttpMethod}, which admits every
 * verb. Three verbs are excluded on purpose:
 *
 * <ul>
 *   <li>{@code HEAD} — a rule declared for {@link #GET} is registered for {@code HEAD} as
 *       well, because Spring MVC and WebFlux both serve {@code HEAD} from the very same
 *       handler as {@code GET}. Allowing a separate {@code HEAD} entry would let a
 *       configuration declare different roles for the two, and only the first registered
 *       rule would ever apply — the other would be silently unreachable.
 *   <li>{@code OPTIONS} — never needs an entry. A CORS pre-flight is answered before the
 *       security chain sees it when CORS is configured, and when it is not configured an
 *       entry cannot help, since a browser needs {@code Access-Control-Allow-Origin}
 *       headers that no access rule can produce. A plain {@code OPTIONS} request is
 *       answered from the controller layer.
 *   <li>{@code TRACE} — echoes the request back to the caller and is a Cross-Site Tracing
 *       vector. There is no legitimate reason to grant it.
 * </ul>
 *
 * @author Gokhan Demir
 */
public enum EndpointMethod {

  /** Also grants {@code HEAD} on the same path, with the same authorities. */
  GET,

  /** Create. */
  POST,

  /** Full replace. */
  PUT,

  /** Partial update. */
  PATCH,

  /** Remove. */
  DELETE;

  /**
   * Returns the Spring {@link HttpMethod} this constant stands for.
   *
   * @return the equivalent {@link HttpMethod}, never {@code null}
   */
  public HttpMethod toHttpMethod() {
    return HttpMethod.valueOf(name());
  }
}
