package org.opentmf.security.config;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import org.opentmf.security.model.Endpoint;
import org.opentmf.security.model.EndpointMethod;
import org.springframework.http.HttpMethod;
import org.springframework.util.StringUtils;

/**
 * Shared translation between the configured access rules and the HTTP methods they cover.
 *
 * @author Gokhan Demir
 */
public final class EndpointRules {

  private EndpointRules() {
    // Utility class.
  }

  /**
   * Returns the HTTP methods an access rule covers. A {@link EndpointMethod#GET} rule covers
   * {@code HEAD} as well, because Spring MVC and WebFlux both serve {@code HEAD} from the
   * handler mapped to {@code GET}; without this the framework would answer a {@code HEAD}
   * request that the security chain had already refused.
   *
   * @param endpoint the configured rule, never {@code null}
   * @return the methods to register the rule for, in registration order
   */
  public static HttpMethod[] httpMethodsFor(Endpoint endpoint) {
    HttpMethod method = endpoint.getMethod().toHttpMethod();
    return HttpMethod.GET.equals(method)
        ? new HttpMethod[] {HttpMethod.GET, HttpMethod.HEAD}
        : new HttpMethod[] {method};
  }

  /**
   * Decides whether a denied request should be answered with the methods the application serves
   * on its path, and which methods to name. Empty means the denial is none of this feature's
   * business and belongs to whatever handler would otherwise have answered it.
   *
   * <p>Stack-neutral on purpose: servlet and reactive must answer the same request the same way,
   * and a copy per stack would let them drift apart one fix at a time.
   *
   * @param requestMethod the method the caller used, never {@code null}
   * @param supported what the application's handler mappings say about the path
   * @return the methods to advertise, or empty to leave the denial alone
   */
  public static Optional<Set<HttpMethod>> allowedFor(
      HttpMethod requestMethod, SupportedMethods supported) {
    if (!supported.pathServed()) {
      return Optional.empty();
    }
    Set<HttpMethod> declared = supported.declared();
    if (HttpMethod.OPTIONS.equals(requestMethod)) {
      // An application that maps OPTIONS itself has an authorization answer to give, not ours.
      return declared.contains(HttpMethod.OPTIONS)
          ? Optional.empty()
          : Optional.of(optionsAllow(declared));
    }
    if (supported.acceptsAnyMethod() || serves(declared, requestMethod)) {
      return Optional.empty();
    }
    return Optional.of(declared);
  }

  /**
   * Mirrors Spring's own method matching, where a {@code HEAD} request is served by the handler
   * mapped to {@code GET}.
   */
  private static boolean serves(Set<HttpMethod> declared, HttpMethod method) {
    return declared.contains(method)
        || (HttpMethod.HEAD.equals(method) && declared.contains(HttpMethod.GET));
  }

  /**
   * Builds the {@code Allow} header value for an {@code OPTIONS} response, reproducing
   * Spring's own {@code HttpOptionsHandler}: the declared methods, plus {@code HEAD} when
   * {@code GET} is declared, plus {@code OPTIONS} itself. When nothing is declared — a
   * mapping that names no method accepts them all — Spring answers with every method except
   * {@code TRACE}, and so do we.
   *
   * @param declared the methods the application declares on the path, never {@code null}
   * @return the methods to advertise, never empty
   */
  public static Set<HttpMethod> optionsAllow(Set<HttpMethod> declared) {
    if (declared.isEmpty()) {
      return Arrays.stream(HttpMethod.values())
          .filter(method -> !HttpMethod.TRACE.equals(method))
          .collect(Collectors.toCollection(LinkedHashSet::new));
    }
    Set<HttpMethod> allowed = new LinkedHashSet<>(declared);
    if (allowed.contains(HttpMethod.GET)) {
      allowed.add(HttpMethod.HEAD);
    }
    allowed.add(HttpMethod.OPTIONS);
    return allowed;
  }

  /**
   * Renders the {@code Allow} value for a {@code 405}, the way Spring renders its own:
   * {@code HttpRequestMethodNotSupportedException.getHeaders()} joins with {@code ", "}.
   *
   * @param methods the methods to advertise, never {@code null}
   * @return the header value
   */
  public static String allowHeader(Set<HttpMethod> methods) {
    return StringUtils.collectionToDelimitedString(methods, ", ");
  }

  /**
   * Renders the {@code Allow} value for an {@code OPTIONS} response, the way Spring renders its
   * own: {@code HttpOptionsHandler} goes through {@code HttpHeaders.setAllow}, which joins with
   * a bare {@code ","}.
   *
   * <p>Yes, the two differ by a space — that is Spring's inconsistency, not ours, and matching
   * each path exactly is the point: whatever this library answers on a denied request should be
   * byte-identical to what the application answers when the same request is allowed through.
   *
   * @param methods the methods to advertise, never {@code null}
   * @return the header value
   */
  public static String optionsAllowHeader(Set<HttpMethod> methods) {
    return StringUtils.collectionToCommaDelimitedString(methods);
  }
}
