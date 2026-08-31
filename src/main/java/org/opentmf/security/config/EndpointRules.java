package org.opentmf.security.config;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.stream.Collectors;
import org.opentmf.security.model.Endpoint;
import org.opentmf.security.model.EndpointMethod;
import org.springframework.http.HttpMethod;

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
   * Renders an {@code Allow} header value.
   *
   * @param methods the methods to advertise, never {@code null}
   * @return a comma-separated header value
   */
  public static String allowHeader(Set<HttpMethod> methods) {
    StringBuilder builder = new StringBuilder();
    for (HttpMethod method : methods) {
      if (!builder.isEmpty()) {
        builder.append(", ");
      }
      builder.append(method.name());
    }
    return builder.toString();
  }
}
